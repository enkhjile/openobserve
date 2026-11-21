#!/usr/bin/env python3
# Copyright 2026 OpenObserve Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""Check selected fail-closed gRPC boundaries on a disposable loopback RBAC server.

This sends empty protobuf requests only to the named methods. It proves denial
at these boundaries, not positive query authorization, all RPC coverage, job
identity propagation, PostgreSQL support, or production readiness. Run with
ZO_RBAC_ENABLED=true and the exact internal token configured on the fixture.
Requires grpcio; no generated protobuf modules or reflection service are used.
"""

import argparse
import ast
import ipaddress
import json
import os
import subprocess
import sys
import urllib.parse
import uuid
from pathlib import Path

import grpc


INTERNAL_METHODS = (
    ("/cluster.Metrics/Query", False),
    ("/cluster.Metrics/Data", True),
    ("/cluster.Metrics/WalMinTs", False),
    ("/cluster.Search/GetTable", False),
    ("/cluster.Search/GetSourcemapFile", False),
    ("/cluster.Event/GetFiles", True),
    ("/cluster.ClusterInfoService/GetDeleteJobStatus", False),
    ("/cluster.QueryCache/DeleteResultCache", False),
    ("/cluster.QueryCache/PublicDashboardStatus", False),
)
PUBLIC_METHODS = (
    "/opentelemetry.proto.collector.logs.v1.LogsService/Export",
    "/cluster.Streams/stream_stats",
)
INGEST_METHOD = "/cluster.Ingest/Ingest"
FORGED_USER = (("user_id", "rbac-smoke-forged@example.invalid"),)


class SmokeFailure(Exception):
    pass


def loopback_target(value):
    try:
        parsed = urllib.parse.urlsplit("//" + value)
        host, port = parsed.hostname, parsed.port
        if (parsed.netloc != value or parsed.path or parsed.query or parsed.fragment
                or parsed.username is not None or parsed.password is not None
                or port is None or not 1 <= port <= 65535):
            raise ValueError
        if host == "localhost":
            host = "127.0.0.1"
        address = ipaddress.ip_address(host or "")
        if not address.is_loopback:
            raise ValueError
    except ValueError:
        raise argparse.ArgumentTypeError(
            "target must be an explicit loopback host:port, e.g. 127.0.0.1:5081 or [::1]:5081"
        ) from None
    return f"[{address}]:{port}" if address.version == 6 else f"{address}:{port}"


def expect_denial(channel, method, metadata, streaming, timeout, label):
    call = channel.unary_stream(method) if streaming else channel.unary_unary(method)
    stream = None
    try:
        result = call(b"", metadata=metadata, timeout=timeout, wait_for_ready=False)
        if streaming:
            stream = result
            next(iter(stream), None)
    except grpc.RpcError as error:
        if error.code() != grpc.StatusCode.PERMISSION_DENIED:
            raise SmokeFailure(
                f"{label}: expected PERMISSION_DENIED, received {error.code().name}"
            ) from None
        print(f"PASS {label}: PERMISSION_DENIED", flush=True)
        return
    finally:
        if stream is not None:
            stream.cancel()
    raise SmokeFailure(f"{label}: RPC returned success instead of PERMISSION_DENIED")


def verify_search(target, org, subject, query, marker, revoked=False):
    target = loopback_target(target)
    schema = Path(__file__).resolve().parents[2] / "src/proto/proto"
    protoc = ["protoc", "-I", str(schema), "cluster/search.proto"]
    fields = {"trace_id": uuid.uuid4().hex, "org_id": org, "stream_type": "logs",
              "rbac_subject": subject, "request": json.dumps(query)}
    message = "\n".join(f"{key}: {json.dumps(value)}" for key, value in fields.items())
    request = subprocess.run(protoc + ["--encode=cluster.SearchRequest"], input=message.encode(),
                             capture_output=True, check=True).stdout
    with grpc.insecure_channel(target, options=(("grpc.enable_http_proxy", 0),)) as channel:
        search = channel.unary_unary("/cluster.Search/Search")
        try:
            response = search(request, timeout=30, metadata=(
                ("authorization", os.environ["O2_RBAC_INTERNAL_GRPC_TOKEN"]),))
        except grpc.RpcError as error:
            if revoked and error.code() == grpc.StatusCode.PERMISSION_DENIED:
                print("PASS revoked delegated subject denied by gRPC search", flush=True)
                return
            raise SmokeFailure(f"delegated search returned {error.code().name}") from None
    if revoked:
        raise SmokeFailure("revoked delegated search succeeded")
    decoded = subprocess.run(protoc + ["--decode=cluster.SearchResponse"], input=response,
                             capture_output=True, check=True).stdout.decode()
    payload = next(line.removeprefix("response: ") for line in decoded.splitlines()
                   if line.startswith("response: "))
    if not any(row.get("smoke_id") == marker for row in json.loads(ast.literal_eval(payload))["hits"]):
        raise SmokeFailure("delegated gRPC search did not return the fixture row")
    print("PASS authorized delegated gRPC search returned the fixture row", flush=True)


def run(args, token):
    authorization = (("authorization", token),)
    with grpc.insecure_channel(
        args.target, options=(("grpc.enable_http_proxy", 0),)
    ) as channel:
        try:
            grpc.channel_ready_future(channel).result(timeout=args.timeout)
        except grpc.FutureTimeoutError:
            raise SmokeFailure("disposable loopback gRPC server did not become ready") from None
        count = 0
        for method, streaming in INTERNAL_METHODS:
            expect_denial(channel, method, authorization, streaming, args.timeout,
                          f"{method} with valid internal token")
            count += 1
        for method in PUBLIC_METHODS:
            for label, metadata in (
                ("without credentials", ()),
                ("with forged user metadata", FORGED_USER),
                ("with internal token and forged user metadata", authorization + FORGED_USER),
            ):
                expect_denial(channel, method, metadata, False, args.timeout,
                              f"{method} {label}")
                count += 1
        for label, metadata in (
            ("with valid internal token", authorization),
            ("with internal token and forged user metadata", authorization + FORGED_USER),
        ):
            expect_denial(channel, INGEST_METHOD, metadata, False, args.timeout,
                          f"{INGEST_METHOD} {label}")
            count += 1
    print(f"PASS {count} selected gRPC denial assertions; positive authorization, other RPCs, jobs and PostgreSQL are not covered.")


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=loopback_target, required=True,
                        help="Explicit loopback gRPC host:port; plaintext disposable fixture only")
    parser.add_argument("--acknowledge-disposable-fixture", action="store_true", required=True,
                        help="Confirm that this is an isolated disposable RBAC-enabled server")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Connection/per-call deadline in seconds (1–30)")
    args = parser.parse_args()
    if not 1 <= args.timeout <= 30:
        parser.error("--timeout must be between 1 and 30 seconds")
    token = os.environ.get("O2_RBAC_INTERNAL_GRPC_TOKEN", "")
    if not token or not token.isascii() or any(ord(char) < 32 or ord(char) > 126 for char in token):
        parser.error("set O2_RBAC_INTERNAL_GRPC_TOKEN to the fixture's nonempty printable ASCII internal token")
    return args, token


if __name__ == "__main__":
    try:
        run(*arguments())
    except SmokeFailure as error:
        print(f"FAIL {error}", file=sys.stderr)
        raise SystemExit(1)
