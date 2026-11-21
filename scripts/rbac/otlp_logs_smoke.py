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

"""Scoped OTLP log ingestion over HTTP and gRPC against fresh loopback SQLite/PostgreSQL servers."""

import argparse
import base64
import contextlib
import importlib.util
import os
import secrets
import shutil
import struct
import tempfile
import time
import uuid
from pathlib import Path

from alert_smoke import free_port
from http_smoke import Client, SmokeFailure, expect, query_payload, require, stream_resource
from pipeline_smoke import definition
from run_http_smoke import postgres, server

EXPORT = "/opentelemetry.proto.collector.logs.v1.LogsService/Export"


def varint(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def field(number, payload):
    return varint(number << 3 | 2) + varint(len(payload)) + payload


def any_string(value):
    return field(1, value.encode())


def key_value(key, value):
    return field(1, key.encode()) + field(2, any_string(value))


def protobuf_export(attributes, body="rbac otlp log"):
    now = time.time_ns()
    record = (varint(1 << 3 | 1) + struct.pack("<Q", now) + field(5, any_string(body))
              + b"".join(field(6, key_value(k, v)) for k, v in attributes.items())
              + varint(11 << 3 | 1) + struct.pack("<Q", now))
    resource = field(1, key_value("service.name", "rbac-otlp-smoke"))
    return field(1, field(1, resource) + field(2, field(2, record)))


def json_export(attributes, body="rbac otlp log"):
    now = str(time.time_ns())
    return {"resourceLogs": [{
        "resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "rbac-otlp-smoke"}}]},
        "scopeLogs": [{"logRecords": [{
            "timeUnixNano": now, "observedTimeUnixNano": now, "body": {"stringValue": body},
            "attributes": [{"key": k, "value": {"stringValue": v}} for k, v in attributes.items()],
        }]}],
    }]}


class GrpcCollector:
    def __init__(self, target, email, password, internal_token=None):
        import grpc

        self.grpc = grpc
        self.channel = grpc.insecure_channel(target)
        self.export = self.channel.unary_unary(EXPORT)
        credential = base64.b64encode(f"{email}:{password}".encode()).decode()
        self.authorization = internal_token or f"Basic {credential}"

    def send(self, org, stream, attributes, extra=()):
        metadata = [("authorization", self.authorization), ("organization", org),
                    ("stream-name", stream), *extra]
        try:
            self.export(protobuf_export(attributes), metadata=metadata, timeout=30)
            return self.grpc.StatusCode.OK
        except self.grpc.RpcError as error:
            return error.code()


def grpc_expect(collector, label, org, stream, attributes, code="OK", extra=()):
    actual = collector.send(org, stream, attributes, extra)
    if actual.name != code:
        raise SmokeFailure(f"{label}: expected gRPC {code}, received {actual.name}")
    print(f"PASS {label}", flush=True)


def http_export(client, label, org, stream, attributes, status=200):
    return expect(client, label, "POST", f"/api/{org}/v1/logs", json_export(attributes),
                  headers={"stream-name": stream}, status=status)


def rows(reader, org, stream, marker, start_time, expected, seconds=30):
    sql = f'SELECT * FROM "{stream}" WHERE marker = \'{marker}\''
    deadline = time.monotonic() + seconds
    while True:
        status, payload = reader.request("POST", f"/api/{org}/_search?type=logs", query_payload(sql, start_time))
        hits = payload.get("hits", []) if status == 200 and isinstance(payload, dict) else []
        if status == 200 and len(hits) == expected:
            print(f"PASS {stream} holds {expected} row(s) for marker", flush=True)
            return
        require(expected > 0 and time.monotonic() < deadline,
                f"{stream}: expected {expected} row(s) for marker, query returned HTTP {status} with {len(hits)}")
        time.sleep(1)


def absent(root, org, names, label):
    listed = expect(root, label, "GET", f"/api/{org}/streams?type=logs")
    present = {item["name"] for item in listed.get("list", [])}
    require(not present.intersection(names), f"{label}: denied export created {present.intersection(names)}")


def provision(root, url, second):
    users = {role: f"otlp-{role}-{uuid.uuid4().hex[:8]}@example.test" for role in ("collector", "viewer")}
    passwords = {role: secrets.token_urlsafe(24) + "Aa1!" for role in users}
    for role, email in users.items():
        expect(root, f"create {role} before enabling RBAC", "POST", "/api/default/users", {
            "email": email, "password": passwords[role], "first_name": "OTLP", "last_name": role,
            "role": "admin", "is_external": False})
    expect(root, "add collector to second organization", "POST", f"/api/{second}/users", {
        "email": users["collector"], "password": passwords["collector"], "first_name": "OTLP",
        "last_name": "collector", "role": "admin", "is_external": False})
    return users, {role: Client(url, users[role], passwords[role]) for role in users}, passwords


def disabled_compatibility(root, clients, grpc_collector, streams, start_time, label):
    for transport in ("http", "grpc"):
        marker = uuid.uuid4().hex
        stream = streams["finance"]
        if transport == "http":
            http_export(clients["collector"], f"{label}: HTTP export to any stream", "default", stream, {"marker": marker})
        else:
            grpc_expect(grpc_collector, f"{label}: gRPC export to any stream", "default", stream, {"marker": marker})
        rows(root, "default", stream, marker, start_time, 1)


def grant_policy(root, org, policy, grants):
    return expect(root, "replace policy", "PUT", f"/api/{org}/rbac/policy",
                  {"expected_version": policy["version"], "grants": grants})


def scoped_user_checks(root, clients, grpc_collector, target, token, streams, start_time, second):
    viewer, collector = clients["viewer"], clients["collector"]
    for transport in ("http", "grpc"):
        marker = uuid.uuid4().hex
        if transport == "http":
            http_export(collector, "HTTP collector writes authorized stream", "default", streams["api"], {"marker": marker})
            http_export(collector, "HTTP collector denied restricted stream", "default", streams["finance"], {"marker": marker}, 403)
            http_export(viewer, "HTTP Viewer cannot ingest", "default", streams["api"], {"marker": marker}, 403)
            http_export(collector, "HTTP collector denied in member-only second org", second, streams["api"], {"marker": marker}, 403)
        else:
            grpc_expect(grpc_collector, "gRPC collector writes authorized stream", "default", streams["api"], {"marker": marker})
            grpc_expect(grpc_collector, "gRPC collector denied restricted stream", "default", streams["finance"],
                        {"marker": marker}, "PERMISSION_DENIED")
            grpc_expect(GrpcCollector(target, *viewer_credentials(clients)), "gRPC Viewer cannot ingest", "default",
                        streams["api"], {"marker": marker}, "PERMISSION_DENIED")
            grpc_expect(grpc_collector, "gRPC collector denied in member-only second org", second, streams["api"],
                        {"marker": marker}, "PERMISSION_DENIED")
            forged = GrpcCollector(target, "", "", internal_token=token)
            grpc_expect(forged, "internal token cannot assert a collector user_id", "default", streams["api"],
                        {"marker": marker}, "PERMISSION_DENIED", extra=[("user_id", clients["collector_email"])])
        rows(viewer, "default", streams["api"], marker, start_time, 1)
        rows(viewer, "default", streams["finance"], marker, start_time, 0)
    absent(root, second, {streams["api"]}, "second organization received no stream")


def viewer_credentials(clients):
    return clients["viewer_email"], clients["viewer_password"]


def token_checks(root, root_email, url, target, policy, grants, streams, start_time, viewer):
    created = expect(root, "Admin creates org ingestion token", "POST", "/api/default/ingestion-tokens",
                     {"name": f"otlp-collector-{uuid.uuid4().hex[:8]}"})["data"]
    subjects = expect(root, "resolve token subject", "GET", "/api/default/rbac/subjects")
    subject = next(item["subject"] for item in subjects
                   if item.get("kind") == "ingestion_token" and item["name"] == created["name"])
    # The Basic username is deliberately privileged; only the verified token row may grant access.
    http_writer = Client(url, root_email, created["token"])
    grpc_writer = GrpcCollector(target, root_email, created["token"])
    marker = uuid.uuid4().hex
    http_export(http_writer, "unassigned token cannot borrow username grants", "default", streams["api"], {"marker": marker}, 403)
    grpc_expect(grpc_writer, "unassigned gRPC token cannot borrow username grants", "default", streams["api"],
                {"marker": marker}, "PERMISSION_DENIED")
    policy = grant_policy(root, "default", policy, grants + [
        {"subject": subject, "role": "ingester", "resources": [stream_resource(streams["api"])]}])
    http_export(http_writer, "scoped token writes authorized stream over HTTP", "default", streams["api"], {"marker": marker})
    grpc_expect(grpc_writer, "scoped token writes authorized stream over gRPC", "default", streams["api"], {"marker": marker})
    rows(viewer, "default", streams["api"], marker, start_time, 2)
    http_export(http_writer, "scoped token denied restricted stream over HTTP", "default", streams["finance"], {"marker": marker}, 403)
    grpc_expect(grpc_writer, "scoped token denied restricted stream over gRPC", "default", streams["finance"],
                {"marker": marker}, "PERMISSION_DENIED")
    expect(root, "disable token row", "PATCH", f"/api/default/ingestion-tokens/{created['name']}", {"enabled": False})
    grpc_status = grpc_writer.send("default", streams["api"], {"marker": marker})
    require(grpc_status.name in ("UNAUTHENTICATED", "PERMISSION_DENIED"), f"disabled gRPC token accepted: {grpc_status.name}")
    print("PASS disabled token denied over gRPC immediately", flush=True)
    http_export(http_writer, "disabled token denied over HTTP", "default", streams["api"], {"marker": marker}, 401)
    rows(viewer, "default", streams["api"], marker, start_time, 2)
    return policy


def pipeline_checks(root, collector, grpc_collector, policy, grants, collector_id, start_time, viewer_id):
    run = uuid.uuid4().hex[:8]
    source, outputs = f"otlp_fanout_src_{run}", [f"otlp_fanout_ok_{run}", f"otlp_fanout_secret_{run}"]
    created = expect(root, "Admin creates scoped fan-out pipeline", "POST", "/api/default/pipelines",
                     definition("default", source, outputs))
    viewer_grant = {"subject": viewer_id, "role": "viewer", "resources": [stream_resource(n) for n in outputs]}
    partial = {"subject": collector_id, "role": "ingester", "resources": [stream_resource(source), stream_resource(outputs[0])]}
    policy = grant_policy(root, "default", policy, grants + [partial, viewer_grant])
    attributes = {"marker": uuid.uuid4().hex, "route": "keep"}
    http_export(collector, "HTTP mixed pipeline destinations rejected", "default", source, attributes, 403)
    grpc_expect(grpc_collector, "gRPC mixed pipeline destinations rejected", "default", source, attributes, "PERMISSION_DENIED")
    absent(root, "default", {source, *outputs}, "mixed rejection wrote no pipeline stream")
    full = dict(partial, resources=[stream_resource(n) for n in [source, *outputs]])
    policy = grant_policy(root, "default", policy, grants + [full, viewer_grant])
    for transport in ("http", "grpc"):
        attributes = {"marker": uuid.uuid4().hex, "route": "keep"}
        if transport == "http":
            http_export(collector, "HTTP pipeline fan-out with every destination granted", "default", source, attributes)
        else:
            grpc_expect(grpc_collector, "gRPC pipeline fan-out with every destination granted", "default", source, attributes)
        for name in outputs:
            rows(root, "default", name, attributes["marker"], start_time, 1)
    expect(root, "delete generated pipeline", "DELETE", f"/api/default/pipelines/{created['id']}")
    return grant_policy(root, "default", policy, grants)


def enabled_suite(root, url, target, token, clients, users, streams, start_time, second):
    policy = expect(root, "bootstrap default organization", "POST", "/api/default/rbac/bootstrap")
    expect(root, "bootstrap second organization", "POST", f"/api/{second}/rbac/bootstrap")
    subjects = expect(root, "resolve fixture subjects", "GET", "/api/default/rbac/subjects")
    ids = {item["email"]: item["subject"] for item in subjects if "email" in item}
    collector_id, viewer_id = ids[users["collector"]], ids[users["viewer"]]
    grants = policy["grants"] + [
        {"subject": collector_id, "role": "ingester", "resources": [stream_resource(streams["api"])]},
        {"subject": viewer_id, "role": "viewer", "resources": [stream_resource(streams["api"]), stream_resource(streams["finance"])]},
    ]
    policy = grant_policy(root, "default", policy, grants)
    grpc_collector = GrpcCollector(target, users["collector"], clients["collector_password"])
    scoped_user_checks(root, clients, grpc_collector, target, token, streams, start_time, second)
    policy = token_checks(root, clients["root_email"], url, target, policy, grants, streams, start_time,
                          clients["viewer"])
    policy = pipeline_checks(root, clients["collector"], grpc_collector, policy, grants, collector_id, start_time, viewer_id)
    revoked = [grant for grant in grants if grant["subject"] != collector_id]
    policy = grant_policy(root, "default", policy, revoked)
    marker = uuid.uuid4().hex
    http_export(clients["collector"], "HTTP collector loses access immediately on revocation", "default",
                streams["api"], {"marker": marker}, 403)
    grpc_expect(grpc_collector, "gRPC collector loses access immediately on revocation", "default", streams["api"],
                {"marker": marker}, "PERMISSION_DENIED")
    rows(clients["viewer"], "default", streams["api"], marker, start_time, 0)
    return policy


def run(binary, store, directory):
    env = {key: value for key, value in os.environ.items() if not key.startswith(("ZO_", "O2_RBAC_"))}
    email, password = "otlp-root@example.test", secrets.token_urlsafe(32) + "Aa1!"
    token = secrets.token_urlsafe(32)
    http_port, grpc_port = free_port(), free_port()
    while grpc_port == http_port:
        grpc_port = free_port()
    url, target = f"http://127.0.0.1:{http_port}", f"127.0.0.1:{grpc_port}"
    root = Client(url, email, password)
    env.update(ZO_ROOT_USER_EMAIL=email, ZO_ROOT_USER_PASSWORD=password, ZO_INTERNAL_GRPC_TOKEN=token,
               ZO_META_STORE=store, ZO_LOCAL_MODE="true", ZO_NODE_ROLE="all", ZO_TELEMETRY="false",
               ZO_HTTP_ADDR="127.0.0.1", ZO_HTTP_PORT=str(http_port), ZO_GRPC_ADDR="127.0.0.1",
               ZO_GRPC_PORT=str(grpc_port), ZO_DATA_DIR=str(directory / "data") + "/")
    run_id = uuid.uuid4().hex[:8]
    streams = {"api": f"otlp_api_{run_id}", "finance": f"otlp_finance_{run_id}"}
    start_time = time.time_ns() // 1000 - 60_000_000
    with postgres() if store == "postgres" else contextlib.nullcontext({}) as database:
        env.update(database)
        with server(binary, directory, env, root, False):
            second = expect(root, "create second organization", "POST", "/api/organizations",
                            {"name": "otlp_rbac_second"})["identifier"]
            users, clients, passwords = provision(root, url, second)
            clients.update(root_email=email, collector_email=users["collector"],
                           collector_password=passwords["collector"],
                           viewer_email=users["viewer"], viewer_password=passwords["viewer"])
            grpc_collector = GrpcCollector(target, users["collector"], passwords["collector"])
            disabled_compatibility(root, clients, grpc_collector, streams, start_time, "RBAC disabled")
        with server(binary, directory, env, root, True):
            policy = enabled_suite(root, url, target, token, clients, users, streams, start_time, second)
        with server(binary, directory, env, root, False):
            disabled_compatibility(root, clients, grpc_collector, streams, start_time, "RBAC rolled back")
        with server(binary, directory, env, root, True):
            current = expect(root, "policy preserved across rollback", "GET", "/api/default/rbac/policy")
            require(current == policy, "rollback changed the policy or its version")
            grpc_expect(grpc_collector, "re-enabled RBAC keeps revoked collector denied", "default", streams["api"],
                        {"marker": uuid.uuid4().hex}, "PERMISSION_DENIED")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--store", choices=["sqlite", "postgres", "both"], default="sqlite")
    parser.add_argument("--acknowledge-disposable-fixture", action="store_true", required=True)
    args = parser.parse_args()
    binary = args.binary.resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        parser.error("--binary must point to the built OpenObserve executable")
    if importlib.util.find_spec("grpc") is None:
        parser.error("install grpcio for this Python interpreter")
    if args.store != "sqlite" and not shutil.which("docker"):
        parser.error("PostgreSQL fixtures require Docker")
    for store in (["sqlite", "postgres"] if args.store == "both" else [args.store]):
        directory = Path(tempfile.mkdtemp(prefix=f"openobserve-otlp-rbac-{store}-"))
        print(f"Running {store} OTLP log suite with isolated data in {directory}", flush=True)
        run(binary, store, directory)
        shutil.rmtree(directory)
        print(f"PASS {store} OTLP log HTTP and gRPC suite", flush=True)
