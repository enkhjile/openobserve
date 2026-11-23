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

"""Run the HTTP and gRPC RBAC suites on fresh loopback SQLite and PostgreSQL fixtures."""

import argparse
import contextlib
import importlib.util
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from alert_smoke import free_port
from http_smoke import Client, expect, promql_result, require

SCRIPTS = Path(__file__).resolve().parent
ACK = "--acknowledge-disposable-fixture"


@contextlib.contextmanager
def postgres():
    name = "openobserve-rbac-" + secrets.token_hex(8)
    password = secrets.token_urlsafe(32)
    subprocess.run(["docker", "run", "--detach", "--rm", "--name", name,
                    "--publish", "127.0.0.1::5432", "--env", "POSTGRES_PASSWORD",
                    "--tmpfs", "/var/lib/postgresql/data", "postgres:16"],
                   env={**os.environ, "POSTGRES_PASSWORD": password}, check=True, stdout=subprocess.DEVNULL)
    try:
        port = subprocess.check_output(["docker", "port", name, "5432/tcp"], text=True).strip().split(":")[-1]
        for _ in range(90):
            if subprocess.run(["docker", "exec", name, "pg_isready", "-q", "-h", "127.0.0.1"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError("PostgreSQL fixture did not become ready")
        yield {"ZO_META_POSTGRES_DSN": f"postgresql://postgres:{password}@127.0.0.1:{int(port)}/postgres"}
    finally:
        subprocess.run(["docker", "stop", name], check=True, stdout=subprocess.DEVNULL)


@contextlib.contextmanager
def server(binary, directory, env, root, enabled):
    with (directory / "server.log").open("ab") as log:
        process = subprocess.Popen([binary], cwd=directory, env={**env, "ZO_RBAC_ENABLED": str(enabled).lower()},
                                   stdout=log, stderr=subprocess.STDOUT)
    try:
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError(f"OpenObserve exited before readiness; inspect {directory}/server.log")
            try:
                if root.request("GET", "/healthz")[0] == 200:
                    break
            except OSError:
                pass
            time.sleep(1)
        else:
            raise RuntimeError(f"OpenObserve readiness timed out; inspect {directory}/server.log")
        yield
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def run(binary, store, directory):
    env = {key: value for key, value in os.environ.items() if not key.startswith(("ZO_", "O2_RBAC_"))}
    email = "fixture-root@example.test"
    password = secrets.token_urlsafe(32) + "Aa1!"
    token = secrets.token_urlsafe(32)
    http_port, grpc_port = free_port(), free_port()
    while grpc_port == http_port:
        grpc_port = free_port()
    url = f"http://127.0.0.1:{http_port}"
    grpc_target = f"127.0.0.1:{grpc_port}"
    root = Client(url, email, password)
    env.update(ZO_ROOT_USER_EMAIL=email, ZO_ROOT_USER_PASSWORD=password, ZO_INTERNAL_GRPC_TOKEN=token,
               ZO_META_STORE=store, ZO_LOCAL_MODE="true", ZO_NODE_ROLE="all", ZO_TELEMETRY="false",
               ZO_HTTP_ADDR="127.0.0.1", ZO_HTTP_PORT=str(http_port), ZO_GRPC_ADDR="127.0.0.1",
               ZO_GRPC_PORT=str(grpc_port), ZO_DATA_DIR=str(directory / "data") + "/")
    with postgres() if store == "postgres" else contextlib.nullcontext({}) as database:
        env.update(database)
        with server(binary, directory, env, root, False):
            org = expect(root, "create second organization", "POST", "/api/organizations", {"name": "rbac_smoke_second"})
            legacy_email = "legacy-member@example.test"
            legacy_password = secrets.token_urlsafe(32) + "Aa1!"
            expect(root, "create legacy member before enabling RBAC", "POST", "/api/default/users",
                   {"email": legacy_email, "password": legacy_password, "first_name": "Legacy",
                    "last_name": "Fixture", "role": "admin", "is_external": False})
            legacy = Client(url, legacy_email, legacy_password)
            sampled_at = int(time.time())
            metrics = [{"__name__": name, "__type__": "gauge", "job": "rbac_smoke",
                        "_timestamp": sampled_at * 1000, "value": value}
                       for name, value in (("rbac_allowed_metric", 1.0), ("rbac_denied_metric", 2.0))]
            seeded = expect(root, "seed named metrics", "POST", "/api/default/ingest/metrics/_json", metrics)
            require(seeded.get("code") == 200, "metric fixture ingestion failed")
        with server(binary, directory, env, root, True):
            client_env = {**env, "O2_RBAC_ROOT_EMAIL": email, "O2_RBAC_ROOT_PASSWORD": password,
                          "O2_RBAC_INTERNAL_GRPC_TOKEN": token, "O2_RBAC_FIXTURE_GRPC_TARGET": grpc_target}
            subprocess.run([sys.executable, SCRIPTS / "http_smoke.py", "--url", url,
                            "--disposable-org", "default", "--second-disposable-org", org["identifier"],
                            "--allowed-metric", "rbac_allowed_metric", "--denied-metric", "rbac_denied_metric",
                            "--metric-time", str(sampled_at), ACK], env=client_env, check=True)
            subprocess.run([sys.executable, SCRIPTS / "grpc_smoke.py", "--target", grpc_target, ACK],
                           env=client_env, check=True)
            metric = f"/api/default/prometheus/api/v1/query?query=rbac_denied_metric&time={sampled_at + 1}"
            policy_path = "/api/default/rbac/policy"
            policy = expect(root, "capture final policy before rollback", "GET", policy_path)
            expect(legacy, "enabled RBAC denies legacy member", "GET", metric, status=403)
        with server(binary, directory, env, root, False):
            payload = expect(legacy, "legacy credentials read stored sample after rollback", "GET", metric)
            series = promql_result(payload, "rollback sample")
            require(any(item["metric"].get("job") == "rbac_smoke" and float(item["value"][1]) == 2.0
                        for item in series), "rollback did not return the preexisting gauge sample")
        with server(binary, directory, env, root, True):
            current = expect(root, "retrieve policy after re-enabling RBAC", "GET", policy_path)
            require(current == policy, "rollback changed the policy or its version")
            expect(legacy, "re-enabled RBAC denies same member and sample", "GET", metric, status=403)



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--store", choices=["sqlite", "postgres", "both"], default="both")
    args = parser.parse_args()
    binary = args.binary.resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        parser.error("--binary must point to the built OpenObserve executable")
    if importlib.util.find_spec("grpc") is None or not shutil.which("protoc"):
        parser.error("install grpcio for this Python interpreter and make protoc available on PATH")
    if args.store != "sqlite" and not shutil.which("docker"):
        parser.error("PostgreSQL fixtures require Docker")
    for store in (["sqlite", "postgres"] if args.store == "both" else [args.store]):
        directory = Path(tempfile.mkdtemp(prefix=f"openobserve-rbac-{store}-"))
        print(f"Running {store} suite with isolated data in {directory}", flush=True)
        run(binary, store, directory)
        shutil.rmtree(directory)
        print(f"PASS {store} HTTP and gRPC suites", flush=True)
