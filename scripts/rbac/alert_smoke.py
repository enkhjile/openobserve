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

"""Run scoped scheduled-alert checks in a new local SQLite instance and loopback sink."""

import argparse
import copy
import http.server
import json
import os
import pathlib
import queue
import secrets
import socket
import sqlite3
import subprocess
import tempfile
import threading
import time
import urllib.request

from http_smoke import Client, expect, require, ingest, await_visible, stream_resource


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def run(binary):
    fixture = pathlib.Path(tempfile.mkdtemp(prefix="o2-rbac-alerts-"))
    deliveries = queue.Queue()

    class Sink(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            payload = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            deliveries.put((time.monotonic(), payload))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *_args):
            pass

    sink = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Sink)
    threading.Thread(target=sink.serve_forever, daemon=True).start()
    email, password = "rbac-root@example.com", secrets.token_urlsafe(32) + "Aa1!"
    http_port, grpc_port = free_port(), free_port()
    env = {key: value for key, value in os.environ.items() if not key.startswith(("ZO_", "O2_RBAC_"))}
    env.update(ZO_ROOT_USER_EMAIL=email, ZO_ROOT_USER_PASSWORD=password,
               ZO_HTTP_ADDR="127.0.0.1", ZO_HTTP_PORT=str(http_port),
               ZO_GRPC_ADDR="127.0.0.1", ZO_GRPC_PORT=str(grpc_port),
               ZO_LOCAL_MODE="true", ZO_META_STORE="sqlite", ZO_NODE_ROLE="all",
               ZO_DATA_DIR=str(fixture / "data") + "/", ZO_TELEMETRY="false",
               ZO_INTERNAL_GRPC_TOKEN=secrets.token_urlsafe(32),
               ZO_ALERT_SCHEDULE_INTERVAL="1", ZO_SSRF_ALLOW_LOOPBACK="true")
    url = f"http://127.0.0.1:{http_port}"
    root = Client(url, email, password)
    process = None

    def stop():
        nonlocal process
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        process = None

    def start(enabled):
        nonlocal process
        env["ZO_RBAC_ENABLED"] = str(enabled).lower()
        with (fixture / f"server-{enabled}.log").open("ab") as log:
            process = subprocess.Popen([str(binary)], cwd=fixture, env=env, stdout=log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            require(process.poll() is None, f"server exited; see {fixture}")
            try:
                status, _ = root.request("GET", "/healthz")
                if status == 200:
                    return
            except OSError:
                pass
            time.sleep(1)
        raise AssertionError("isolated server readiness timed out")

    def fixture_row(sql, parameters):
        for path in (fixture / "data").rglob("*"):
            if path.is_file() and path.suffix in (".db", ".sqlite", ".sqlite3"):
                try:
                    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as db:
                        row = db.execute(sql, parameters).fetchone()
                        if row:
                            return row
                except sqlite3.DatabaseError:
                    continue
        raise AssertionError("fixture database row not found")

    def stored_subject(alert_id):
        return fixture_row("SELECT execution_subject FROM alerts WHERE id = ?", (alert_id,))[0]

    def await_delivery(label, timeout=90):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                _when, payload = deliveries.get(timeout=1)
                require(json.loads(payload)["fixture"] == "rbac-alert", "unexpected notification payload")
                print("PASS " + label, flush=True)
                return
            except queue.Empty:
                pass
        raise AssertionError(label + f" timed out; see {fixture}")

    def no_delivery(label):
        time.sleep(1)
        while not deliveries.empty():
            deliveries.get_nowait()
        sql = "SELECT claim_epoch, status FROM scheduled_jobs WHERE module_key = ?"
        baseline = fixture_row(sql, (alert_id,))[0]
        deadline = time.monotonic() + 150
        while time.monotonic() < deadline:
            try:
                deliveries.get(timeout=0.5)
                raise AssertionError(label + ": unexpected notification")
            except queue.Empty:
                epoch, status = fixture_row(sql, (alert_id,))
                if epoch > baseline and status == 0:
                    try:
                        deliveries.get(timeout=2)
                    except queue.Empty:
                        print("PASS " + label + " after completed scheduler claim", flush=True)
                        return
                    raise AssertionError(label + ": late notification")
        raise AssertionError(label + ": scheduler did not complete a new claim")

    org = "/api/default"
    alerts = "/api/v2/default/alerts"
    editor_email, editor_password = "alert-editor@example.com", secrets.token_urlsafe(32) + "Aa1!"
    editor = Client(url, editor_email, editor_password)
    draft = {"name": "scoped_sql", "stream_type": "logs", "stream_name": "allowed",
             "is_real_time": False, "query_condition": {"type": "sql", "sql": 'SELECT id FROM "allowed"'},
             "trigger_condition": {"period": 5, "operator": ">=", "threshold": 1,
                                   "frequency_type": "cron", "cron": "*/5 * * * * *", "silence": 0},
             "destinations": ["local_sink"], "enabled": True}
    try:
        print(f"Disposable alert fixture: {fixture}", flush=True)
        start(False)
        expect(root, "create local custom template", "POST", org + "/alerts/templates",
               {"name": "local_template", "type": "http", "kind": "custom", "body": '{"fixture":"rbac-alert"}'})
        expect(root, "create loopback destination", "POST", org + "/alerts/destinations",
               {"name": "local_sink", "type": "http", "method": "post",
                "url": f"http://127.0.0.1:{sink.server_port}/notification", "template": "local_template"})
        stop()
        start(True)
        policy = expect(root, "bootstrap disposable alert organization", "POST", org + "/rbac/bootstrap")
        expect(root, "create scoped alert editor", "POST", org + "/users",
               {"email": editor_email, "password": editor_password, "first_name": "Alert", "last_name": "Fixture",
                "role": "admin", "is_external": False})
        subjects = expect(root, "resolve alert editor UUID", "GET", org + "/rbac/subjects")
        subject = next(item["subject"] for item in subjects if item["email"] == editor_email)
        resource = stream_resource("allowed")
        alert_resource = {"kind": "alert", "stream_type": "", "name": "*"}
        grants = policy["grants"] + [{"subject": subject, "role": "editor", "resources": [resource, alert_resource]}]
        policy = expect(root, "grant scoped alert rights", "PUT", org + "/rbac/policy",
                        {"expected_version": policy["version"], "grants": grants})
        ingest(root, "ingest allowed scheduler data", org, "allowed", "alert-fixture")
        ingest(root, "ingest restricted scheduler data", org, "secret", "alert-fixture")
        await_visible(editor, org, 'SELECT id, smoke_id FROM "allowed"', time.time_ns() // 1000 - 60_000_000,
                      "alert-fixture", 30)
        expect(editor, "unapproved destination denied on save", "POST", alerts, draft, status=403)
        policy = expect(root, "approve exact destination/source binding", "PUT", org + "/rbac/destinations",
                        {"expected_version": policy["version"], "approvals": [{"destination_name": "local_sink", "sources": [resource]}]})
        available = expect(editor, "editor sees only approved destination names", "POST",
                           org + "/rbac/destinations/available", {"sql": 'SELECT id FROM "allowed"', "stream_type": "logs"})
        require(available == [{"name": "local_sink"}], "destination picker disclosed unapproved metadata")
        for sql in ['SELECT id FROM "secret"', ""]:
            expect(editor, "unauthorized destination lookup denied", "POST", org + "/rbac/destinations/available",
                   {"sql": sql, "stream_type": "logs"}, status=403)
        expect(editor, "editor cannot approve destinations", "PUT", org + "/rbac/destinations",
               {"expected_version": policy["version"], "approvals": []}, status=403)
        restricted = copy.deepcopy(draft)
        restricted["query_condition"]["sql"] = 'SELECT id FROM "secret"'
        restricted["owner"] = email
        restricted["execution_subject"] = next(item["subject"] for item in subjects if item["email"] == email)
        expect(editor, "forged principal cannot authorize restricted SQL", "POST", alerts, restricted, status=403)
        unsafe = copy.deepcopy(draft)
        unsafe["is_real_time"] = True
        expect(editor, "realtime remains denied", "POST", alerts, unsafe, status=403)
        draft["owner"] = email
        draft["execution_subject"] = restricted["execution_subject"]
        created = expect(editor, "create approved scheduled SQL alert", "POST", alerts, draft)
        alert_id = created["id"]
        require(stored_subject(alert_id) == subject, "alert persisted untrusted owner/client principal")
        expect(editor, "read scoped alert", "GET", alerts + "/" + alert_id)
        hidden = copy.deepcopy(draft)
        hidden.update(name="aaa_hidden", enabled=False)
        hidden_id = expect(root, "create unlisted alert", "POST", alerts, hidden)["id"]
        stop()
        start(False)
        composite_id = expect(root, "seed pre-RBAC composite", "POST", alerts,
                              {"name": "legacy_parent", "alert_type": "composite", "enabled": False,
                               "composite_condition": {"expression": f"{{{alert_id}}} && {{{hidden_id}}}"}})["id"]
        stop()
        start(True)
        scoped_grants = copy.deepcopy(grants)
        scoped_grants[-1]["resources"] = [resource, {**alert_resource, "name": alert_id}]
        policy = expect(root, "replace wildcard with a single alert grant", "PUT", org + "/rbac/policy",
                        {"expected_version": policy["version"], "grants": scoped_grants})
        listed = expect(editor, "list named alert before pagination", "GET", alerts + "?sort_by=name&page_size=1")
        observed_ids = [item["alert_id"] for item in listed["list"]]
        require(observed_ids == [alert_id], f"expected first-page alert {alert_id}, received {observed_ids}")
        require(listed["list"][0]["referenced_by_composite_count"] == 0, "hidden parent count leaked")
        listed = expect(editor, "hidden alert query yields no metadata", "GET", alerts + "?alert_name_substring=aaa_hidden")
        require(listed["list"] == [], "unpermitted alert name leaked")
        expect(editor, "named alert grant denies hidden detail", "GET", alerts + "/" + hidden_id, status=403)
        conflict = expect(editor, "hidden parent omitted from deletion conflict", "DELETE", alerts + "/" + alert_id,
                          status=409)
        require(conflict["references"] == [] and conflict["hidden_reference_count"] == 0,
                "deletion conflict exposed hidden parent metadata")
        scoped_grants[-1]["resources"] = [resource, {**alert_resource, "name": composite_id}]
        policy = expect(root, "assign only the legacy composite", "PUT", org + "/rbac/policy",
                        {"expected_version": policy["version"], "grants": scoped_grants})
        listed = expect(editor, "merged collection respects exact composite grant", "GET", alerts)["list"]
        require([item["alert_id"] for item in listed] == [composite_id], "merged list disclosed or dropped IDs")
        require(listed[0].get("expression_summary") is None and listed[0].get("child_count") is None,
                "composite exposed hidden child names or counts")
        detail = expect(editor, "composite detail masks hidden operands", "GET", alerts + "/" + composite_id)
        require(detail["children"] == [] and detail["composite_condition"]["expression"] is None
                and detail["evaluation"] is None, "composite detail disclosed unavailable operands")
        scoped_grants[-1]["resources"].append({**alert_resource, "name": alert_id})
        policy = expect(root, "grant one composite operand", "PUT", org + "/rbac/policy",
                        {"expected_version": policy["version"], "grants": scoped_grants})
        detail = expect(editor, "mixed composite detail retains only granted child", "GET", alerts + "/" + composite_id)
        require([child["alert_id"] for child in detail["children"]] == [alert_id]
                and detail["composite_condition"]["expression"] is None,
                "composite detail omitted authorized child or exposed restricted expression")
        scoped_grants[-1]["resources"] = [resource]
        policy = expect(root, "remove remaining alert grants", "PUT", org + "/rbac/policy",
                        {"expected_version": policy["version"], "grants": scoped_grants})
        require(expect(editor, "stream-only member lists no alerts", "GET", alerts)["list"] == [],
                "stream-only membership exposed alerts")
        policy = expect(root, "restore alert fixture grants", "PUT", org + "/rbac/policy",
                        {"expected_version": policy["version"], "grants": grants})
        expect(root, "remove pre-RBAC composite fixture", "DELETE", alerts + "/" + composite_id)
        # Earlier runs queued deliveries, some while RBAC was off; only a fresh one proves this one.
        while not deliveries.empty():
            deliveries.get_nowait()
        await_delivery("scheduled SQL delivers to approved loopback sink")
        grants[-1]["resources"] = [alert_resource]
        policy = expect(root, "revoke editor source query rights", "PUT", org + "/rbac/policy",
                        {"expected_version": policy["version"], "grants": grants})
        no_delivery("scheduled delivery stops after query grant revocation")
        grants[-1]["resources"] = [resource, alert_resource]
        policy = expect(root, "restore editor source query rights", "PUT", org + "/rbac/policy",
                        {"expected_version": policy["version"], "grants": grants})
        await_delivery("scheduled execution recovers after current grant restoration")
        alert_path = alerts + "/" + alert_id
        saver = stored_subject(alert_id)
        expect(root, "another Writer disables the alert", "PATCH", alert_path + "/enable?value=false")
        require(expect(editor, "read disabled alert", "GET", alert_path).get("enabled") is False,
                "alert disable did not apply")
        expect(root, "another Writer re-enables the alert", "PATCH", alert_path + "/enable?value=true")
        expect(root, "another Writer triggers the alert by hand", "PATCH", alert_path + "/trigger")
        require(stored_subject(alert_id) == saver, "a toggle or trigger replaced the alert's run-as identity")
        print("PASS a toggled alert keeps its saver's identity", flush=True)
        policy = expect(root, "revoke destination approval", "PUT", org + "/rbac/destinations",
                        {"expected_version": policy["version"], "approvals": []})
        no_delivery("scheduled delivery stops after destination approval revocation")
        expect(editor, "delete scoped alert", "DELETE", alert_path)
        print("PASS scheduled SQL alert isolation and revocation", flush=True)
    finally:
        stop()
        sink.shutdown()
        sink.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=pathlib.Path, required=True)
    parser.add_argument("--acknowledge-disposable-fixture", action="store_true", required=True)
    args = parser.parse_args()
    require(args.binary.resolve().is_file(), "binary does not exist")
    run(args.binary.resolve())
