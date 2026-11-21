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

"""Exercise scoped visual reports using a fresh local instance, Chrome, and an SMTP sink."""

import argparse
import copy
import email
import email.policy
import os
import pathlib
import queue
import secrets
import signal
import shutil
import socketserver
import sqlite3
import subprocess
import tempfile
import threading
import time

from alert_smoke import free_port
from http_smoke import Client, expect, require, ingest, await_visible, stream_resource


def run(binary, chrome):
    fixture = pathlib.Path(tempfile.mkdtemp(prefix="o2-rbac-reports-"))
    deliveries = queue.Queue()

    class SMTP(socketserver.StreamRequestHandler):
        def handle(self):
            self.wfile.write(b"220 local fixture\r\n")
            recipients = []
            while line := self.rfile.readline():
                verb = line.split(b" ", 1)[0].strip().upper()
                if verb == b"DATA":
                    self.wfile.write(b"354 Send message\r\n")
                    parts = []
                    while (part := self.rfile.readline()) not in (b".\r\n", b""):
                        parts.append(part[1:] if part.startswith(b"..") else part)
                    deliveries.put((recipients[:], b"".join(parts)))
                    self.wfile.write(b"250 accepted\r\n")
                elif verb == b"RCPT":
                    recipients.append(line.decode().strip().split(":", 1)[1].strip().strip("<>"))
                    self.wfile.write(b"250 accepted\r\n")
                elif verb == b"QUIT":
                    self.wfile.write(b"221 bye\r\n")
                    return
                elif verb == b"EHLO":
                    self.wfile.write(b"250-local fixture\r\n250 8BITMIME\r\n")
                else:
                    if verb in (b"MAIL", b"RSET"):
                        recipients.clear()
                    self.wfile.write(b"250 ok\r\n")

    smtp = socketserver.ThreadingTCPServer(("127.0.0.1", 0), SMTP)
    threading.Thread(target=smtp.serve_forever, daemon=True).start()
    root_email, root_password = "root@example.com", secrets.token_urlsafe(32) + "Aa1!"
    renderer_email, renderer_password = "renderer@example.com", secrets.token_urlsafe(32) + "Aa1!"
    author_email, author_password = "author@example.com", secrets.token_urlsafe(32) + "Aa1!"
    recipient = author_email
    http_port, grpc_port = free_port(), free_port()
    url = f"http://127.0.0.1:{http_port}"
    env = {key: value for key, value in os.environ.items() if not key.startswith(("ZO_", "O2_RBAC_"))}
    env.update(RUST_LOG="warn,openobserve_core::dashboards::reports=debug", ZO_ROOT_USER_EMAIL=root_email, ZO_ROOT_USER_PASSWORD=root_password,
               ZO_HTTP_ADDR="127.0.0.1", ZO_HTTP_PORT=str(http_port), ZO_GRPC_ADDR="127.0.0.1",
               ZO_GRPC_PORT=str(grpc_port), ZO_LOCAL_MODE="true", ZO_META_STORE="sqlite",
               ZO_NODE_ROLE="all", ZO_DATA_DIR=str(fixture / "data") + "/", ZO_TELEMETRY="false",
               ZO_INTERNAL_GRPC_TOKEN=secrets.token_urlsafe(32), ZO_WEB_URL=url,
               ZO_REPORT_USER_NAME=renderer_email, ZO_REPORT_USER_EMAIL=renderer_email,
               ZO_REPORT_USER_PASSWORD=renderer_password, ZO_REPORT_SERVER_URL="", ZO_CHROME_ENABLED="true",
               ZO_CHROME_PATH=str(chrome), ZO_CHROME_AUTO_DOWNLOAD="false", ZO_CHROME_SLEEP_SECS="20",
               ZO_SMTP_ENABLED="true", ZO_SMTP_HOST="127.0.0.1", ZO_SMTP_PORT=str(smtp.server_address[1]),
               ZO_SMTP_FROM_EMAIL="fixture@example.test", ZO_SMTP_ENCRYPTION="none", ZO_ALERT_SCHEDULE_INTERVAL="1")
    root, author = Client(url, root_email, root_password), Client(url, author_email, author_password)
    process = None
    author.timeout = 180

    def stop():
        nonlocal process
        if process and process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        process = None

    def start(enabled):
        nonlocal process
        env["ZO_RBAC_ENABLED"] = str(enabled).lower()
        with (fixture / f"server-{enabled}.log").open("ab") as log:
            process = subprocess.Popen([str(binary)], cwd=fixture, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        for _ in range(180):
            require(process.poll() is None, f"server exited; see {fixture}")
            try:
                if root.request("GET", "/healthz")[0] == 200:
                    return
            except OSError:
                pass
            time.sleep(1)
        raise AssertionError("server readiness timeout")

    def row(sql, args):
        for path in (fixture / "data").rglob("*"):
            if path.is_file() and path.suffix in (".db", ".sqlite", ".sqlite3"):
                try:
                    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as db:
                        result = db.execute(sql, args).fetchone()
                        if result:
                            return result
                except sqlite3.DatabaseError:
                    pass
        raise AssertionError("fixture row missing")

    org = "/api/default"
    reports = "/api/v2/default/reports"
    dashboard = {"version": 8, "title": "Scoped report", "description": "Disposable fixture",
                 "tabs": [{"tabId": "main", "name": "Main", "panels": [{
                     "id": "panel1", "type": "table", "title": "Authorized rows", "description": "",
                     "config": {"show_legends": False}, "queryType": "sql",
                     "layout": {"x": 0, "y": 0, "w": 24, "h": 12, "i": 0},
                     "queries": [{"query": 'SELECT id, smoke_id FROM "report_logs"', "customQuery": True,
                                  "fields": {"stream": "report_logs", "stream_type": "logs", "x": [
                                      {"label": "ID", "alias": "id", "column": "id", "color": None},
                                      {"label": "Fixture", "alias": "smoke_id", "column": "smoke_id", "color": None}],
                                             "y": [], "z": [], "filter": {"filterType": "group", "logicalOperator": "AND", "conditions": []}}, "config": {"promql_legend": ""}}]}]}]}
    try:
        print(f"Disposable report fixture: {fixture}", flush=True)
        start(False)
        for user, password in [(author_email, author_password), (renderer_email, renderer_password)]:
            expect(root, "create dedicated report identity", "POST", org + "/users",
                   {"email": user, "password": password, "first_name": "Report", "last_name": "Fixture",
                    "role": "admin", "is_external": False})
        expect(root, "create mail template", "POST", org + "/alerts/templates",
               {"name": "mail_template", "type": "email", "kind": "custom", "body": "Approved report", "title": "Report"})
        expect(root, "create approved recipient destination", "POST", org + "/alerts/destinations",
               {"name": "approved_mail", "type": "email", "emails": [recipient], "template": "mail_template"})
        saved = expect(root, "create static SQL dashboard", "POST", org + "/dashboards", dashboard)
        dashboard_id = saved["v8"]["dashboardId"]
        stop()
        start(True)
        policy = expect(root, "bootstrap report fixture", "POST", org + "/rbac/bootstrap")
        subjects = expect(root, "resolve report identities", "GET", org + "/rbac/subjects")
        identities = {item["email"]: item["subject"] for item in subjects}
        source = stream_resource("report_logs")
        board = {"kind": "dashboard", "stream_type": "", "name": dashboard_id}
        grants = policy["grants"] + [
            {"subject": identities[author_email], "role": "editor", "resources": [{"kind": "report", "stream_type": "", "name": "*"}]},
            {"subject": identities[author_email], "role": "viewer", "resources": [board]},
            {"subject": identities[author_email], "role": "exporter", "resources": [source]},
            {"subject": identities[renderer_email], "role": "viewer", "resources": [board]},
            {"subject": identities[renderer_email], "role": "exporter", "resources": [source]}]
        policy = expect(root, "grant bounded author and renderer scopes", "PUT", org + "/rbac/policy",
                        {"expected_version": policy["version"], "grants": grants})
        policy = expect(root, "approve report recipient and source binding", "PUT", org + "/rbac/destinations",
                        {"expected_version": policy["version"], "approvals": [{"destination_name": "approved_mail", "sources": [source]}]})
        ingest(root, "ingest report data", org, "report_logs", "report-fixture")
        await_visible(author, org, 'SELECT id, smoke_id FROM "report_logs"', time.time_ns() // 1000 - 60_000_000,
                      "report-fixture", 30)
        draft = {"name": "scoped_visual", "title": "Scoped visual report", "orgId": "default",
                 "frequency": {"type": "weeks", "interval": 1}, "enabled": False, "timezone": "UTC",
                 "message": '<img src="https://example.invalid/report-probe">',
                 "dashboards": [{"dashboard": dashboard_id, "folder": "default", "tabs": ["main"],
                                 "timerange": {"type": "relative", "period": "15m", "from": 0, "to": 0}}],
                 "destinations": [{"email": recipient}], "deliveryDestinations": ["approved_mail"],
                 "executionContext": {"author_subject": identities[root_email], "renderer_subject": identities[root_email]}}
        unsafe = copy.deepcopy(draft)
        unsafe["destinations"] = [{"email": "unapproved@example.test"}]
        expect(author, "unapproved report recipient denied", "POST", reports, unsafe, status=403)
        excess = {"subject": identities[renderer_email], "role": "viewer",
                  "resources": [{"kind": "dashboard", "stream_type": "", "name": "*"}]}
        policy = expect(root, "exercise excessive renderer scope", "PUT", org + "/rbac/policy",
                        {"expected_version": policy["version"], "grants": grants + [excess]})
        expect(author, "broad renderer grant set denied", "POST", reports, draft, status=403)
        policy = expect(root, "restore exact renderer scope", "PUT", org + "/rbac/policy",
                        {"expected_version": policy["version"], "grants": grants})
        expect(author, "create scoped visual report", "POST", reports, draft)
        report_id, context = row("SELECT id, execution_context FROM reports WHERE name = ?", (draft["name"],))
        import json
        require(json.loads(context)["author_subject"] == identities[author_email], "forged execution context persisted")
        hidden = {**draft, "name": "hidden_list_fixture"}
        expect(author, "create report outside named grant", "POST", reports, hidden)
        hidden_id = row("SELECT id FROM reports WHERE name = ?", (hidden["name"],))[0]
        scoped_grants = copy.deepcopy(grants)
        for grant in scoped_grants:
            if grant["subject"] == identities[author_email] and grant["role"] == "editor":
                grant["role"] = "viewer"
                grant["resources"] = [{"kind": "report", "stream_type": "", "name": report_id}]
        policy = expect(root, "assign Viewer on one report", "PUT", org + "/rbac/policy",
                        {"expected_version": policy["version"], "grants": scoped_grants})
        listed = expect(author, "Viewer discovers only the named report", "GET", reports)
        require([item["report_id"] for item in listed] == [report_id], "report list disclosed or dropped an ID")
        renderer = Client(url, renderer_email, renderer_password)
        require(expect(renderer, "renderer lists no reports", "GET", reports) == [],
                "dashboard and export grants exposed reports")
        expect(author, "Viewer cannot open hidden report", "GET", reports + "/" + hidden_id, status=403)
        policy = expect(root, "restore report fixture grants", "PUT", org + "/rbac/policy",
                        {"expected_version": policy["version"], "grants": grants})
        result = expect(author, "trigger complete scoped browser report", "PUT", reports + "/" + report_id + "/trigger")
        recipients, message = deliveries.get(timeout=30)
        require(recipients == [recipient], "SMTP envelope escaped approved recipient")
        parsed = email.message_from_bytes(message, policy=email.policy.default)
        pdf = next(part.get_payload(decode=True) for part in parsed.walk() if part.get_content_type() == "application/pdf")
        require(pdf.startswith(b"%PDF"), "report did not deliver a PDF")
        (fixture / "approved-report.pdf").write_bytes(pdf)
        extracted = subprocess.run(["pdftotext", "-", "-"], input=pdf, stdout=subprocess.PIPE, check=True).stdout
        require(b"report-fixture" in extracted, "rendered PDF does not contain the authorized fixture row")
        html = next(part.get_content() for part in parsed.walk() if part.get_content_type() == "text/html")
        require("<img" not in html and "&lt;img" in html, "report message included active client HTML")
        print("PASS report message HTML escaped before approved delivery", flush=True)
        print("PASS complete browser-rendered PDF delivered to approved SMTP recipient", flush=True)
        draft["enabled"] = True
        draft["frequency"] = {"type": "cron", "cron": "*/30 * * * * *"}
        expect(author, "enable approved scheduled report", "PUT", reports + "/" + report_id, draft)
        scheduled_recipients, scheduled_message = deliveries.get(timeout=180)
        require(scheduled_recipients == [recipient], "scheduled envelope escaped approval")
        scheduled = email.message_from_bytes(scheduled_message, policy=email.policy.default)
        require(any(part.get_content_type() == "application/pdf" and part.get_payload(decode=True).startswith(b"%PDF")
                    for part in scheduled.walk()), "scheduled report did not deliver a PDF")
        print("PASS elected scheduler delivers approved scoped PDF", flush=True)
        grants = [grant for grant in grants if not (grant["subject"] == identities[author_email] and grant["role"] == "exporter")]
        policy = expect(root, "revoke author export", "PUT", org + "/rbac/policy",
                        {"expected_version": policy["version"], "grants": grants})
        expect(author, "report save denied after author export revocation", "PUT", reports + "/" + report_id, draft, status=403)
        status, _ = author.request("PUT", reports + "/" + report_id + "/trigger")
        require(status in (403, 500), "revoked report trigger succeeded")
        require(deliveries.empty(), "revoked report delivered mail")
        print("PASS revoked author export blocks existing report delivery", flush=True)
        baseline = row("SELECT claim_epoch FROM scheduled_jobs WHERE module_key = ?", (report_id,))[0]
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            try:
                deliveries.get(timeout=1)
                raise AssertionError("revoked scheduled report delivered mail")
            except queue.Empty:
                epoch, status = row("SELECT claim_epoch, status FROM scheduled_jobs WHERE module_key = ?", (report_id,))
                if epoch > baseline and status == 0:
                    print("PASS revoked export blocks delivery after completed scheduler claim", flush=True)
                    break
        else:
            raise AssertionError("report scheduler did not complete a revoked claim")
    finally:
        stop()
        smtp.shutdown()
        smtp.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=pathlib.Path, required=True)
    parser.add_argument("--chrome", type=pathlib.Path, default=pathlib.Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"))
    parser.add_argument("--acknowledge-disposable-fixture", action="store_true", required=True)
    args = parser.parse_args()
    require(args.binary.resolve().is_file() and args.chrome.is_file(), "binary or Chrome missing")
    require(shutil.which("pdftotext"), "pdftotext is required to verify rendered report content")
    run(args.binary.resolve(), args.chrome)
