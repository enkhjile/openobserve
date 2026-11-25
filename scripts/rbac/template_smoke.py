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

"""Template isolation checks using a fresh disposable local SQLite server."""

import argparse
import os
import pathlib
import secrets
import socket
import subprocess
import tempfile
import time

from http_smoke import Client, expect, require


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def run(binary):
    fixture = pathlib.Path(tempfile.mkdtemp(prefix="o2-rbac-templates-"))
    email, password = "template-root@example.com", secrets.token_urlsafe(32) + "Aa1!"
    port = free_port()
    env = {key: value for key, value in os.environ.items() if not key.startswith(("ZO_", "O2_RBAC_"))}
    env.update(ZO_ROOT_USER_EMAIL=email, ZO_ROOT_USER_PASSWORD=password,
               ZO_HTTP_ADDR="127.0.0.1", ZO_HTTP_PORT=str(port),
               ZO_GRPC_ADDR="127.0.0.1", ZO_GRPC_PORT=str(free_port()),
               ZO_LOCAL_MODE="true", ZO_META_STORE="sqlite", ZO_NODE_ROLE="all",
               ZO_DATA_DIR=str(fixture / "data") + "/", ZO_TELEMETRY="false",
               ZO_INTERNAL_GRPC_TOKEN=secrets.token_urlsafe(32), ZO_SSRF_ALLOW_LOOPBACK="true",
               ZO_CREATE_ORG_THROUGH_INGESTION="true")
    root = Client(f"http://127.0.0.1:{port}", email, password)
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
                if root.request("GET", "/healthz")[0] == 200:
                    return
            except OSError:
                pass
            time.sleep(1)
        raise AssertionError("isolated server readiness timed out")

    def draft(name, body="private body"):
        return {"name": name, "type": "http", "kind": "custom", "body": body}

    default = "/api/default/alerts/templates"
    other = "/api/template-other/alerts/templates"
    try:
        print(f"Disposable template fixture: {fixture}", flush=True)
        start(False)
        expect(root, "seed legacy shared default template", "POST", default, draft("shared_fixture"))
        stop()
        start(True)
        expect(root, "bootstrap default template administrator", "POST", "/api/default/rbac/bootstrap")
        expect(root, "single-org Admin creates local custom template", "POST", default, draft("single_org_local"))
        expect(root, "single-org Admin edits local custom template", "PUT", default + "/single_org_local", draft("single_org_local", "edited"))
        expect(root, "single-org Admin reads local custom template", "GET", default + "/single_org_local")
        expect(root, "single-org Admin deletes local custom template", "DELETE", default + "/single_org_local")
        stop()
        start(False)
        expect(root, "create other organization fixture", "POST", "/api/template-other/template_fixture/_json", [{"fixture": "template-isolation"}])
        expect(root, "create metadata organization fixture", "POST", "/api/_meta/template_fixture/_json", [{"fixture": "user-isolation"}])
        expect(root, "seed foreign destination reference", "POST", "/api/template-other/alerts/destinations",
               {"name": "foreign_binding", "type": "http", "method": "post",
                "url": "http://127.0.0.1:9999/never-send", "template": "shared_fixture"})
        stop()
        start(True)
        expect(root, "bootstrap other template administrator", "POST", "/api/template-other/rbac/bootstrap")
        expect(root, "root cannot inherit another organization's template", "GET", other + "/shared_fixture", status=404)
        expect(root, "root cannot edit shared default through another path", "PUT", other + "/shared_fixture", draft("shared_fixture", "changed"), status=404)
        expect(root, "root cannot delete shared default through another path", "DELETE", other + "/shared_fixture", status=404)
        listed = expect(root, "other organization list excludes default bodies", "GET", other + "?include_usage=true")
        require(not any(row.get("name") == "shared_fixture" for row in listed), "shared template leaked in list")
        expect(root, "legacy foreign-bound template cannot be modified", "PUT", default + "/shared_fixture", draft("shared_fixture", "changed"), status=403)
        expect(root, "legacy foreign-bound template cannot be deleted", "DELETE", default + "/shared_fixture", status=403)
        shared = expect(root, "default usage excludes foreign references", "GET", default + "/shared_fixture")
        require(shared.get("used_by", {}).get("destinations") == 0, "foreign destination usage disclosed")
        expect(root, "default Admin creates local custom template", "POST", default, draft("local_fixture"))
        expect(root, "default Admin reads local custom template", "GET", default + "/local_fixture")
        expect(root, "default Admin edits local custom template", "PUT", default + "/local_fixture", draft("local_fixture", "edited"))
        expect(root, "default Admin deletes local custom template", "DELETE", default + "/local_fixture")
        expect(root, "deleted local template is absent", "GET", default + "/local_fixture", status=404)
        expect(root, "create picker custom template", "POST", default, draft("picker_template"))
        expect(root, "create picker destination", "POST", "/api/default/alerts/destinations",
               {"name": "picker_sink", "type": "http", "method": "post",
                "url": "http://127.0.0.1:9999/never-send", "template": "picker_template"})
        policy = expect(root, "read destination approval revision", "GET", "/api/default/rbac/policy")
        resource = {"kind": "stream", "stream_type": "logs", "name": "approved_source"}
        policy = expect(root, "approve exact source destination", "PUT", "/api/default/rbac/destinations",
                        {"expected_version": policy["version"], "approvals": [{"destination_name": "picker_sink", "sources": [resource]}]})
        editor_email, editor_password = "picker-editor@example.com", secrets.token_urlsafe(32) + "Aa1!"
        expect(root, "create picker Editor identity", "POST", "/api/default/users",
               {"email": editor_email, "password": editor_password, "first_name": "Picker", "last_name": "Editor", "role": "admin", "is_external": False})
        expect(root, "bootstrap metadata organization administrator", "POST", "/api/_meta/rbac/bootstrap")
        scoped_users = expect(root, "metadata user listing remains organization scoped", "GET", "/api/_meta/users?list_all=true")
        require(not any(row["email"] == editor_email for row in scoped_users["data"]), "metadata Admin disclosed a foreign organization user")
        subjects = expect(root, "resolve picker Editor identity", "GET", "/api/default/rbac/subjects")
        subject = next(item["subject"] for item in subjects if item.get("email") == editor_email)
        grants = policy["grants"] + [{"subject": subject, "role": "editor", "resources": [resource, {"kind": "alert", "stream_type": "", "name": "*"}]}]
        policy = expect(root, "grant scoped Editor query and alert writes", "PUT", "/api/default/rbac/policy", {"expected_version": policy["version"], "grants": grants})
        editor = Client(root.base_url, editor_email, editor_password)
        endpoint = "/api/default/rbac/destinations/available"
        names = expect(editor, "Editor picker returns approved names only", "POST", endpoint, {"sql": "SELECT * FROM approved_source", "stream_type": "logs"})
        require(names == [{"name": "picker_sink"}], "picker exposed unexpected fields or destinations")
        expect(editor, "picker rejects unauthorized source SQL", "POST", endpoint, {"sql": "SELECT * FROM secret_source", "stream_type": "logs"}, status=403)
        expect(editor, "picker rejects unresolved query", "POST", endpoint, {"sql": "", "stream_type": "logs"}, status=403)
        expect(editor, "Editor cannot fetch destination configurations", "GET", "/api/default/alerts/destinations", status=403)
        expect(root, "change approved custom template", "PUT", default + "/picker_template", draft("picker_template", "changed"))
        names = expect(editor, "picker hides a changed delivery configuration", "POST", endpoint, {"sql": "SELECT * FROM approved_source", "stream_type": "logs"})
        require(names == [], "changed target retained picker authorization")
        grants[-1]["role"] = "viewer"
        expect(root, "revoke Editor alert write grant", "PUT", "/api/default/rbac/policy", {"expected_version": policy["version"], "grants": grants})
        expect(editor, "Viewer cannot use alert destination picker", "POST", endpoint, {"sql": "SELECT * FROM approved_source", "stream_type": "logs"}, status=403)

    finally:
        stop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=pathlib.Path, required=True)
    parser.add_argument("--acknowledge-disposable-fixture", action="store_true", required=True)
    args = parser.parse_args()
    require(args.binary.resolve().is_file(), "binary does not exist")
    run(args.binary.resolve())
