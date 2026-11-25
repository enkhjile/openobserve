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

"""Destructive fixture tests against an explicitly supplied disposable local RBAC instance."""

import argparse
import base64
import ipaddress
import json
import os
import re
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


class SmokeFailure(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise SmokeFailure("Redirect refused; use the instance's exact base URL")


class Client:
    def __init__(self, base_url, email, password):
        self.base_url = base_url.rstrip("/")
        self.timeout = 45
        self.authorization = "Basic " + base64.b64encode(
            f"{email}:{password}".encode()
        ).decode()
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirect()
        )

    def request(self, method, path, body=None, form=None, headers=None):
        data = None if body is None else json.dumps(body).encode()
        content_type = "application/json"
        if form is not None:
            require(body is None, "request cannot contain both JSON and form data")
            data = urllib.parse.urlencode(form).encode()
            content_type = "application/x-www-form-urlencoded"
        request = urllib.request.Request(
            self.base_url + path,
            data=data,
            method=method,
            headers={
                "Authorization": self.authorization,
                "Content-Type": content_type,
                "Accept": "application/json",
                **(headers or {}),
            },
        )
        try:
            response = self.opener.open(request, timeout=self.timeout)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read(8 * 1024 * 1024)
            if response.headers.get_content_type() == "text/event-stream":
                return response.status, raw.decode()
            try:
                payload = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError):
                payload = None
            return response.status, payload


def expect(client, label, method, path, body=None, status=200, form=None, headers=None):
    actual, payload = client.request(method, path, body, form=form, headers=headers)
    if actual != status:
        raise SmokeFailure(f"{label}: expected HTTP {status}, received HTTP {actual}")
    print(f"PASS {label}", flush=True)
    return payload


def require(condition, message):
    if not condition:
        raise SmokeFailure(message)


def stream_resource(name):
    return {"kind": "stream", "stream_type": "logs", "name": name}


def query_payload(sql, start_time):
    return {
        "query": {
            "sql": sql,
            "start_time": start_time,
            "end_time": time.time_ns() // 1000 + 60_000_000,
            "from": 0,
            "size": 10,
        }
    }


def ingest(client, label, org_path, stream, run_id):
    body = [{"_timestamp": time.time_ns() // 1000, "id": 1,
             "smoke_id": run_id, "message": "RBAC disposable fixture"}]
    result = expect(client, label, "POST", f"{org_path}/{stream}/_json", body)
    require(isinstance(result, dict), f"{label}: missing ingestion response")
    statuses = result.get("status", [])
    require(result.get("code") == 200 and
            sum(item.get("successful", 0) for item in statuses) == 1 and
            sum(item.get("failed", 0) for item in statuses) == 0,
            f"{label}: HTTP success did not acknowledge exactly one written record")


def await_visible(client, org_path, sql, start_time, run_id, seconds):
    deadline = time.monotonic() + seconds
    while True:
        status, payload = client.request("POST", f"{org_path}/_search?type=logs",
                                         query_payload(sql, start_time))
        require(status == 200, f"viewer allowed query: expected HTTP 200, received {status}")
        require(isinstance(payload, dict), "viewer allowed query: missing JSON response")
        if any(hit.get("smoke_id") == run_id for hit in payload.get("hits", [])):
            print("PASS viewer reads authorized ingested row", flush=True)
            return
        require(time.monotonic() < deadline,
                "viewer allowed query: ingested fixture did not become visible before timeout")
        time.sleep(1)


def organization_resource():
    return {"kind": "organization", "stream_type": "", "name": "organization"}


def dashboard_resource():
    return {"kind": "dashboard", "stream_type": "", "name": "*"}


def exercise_editor(editor, org_path, stream, run_id, label):
    draft = {"version": 8, "title": f"RBAC {label} {run_id}",
             "description": "Disposable RBAC fixture", "tabs": [{"tabId": "main", "name": "Main", "panels": []}]}
    created = expect(editor, label + " creates permitted dashboard", "POST",
                     f"{org_path}/dashboards?folder=default", draft)
    dashboard_id = created["v8"]["dashboardId"]
    require(bool(dashboard_id) and bool(created["hash"]), "dashboard creation omitted id/hash")
    edited = dict(created["v8"])
    edited["version"] = 8
    edited["title"] = f"RBAC {label} edited {run_id}"
    params = urllib.parse.urlencode({"folder": "default", "hash": created["hash"]})
    expect(editor, label + " edits permitted dashboard", "PUT",
           f"{org_path}/dashboards/{dashboard_id}?{params}", edited)
    current = expect(editor, label + " reads edited dashboard", "GET",
                     f"{org_path}/dashboards/{dashboard_id}")
    require(current["v8"]["title"] == edited["title"], "dashboard update was not persisted")
    panel = {"id": "sample", "type": "markdown", "title": "Initial", "description": "",
             "config": {"show_legends": False}, "queries": [], "markdownContent": "fixture"}
    panel_path = f"{org_path}/dashboards/{dashboard_id}/panels"
    added = expect(editor, label + " adds a dashboard panel", "POST", panel_path + "?hash=" + current["hash"],
                   {"tabId": "main", "panel": panel})
    panel["title"] = "Edited"
    changed = expect(editor, label + " updates a dashboard panel", "PUT", panel_path + "/sample?hash=" + added["hash"],
                     {"tabId": "main", "panel": panel})
    expect(editor, label + " deletes a dashboard panel", "DELETE", panel_path + "/sample?tabId=main&hash=" + changed["hash"])
    expect(editor, label + " cannot administer users", "GET", f"{org_path}/users", status=403)
    expect(editor, label + " cannot administer roles", "GET", f"{org_path}/rbac/policy", status=403)
    expect(editor, label + " cannot delete streams", "DELETE",
           f"{org_path}/streams/{stream}?type=logs", status=403)


def exercise_second_org(args, root, org_path, users, passwords, ids, streams, run_id, start_time):
    second_path = "/api/" + urllib.parse.quote(args.second_disposable_org, safe="")
    policy = expect(root, "bootstrap second disposable organization", "POST", f"{second_path}/rbac/bootstrap")
    require(policy["version"] == 1, "second organization is not a fresh policy fixture")
    outsider = Client(args.url, users["viewer"], passwords["viewer"])
    expect(outsider, "identity without second-org membership cannot query", "POST", f"{second_path}/_search?type=logs",
           query_payload(f'SELECT * FROM "{streams["api"]}"', start_time), status=401)
    for role in ("viewer", "ingester", "admin_a"):
        expect(root, f"add {role} membership in second organization without grants", "POST",
               f"{second_path}/users/{urllib.parse.quote(users[role], safe='')}", {"role": "admin"})
    admin_b_email = f"rbac-smoke-admin-b-{run_id}@example.com"
    admin_b_password = "Rbac!Aa1-" + secrets.token_urlsafe(24)
    print(json.dumps({"second_disposable_org": args.second_disposable_org,
                      "admin_b_fixture": admin_b_email}), flush=True)
    expect(root, "create second organization admin identity", "POST", f"{second_path}/users", {
        "email": admin_b_email, "password": admin_b_password, "first_name": "RBAC smoke",
        "last_name": "admin B", "role": "admin", "is_external": False,
    })
    subjects = expect(root, "resolve second organization identities", "GET", f"{second_path}/rbac/subjects")
    second_ids = {item["email"]: item["subject"] for item in subjects if "email" in item}
    require(second_ids[users["viewer"]] == ids[users["viewer"]], "identity UUID changed across organizations")
    second_grants = policy["grants"] + [
        {"subject": ids[users["viewer"]], "role": "editor",
         "resources": [stream_resource(streams["api"]), dashboard_resource()]},
        {"subject": second_ids[admin_b_email], "role": "admin", "resources": [organization_resource()]},
    ]
    expect(root, "assign different roles in second organization", "PUT", f"{second_path}/rbac/policy", {
        "expected_version": policy["version"], "grants": second_grants,
    })
    viewer = Client(args.url, users["viewer"], passwords["viewer"])
    ingester = Client(args.url, users["ingester"], passwords["ingester"])
    admin_a = Client(args.url, users["admin_a"], passwords["admin_a"])
    admin_b = Client(args.url, admin_b_email, admin_b_password)
    first_me = expect(viewer, "same identity remains Viewer in first organization", "GET", f"{org_path}/rbac/me")
    second_me = expect(viewer, "same identity is Editor in second organization", "GET", f"{second_path}/rbac/me")
    require({grant["role"] for grant in first_me["grants"]} == {"viewer"}, "first org role was elevated")
    require({grant["role"] for grant in second_me["grants"]} == {"editor"}, "second org Editor grant missing")
    expect(viewer, "second-org Editor cannot create first-org dashboard", "POST", f"{org_path}/dashboards", {
        "version": 8, "title": "Must not create", "description": "negative fixture", "tabs": [],
    }, status=403)
    ingest(root, "root ingests same-named stream in second organization", second_path, streams["api"], run_id)
    exercise_editor(viewer, second_path, streams["api"], run_id, "Second-org Editor")
    expect(ingester, "first-org ingestion grant cannot cross organizations", "POST",
           f"{second_path}/{streams['api']}/_json", [{"id": 3}], status=403)
    expect(admin_a, "first-org Admin cannot read second-org policy", "GET", f"{second_path}/rbac/policy", status=403)
    expect(admin_a, "first-org Admin cannot query same-named second-org stream", "POST", f"{second_path}/_search?type=logs",
           query_payload(f'SELECT * FROM "{streams["api"]}"', start_time), status=403)
    expect(admin_a, "Admin A adds existing Admin B as a member", "POST",
           f"{org_path}/users/{urllib.parse.quote(admin_b_email, safe='')}", {"role": "admin"})
    expect(admin_a, "Admin A cannot reset Admin B global password", "PUT",
           f"{org_path}/users/{urllib.parse.quote(admin_b_email, safe='')}", {
               "change_password": True, "new_password": "Attempt!Aa1-" + secrets.token_urlsafe(24),
           }, status=403)
    after = expect(admin_b, "Admin B original password and grants remain intact", "GET", f"{second_path}/rbac/me")
    require(after["can_manage"] is True, "Admin B lost its verified administrative identity")
    credential_failures = []
    for target_label, target in [("root", os.environ["O2_RBAC_ROOT_EMAIL"]), ("human member", admin_b_email)]:
        target_path = f"{org_path}/service_accounts/{urllib.parse.quote(target, safe='')}?rotateToken=true"
        for method in ("GET", "PUT"):
            label = f"Admin A cannot {method} {target_label} credentials through service-account API"
            status, _ = admin_a.request(method, target_path, {} if method == "PUT" else None)
            if status == 403:
                print("PASS " + label, flush=True)
            else:
                failure = f"{label}: expected HTTP 403, received HTTP {status}"
                credential_failures.append(failure)
                print("FAIL " + failure, flush=True)
    require(not credential_failures, "; ".join(credential_failures))



def exercise_service_accounts(args, root, org_path, policy, grants, streams, run_id, start_time):
    accounts = {}
    for role in ("ingester", "viewer"):
        email = f"rbac-smoke-sa-{role}-{run_id}@example.com"
        created = expect(root, f"create real {role} service account", "POST", f"{org_path}/service_accounts", {
            "email": email, "first_name": "RBAC service fixture", "last_name": role,
        })
        require(created.get("code") == 200 and created.get("user") == email and bool(created.get("token")),
                "service account creation did not return its own credential")
        accounts[role] = {"email": email, "client": Client(args.url, email, created["token"])}
        expect(accounts[role]["client"], f"unassigned {role} service account gets no implicit grants", "GET",
               f"{org_path}/rbac/me", status=403)
    print(json.dumps({"service_account_fixtures": [account["email"] for account in accounts.values()]}), flush=True)
    subjects = expect(root, "resolve service account stable identities", "GET", f"{org_path}/rbac/subjects")
    ids = {item["email"]: item["subject"] for item in subjects if "email" in item}
    scoped = list(grants)
    for role, account in accounts.items():
        require(account["email"] in ids, "service account has no stable organization subject")
        account["subject"] = ids[account["email"]]
        scoped.append({"subject": account["subject"], "role": role,
                       "resources": [stream_resource(streams["api"])]})
    policy = expect(root, "grant scoped service account roles", "PUT", f"{org_path}/rbac/policy", {
        "expected_version": policy["version"], "grants": scoped,
    })
    writer = accounts["ingester"]["client"]
    reader = accounts["viewer"]["client"]
    for role, account in accounts.items():
        me = expect(account["client"], f"{role} service token resolves own UUID", "GET", f"{org_path}/rbac/me")
        require(me["subject"] == account["subject"] and not me["can_manage"],
                "service account credential resolved an administrative or incorrect principal")
    ingest(writer, "Ingester service account writes authorized stream", org_path, streams["api"], run_id)
    allowed_sql = f'SELECT * FROM "{streams["api"]}" WHERE smoke_id = \'{run_id}\''
    allowed_query = query_payload(allowed_sql, start_time)
    expect(writer, "Ingester service account cannot query", "POST", f"{org_path}/_search?type=logs", allowed_query, status=403)
    expect(writer, "Ingester service account cannot write restricted stream", "POST",
           f"{org_path}/{streams['finance']}/_json", [{"id": 5}], status=403)
    hits = expect(reader, "Viewer service account queries authorized stream", "POST", f"{org_path}/_search?type=logs", allowed_query)
    require(any(hit.get("smoke_id") == run_id for hit in hits.get("hits", [])),
            "service-account query did not return its authorized fixture row")
    expect(reader, "Viewer service account cannot query restricted stream", "POST", f"{org_path}/_search?type=logs",
           query_payload(f'SELECT * FROM "{streams["finance"]}"', start_time), status=403)
    expect(reader, "Viewer service account cannot ingest", "POST", f"{org_path}/{streams['api']}/_json", [{"id": 5}], status=403)
    expect(writer, "service account cannot assign its own roles", "PUT", f"{org_path}/rbac/policy", {
        "expected_version": policy["version"], "grants": scoped,
    }, status=403)

    writer_path = f"{org_path}/service_accounts/{urllib.parse.quote(accounts['ingester']['email'], safe='')}"
    rotated = expect(root, "rotate existing service account credential", "PUT", writer_path + "?rotateToken=true", {})
    require(rotated.get("user") == accounts["ingester"]["email"] and bool(rotated.get("token")),
            "rotation did not return the service account's own credential")
    expect(writer, "rotated service credential is immediately rejected", "GET", f"{org_path}/rbac/me", status=401)
    new_writer = Client(args.url, accounts["ingester"]["email"], rotated["token"])
    ingest(new_writer, "rotated credential retains explicit Ingest grant", org_path, streams["api"], run_id)

    policy = expect(root, "revoke both service account policy grants", "PUT", f"{org_path}/rbac/policy", {
        "expected_version": policy["version"], "grants": grants,
    })
    expect(new_writer, "revoked service account cannot ingest", "POST", f"{org_path}/{streams['api']}/_json", [{"id": 5}], status=403)
    expect(reader, "revoked service account cannot query", "POST", f"{org_path}/_search?type=logs", allowed_query, status=403)
    expect(root, "delete only smoke writer account to revoke authentication", "DELETE", writer_path)
    expect(new_writer, "deleted service account credential is rejected", "GET", f"{org_path}/rbac/me", status=401)
    return policy


def promql_result(payload, label):
    require(isinstance(payload, dict) and payload.get("status") == "success", label + ": missing successful PromQL response")
    result = payload.get("data", {}).get("result", [])
    require(bool(result), label + ": expected an actual fixture series, not empty success")
    return result


def exercise_promql(args, root, viewer, ingester, org_path):
    base = f"{org_path}/prometheus/api/v1"
    instant = {"query": args.allowed_metric, "time": str(args.metric_time + 1)}
    denied_instant = {"query": args.denied_metric, "time": str(args.metric_time + 1)}
    fixture = expect(root, "root verifies restricted metric fixture exists", "GET",
                     base + "/query?" + urllib.parse.urlencode(denied_instant))
    promql_result(fixture, "root restricted metric fixture")
    for method in ("GET", "POST"):
        for endpoint in ("query", "query_range"):
            params = dict(instant)
            if endpoint == "query_range":
                params = {"query": args.allowed_metric, "start": str(args.metric_time - 30),
                          "end": str(args.metric_time + 10), "step": "10"}
            path = base + "/" + endpoint
            if method == "GET":
                result = expect(viewer, f"Viewer PromQL {method} {endpoint} allowed", method,
                                path + "?" + urllib.parse.urlencode(params))
            else:
                result = expect(viewer, f"Viewer PromQL {method} {endpoint} allowed", method, path, form=params)
            promql_result(result, f"Viewer {method} {endpoint}")
            denied = dict(params, query=args.denied_metric)
            if method == "GET":
                expect(viewer, f"Viewer PromQL {method} {endpoint} restricted metric denied", method,
                       path + "?" + urllib.parse.urlencode(denied), status=403)
            else:
                expect(viewer, f"Viewer PromQL {method} {endpoint} restricted metric denied", method,
                       path, status=403, form=denied)
    for expression in [f"{args.allowed_metric} + {args.denied_metric}",
                       f"sum(rate({args.denied_metric}[1m]))", '{job="rbac_smoke"}',
                       '{__name__=~"rbac_.*"}']:
        expect(viewer, "PromQL unauthorized or unresolved selector denied", "GET", base + "/query?" +
               urllib.parse.urlencode(dict(instant, query=expression)), status=403)
    expect(ingester, "Ingester cannot query metrics", "GET", base + "/query?" + urllib.parse.urlencode(instant), status=403)
    write_path = f"{org_path}/ingest/metrics/_json"
    batch_id = uuid.uuid4().hex
    at = int(time.time())
    def row(name, label):
        return {"__name__": name, "__type__": "gauge", "value": 7,
                "_timestamp": at * 1_000_000, "rbac_batch": label}
    expect(viewer, "Viewer metrics ingestion denied", "POST", write_path,
           [row(args.allowed_metric, batch_id)], status=403)
    expect(ingester, "Ingester mixed metric batch rejected atomically", "POST", write_path,
           [row(args.allowed_metric, batch_id), row(args.denied_metric, batch_id)], status=403)
    expect(ingester, "Ingester restricted metric denied", "POST", write_path,
           [row(args.denied_metric, batch_id)], status=403)
    positive_id = uuid.uuid4().hex
    accepted = expect(ingester, "Ingester authorized metrics stream accepted", "POST", write_path,
                      [row(args.allowed_metric, positive_id)])
    require(sum(item.get("successful", 0) for item in accepted.get("status", [])) == 1,
            "metrics ingestion did not acknowledge one sample")
    visible = expect(viewer, "Viewer sees authorized ingested metric sample", "GET", base + "/query?" +
                     urllib.parse.urlencode({"query": f'{args.allowed_metric}{{rbac_batch="{positive_id}"}}', "time": str(at + 1)}))
    promql_result(visible, "authorized newly ingested metric")
    for name in (args.allowed_metric, args.denied_metric):
        absent = expect(root, "Rejected mixed metric batch wrote no samples", "GET", base + "/query?" +
                        urllib.parse.urlencode({"query": f'{name}{{rbac_batch="{batch_id}"}}', "time": str(at + 1)}))
        require(absent.get("data", {}).get("result") == [], "rejected metric batch partially wrote data")


def run(args):
    root = Client(args.url, os.environ["O2_RBAC_ROOT_EMAIL"],
                  os.environ["O2_RBAC_ROOT_PASSWORD"])
    org_path = "/api/" + urllib.parse.quote(args.disposable_org, safe="")
    run_id = uuid.uuid4().hex[:12]
    streams = {"api": f"api_logs_{run_id}", "finance": f"finance_logs_{run_id}",
               "traces": f"app_traces_{run_id}", "restricted_traces": f"secret_traces_{run_id}"}
    roles = ["viewer", "ingester", "editor", "exporter"]
    if args.second_disposable_org:
        roles.append("admin_a")
    users = {role: f"rbac-smoke-{role}-{run_id}@example.com" for role in roles}
    passwords = {role: "Rbac!Aa1-" + secrets.token_urlsafe(24) for role in users}
    print(json.dumps({"disposable_org": args.disposable_org, "run_id": run_id,
                      "fixture_users": users, "fixture_streams": streams}), flush=True)
    print("Fixtures and policy are retained except one generated service account deleted for revocation testing; discard this isolated instance afterward.", flush=True)

    expect(root, "root cannot query an uninitialized organization", "POST", f"{org_path}/_search?type=logs",
           query_payload(f'SELECT * FROM "{streams["api"]}"', time.time_ns() // 1000 - 60_000_000), status=403)
    policy = expect(root, "explicit one-time root bootstrap", "POST", f"{org_path}/rbac/bootstrap")
    require(isinstance(policy, dict) and policy.get("version") == 1,
            "bootstrap did not return a new revision-1 policy; use an uninitialized disposable org")
    expect(root, "repeated bootstrap cannot overwrite policy", "POST", f"{org_path}/rbac/bootstrap", status=403)
    fetched = expect(root, "admin reads policy", "GET", f"{org_path}/rbac/policy")
    require(fetched == policy, "policy read differs from bootstrap result")
    me = expect(root, "root current grants", "GET", f"{org_path}/rbac/me")
    require(me.get("enabled") is True and me.get("can_manage") is True,
            "server is not running initialized RBAC")

    for role, email in users.items():
        expect(root, f"create {role} fixture identity", "POST", f"{org_path}/users", {
            "email": email, "password": passwords[role], "first_name": "RBAC smoke",
            "last_name": role, "role": "admin", "is_external": False,
        })
    subjects = expect(root, "admin resolves stable subjects", "GET", f"{org_path}/rbac/subjects")
    require(isinstance(subjects, list), "subject picker did not return an array")
    ids = {item["email"]: item["subject"] for item in subjects if "email" in item}
    require(all(email in ids for email in users.values()), "fixture UUIDs missing from subject picker")
    original_grants = policy["grants"]
    dashboard_ids = {}
    for suffix in ("A denied", "Z allowed"):
        created = expect(root, f"create {suffix} dashboard fixture", "POST",
                         f"{org_path}/dashboards?folder=default", {
                             "version": 8, "title": f"{run_id} {suffix}",
                             "description": "Disposable scoped listing fixture", "tabs": [],
                         })
        dashboard_ids[suffix] = created["v8"]["dashboardId"]
    grants = list(original_grants)
    for role, email in users.items():
        resources = [stream_resource(streams["api"])]
        if role == "viewer":
            resources.append({"kind": "dashboard", "stream_type": "",
                              "name": dashboard_ids["Z allowed"]})
        if role in ("viewer", "ingester"):
            resources.append({"kind": "stream", "stream_type": "traces", "name": streams["traces"]})
        if role in ("viewer", "ingester") and args.allowed_metric:
            resources.append({"kind": "stream", "stream_type": "metrics", "name": args.allowed_metric})
        if role == "editor":
            resources.append(dashboard_resource())
        elif role == "admin_a":
            resources = [organization_resource()]
        grants.append({"subject": ids[email], "role": "admin" if role == "admin_a" else role,
                       "resources": resources})
    update = {"expected_version": policy["version"], "grants": grants}
    policy = expect(root, "assign scoped roles through CAS", "PUT", f"{org_path}/rbac/policy", update)
    require(policy["version"] == update["expected_version"] + 1, "policy revision did not advance")
    expect(root, "stale policy update denied", "PUT", f"{org_path}/rbac/policy", update, status=403)
    viewer = Client(args.url, users["viewer"], passwords["viewer"])
    ingester = Client(args.url, users["ingester"], passwords["ingester"])
    editor = Client(args.url, users["editor"], passwords["editor"])
    expect(root, "Admin lists organization delivery destinations", "GET", f"{org_path}/alerts/destinations")
    expect(editor, "Editor cannot inspect destination credentials", "GET", f"{org_path}/alerts/destinations", status=403)
    viewer_me = expect(viewer, "Viewer sees own grants", "GET", f"{org_path}/rbac/me")
    require(viewer_me["subject"] == ids[users["viewer"]] and not viewer_me["can_manage"],
            "Viewer current grants report administrative access")
    require(all(grant["subject"] == ids[users["viewer"]] for grant in viewer_me["grants"]),
            "Viewer current grants leaked another subject's assignments")

    expect(root, "Admin updates organization settings", "POST", org_path + "/settings",
           {"scrape_interval": 17})
    settings = expect(root, "Admin reads organization settings", "GET", org_path + "/settings")
    require(settings["data"]["scrape_interval"] == 17, "organization setting was not persisted")
    expect(viewer, "Viewer cannot change organization settings", "POST", org_path + "/settings",
           {"scrape_interval": 18}, status=403)
    organizations = expect(viewer, "Viewer organization switcher uses the public response schema",
                           "GET", "/api/organizations")["data"]
    require(len(organizations) == 1 and organizations[0]["identifier"] == args.disposable_org
            and organizations[0]["UserObj"]["email"] == users["viewer"]
            and organizations[0]["type"] and organizations[0]["owner_email"] == "",
            "organization listing changed response shape or leaked owner data")
    start_time = time.time_ns() // 1000 - 60_000_000
    ingest(root, "root ingests authorized API logs", org_path, streams["api"], run_id)
    ingest(root, "root ingests restricted finance logs", org_path, streams["finance"], run_id)
    allowed = f'SELECT * FROM "{streams["api"]}" WHERE smoke_id = \'{run_id}\''
    await_visible(viewer, org_path, allowed, start_time, run_id, args.visibility_timeout)
    grpc_target = os.environ.get("O2_RBAC_FIXTURE_GRPC_TARGET")
    if grpc_target:
        from grpc_smoke import verify_search
        verify_search(grpc_target, args.disposable_org, ids[users["viewer"]],
                      query_payload(allowed, start_time), run_id)
    exporter = Client(args.url, users["exporter"], passwords["exporter"])
    download_path = f"{org_path}/_search?type=logs&search_type=download"
    exported = expect(exporter, "Exporter downloads authorized rows", "POST", download_path,
                      query_payload(allowed, start_time))
    require(any(row.get("smoke_id") == run_id for row in exported.get("hits", [])),
            "authorized download returned no fixture row")
    expect(viewer, "Viewer query grant cannot authorize named download", "POST", download_path,
           query_payload(allowed, start_time), status=403)
    mixed = f'SELECT * FROM "{streams["api"]}" UNION ALL SELECT * FROM "{streams["finance"]}"'
    expect(exporter, "download requires grants on every source", "POST", download_path,
           query_payload(mixed, start_time), status=403)
    exercise_editor(editor, org_path, streams["api"], run_id, "Editor")
    listed = expect(viewer, "Viewer stream listing", "GET", f"{org_path}/streams?type=logs")
    names = {stream["name"] for stream in listed["list"]}
    require(streams["api"] in names and streams["finance"] not in names,
            "Viewer list did not filter unauthorized streams")
    for label, params in (
        ("default folder", {}),
        ("explicit folder", {"folder": "default"}),
        ("all-folder title pagination", {"title": run_id, "page_size": 1}),
        ("folder title pagination", {"folder": "default", "title": run_id, "page_size": 1}),
    ):
        listing = expect(viewer, f"Viewer scoped dashboard listing: {label}", "GET",
                         f"{org_path}/dashboards?{urllib.parse.urlencode(params)}")
        require([item["dashboard_id"] for item in listing["dashboards"]] ==
                [dashboard_ids["Z allowed"]], "dashboard listing leaked or omitted scoped records")
    expect(viewer, "Viewer cannot delete a panel in a readable dashboard", "DELETE",
           f'{org_path}/dashboards/{dashboard_ids["Z allowed"]}/panels/sample?hash=unused', status=403)
    restricted_title = urllib.parse.urlencode({"title": f"{run_id} A denied", "page_size": 1})
    hidden = expect(viewer, "restricted dashboard title search is empty", "GET",
                    f"{org_path}/dashboards?{restricted_title}")
    require(hidden["dashboards"] == [], "restricted dashboard metadata leaked")
    hidden = expect(ingester, "Ingester dashboard listing is empty", "GET", f"{org_path}/dashboards")
    require(hidden["dashboards"] == [], "stream-only principal received dashboard metadata")
    expect(viewer, "restricted dashboard direct read denied", "GET",
           f"{org_path}/dashboards/{dashboard_ids['A denied']}", status=403)

    api, finance = f'"{streams["api"]}"', f'"{streams["finance"]}"'
    for label, sql in [
        ("CTE", f"WITH source AS (SELECT * FROM {api}) SELECT smoke_id FROM source"),
        ("subquery", f"SELECT q.smoke_id FROM (SELECT * FROM {api}) AS q"),
        ("join", f"SELECT a.smoke_id FROM {api} a JOIN {api} b ON a.id = b.id"),
        ("union", f"SELECT smoke_id FROM {api} UNION ALL SELECT smoke_id FROM {api}"),
    ]:
        result = expect(viewer, f"authorized {label} returns fixture data", "POST",
                        org_path + "/_search?type=logs", query_payload(sql, start_time))
        require(any(row.get("smoke_id") == run_id for row in result["hits"]),
                f"authorized {label} did not return the fixture row")
    events = expect(viewer, "Viewer opens scoped streaming search", "POST",
                    org_path + "/_search_stream?type=logs", query_payload(allowed, start_time))
    require(isinstance(events, str) and "data: [[DONE]]" in events, "streaming query did not complete")
    hits = []
    for event in events.split("\n\n"):
        if "event: search_response_hits" in event:
            data = next(line[5:] for line in event.splitlines() if line.startswith("data:"))
            hits.extend(json.loads(data)["hits"])
    require(any(hit.get("smoke_id") == run_id for hit in hits), "stream omitted authorized fixture row")
    batch = {"sql": [allowed, f"SELECT * FROM {finance}"], "start_time": start_time,
             "end_time": time.time_ns() // 1000, "size": 10}
    for route in ("_search_multi", "_search_multi_stream", "_search_partition_multi"):
        expect(viewer, f"mixed batch denied before {route} returns data", "POST",
               f"{org_path}/{route}?type=logs", batch, status=403)
    positive_batch = {**batch, "sql": [allowed, allowed]}
    results = expect(viewer, "Viewer runs a batch with two authorized queries", "POST",
                     org_path + "/_search_multi?type=logs", positive_batch)
    require(any(row["smoke_id"] == run_id for row in results["hits"]), "authorized batch omitted fixture row")
    expect(viewer, "batch download requires Export even for readable streams", "POST",
           org_path + "/_search_multi?type=logs&search_type=download", positive_batch, status=403)
    denied_queries = {
        "direct restricted stream": f"SELECT * FROM {finance}",
        "JOIN restricted source": f"SELECT a.id FROM {api} a JOIN {finance} f ON a.id = f.id",
        "CTE restricted source": f"WITH secret AS (SELECT id FROM {finance}) SELECT * FROM secret",
        "subquery restricted source": f"SELECT * FROM {api} WHERE id IN (SELECT id FROM {finance})",
        "UNION restricted source": f"SELECT id FROM {api} UNION ALL SELECT id FROM {finance}",
    }
    for label, sql in denied_queries.items():
        expect(viewer, label + " denied", "POST", f"{org_path}/_search?type=logs",
               query_payload(sql, start_time), status=403)
    expect(viewer, "Viewer stream deletion denied", "DELETE", f"{org_path}/streams/{streams['api']}?type=logs", status=403)
    expect(viewer, "Viewer ingestion denied", "POST", f"{org_path}/{streams['api']}/_json", [{"id": 2}], status=403)
    expect(viewer, "Viewer policy read denied", "GET", f"{org_path}/rbac/policy", status=403)
    escalation = {"expected_version": policy["version"], "grants": grants + [{
        "subject": ids[users["viewer"]], "role": "admin",
        "resources": [{"kind": "organization", "stream_type": "", "name": "organization"}],
    }]}
    expect(viewer, "Viewer self-escalation denied", "PUT", f"{org_path}/rbac/policy", escalation, status=403)
    expect(editor, "Editor role administration denied", "PUT", f"{org_path}/rbac/policy", escalation, status=403)
    expect(editor, "Editor user role assignment denied", "POST",
           f"{org_path}/users/{urllib.parse.quote(users['ingester'], safe='')}", {"role": "admin"}, status=403)
    expect(viewer, "Viewer role assignment denied", "POST",
           f"{org_path}/users/{urllib.parse.quote(users['ingester'], safe='')}", {"role": "admin"}, status=403)
    ingest(ingester, "Ingester writes explicitly granted stream", org_path, streams["api"], run_id)
    line = {"id": 2, "smoke_id": run_id}
    written = expect(ingester, "Ingester writes named multiline destination", "POST",
                     f'{org_path}/{streams["api"]}/_multi', line)
    require(sum(item["successful"] for item in written["status"]) == 1,
            "multiline ingestion did not acknowledge the record")
    expect(ingester, "multiline ingestion denies other destinations", "POST",
           f'{org_path}/{streams["finance"]}/_multi', line, status=403)
    expect(viewer, "Viewer cannot write through multiline ingestion", "POST",
           f'{org_path}/{streams["api"]}/_multi', line, status=403)
    expect(ingester, "Ingester query denied", "POST", f"{org_path}/_search?type=logs",
           query_payload(allowed, start_time), status=403)
    expect(ingester, "Ingester restricted destination denied", "POST",
           f"{org_path}/{streams['finance']}/_json", [{"id": 2}], status=403)
    expect(root, "undeclared route denied even for Admin", "GET",
           f"{org_path}/rbac_smoke_unknown_{run_id}", status=403)

    if args.second_disposable_org:
        exercise_second_org(args, root, org_path, users, passwords, ids, streams, run_id, start_time)

    if args.allowed_metric:
        exercise_promql(args, root, viewer, ingester, org_path)

    from trace_smoke import exercise_traces
    exercise_traces(root, viewer, ingester, org_path, streams, run_id, start_time)

    policy = exercise_service_accounts(args, root, org_path, policy, grants, streams, run_id, start_time)
    from token_smoke import exercise_tokens
    policy = exercise_tokens(args, root, editor, org_path, policy, grants, streams, run_id, start_time)
    from pipeline_smoke import exercise_pipelines
    policy = exercise_pipelines(args, root, editor, ingester, viewer, org_path, policy, grants, ids, users, run_id, start_time)

    revoked = {"expected_version": policy["version"],
               "grants": [grant for grant in grants if grant["subject"] != ids[users["viewer"]]]}
    expect(root, "revoke Viewer grant", "PUT", f"{org_path}/rbac/policy", revoked)
    expect(viewer, "revoked Viewer query denied immediately", "POST", f"{org_path}/_search?type=logs",
           query_payload(allowed, start_time), status=403)
    expect(viewer, "revoked Viewer streaming query denied immediately", "POST",
           org_path + "/_search_stream?type=logs", query_payload(allowed, start_time), status=403)
    if grpc_target:
        verify_search(grpc_target, args.disposable_org, ids[users["viewer"]],
                      query_payload(allowed, start_time), run_id, revoked=True)
    if args.allowed_metric:
        params = urllib.parse.urlencode({"query": args.allowed_metric, "time": str(args.metric_time + 1)})
        expect(viewer, "revoked Viewer cannot query metrics", "GET", f"{org_path}/prometheus/api/v1/query?{params}", status=403)
    if args.second_disposable_org:
        second_path = "/api/" + urllib.parse.quote(args.second_disposable_org, safe="")
        remaining = expect(viewer, "first-org revocation preserves second-org Editor grants", "GET", f"{second_path}/rbac/me")
        require({grant["role"] for grant in remaining["grants"]} == {"editor"}, "revocation crossed organization boundary")
        second_policy = expect(root, "capture policy before membership removal", "GET", second_path + "/rbac/policy")
        expect(root, "remove generated Editor membership while policy grant remains", "DELETE",
               second_path + "/users/" + urllib.parse.quote(users["viewer"], safe=""))
        for method, suffix, body in [
            ("GET", "/rbac/me", None), ("GET", "/config", None),
            ("POST", "/_search?type=logs", query_payload(allowed, start_time)),
        ]:
            status, _ = viewer.request(method, second_path + suffix, body)
            require(status in (401, 403), f"removed member retained access to {suffix}")
            print(f"PASS removed member denied at {suffix}", flush=True)
        expect(root, "Admin cannot reassign grants to removed member", "PUT",
               second_path + "/rbac/policy", {"expected_version": second_policy["version"],
                                              "grants": second_policy["grants"]}, status=403)
        if grpc_target:
            verify_search(grpc_target, args.second_disposable_org, ids[users["viewer"]],
                          query_payload(allowed, start_time), run_id, revoked=True)
    print("PASS all requested HTTP smoke assertions; this does not cover gRPC, jobs, PostgreSQL, or all routes.")


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True, help="Exact loopback HTTP(S) URL, including configured base URI")
    parser.add_argument("--disposable-org", required=True, help="Existing disposable organization with no RBAC policy")
    parser.add_argument("--second-disposable-org", help="Optional existing uninitialized org for cross-org and password-takeover tests")
    parser.add_argument("--acknowledge-disposable-fixture", action="store_true", required=True,
                        help="Acknowledge that the script creates users/data and changes policy; no automatic cleanup")
    parser.add_argument("--allowed-metric", help="Named metric seeded into the first org while RBAC was disabled")
    parser.add_argument("--denied-metric", help="Different named metric seeded into the same org without a Viewer grant")
    parser.add_argument("--metric-time", type=int, help="Unix seconds of the pre-seeded metric samples")
    parser.add_argument("--visibility-timeout", type=int, default=30)
    args = parser.parse_args()
    parsed = urllib.parse.urlsplit(args.url)
    loopback = parsed.hostname == "localhost"
    if not loopback:
        try:
            loopback = ipaddress.ip_address(parsed.hostname or "").is_loopback
        except ValueError:
            pass
    if parsed.scheme not in ("http", "https") or not loopback or parsed.username or parsed.password or parsed.query or parsed.fragment:
        parser.error("--url must be an exact loopback HTTP(S) base URL without credentials, query, or fragment")
    if not args.disposable_org or any(char in args.disposable_org for char in "/\\*\x00"):
        parser.error("provide one existing organization identifier")
    if args.second_disposable_org:
        if args.second_disposable_org == args.disposable_org or any(char in args.second_disposable_org for char in "/\\*\x00"):
            parser.error("--second-disposable-org must be a different existing organization identifier")
    metric_args = (args.allowed_metric, args.denied_metric, args.metric_time)
    if any(value is not None for value in metric_args):
        if any(value is None for value in metric_args):
            parser.error("--allowed-metric, --denied-metric and --metric-time must be supplied together")
        if args.allowed_metric == args.denied_metric or args.metric_time <= 0:
            parser.error("metrics must differ and --metric-time must be positive Unix seconds")
        if not all(re.fullmatch(r"[A-Za-z_:][A-Za-z0-9_:]*", value) for value in metric_args[:2]):
            parser.error("metric names must be plain Prometheus metric identifiers")
    if not 1 <= args.visibility_timeout <= 300:
        parser.error("--visibility-timeout must be between 1 and 300 seconds")
    if not os.environ.get("O2_RBAC_ROOT_EMAIL") or not os.environ.get("O2_RBAC_ROOT_PASSWORD"):
        parser.error("set O2_RBAC_ROOT_EMAIL and O2_RBAC_ROOT_PASSWORD in the environment")
    return args


if __name__ == "__main__":
    try:
        run(arguments())
    except (SmokeFailure, urllib.error.URLError, TimeoutError, KeyError, TypeError) as error:
        print(f"FAIL {error}", file=sys.stderr)
        raise SystemExit(1)
