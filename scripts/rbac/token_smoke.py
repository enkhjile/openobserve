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

"""Scoped organization credential checks for the disposable HTTP smoke fixture."""

import os
import urllib.parse


def exercise_tokens(args, root, editor, org_path, policy, grants, streams, run_id, start_time):
    from http_smoke import Client, expect, require, query_payload, stream_resource

    path = f"{org_path}/ingestion-tokens"
    name = f"rbac-collector-{run_id}"
    expect(editor, "Editor cannot manage organization credentials", "GET", path, status=403)
    expect(root, "feature-owned token names remain reserved", "POST", path,
           {"name": "_o2_rbac_smoke_reserved"}, status=400)
    created = expect(root, "Admin creates named org ingestion credential", "POST", path, {"name": name})["data"]
    require(bool(created.get("token")), "credential creation did not return a secret")
    listed = expect(root, "Admin lists only manageable org credentials", "GET", path)["data"]
    require(all(not row["name"].startswith("_o2_") and row["created_by"] != "system" for row in listed),
            "credential list exposed feature/system token")
    subjects = expect(root, "resolve credential stable subject", "GET", f"{org_path}/rbac/subjects")
    token_subjects = [item for item in subjects if item.get("kind") == "ingestion_token" and item.get("name") == name]
    require(len(token_subjects) == 1 and token_subjects[0]["subject"].startswith("org-token:"),
            "credential picker did not bind an explicit token namespace")
    subject = token_subjects[0]["subject"]
    # The supplied username is deliberately privileged; only the verified token row may grant access.
    writer = Client(args.url, os.environ["O2_RBAC_ROOT_EMAIL"], created["token"])
    write_path = f"{org_path}/{streams['api']}/_json"
    expect(writer, "unassigned token cannot borrow Basic username grants", "POST", write_path, [{"token_id": run_id}], status=403)
    resources = [stream_resource(streams["api"]), {"kind": "stream", "stream_type": "traces", "name": streams["traces"]}]
    if args.allowed_metric:
        resources.append({"kind": "stream", "stream_type": "metrics", "name": args.allowed_metric})
    scoped = grants + [{"subject": subject, "role": "ingester", "resources": resources}]
    policy = expect(root, "assign explicit org token stream grants", "PUT", f"{org_path}/rbac/policy",
                    {"expected_version": policy["version"], "grants": scoped})
    accepted = expect(writer, "scoped org token writes allowed log stream", "POST", write_path, [{"token_id": run_id}])
    require(sum(item.get("successful", 0) for item in accepted.get("status", [])) == 1, "token write did not ingest sample")
    expect(writer, "org token cannot write restricted stream", "POST", f"{org_path}/{streams['finance']}/_json", [{"token_id": run_id}], status=403)
    # Off its ingestion routes a token is not a credential at all, so authentication answers 401.
    for endpoint in ("rbac/me", "users", "ingestion-tokens"):
        expect(writer, "org token cannot use identity or management APIs", "GET", f"{org_path}/{endpoint}", status=401)
    expect(writer, "org token cannot query", "POST", f"{org_path}/_search?type=logs",
           query_payload(f'SELECT * FROM "{streams["api"]}"', start_time), status=401)
    other = args.second_disposable_org or "rbac_other_org"
    expect(writer, "org token cannot cross organization boundary", "POST",
           f"/api/{urllib.parse.quote(other, safe='')}/{streams['api']}/_json", [{"token_id": run_id}], status=401)
    if args.allowed_metric:
        sample = {"__name__": args.allowed_metric, "value": 2, "token_id": run_id}
        expect(writer, "scoped org token writes named metrics", "POST", f"{org_path}/ingest/metrics/_json", [sample])
        expect(writer, "org token mixed metrics batch denied", "POST", f"{org_path}/ingest/metrics/_json",
               [sample, dict(sample, __name__=args.denied_metric)], status=403)
        expect(writer, "malformed metric batch is a bad request, not a denial", "POST",
               f"{org_path}/ingest/metrics/_json", [{"value": 1, "token_id": run_id}], status=400)
    from trace_smoke import span_batch
    import uuid
    expect(writer, "scoped org token writes authorized trace", "POST", f"{org_path}/v1/traces",
           span_batch(uuid.uuid4().hex), headers={"stream-name": streams["traces"]})
    expect(writer, "org token cannot redirect trace destination", "POST", f"{org_path}/v1/traces",
           span_batch(uuid.uuid4().hex), headers={"stream-name": streams["restricted_traces"]}, status=403)
    named = f"{path}/{urllib.parse.quote(name, safe='')}"
    expect(root, "disable scoped org token", "PATCH", named, {"enabled": False})
    expect(writer, "disabled token rejected despite previous authentication", "POST", write_path, [{"token_id": run_id}], status=401)
    expect(root, "reenable same credential row", "PATCH", named, {"enabled": True})
    expect(writer, "reenabled row retains explicit scope", "POST", write_path, [{"token_id": run_id}])
    policy = expect(root, "revoke org credential policy grant", "PUT", f"{org_path}/rbac/policy",
                    {"expected_version": policy["version"], "grants": grants})
    expect(writer, "valid token loses ingestion on policy revocation", "POST", write_path, [{"token_id": run_id}], status=403)
    return policy
