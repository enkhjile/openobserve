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

"""Real scoped local pipeline filtering and all-output authorization checks."""

import uuid


def definition(org, source, destinations):
    nodes = [{"id": "source", "data": {"node_type": "stream", "org_id": org, "stream_type": "logs", "stream_name": source},
              "position": {"x": 0, "y": 0}, "io_type": "input"},
             {"id": "filter", "data": {"node_type": "condition", "conditions": [{"column": "route", "operator": "=", "value": "keep", "ignore_case": False}]},
              "position": {"x": 10, "y": 0}, "io_type": "default"}]
    edges = [{"id": "source-filter", "source": "source", "target": "filter"}]
    for index, name in enumerate(destinations):
        node_id = f"output{index}"
        nodes.append({"id": node_id, "data": {"node_type": "stream", "org_id": org, "stream_type": "logs", "stream_name": name},
                      "position": {"x": 20, "y": index}, "io_type": "output"})
        edges.append({"id": f"filter-{node_id}", "source": "filter", "target": node_id})
    return {"name": f"rbac-routing-{source}", "org": org, "enabled": True, "nodes": nodes, "edges": edges,
            "execution_subject": "forged-identity-must-be-ignored"}


def exercise_pipelines(args, root, editor, ingester, viewer, org_path, policy, grants, ids, users, run_id, start_time):
    from http_smoke import expect, require, query_payload, stream_resource

    source = f"pipeline_input_{run_id}"
    destinations = [f"pipeline_output_{run_id}", f"pipeline_other_{run_id}"]
    executor = ids[users["editor"]]
    trigger = ids[users["ingester"]]
    managing = {"subject": executor, "role": "admin", "resources": [{"kind": "pipeline", "stream_type": "", "name": "*"}]}
    source_read = {"subject": executor, "role": "viewer", "resources": [stream_resource(source)]}
    output_write = {"subject": executor, "role": "ingester", "resources": [stream_resource(name) for name in destinations]}
    trigger_one = {"subject": trigger, "role": "ingester", "resources": [stream_resource(source), stream_resource(destinations[0])]}
    trigger_all = dict(trigger_one, resources=[stream_resource(name) for name in [source] + destinations])

    def policy_with(extra, label):
        nonlocal policy
        policy = expect(root, label, "PUT", f"{org_path}/rbac/policy", {"expected_version": policy["version"], "grants": grants + extra})

    def ingest(marker, status=200):
        return expect(ingester, "scoped pipeline ingestion", "POST", f"{org_path}/{source}/_json",
                      [{"route": "keep", "pipeline_marker": marker}, {"route": "drop", "pipeline_marker": marker}], status=status)

    def output(marker, expected):
        for name in destinations:
            response = expect(root, "verify exact pipeline output rows", "POST", f"{org_path}/_search?type=logs",
                              query_payload(f'SELECT * FROM "{name}" WHERE pipeline_marker = \'{marker}\'', start_time))
            hits = response.get("hits", [])
            require(len(hits) == expected, "pipeline output count differs from authorized filter result")
            require(all(row.get("route") == "keep" for row in hits), "condition node did not filter dropped rows")

    policy_with([managing, source_read, output_write, trigger_one], "grant independent pipeline executor and trigger scopes")
    body = definition(args.disposable_org, source, destinations)
    expect(viewer, "Viewer cannot create a routing pipeline", "POST", f"{org_path}/pipelines", body, status=403)
    created = expect(editor, "scoped pipeline Admin creates real local filter and fan-out", "POST", f"{org_path}/pipelines", body)
    pipeline_id = created["id"]
    require(bool(pipeline_id), "pipeline create did not return identity")
    first = uuid.uuid4().hex
    ingest(first, status=403)
    streams = expect(root, "rejected pipeline batch creates neither destination", "GET", f"{org_path}/streams?type=logs")
    require(all(name not in str(streams) for name in destinations), "mixed-scope pipeline wrote destination metadata")
    policy_with([managing, source_read, output_write, trigger_all], "grant trigger every actual pipeline output")
    positive = uuid.uuid4().hex
    ingest(positive)
    output(positive, 1)
    policy_with([managing, output_write, trigger_all], "revoke executor source Query immediately")
    revoked = uuid.uuid4().hex
    ingest(revoked, status=403)
    output(revoked, 0)
    policy_with([managing, source_read, output_write, trigger_one], "revoke one trigger destination immediately")
    mixed = uuid.uuid4().hex
    ingest(mixed, status=403)
    output(mixed, 0)
    expect(editor, "delete only generated pipeline", "DELETE", f"{org_path}/pipelines/{pipeline_id}")
    policy_with([], "restore original fixture grants after pipeline runtime checks")
    return policy
