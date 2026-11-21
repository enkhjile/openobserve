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

"""Scoped OTLP trace ingestion and query checks against the disposable fixture."""

import time
import urllib.parse
import uuid


def span_batch(trace_id):
    now = time.time_ns()
    return {"resourceSpans": [{"resource": {"attributes": [
        {"key": "service.name", "value": {"stringValue": "rbac-smoke"}}
    ]}, "scopeSpans": [{"spans": [{
        "traceId": trace_id, "spanId": uuid.uuid4().hex[:16], "name": "rbac scoped span",
        "kind": 2, "startTimeUnixNano": str(now - 1000000), "endTimeUnixNano": str(now),
        "status": {"code": 1}
    }]}]}]}


def exercise_traces(root, viewer, ingester, org_path, streams, run_id, start_time):
    from http_smoke import expect, require, query_payload

    allowed = streams["traces"]
    denied = streams["restricted_traces"]
    trace_id = uuid.uuid4().hex
    rejected_id = uuid.uuid4().hex
    write = f"{org_path}/v1/traces"
    body = span_batch(trace_id)
    expect(viewer, "Viewer cannot ingest trace spans", "POST", write, body,
           headers={"stream-name": allowed}, status=403)
    expect(ingester, "trace ingestion rejects unauthorized destination before writes", "POST", write,
           span_batch(rejected_id), headers={"stream-name": denied}, status=403)
    expect(ingester, "trace org header cannot redirect ingestion", "POST", write, body,
           headers={"stream-name": allowed, "organization": "other-org"}, status=403)
    expect(ingester, "Ingester writes authorized OTLP trace", "POST", write, body, headers={"stream-name": allowed})
    result = expect(viewer, "Viewer SQL reads authorized trace", "POST", f"{org_path}/_search?type=traces",
                    query_payload(f'SELECT * FROM "{allowed}" WHERE trace_id = \'{trace_id}\'', start_time))
    require(any(hit.get("trace_id") == trace_id for hit in result.get("hits", [])), "authorized trace not returned")
    params = urllib.parse.urlencode({"start_time": start_time, "end_time": time.time_ns() // 1000 + 60000000, "size": 10})
    latest = expect(viewer, "Viewer latest traces returns scoped trace", "GET", f"{org_path}/{allowed}/traces/latest?{params}")
    require(trace_id in str(latest), "latest trace response missed ingested trace")
    for client, stream in ((viewer, denied), (ingester, allowed)):
        expect(client, "trace listing denies missing Query scope", "GET", f"{org_path}/{stream}/traces/latest?{params}", status=403)
        expect(client, "streamed trace listing denies before producing data", "GET", f"{org_path}/{stream}/traces/latest_stream?{params}", status=403)
    schema = expect(root, "authorized trace metadata remains readable", "GET", f"{org_path}/streams/{allowed}/schema?type=traces")
    require(bool(schema), "trace schema missing after successful ingestion")
    rows = expect(root, "verify denied trace created no schema", "GET", f"{org_path}/streams?type=traces")
    require(denied not in str(rows), "denied trace ingestion created destination metadata")
