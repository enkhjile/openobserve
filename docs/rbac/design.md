# Modular OSS RBAC design

Feature tier. Baseline: c828ccec7a43f58e98cc51e0838b745544a15789.

## Architecture and permission map

Every HTTP route has a declared disposition: public, member, a specific permission, or unsupported. Undeclared routes are denied while RBAC is enabled. Authentication stays with OpenObserve. RBAC maps the authenticated account to its stable user ID, never its email. An organization ingestion token acts as its own policy subject.

SQL searches are authorized on every stream the query names, before any schema or storage access. PromQL is authorized per named metric. gRPC calls and background jobs are separate boundaries: the cluster's internal credential proves the caller is a node, not that the request is permitted. Scheduled alerts, reports and pipelines run as the identity recorded when they were last saved. Objects saved before RBAC have no recorded identity and do not run.

| Operation family | Required action/resource |
| --- | --- |
| Organization/users/roles/service accounts | Manage organization |
| Dashboards/alerts/pipelines/reports/saved queries | Read, Write or Delete typed resource |
| SQL/PromQL/traces/search | Query each resolved typed stream |
| Exports/downloads | Export each source stream plus result ownership |
| Logs/metrics/traces ingestion | Ingest every destination typed stream |
| Stream metadata/deletion | Read/Delete typed stream |
| Jobs and internal RPCs | Same operation under preserved principal; missing context denies |
| Health/readiness/static assets | Explicit public declaration |
| Unclassified routes | Deny |

## Numbered security rules

1. Disabled mode preserves existing behavior; enabled failures never grant access.
2. Policy subjects are stable UUIDs or verified credential identities, never emails or caller headers.
3. Organization is part of every decision and every durable policy document.
4. Admin, Editor, Viewer and Ingester are explicit assignments; ordinary memberships confer no grants. A user's UUID must have current organization membership in the primary database. Removing a membership disables its retained policy grants. The persisted root identity can use an explicit policy grant without membership, which permits administrators to bootstrap an existing organization. Multiple assignments union privileges only within their explicit scopes.
5. Stream grants include stream type/name; Ingester requires explicit destinations and has no reads.
6. Casbin evaluates each permission. Unknown action/resource, invalid/missing policy, or unknown identity denies.
7. Metadata documents are versioned; conditional SQL compare-and-swap through the primary SeaORM connection serializes changes and stale writes fail. No cached permit may survive the configured revocation bound.
8. Bootstrap preserves root but grants only explicitly initialized organization administration; never auto-promote other users.
9. Every HTTP operation has an explicit disposition, and downstream queries authorize every resolved source. A SQL string must contain one statement. Batch endpoints resolve the complete set of statements before checking a single current policy snapshot.
10. Alternate authentication, gRPC, proxy, caches, exports and background work cannot bypass the boundary. Unsupported paths deny until a reliable adapter exists.
11. Role administration is itself authorized; callers cannot escalate through policy updates.
12. UI consumes server permissions; backend remains authoritative.

## Components

- **Policy engine:** evaluates typed permissions with Casbin. Unknown actions, resources or identities deny.
- **Policy store:** keeps each organization's policy as a versioned document in OpenObserve's existing metadata database. Updates are compare-and-swap, so a stale edit is refused.
- **HTTP gate:** applies each route's declared disposition and serves the role-management API.
- **Search, ingestion, RPC and job checks:** authorize the resolved streams and destinations at the point where data is read or written.
- **Route inventory:** a generated table of every HTTP operation and its disposition. CI fails when it drifts.
- **UI:** shows the caller's grants and the administration screens, and hides controls the caller cannot use. The server stays authoritative.

No new SQL tables are needed: additive versioned metadata keys use the existing SQLite/PostgreSQL transactional abstraction. Policy reads use the primary database on every decision. A process can reuse a compiled Casbin engine only when its full policy document equals that primary read. `ZO_RBAC_POLICY_CACHE_ENTRIES` limits stored engines per process (default 64, zero disables reuse). Revocation takes effect at the next authorization decision. Existing data remains untouched on rollback. Initial implementation must document unsupported surfaces explicitly and cannot be called production-ready until the complete boundary test matrix passes.

## Verification

Positive and negative role and scoping tests, malformed-policy and concurrent-update tests, real HTTP and gRPC boundary tests, SQL source tests, background context tests, disabled-mode tests and route coverage. Run Cargo fmt, workspace clippy, relevant tests/build and Vue format/type/lint tests; report environmental blockers honestly. Never infer verification from source inspection.

### Destination approval extension

Delivery approvals are stored in the same policy document and default to none. Existing policies keep working and grant no delivery access. Older binaries refuse a policy that contains approvals, so mixed-version deployments must not enable delivery approvals.

Approval and role updates share one policy version; a role-only update keeps the approvals. Delivery requires current membership, Query on every source stream, and an approval that matches the destination's exact stored configuration and linked template. Any change to the destination or template invalidates the approval. No destination name wildcard or stream wildcard approval is accepted. Admin approvals do not bypass execution-time source permissions. Dispatch uses the current stored destination, not a cached copy. A send that has already started cannot be recalled.
