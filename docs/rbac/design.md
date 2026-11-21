# Modular OSS RBAC design

Feature tier. Baseline: c828ccec7a43f58e98cc51e0838b745544a15789. Requirements: requirements.md.

## Architecture and permission map

The Axum router composes standard, alternative ingestion, public and proxy routes (`src/api/http/src/handler/http/router/mod.rs`, auth_middleware and local_routes). Its existing openapi_coverage parser inventories method/path combinations. A route declaration guard denies undeclared routes while enabled. Authentication remains upstream-owned. The identity adapter resolves an authenticated email to the persisted user UUID through the primary database. Organization ingestion tokens use the validated token row's own policy subject.

SQL resolves typed table references in `src/search/src/sql/mod.rs` before schemas/storage. PromQL has separate storage and metadata paths. gRPC and jobs are independent boundaries; internal transport authentication does not imply authorization. Scheduled SQL alerts use a server-stamped execution subject. Legacy alerts without one deny at execution.

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

- `src/extensions/rbac`: typed policy model and Casbin decisions; pure validation, async engine construction.
- `src/infra/src/rbac.rs`: metadata persistence, credential mapping, policy reads and atomic writes [strong].
- HTTP adapter: authenticated requests to typed decisions and role-management responses.
- Query/RPC/job adapters: enforce at resolved source and independent execution boundaries.
- Route inventory: every operation declares public, enforced, or unsupported disposition.
- Vue adapter: current grants, administration and denial presentation.

No new SQL tables are needed: additive versioned metadata keys use the existing SQLite/PostgreSQL transactional abstraction. Policy reads use the primary database on every decision. A process can reuse a compiled Casbin engine only when its full policy document equals that primary read. `ZO_RBAC_POLICY_CACHE_ENTRIES` limits stored engines per process (default 64, zero disables reuse). Revocation takes effect at the next authorization decision. Existing data remains untouched on rollback. Initial implementation must document unsupported surfaces explicitly and cannot be called production-ready until the complete boundary test matrix passes.

## Verification

Positive and negative role/scoping tests, malformed policy and CAS race tests, actual Axum/gRPC boundary tests, parser-resolved SQL tests, background context tests, disabled-mode tests and route coverage. Run Cargo fmt, workspace clippy, relevant tests/build and Vue format/type/lint tests; report environmental blockers honestly. Never infer verification from source inspection.

### Destination approval extension

`PolicyDocument.destination_approvals` is additive and defaults to empty. Empty values are omitted when serializing, preserving canonical legacy policy CAS comparisons. New binaries read existing policies without granting delivery access. Older binaries reject policies with nonempty approvals; mixed-version deployment with enabled delivery approvals is unsupported.

Approval updates and role updates share one version/CAS record; role-only updates preserve approvals. The adapter validates persisted subject membership and performs source Query checks before matching exact source scopes against a destination ID/configuration fingerprint. Fingerprints canonicalize JSON object keys and include all persisted target fields and linked template content. No destination name wildcard or stream wildcard approval is accepted. Admin approvals do not bypass execution-time source permissions. Primary snapshots avoid stale destination/template cache use; external delivery remains a point-in-time authorization decision.
