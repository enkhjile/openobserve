# Optional RBAC for OpenObserve OSS

This adds organization-scoped, role-based access control to the Community Edition using Casbin. It is off by default, needs no service besides OpenObserve's own metadata database, and works with any authentication OpenObserve accepts: passwords, API tokens, service accounts, organization ingestion tokens, and OIDC if enabled. Ordinary organization membership grants nothing while RBAC is on; every permission comes from an explicit grant.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `ZO_RBAC_ENABLED` | `false` | Enable RBAC. Off restores stock OpenObserve authorization. |
| `ZO_RBAC_POLICY_CACHE_ENTRIES` | `64` | Compiled policies a process may reuse. Reuse requires the whole stored policy to match, so revocation still applies at the next decision. `0` disables reuse. |

Upgrade every node, including schedulers, ingesters and queriers, before enabling RBAC, and keep routers and data nodes on the same setting.

## Enable and bootstrap

1. Back up the metadata database and keep a working root credential.
2. Set `ZO_RBAC_ENABLED=true` and restart. Organizations without a policy now refuse requests, apart from health, login, minimal configuration and the static UI.
3. Bootstrap each organization as the root user. This gives root the Admin role in that organization; it cannot overwrite an existing policy.

   ```sh
   curl --fail-with-body -u "$ROOT_EMAIL:$ROOT_PASSWORD" -X POST "$OPENOBSERVE_URL/api/$ORG/rbac/bootstrap"
   ```

4. Look up members' stable IDs and assign roles. Grants name members by ID, never by email.

   ```sh
   curl --fail-with-body -u "$ADMIN_EMAIL:$ADMIN_PASSWORD" "$OPENOBSERVE_URL/api/$ORG/rbac/subjects"
   curl --fail-with-body -u "$ADMIN_EMAIL:$ADMIN_PASSWORD" "$OPENOBSERVE_URL/api/$ORG/rbac/policy"
   ```

   Replace the policy with the complete grant set, using the current `version` as `expected_version`:

   ```json
   {
     "expected_version": 1,
     "grants": [
       {"subject": "ADMIN_ID", "role": "admin", "resources": [{"kind": "organization", "stream_type": "", "name": "organization"}]},
       {"subject": "ALICE_ID", "role": "viewer", "resources": [{"kind": "stream", "stream_type": "logs", "name": "api-logs"}]},
       {"subject": "COLLECTOR_ID", "role": "ingester", "resources": [{"kind": "stream", "stream_type": "logs", "name": "api-logs"}]}
     ]
   }
   ```

   ```sh
   curl --fail-with-body -u "$ADMIN_EMAIL:$ADMIN_PASSWORD" -H 'Content-Type: application/json' \
     -X PUT --data-binary @policy.json "$OPENOBSERVE_URL/api/$ORG/rbac/policy"
   ```

   A stale `expected_version` is refused; reload and edit again. Keep at least one organization Admin. `GET /api/$ORG/rbac/me` shows any caller their own grants. Admins can also manage grants from the IAM page.

## Roles

| Role | Permissions |
| --- | --- |
| Admin | On the organization: everything, including users, roles, credentials and delivery approvals. On a single resource, such as one pipeline or all pipelines: every action on that resource. |
| Editor | Read and query granted streams; read, change and delete granted dashboards, alerts, reports and saved queries. No pipelines, no user or role administration, no stream deletion. |
| Viewer | Read and query granted streams; read granted dashboards, alerts, reports and saved queries. No changes. |
| Ingester | Write to the named streams only. Cannot query, export, delete or administer. |
| Exporter | Read, query and download the named streams. |

A user may hold several grants; permissions add up within their resources. Stream grants name the stream type and exact stream. Removing a member's organization membership disables their grants immediately. An organization ingestion token can hold only Ingester grants on named streams, and acts as the token itself, whatever username it is sent with.

## What is enforced

- **HTTP:** every route has a declared permission, and undeclared routes, including new upstream ones, are refused. Listings of streams, dashboards, alerts, reports, saved views and pipelines show only what the caller may read.
- **Folders:** any caller with a grant in the organization can list dashboard, alert and report folders, and sees `default` and the folders that hold something the caller can read; a caller who can read every object of that type sees every folder. Opening a hidden or missing folder returns 403. Creating, renaming and deleting folders needs Admin on the organization. Moving objects needs Write on each one and a destination the caller can see; one denial moves nothing. Other folder types, and alert moves that include anomaly configs, are refused.
- **Search:** SQL is checked against every stream it names, including joins, subqueries, CTEs and unions; downloads also need Export. Searches that use a query function (VRL) are refused and the shared result cache is bypassed. PromQL instant and range queries must name each metric.
- **Search helpers:** field values (`_values`, `_values_stream`), surrounding log lines (`_around`, `_around_multi`), trace details, the trace DAG and result schemas need Query on every stream they read. Field values check the stream before revealing which fields exist. Trace details need a time range from the caller, because RBAC does not authorize the trace time index; the `traces/time_range` lookups and search history stay refused.
- **Ingestion:** JSON and multiline logs, OTLP logs over HTTP and gRPC, JSON metric batches and OTLP traces over HTTP check every destination stream, and every pipeline output, before the first write. One unauthorized destination rejects the whole request with nothing written. OpenObserve's own background writers, such as usage records, alert trigger history and SLO results, need no grant, but pipelines do not run on their data while RBAC is on; reading those streams still needs a grant.
- **Identity:** a search runs as the authenticated caller; a `user_id` header from the client never changes it. The identity follows work into background tasks and to other querier nodes, and is checked again there.
- **Revocation:** policy is read at each decision, so a revoked grant denies the next request. A request already running is not cancelled.

Not supported yet: 471 of 589 active HTTP operations, listed in [endpoints.md](endpoints.md), return 403 while RBAC is on, even for Admins. This includes public dashboards, generic proxying, and protocols such as `_bulk`, HEC and Loki. Node-to-node RPCs are listed in [rpc.md](rpc.md). Check both against what your installation uses before enabling RBAC.

## Scheduled work

Alerts, reports and pipelines run as the user who last saved them. Enabling, disabling or triggering one needs Write on it and leaves that identity unchanged. Anything saved before RBAC was enabled has no recorded identity and does not run until an authorized editor saves it again.

- **Alerts:** only scheduled SQL alerts with named source streams are supported. The creator must keep Query on every source, and an Admin must approve each source stream for each destination (`PUT /api/$ORG/rbac/destinations`). Approval binds the destination's exact configuration, so changing the destination or its template needs a new approval. Approvals and source access are checked again right before each notification.
- **Reports:** set `ZO_REPORT_SERVER_URL=` (empty) to use the built-in browser renderer; the separate report server is refused under RBAC. Configure `ZO_CHROME_ENABLED=true`, `ZO_CHROME_PATH`, and a dedicated non-root renderer account in `ZO_REPORT_USER_NAME`/`ZO_REPORT_USER_PASSWORD` that belongs to one organization and holds only Viewer on the report's dashboard and Exporter on its streams. Reports support v8 dashboards with ordinary SQL panels, PDF attachments, and approved email destinations only.
- **Pipelines:** realtime log pipelines with stream and condition nodes are supported. The pipeline's owner needs Query on the source and Ingest on every output, and whoever writes to the source needs Ingest on every output too.

## Deployment and rollback

Policies are stored in the existing metadata tables on SQLite or PostgreSQL; nothing else is needed. The upgrade adds one optional field each to alerts, reports and pipelines, which stays empty until a scoped object is saved.

To roll back, set `ZO_RBAC_ENABLED=false` and restart. This removes all RBAC restrictions, so treat it as a deliberate security decision. Policies and recorded identities stay in the database for re-enabling; don't delete them.

Behind a dedicated router, enable RBAC on the router and on every data node; each data node checks requests again. Upgrade data nodes before enabling RBAC on routers.

See also: [security notes](security.md), [maintenance](maintenance.md).
