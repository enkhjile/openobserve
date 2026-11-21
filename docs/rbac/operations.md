# OSS RBAC operations and upstream maintenance

OSS RBAC is opt-in. Enabling it makes unsupported operations return 403 for every role, including Admin. Compare the endpoints and background jobs your installation uses with `endpoints.md`, `rpc.md`, `scheduled-alerts.md` and `scheduled-reports.md` before rollout. The tested configurations and limits are recorded in `verification.md`.

## Apply to a stock checkout

The branch is a set of commits on top of a stock OpenObserve commit. To carry it onto another stock checkout, fetch `feature/rbac` and rebase it onto that commit. Then follow the rebase procedure below before building.

```sh
git fetch origin feature/rbac
git switch -c rbac-on-stock origin/feature/rbac
git rebase --onto "$STOCK_COMMIT" c828ccec7a43f58e98cc51e0838b745544a15789
cargo build
```

The build leaves RBAC disabled, so the server behaves like stock OpenObserve until `ZO_RBAC_ENABLED=true`. Every hook checks that flag first. No migration grants permissions, and the additive columns stay empty until a scoped definition is saved.

## Enable and initialize

The baseline is `c828ccec7a43f58e98cc51e0838b745544a15789`; changes live on `feature/rbac`. Authentication remains OpenObserve's existing authentication. No OIDC changes are required.

Set `ZO_RBAC_ENABLED=true` and restart. Its default is false. Before enabling, preserve an existing root credential, back up the metadata database, and rehearse the rollout against a copy. Enabled servers reject requests needing an uninitialized or invalid organization policy; they do not infer roles from existing memberships. Health, login, minimal configuration and static UI remain reachable. Initialization is explicit per organization:

```sh
curl --fail-with-body -u "$ROOT_EMAIL:$ROOT_PASSWORD" \
  -X POST "$OPENOBSERVE_URL/api/$ORG/rbac/bootstrap"
```

The existing persisted root user is the only caller accepted for bootstrap. It creates the initial Admin assignment for that user in that organization. Bootstrap cannot replace an existing policy, and root has no unconditional authorization bypass afterward. Every other role assignment is explicit. Non-root user and service-account subjects must currently belong to the organization. Removing a membership blocks its existing grants, including delegated queries. Remove stale grants before adding that identity back to the organization if its old permissions should expire permanently.

Read the current grants and resolve existing organization members to stable IDs:

```sh
curl --fail-with-body -u "$ADMIN_EMAIL:$ADMIN_PASSWORD" "$OPENOBSERVE_URL/api/$ORG/rbac/me"
curl --fail-with-body -u "$ADMIN_EMAIL:$ADMIN_PASSWORD" "$OPENOBSERVE_URL/api/$ORG/rbac/subjects"
curl --fail-with-body -u "$ADMIN_EMAIL:$ADMIN_PASSWORD" "$OPENOBSERVE_URL/api/$ORG/rbac/policy"
```

`/subjects` and `/policy` require Manage Organization. `/me` exposes only the caller's grants. Policy grants use the returned UUID, never the email. Service accounts also require an existing stable user identity and explicit grants. Organization administration cannot reset another user’s global password while RBAC is enabled, including when the caller is root. Only the existing self-update flow with current-password verification can change a password.

Use the `exporter` role to allow named SQL downloads from explicitly listed streams. It grants Read, Query and Export on those streams. It has no ingestion, data mutation or administration permissions. A Viewer can still read authorized query results; the Export permission controls operations identified by the service as downloads.

Under RBAC, trace listing uses the bounded SQL fallback. Trace ingestion omits the optional derivative metadata index, and trace readers skip index lookups. Operators should account for the extra query work and the existing fallback's behavior when traces span the requested time window.

To replace a policy, preserve at least one organization Admin, use the latest returned `version` as `expected_version`, and submit the complete grant set. Example `policy-update.json` (replace UUID placeholders):

```json
{
  "expected_version": 1,
  "grants": [
    {"subject": "ADMIN_UUID", "role": "admin", "resources": [{"kind": "organization", "stream_type": "", "name": "organization"}]},
    {"subject": "ALICE_UUID", "role": "viewer", "resources": [{"kind": "stream", "stream_type": "logs", "name": "api-logs"}]},
    {"subject": "COLLECTOR_UUID", "role": "ingester", "resources": [{"kind": "stream", "stream_type": "logs", "name": "api-logs"}]}
  ]
}
```

```sh
curl --fail-with-body -u "$ADMIN_EMAIL:$ADMIN_PASSWORD" \
  -H 'Content-Type: application/json' -X PUT \
  --data-binary @policy-update.json "$OPENOBSERVE_URL/api/$ORG/rbac/policy"
```

Changes are atomic compare-and-swap updates. A stale revision is refused; reload before editing again. The current HTTP adapter deliberately returns a generic denial for errors, including stale updates. Every decision reads the current document from the metadata writer. `ZO_RBAC_POLICY_CACHE_ENTRIES` controls how many compiled Casbin engines a process can reuse (default 64, zero disables reuse). Reuse requires the entire stored document to match. Revocation applies to the next decision. Requests already executing are not canceled by a policy change.

## Supported and blocked surfaces

The HTTP gate denies undeclared routes, including new upstream routes. SQL search, multi-search, partition and streaming requests authorize every resolved source. Named downloads also require Export on each source. Dynamic query functions and unresolved sources are denied.

PromQL instant and range queries accept GET and form POST. Each metric selector must identify an exact metric name. Metadata, label discovery, series and exemplar APIs remain blocked. Trace listing uses the authorized trace stream. Supported writes include JSON and multiline logs, OTLP logs over HTTP and gRPC, JSON metric batches and HTTP OTLP traces. A mixed metric batch requires permission on every resolved output before writing any rows. User credentials, service accounts and scoped organization ingestion tokens each require grants on the destination streams.

Stream, dashboard and saved-view listings filter before pagination. Named grants make authorized objects discoverable. Stream schema and mutation requests check the typed stream. Dashboard panel changes require Write on the containing dashboard. Organization listing returns grants held by current members. A bootstrapped root can also discover its explicitly granted organizations when it lacks a membership row. The listing omits owner contact details.

Scheduled SQL alerts carry their creator's stable subject and require explicit delivery approval for every source. See the scheduled-alerts guide for supported definitions and revocation behavior. The endpoint matrix records individual HTTP operations. Unsupported operations return 403 even for organization Admins. Examples include public dashboards, generic proxy forwarding and ingestion protocols without scoped adapters. Independent gRPC and background guards also require trustworthy execution context.

## Persistence, rollback and upgrade

Policies are additive versioned documents in the existing `meta` table under the `rbac` module and organization key. Atomic conditional INSERT/UPDATE statements use the existing primary SeaORM pool and metadata unique index, with start_dt fixed at zero. SQLite and PostgreSQL reuse existing metadata storage; no external server or separate database is introduced. Existing users, memberships and resource records are preserved. Back up metadata before changes. Disabling `ZO_RBAC_ENABLED` and restarting restores upstream authorization behavior; this intentionally removes the new restrictions and must be treated as an operator-controlled security rollback. Policy documents may remain for re-enabling. Do not delete them during routine rollback.

The alert, report and pipeline migrations add nullable text fields for execution identity or context. Existing rows keep their IDs and data. With RBAC enabled, an unbound scheduled definition cannot run until an authorized editor saves a supported definition. Review the intended executor, source grants and delivery approvals before doing so. Upgrade all schedulers, ingesters and query nodes before turning the feature on. Before restoring an older binary, stop or drain jobs that depend on these checks. Keep the additive columns and policy records for a subsequent upgrade.

For the scoped dashboard report renderer, set `ZO_REPORT_SERVER_URL` to an empty value to select the embedded browser. Use a dedicated organization-local renderer login with the grants described in `scheduled-reports.md`. The default points at the separate report service, whose requests are denied while RBAC is enabled.

### Rebase procedure

Set `OLD` to the stock commit the branch currently sits on and `NEW` to the target stock commit.

1. List upstream changes to the files that carry hooks. Review each against its purpose in `modified-files.md`. A route can keep its path and still change which identity or destination it uses.

   ```sh
   git diff --stat "$OLD" "$NEW" -- $(sed -n 's/^- `\([^`]*\)`.*/\1/p' docs/rbac/modified-files.md)
   ```

2. List changed routes, handlers and RPC declarations. Check authentication results and org-token provenance in particular. A token username must never become a user UUID.

   ```sh
   git diff "$OLD" "$NEW" -- src/api/http/src/handler/http/router/mod.rs src/api/grpc/src/server.rs \
     src/api/grpc/src/router src/proto/proto src/api/common/src/auth src/api/grpc/src/handler/grpc/auth
   git diff --stat "$OLD" "$NEW" -- 'src/api/*/src/request' 'src/core/src/logs' 'src/core/src/traces' 'src/core/src/metrics'
   ```

3. Rebase, then regenerate the HTTP inventory and check the RPC inventory. The script fails when a cluster RPC is missing from `rpc.md` or no longer exists. `git diff` on the generated matrix lists every route whose path or disposition changed. New routes are `Unsupported` until reviewed, and the runtime gate denies them. Review the OTLP rows in `rpc.md` by hand whenever `src/api/grpc/src/server.rs` or the router's OTLP proxies change.

   ```sh
   python3 scripts/rbac/endpoint_inventory.py
   git diff docs/rbac/endpoints.md
   python3 scripts/rbac/endpoint_inventory.py --check
   ```

4. Run the authorization regressions: route gate and coverage snapshot, Casbin engine, gRPC interceptors and ingestion hooks.

   ```sh
   cargo test -p openobserve-api-http --lib rbac
   cargo test -p openobserve-api-http --lib openapi_coverage
   cargo test -p openobserve-rbac
   cargo test -p openobserve-api-grpc --lib auth
   cargo test -p openobserve-core --lib logs::otlp
   ```

5. Run `cargo fmt --all`, workspace Clippy with the `AGENTS.md` flags, the debug build, and the relevant Vue format/type/lint/unit checks. Report any check you could not run. The Enterprise stubs do not verify an Enterprise build.
6. Run the live suites. The HTTP launcher covers Admin, Editor, Viewer and Ingester identities, restricted and cross-org streams, SQL joins/CTEs/unions and revocation on SQLite and PostgreSQL. The OTLP log suite covers collectors over HTTP and gRPC. Use the scripts listed under the smoke-test sections below.

## Disposable HTTP smoke test

From the repository root, build the debug server and run the full HTTP and gRPC suites against fresh SQLite and PostgreSQL instances. Install the Protocol Buffers compiler (`protoc`) and start Docker locally. The PostgreSQL run uses the official `postgres:16` image. The launcher requires Python 3.10 or later.

```sh
cargo build
python3 -m venv .venv-rbac
.venv-rbac/bin/python -m pip install grpcio
.venv-rbac/bin/python scripts/rbac/run_http_smoke.py --binary target/debug/openobserve
```

Use `--store sqlite` to run only SQLite, or `--store postgres` for PostgreSQL. The SQLite run needs no Docker. The launcher generates credentials, binds ephemeral loopback ports, seeds both organizations and metric samples, and restarts OpenObserve with RBAC enabled. It exercises cross-organization access, PromQL and delegated gRPC against each store. It then disables RBAC, verifies that a legacy member can read a pre-existing metric sample, re-enables RBAC, and checks that the same request is denied and the full policy and revision are preserved. The launcher stops its services and removes successful local runs. On failure it prints the private fixture directory at startup and retains the server log and OpenObserve data there for diagnosis. The PostgreSQL container and its ephemeral database are removed at shutdown.

For a manually provisioned disposable loopback server, `scripts/rbac/http_smoke.py` can also run directly. Set `O2_RBAC_ROOT_EMAIL` and `O2_RBAC_ROOT_PASSWORD` in the environment and supply the uninitialized organization. The test bootstraps revision 1 and refuses to reuse a previously bootstrapped fixture.

```sh
python3 scripts/rbac/http_smoke.py \
  --url http://127.0.0.1:5080 \
  --disposable-org default \
  --acknowledge-disposable-fixture
```

To include cross-organization isolation and the global-password takeover regression, create a second fresh organization on the disposable instance **before enabling RBAC** using `POST /api/organizations` with Basic root credentials and JSON `{"name":"rbac_smoke_second"}`. The handler returns HTTP 200 with the generated identifier in the top-level `identifier` field. It generates a UUID even if the request includes an identifier; use the returned value. Then supply `--second-disposable-org RETURNED_IDENTIFIER` to the smoke command after enabling RBAC. This second organization must also have no existing policy.

To include delegated SQL over gRPC, set `O2_RBAC_FIXTURE_GRPC_TARGET` to the disposable server's loopback host and port and supply `O2_RBAC_INTERNAL_GRPC_TOKEN`. Install `grpcio` for the script interpreter and make `protoc` available on PATH. The test encodes requests from the checked-in cluster protocol, verifies a specific authorized row and repeats the request after revocation.

The optional PromQL suite takes `--allowed-metric NAME --denied-metric NAME --metric-time UNIX_SECONDS`. Seed both named gauge metrics into the first disposable organization while RBAC is disabled through `POST /api/{org}/ingest/metrics/_json`, with records shaped as `{"__name__":"NAME","__type__":"gauge","job":"rbac_smoke","_timestamp":UNIX_SECONDS*1000,"value":1.0}`. Supply integer milliseconds as `_timestamp`; the `*1000` notation describes conversion, not literal JSON. The runner then grants the Viewer access to only the first metric. Both GET/form-POST instant and range queries require real positive series, and restricted, combined, unnamed, regex and revoked selectors must deny. The enabled-state suite separately verifies scoped batch ingestion and checks the stored rows after a mixed-permission request.

The optional suite gives the same identity Viewer in the first organization and Editor in the second, confirms membership alone grants nothing to the first-org Ingester/Admin in the second organization, and exercises identical stream names across the boundary. Admin A adds existing Admin B to A, attempts to reset B's global password, and must receive 403; B's original credentials must still work. A's Viewer revocation must preserve that identity's Editor grant in B.

The script accepts loopback URLs only, disables proxy inheritance and refuses redirects. It creates unique Viewer/Editor/Ingester identities and unique API/finance streams, never prints passwords, and does not automatically delete anything. Discard the disposable instance and its entire fixture metadata/data after testing; do not use cleanup commands against existing data. The upstream OSS membership role is Admin for both users because the existing OSS creation handler assigns it; the test verifies that independent Casbin grants nevertheless restrict those identities.

The Editor suite creates a version-8 empty dashboard, edits it with the returned concurrency hash, reads back the changed title, and rejects user/role administration and stream deletion. Assertions cover bootstrap, current grants, member UUID lookup, policy compare-and-swap and stale updates, root ingestion, Viewer positive reads and filtered listing, direct/JOIN/CTE/subquery/UNION denial, Viewer mutations and escalation, Ingester writes versus reads, restricted destinations, undeclared routes and immediate revocation. Positive ingestion checks record acknowledgement, and positive search checks a unique row rather than only HTTP status. Visibility polling is bounded and never retries an authorization failure. This script does not replace gRPC/background/PostgreSQL coverage. Authoring checks (`py_compile`, `--help`) do not demonstrate that the HTTP assertions pass; record the actual run result separately.

### OTLP log collector check

The OTLP log suite starts its own loopback servers with fresh data. It needs the debug binary and `grpcio`, and Docker for PostgreSQL. It ingests with RBAC disabled, then enables RBAC and bootstraps both organizations. It then checks HTTP JSON and gRPC protobuf exports for a user collector and a scoped org ingestion token:

- authorized writes, with the row read back;
- restricted-stream, Viewer and cross-organization denials;
- forged `user_id` behind the internal token;
- pipeline fan-out whose outputs are only partly granted, rejected with no stream created;
- immediate revocation of the user grant and the disabled token.

Finally it rolls back to disabled mode and back to enabled, and verifies the policy is unchanged.

```sh
.venv-rbac/bin/python scripts/rbac/otlp_logs_smoke.py --binary target/debug/openobserve --store both --acknowledge-disposable-fixture
```

### Browser and background checks

For the Admin and Viewer browser check, start a fresh loopback instance with RBAC enabled, an uninitialized default organization and built Vue assets. Install the locked dependencies in `tests/ui-testing` and use an installed Google Chrome. Set `O2_RBAC_BROWSER_URL`, `O2_RBAC_ROOT_EMAIL` and `O2_RBAC_ROOT_PASSWORD` for this instance. Run `node tests/ui-testing/scripts/rbac-browser-smoke.cjs --acknowledge-disposable-fixture`. It creates the users, dashboard and policy fixture and checks both identities through the login page.

The following scripts start their own isolated servers and require the local debug binary. The alert check uses a loopback webhook and the report check uses a loopback SMTP listener. To select a different Chrome executable, pass `--chrome PATH` to the report runner.

```sh
python3 scripts/rbac/template_smoke.py --binary target/debug/openobserve --acknowledge-disposable-fixture
python3 scripts/rbac/alert_smoke.py --binary target/debug/openobserve --acknowledge-disposable-fixture
python3 scripts/rbac/report_smoke.py --binary target/debug/openobserve --acknowledge-disposable-fixture
```

## Dedicated routers

Enable RBAC on the router and its data nodes. The router forwards supported API requests to the downstream `/internal/rbac/v1/api` mount. The receiving node authenticates the request and applies its own policy checks. A downstream version without the enforcing mount returns an error during a rolling upgrade. Upgrade data nodes before directing traffic through an enabled router. Keep direct access to legacy or RBAC-disabled data nodes closed during rollout. A configured base URI applies at both ends.

## Upstream integration points

- `src/api/http/src/handler/http/router/mod.rs`: post-auth identity adapter, RBAC management routes, safe organization list adapter, outer deny gate.
- `src/api/http/src/handler/http/router/rbac.rs`: isolated HTTP declarations, typed enforcement, management handlers and gate tests.
- `src/api/http/src/handler/http/router/openapi_coverage/`: existing parser reused for the review snapshot; UI-only extension endpoints explicitly excluded from public data OpenAPI.
- `src/api/management/src/request/stream/mod.rs`: filter allowed typed streams before totals/pagination.
- `src/api/common/src/auth/validator.rs`: prevent authentication-driven organization auto-creation when enabled.
- `src/core/src/users.rs`: deny cross-identity global password resets so organization administration cannot take over a principal authorized elsewhere.
- `src/infra/src/db/nats.rs` and `src/infra/src/file_list/mod.rs`: explicit string-slice concatenation resolves type ambiguity introduced by Casbin’s transitive smartstring implementation.
- `src/config/src/config.rs`, root/infra Cargo manifests, and `src/infra/src/lib.rs`: opt-in configuration and module wiring.
- `src/infra/src/rbac.rs` and `src/extensions/rbac/`: persistence, bootstrap, stable identities, Casbin policy model and typed decisions.
- `src/core/src/logs/ingest.rs` (`authorize_scoped_destinations`): the shared pre-write check for log destinations. Both `_json`/`_multi` and OTLP logs call it. It authorizes the destination stream and loads only scoped pipelines, whose outputs the trigger identity must also hold Ingest on.
- `src/core/src/logs/otlp.rs`: takes the verified org-token principal, calls the shared check before `check_ingestion_allowed`, and returns pipeline failures as denials instead of writing the source.
- `src/api/ingest/src/request/logs/ingest.rs` (`otlp_logs_write`): passes the authenticated org-token principal and maps a denial to 403.
- `src/api/grpc/src/handler/grpc/auth/mod.rs`, `src/api/grpc/src/server.rs`, `src/api/grpc/src/handler/grpc/request/{otlp,logs}.rs`: a logs-only interceptor that refuses the internal token while RBAC is enabled, and the async primary re-read of org ingestion tokens. Other OTLP services keep the deny-all interceptor.
- `src/api/grpc/src/router/grpc/ingest/logs.rs`: forwards the caller's credential instead of the internal token when RBAC is enabled.
- Search, streaming/cache, logs ingestion, PromQL, Flight/gRPC guards: consult the final branch diff for the exact execution hooks; they must remain aligned with HTTP supported declarations.
- Vue IAM panel and shared access-denied handling: UI consumes server grants; it is not the security boundary.

The endpoint exporter compiles only the existing route parser and classifier in a temporary crate. Its output documents all editions, but its active flag reflects OSS defaults. The CI snapshot requires conscious review after route or disposition changes. Preserve all AGPL notices when redistributing this branch.

### Scheduled delivery approvals

An organization Admin reviews an existing destination configuration, then approves its name and exact source streams through the IAM delivery approval editor or `PUT /api/{org}/rbac/destinations`. The request is `{ "expected_version": 3, "approvals": [{ "destination_name": "ops", "sources": [{ "kind": "stream", "stream_type": "logs", "name": "api" }] }] }`. This replaces the entire approval list under the same policy revision CAS as role grants. An empty list revokes all delivery approvals. Existing entries should include `expected_target_fingerprint` from the policy response; changed bindings fail instead of silently approving a new target.

Approvals bind the organization, persisted destination ID, complete target configuration, and linked template ID/content. Deleting and recreating a name does not inherit approval. Target/template changes require explicit removal and reapproval after configuration review. The supported initial delivery types are static HTTP (untyped/custom) and email with a linked custom template; SNS, Slack, Jira and content/chart templates fail closed. Approval input never accepts a webhook URL or recipient list.

At execution, the principal must still exist with exact organization membership, retain Query on every resolved source stream, and every source must be approved for every destination. Dispatch consumes the authorized primary destination/template snapshot rather than cached delivery configuration. Approval revocation is checked immediately before dispatch; an external send already started cannot be recalled. Alert-level template overrides and other unsupported delivery modes must remain rejected by the alert adapter.

### OTLP log collectors

Point a collector at `POST /api/{org}/v1/logs` (OTLP/HTTP) or the gRPC `LogsService/Export` with `organization` and `stream-name` metadata. Authenticate with a user or service-account credential, or with an organization ingestion token. The destination is the `stream-name` value, or `default` when it is absent. Grant the credential Ingester on that exact `logs` stream. If an enabled realtime pipeline reads the stream, also grant Ingester on every pipeline output stream. The pipeline itself must have a scoped execution subject. A request whose destination or any pipeline output is not granted returns HTTP 403 or gRPC `PERMISSION_DENIED`, and nothing from it is written.

The gRPC service refuses the cluster's internal token while RBAC is enabled, because that token can assert any `user_id`. A dedicated router forwards the collector's own credential to the ingester, which authenticates it again. Upgrade ingesters before enabling RBAC on routers, and keep both on the same setting. Org ingestion tokens are re-read from the primary store on every export, so disabling a token takes effect immediately. OTLP metrics, OTLP traces over gRPC and OTLP profiles remain denied.

### Scoped organization ingestion tokens

The Admin member picker also lists enabled organization ingestion tokens by name, without exposing credential values. Their policy subjects are `org-token:<persisted-row-id>`; despite the historical `ider::uuid()` function name, current row IDs are KSUIDs. Token subjects accept only Ingester grants on exact typed stream names. Namespace validation rejects malformed IDs, other roles, and wildcard scopes.

Assignments and ingestion authorization re-read the primary token row and require its organization, enabled state and non-feature-writer status. Reserved `_o2_` token names and `created_by = system` rows cannot receive ordinary policy grants. Deleting and recreating a token changes its subject; rotating the secret on the same row preserves its scopes. The authentication adapter must derive this identity from a validated secret; names and caller-supplied subject strings are not credentials.

### Organization-local template administration

With RBAC enabled, template CRUD and reads require organization administration. Template name lookups and lists use the primary store and exact path organization, including for root. Shared-default inheritance and rename fallback are unavailable. The default organization remains usable on a normal single-node installation: an Admin can create, read, update and delete ordinary local custom templates. Content/chart templates, preview/system-template routes and compiled templates are outside this initial write surface.

Before enabling RBAC on an installation that used shared defaults, copy the required custom template into each consuming organization, update that organization's destination binding, then explicitly approve the destination and its exact source streams. Existing rows are not migrated or deleted. Background consumers that depended on default inheritance fail closed until their local binding is recreated. In mixed configurations, do not assume old nodes enforce this lookup rule.

A legacy default template still bound from another organization cannot be changed or deleted through the enabled administration API. Primary checks cover foreign destination template IDs and alert, anomaly, synthetic, on-call and composite template-name bindings. Refusals reveal neither foreign names nor counts. Usage responses are restricted to the requested organization. Remove or migrate foreign bindings before editing the formerly shared row; an unrelated local default-org template remains editable.
