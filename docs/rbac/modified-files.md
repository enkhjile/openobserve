# Modified files

Branch `feature/rbac` is based on `c828ccec7a43f58e98cc51e0838b745544a15789`. The extension crate owns role semantics and policy decisions. The infrastructure crate reads authoritative policy, membership, credentials and job definitions. Transport and execution adapters pass verified identities and resolved resources to these boundaries.

The file inventory includes additive migrations, generated protocol bindings, authorization tests, Vue components and operational guides. Several string concatenations in the cluster-state, file-list, system settings and bulk ingestion code use explicit string slices to resolve a trait ambiguity introduced by a transitive dependency of the policy engine.

Each entry for a file that exists upstream states the behaviour its hook adds. Review that behaviour when an upstream change touches the file. Entries without a description are files RBAC adds, which upstream changes cannot conflict with. With RBAC disabled, every hook leaves existing behaviour unchanged.

## Workspace configuration

- `Cargo.lock`: Mechanical: generated lockfile update for the policy engine and its transitive dependencies.
- `Cargo.toml`: Mechanical: registers the RBAC extension as a workspace member and points a browser-protocol dependency at a vendored copy so the build resolves.
- `vendor/chromiumoxide_types/.gitignore`
- `vendor/chromiumoxide_types/Cargo.toml`
- `vendor/chromiumoxide_types/LICENSE-APACHE`
- `vendor/chromiumoxide_types/LICENSE-MIT`
- `vendor/chromiumoxide_types/README.md`
- `vendor/chromiumoxide_types/src/lib.rs`

## Design and operations

- `docs/rbac/design.md`
- `docs/rbac/endpoints.md`
- `docs/rbac/identity-context.md`
- `docs/rbac/modified-files.md`
- `docs/rbac/operations.md`
- `docs/rbac/rpc.md`
- `docs/rbac/scheduled-alerts.md`
- `docs/rbac/scheduled-reports.md`
- `docs/rbac/verification.md`

## Verification and CI

- `scripts/rbac/alert_smoke.py`
- `scripts/rbac/endpoint_inventory.py`
- `scripts/rbac/grpc_smoke.py`
- `scripts/rbac/http_smoke.py`
- `scripts/rbac/otlp_logs_smoke.py`
- `scripts/rbac/pipeline_smoke.py`
- `scripts/rbac/report_smoke.py`
- `scripts/rbac/run_http_smoke.py`
- `scripts/rbac/template_smoke.py`
- `scripts/rbac/token_smoke.py`
- `scripts/rbac/trace_smoke.py`
- `tests/ui-testing/scripts/rbac-browser-smoke.cjs`

## Rust integration in api

- `src/api/common/src/auth/delegation.rs`: Mechanical: delegated validation carries the new verified-token field, always unset because it never yields an org ingestion token.
- `src/api/common/src/auth/token.rs`: Mechanical: both validation results on this path carry the new verified-token field, unset.
- `src/api/common/src/auth/validator.rs`: With RBAC enabled, org ingestion tokens are verified against the primary store, accepted only on ingestion-write routes, and never trigger automatic org creation.
- `src/api/grpc/src/handler/grpc/auth/mod.rs`: With RBAC enabled, gRPC services without a scoped adapter refuse every caller; OTLP log export refuses the internal credential, which could claim any user, and re-checks org ingestion tokens against the primary store.
- `src/api/grpc/src/handler/grpc/request/logs.rs`: With RBAC enabled, the verified org ingestion token is the ingest identity and every destination is authorized before writing.
- `src/api/grpc/src/handler/grpc/request/event.rs`: With RBAC enabled, downloading latest files from peer nodes is disabled and the file-list RPC is rejected without a scoped execution identity.
- `src/api/grpc/src/handler/grpc/request/metrics/querier.rs`: With RBAC enabled, the metrics query RPC requires a verified subject, denials return permission denied, and the other metrics RPCs are rejected outright.
- `src/api/grpc/src/handler/grpc/request/otlp.rs`: Adds a logs-only OTLP interceptor that keeps the existing memory-pressure refusal.
- `src/api/grpc/src/handler/grpc/request/query_cache.rs`: With RBAC enabled, both query-cache RPCs return permission denied because cached results are not scoped to a subject.
- `src/api/grpc/src/router/grpc/ingest/logs.rs`: With RBAC enabled, the router forwards the caller's own credential instead of the internal token so the ingester authenticates and scopes it.
- `src/api/grpc/src/server.rs`: Serves the OTLP logs service on ingester and router behind the logs-only interceptor, while other OTLP services stay denied.
- `src/api/http/src/handler/http/router/mod.rs`: Wires authorization into the HTTP stack after authentication, scopes each request to its verified caller, adds the RBAC routes, and mounts the versioned `/internal/rbac/v1/api` forwarding routes.
- `src/api/http/src/handler/http/router/openapi_coverage/excluded_routes.txt`: Excludes the new browser-only RBAC policy, subject, bootstrap and destination routes from the public OpenAPI contract.
- `src/api/http/src/handler/http/router/openapi_coverage/mod.rs`: Treats forwarding-route aliases as their canonical API operations and tests that every endpoint has a reviewed RBAC disposition in `docs/rbac/endpoints.md`.
- `src/api/http/src/handler/http/router/rbac.rs`
- `src/api/http/src/handler/http/router/rbac_destinations.rs`
- `src/api/http/src/handler/http/router/rbac_forwarding_tests.rs`
- `src/api/http/src/router/http/mod.rs`: With RBAC enabled, the router tier forwards requests to nodes under `/internal/rbac/v1` so nodes re-authorize them, disables body-based result-cache routing, and serves the RBAC proxy routes.
- `src/api/ingest/src/request/logs/ingest.rs`: Log ingestion over JSON, multi and OTLP accepts the verified org ingestion token as the ingest identity, and authorization denials return HTTP 403.
- `src/api/ingest/src/request/metrics/ingest.rs`: Metrics JSON ingestion uses the verified org ingestion token as identity and returns 403 instead of 400 on authorization denial.
- `src/api/management/src/models/alerts/requests.rs`: Test only: proves an execution identity supplied by the client in alert create or update bodies is ignored.
- `src/api/management/src/request/alerts/mod.rs`: With RBAC enabled, only scheduled alerts are allowed, the alert is bound to its creator's identity and organization on create and update, and list and detail responses show only readable alerts.
- `src/api/management/src/request/alerts/templates.rs`: Test only: asserts a template authorization denial returns HTTP 403.
- `src/api/management/src/request/dashboards/mod.rs`: With RBAC enabled, the dashboard list shows only allowed dashboards and pagination applies after filtering.
- `src/api/management/src/request/dashboards/reports.rs`: With RBAC enabled, scheduled reports are bound to their author with organization, folder-move and renderer checks and a public denial, and the report list shows only readable reports.
- `src/api/management/src/request/organization/ingestion_tokens.rs`: With RBAC enabled, enabling or disabling default, system or writer ingestion tokens is forbidden because they are not manageable credentials.
- `src/api/management/src/request/service_accounts/mod.rs`: Before rotating a service-account token, checks the target's org membership and role against the primary store.
- `src/api/management/src/request/stream/mod.rs`: The stream list shows only streams the caller may read, before totals and pagination; a policy error returns 403.
- `src/api/pipelines/src/models/pipelines.rs`: With RBAC enabled, historic error samples are omitted from pipeline responses so they cannot leak data from unreadable streams; tested in both modes.
- `src/api/pipelines/src/request/pipeline.rs`: With RBAC enabled, pipeline create and update run as the verified user, and the pipeline list shows only allowed pipelines.
- `src/api/search/src/promql/mod.rs`: RBAC denials in PromQL return HTTP 403 while syntax errors stay 400.
- `src/api/search/src/search/multi_streams.rs`: Every query of a multi-stream or partitioned multi-stream search is authorized before execution, and background producers keep the caller's identity.
- `src/api/search/src/search/saved_view.rs`: The saved-view list shows only saved queries the caller may read; a decision error returns 403.
- `src/api/search/src/search/search_stream.rs`: Background streaming producers keep the request's caller so their SQL is authorized for it.
- `src/api/search/src/traces/list/query.rs`: With RBAC enabled, the trace-list time index is disabled so trace listing goes through the authorized search path.
- `src/api/search/src/traces/mod.rs`: With RBAC enabled, trace queries require Query permission on the traces stream, trace writes use the verified org ingestion token, and an org header differing from the route org is rejected.
- `src/api/search/src/traces/list/stream.rs`: The streamed trace listing's background task keeps the request's caller, so its search is authorized for that caller instead of being denied.

## Rust integration in config

- `src/config/src/config.rs`: Adds the `ZO_RBAC_ENABLED` and `ZO_RBAC_POLICY_CACHE_ENTRIES` settings and raises the database schema version for three new migrations.
- `src/config/src/datafusion/request.rs`: Carries the verified subject in query requests across nodes, with tests.
- `src/config/src/meta/alerts/alert.rs`: Persists the identity a scheduled alert executes as.
- `src/config/src/meta/dashboards/reports.rs`: Adds the report's execution identity, folder and approved delivery destinations, none of which can be set from client input.
- `src/config/src/meta/user.rs`: Adds the type representing a verified org ingestion token.

## Rust integration in core

- `src/core/Cargo.toml`: Mechanical: adds dependencies for an isolated browser profile and the embedded stream worker used in scoped report rendering.
- `src/core/src/alerts/alert.rs`: With RBAC enabled, alert evaluation and notification are authorized as the alert's identity, only approved custom-template destinations are used and re-checked at dispatch, and legacy recovery notifications are refused.
- `src/core/src/alerts/derived_streams.rs`: Mechanical: derived-stream queries run with no recorded identity, so they are denied while RBAC is enabled.
- `src/core/src/alerts/mod.rs`: With RBAC enabled, scheduled alert queries validate the stored execution identity, authorize their SQL and run as that identity; realtime evaluation and hybrid caching are refused or disabled.
- `src/core/src/alerts/rbac.rs`
- `src/core/src/alerts/templates.rs`: With RBAC enabled, template fallback stops at org boundaries, shared or non-custom templates cannot be updated, and foreign references are checked before local changes.
- `src/core/src/dashboards/reports.rs`: With RBAC enabled, scheduled report sends require authorization, render in an isolated browser limited to the report's own requests that signs in only once the login form has settled, recheck recipients, and escape email content.
- `src/core/src/dashboards/reports/browser_scope.rs`
- `src/core/src/dashboards/reports/scoped.rs`
- `src/core/src/http.rs`: Template authorization denials return an HTTP 403 "Access denied" response.
- `src/core/src/ingestion_tokens.rs`: With RBAC enabled, default, system and writer tokens are hidden from the token list so only manageable org ingestion tokens are visible.
- `src/core/src/logs/bulk.rs`: Mechanical: string concatenation uses an explicit string slice to resolve a trait ambiguity.
- `src/core/src/logs/ingest.rs`: With RBAC enabled, derived ingestion is refused and the destination stream and every pipeline output are authorized before any write; pipeline failures become denials instead of partial writes.
- `src/core/src/logs/otlp.rs`: OTLP log ingestion accepts the verified org ingestion token, authorizes the destination and every pipeline output before accepting data, attributes writes to the token, and rejects pipeline failures instead of writing the source.
- `src/core/src/metrics/json.rs`: With RBAC enabled, every destination stream of a metrics batch is authorized before buffering; with RBAC disabled no streams are checked.
- `src/core/src/metrics/mod.rs`: Mechanical: declares the RBAC-owned metrics module.
- `src/core/src/organization.rs`: With RBAC enabled, service-account passcode rotation requires a verified org membership and role target, and the service-account path no longer diverts to the root-only branch.
- `src/core/src/pipeline/batch_execution.rs`: With RBAC enabled, a pipeline's scoped identity is validated before execution and its outputs afterward, failing closed on task errors.
- `src/core/src/pipeline/db.rs`: Pipeline writes can persist the identity the pipeline executes as; existing writes persist none.
- `src/core/src/pipeline/mod.rs`: Pipeline saves are validated against the saving user's authority, updates always count as changes under RBAC, and pipelines can be saved or updated as a verified user.
- `src/core/src/pipeline/rbac.rs`
- `src/core/src/metrics/rbac.rs`
- `src/core/src/traces/mod.rs`: With RBAC enabled, trace ingestion requires Ingest permission on the traces stream, streams with pipelines are rejected, and the trace time-index write is skipped.
- `src/core/src/users.rs`: With RBAC enabled, only a verified self password change is allowed, and cross-org and role-less member listing are disabled.

## Rust integration in db

- `src/db/src/alerts/alert.rs`: Mechanical: a test fixture carries the new alert execution identity, unset.
- `src/db/src/alerts/templates.rs`: With RBAC enabled, templates are read and listed from the primary store without default-org inheritance, and cross-org references are checked before changes.
- `src/db/src/alerts/templates/rbac.rs`
- `src/db/src/dashboards/reports.rs`: Mechanical: a test fixture carries the new report execution context and delivery destinations, both empty.
- `src/db/src/system_settings.rs`: Mechanical: string concatenation uses an explicit string slice to resolve a trait ambiguity.

## Policy engine

- `src/extensions/rbac/Cargo.toml`
- `src/extensions/rbac/model.conf`
- `src/extensions/rbac/src/lib.rs`
- `src/extensions/rbac/tests/authorization.rs`

## Rust integration in infra

- `src/infra/Cargo.toml`: Mechanical: adds the RBAC extension dependency so infra can host the policy store and decisions.
- `src/infra/src/db/nats.rs`: Mechanical: string concatenations use explicit string slices to resolve a trait ambiguity.
- `src/infra/src/errors/mod.rs`: Adds an authorization-denied error (code 20015, HTTP 403) so denials keep their status across RPC.
- `src/infra/src/file_list/mod.rs`: Mechanical: file key concatenation uses explicit string slices to resolve a trait ambiguity.
- `src/infra/src/lib.rs`: Mechanical: declares the new RBAC module.
- `src/infra/src/pipeline/execution.rs`
- `src/infra/src/pipeline/mod.rs`: Pipeline creates and updates can store an execution identity; the legacy create stores none.
- `src/infra/src/pipeline/postgres.rs`: Stores the pipeline's execution identity in the same transaction as the pipeline write.
- `src/infra/src/pipeline/sqlite.rs`: Stores the pipeline's execution identity in the same transaction as the pipeline write.
- `src/infra/src/rbac.rs`
- `src/infra/src/rbac/cache.rs`
- `src/infra/src/rbac/caller.rs`
- `src/infra/src/rbac/destinations.rs`
- `src/infra/src/rbac/pipelines.rs`
- `src/infra/src/rbac/tokens.rs`
- `src/infra/src/table/alerts/mod.rs`: Reads and updates an alert's execution identity in storage, with a roundtrip test.
- `src/infra/src/table/entity/alerts.rs`: Adds the execution identity column to stored alerts.
- `src/infra/src/table/entity/reports.rs`: Adds a text column holding the report's serialized execution context.
- `src/infra/src/table/migration/m20261223_000001_add_alert_execution_subject.rs`
- `src/infra/src/table/migration/m20261224_000001_add_report_execution_context.rs`
- `src/infra/src/table/migration/m20261225_000001_add_pipeline_execution_subject.rs`
- `src/infra/src/table/migration/mod.rs`: Registers three additive migrations for alert execution identity, report execution context and pipeline execution identity, raising the schema version from 157 to 160.
- `src/infra/src/table/org_ingestion_tokens.rs`: Adds a primary-store lookup of enabled non-writer org ingestion tokens used as the verified ingestion identity, with a rotation and row-identity test.
- `src/infra/src/table/reports/mod.rs`: Persists the report's execution context as text on create and update.
- `src/infra/src/table/reports/queries.rs`: Restores the stored execution context when reading a report and derives its delivery destinations from it.

## Rust integration in ingestion_common

- `src/ingestion_common/src/lib.rs`: Adds an ingest identity for org ingestion tokens, recorded in audit as `org-token:<id>`.

## Rust integration in node

- `src/node/src/cluster_info.rs`: With RBAC enabled, the cluster-info RPC fails closed without a scoped execution identity.

## Rust integration in promql_service

- `src/promql_service/src/lib.rs`: Mechanical: declares the new RBAC module.
- `src/promql_service/src/rbac.rs`
- `src/promql_service/src/search/grpc/mod.rs`: With RBAC enabled, metrics gRPC search allows only named queries (no data, exemplar or download operations), authorizes each scanned metric stream, and refuses the PromQL data RPC.
- `src/promql_service/src/search/grpc/wal.rs`: Mechanical: passes the verified subject through WAL search so it stays authorized.
- `src/promql_service/src/search/mod.rs`: With RBAC enabled, the user is resolved to a subject, the PromQL query is authorized, exemplars and download are rejected, the subject travels with the request, and result caching is disabled.
- `src/promql_service/src/service.rs`: Mechanical: metrics query conversion carries the new subject field, unset.

## Rust integration in proto

- `src/proto/proto/cluster/metrics.proto`: Adds an optional verified subject to metrics query requests so it crosses nodes.
- `src/proto/proto/cluster/plan.proto`: Adds an optional verified subject to distributed query plans.
- `src/proto/proto/cluster/search.proto`: Adds an optional verified subject to search requests.
- `src/proto/src/generated/cluster.rs`: Mechanical: generated bindings for the three new subject fields.

## Rust integration in report_server

- `src/report_server/src/router.rs`: With RBAC enabled, the standalone report server rejects send requests with 403 because it has no scoped execution identity; tested.

## Rust integration in search

- `src/search/src/datafusion/distributed/remote_scan/node.rs`: Remote scans receive the verified subject so they authorize as the same caller.
- `src/search/src/datafusion/exec.rs`: With RBAC enabled, custom user-defined functions are not registered in scoped queries.
- `src/search/src/lib.rs`: Mechanical: declares the new RBAC module.
- `src/search/src/rbac.rs`
- `src/search/src/sql/mod.rs`: While a query's SQL is parsed, every stream it references is authorized for the request's subject or user, or for the current caller scope, and denied when no identity exists.

## Rust integration in search_service

- `src/search_service/src/cache/mod.rs`: With RBAC enabled, query functions are refused, the result cache is bypassed, and authorization errors during cache preparation are returned instead of running uncached.
- `src/search_service/src/grpc/flight/mod.rs`: With RBAC enabled, Flight requests are authorized for Query on the stream as the request's subject or user, failing closed without an identity.
- `src/search_service/src/grpc_search.rs`: Outgoing search requests carry the current caller's subject so a delegated identity reaches the querier.
- `src/search_service/src/grpc_server.rs`: The search RPC runs as the identity in the internal request, other RPCs without a scoped identity are rejected, and 403 maps to permission denied.
- `src/search_service/src/lib.rs`: With RBAC enabled, query functions are refused, a delegated caller identity is carried into the search request, and every query of a multi-search is authorized.
- `src/search_service/src/streaming/collect.rs`: Background partition-mode producers keep the caller's identity.
- `src/search_service/src/streaming/execution.rs`: Background pattern-extraction search slices keep the caller's identity.
- `src/search_service/src/streaming/mod.rs`: Streaming searches are authorized and query functions refused up front, with a denial sent to the client; background multi-stream tasks keep the caller's identity.

## Rust integration in web

- `src/web/build.rs`: Mechanical: build step that finds the single hashed stream worker asset and exposes its name, leaving it empty if the match is not unique.
- `src/web/src/lib.rs`: Exposes the stream worker asset name so scoped report rendering can allow exactly that worker URL.
- `src/web/src/ui.rs`: Serves the embedded stream worker with a no-network content security policy so it cannot make requests outside the report browser's limits; tested.

## RBAC regression tests beside upstream modules

Each file is declared from its upstream module as a test-only module, so upstream test modules stay unchanged.

- `src/api/grpc/src/handler/grpc/auth/rbac_tests.rs`
- `src/api/http/src/handler/http/router/openapi_coverage/rbac_tests.rs`
- `src/api/management/src/models/alerts/requests_rbac_tests.rs`
- `src/api/management/src/request/alerts/templates_rbac_tests.rs`
- `src/api/pipelines/src/models/pipelines_rbac_tests.rs`
- `src/api/search/src/promql/rbac_tests.rs`
- `src/api/search/src/search/saved_view_rbac_tests.rs`
- `src/core/src/alerts/rbac_tests.rs`
- `src/core/src/dashboards/reports_rbac_tests.rs`
- `src/core/src/logs/otlp_rbac_tests.rs`
- `src/core/src/organization_rbac_tests.rs`
- `src/core/src/users_rbac_tests.rs`
- `src/infra/src/errors/rbac_tests.rs`
- `src/infra/src/table/alerts/rbac_tests.rs`
- `src/infra/src/table/org_ingestion_tokens_rbac_tests.rs`
- `src/report_server/src/router_rbac_tests.rs`
- `src/search_service/src/cache/rbac_tests.rs`
- `src/web/src/ui_rbac_tests.rs`

## Web application

- `web/src/components/alerts/AddAlert.vue`: The alert form offers only approved delivery destinations instead of all destinations and shows a help banner when delivery approval is required.
- `web/src/components/iam/RbacPolicy.spec.ts`
- `web/src/components/iam/RbacPolicy.vue`
- `web/src/composables/useAlertForm.ts`: The alert form's destination picker lists only destinations approved for the authorized scheduled SQL query.
- `web/src/composables/useApprovedAlertDestinations.spec.ts`
- `web/src/composables/useApprovedAlertDestinations.ts`
- `web/src/composables/useDashboardRbac.spec.ts`
- `web/src/composables/useDashboardRbac.ts`
- `web/src/locales/languages/en-US.json`: Adds the text for the permissions editor, delivery approvals and role names.
- `web/src/services/http.ts`: Shows the access-denied toast in OSS too when the response reason is `rbac_denied`.
- `web/src/services/rbac.ts`
- `web/src/views/AddAlertView.spec.ts`: Tests that destinations and templates are not fetched for an enabled non-admin and that a stale organization's denial cannot clear the new organization's data.
- `web/src/views/AddAlertView.vue`: Fetches destinations and templates only when RBAC is disabled or the caller can manage them, and discards responses that arrive after an organization switch.
- `web/src/views/Dashboards/Dashboards.spec.ts`: Tests that bulk mutation actions are hidden for an RBAC Viewer.
- `web/src/views/Dashboards/Dashboards.vue`: Hides add, import, move, duplicate, delete and set-home controls unless the caller may mutate that dashboard.
- `web/src/views/Dashboards/ViewDashboard.vue`: Makes the dashboard view read-only for non-mutators by gating panel add, settings, JSON edit, layout edit, set-home and alert creation behind per-dashboard permission.
- `web/src/views/User.rbac.spec.ts`
- `web/src/views/User.vue`: Embeds the permissions editor and shows the user list only when RBAC is disabled or the caller can manage permissions for the current organization.
