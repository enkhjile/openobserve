# Modified files

Branch `feature/rbac` is based on `c828ccec7a43f58e98cc51e0838b745544a15789`. The extension crate owns role semantics and Casbin decisions. The infrastructure crate reads authoritative policy, membership, credentials and job definitions. Transport and execution adapters pass verified identities and resolved resources to these boundaries.

The file inventory includes additive migrations, generated protocol bindings, authorization tests, Vue components and operational guides. NATS, file-list, system settings and bulk ingestion string concatenations use explicit string slices to resolve a trait ambiguity introduced by Casbin's transitive smartstring dependency.

Each entry for a file that exists upstream states the purpose of its hook. Review that purpose when an upstream change touches the file. Entries without a purpose are files RBAC adds, which upstream changes cannot conflict with.

## Workspace configuration

- `Cargo.lock`: generated lockfile update adding casbin, openobserve-rbac and their transitive crates (smartstring, rhai, petgraph and others); purely mechanical.
- `Cargo.toml`: registers the `src/extensions/rbac` workspace member and dependency, and patches chromiumoxide_types to the vendored copy (excluded from the workspace) so the RBAC build resolves.
- `vendor/chromiumoxide_types/.gitignore`
- `vendor/chromiumoxide_types/Cargo.toml`
- `vendor/chromiumoxide_types/LICENSE-APACHE`
- `vendor/chromiumoxide_types/LICENSE-MIT`
- `vendor/chromiumoxide_types/README.md`
- `vendor/chromiumoxide_types/src/lib.rs`

## Design and operations

- `docs/rbac/design.md`
- `docs/rbac/endpoints.md`
- `docs/rbac/modified-files.md`
- `docs/rbac/operations.md`
- `docs/rbac/requirements.md`
- `docs/rbac/rpc.md`
- `docs/rbac/scheduled-alerts.md`
- `docs/rbac/scheduled-reports.md`
- `docs/rbac/verification.md`
- `docs/superpowers/plans/2026-11-20-rbac.md`

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

- `src/api/common/src/auth/delegation.rs`: mechanical; initializes the new `ingestion_principal: None` field on `AuthValidationResult` because delegated validation never yields an org ingestion token.
- `src/api/common/src/auth/token.rs`: mechanical; adds `ingestion_principal: None` to the two `AuthValidationResult` initializers in `token_validator`.
- `src/api/common/src/auth/validator.rs`: when RBAC is enabled, resolves `o2oi_` org ingestion tokens against the primary store (restricted to ingestion-write routes) into an `OrgIngestionPrincipal`, and skips auto-creating orgs; other initializers just add `ingestion_principal: None`.
- `src/api/grpc/src/handler/grpc/auth/mod.rs`: with RBAC enabled, `check_auth`, `check_otlp_auth` and `check_ingest_auth` fail closed; `check_otlp_logs_auth` refuses the internal token, which can assert any `user_id`, and `scoped_otlp_principal` re-reads an org ingestion token from the primary store.
- `src/api/grpc/src/handler/grpc/request/logs.rs`: with RBAC enabled, resolves the org ingestion token principal before the export reaches core, which authorizes every destination.
- `src/api/grpc/src/handler/grpc/request/event.rs`: with RBAC enabled, disables downloading latest files from peer nodes and rejects the file-list RPC without a scoped execution identity, so cluster RPC cannot bypass authorization.
- `src/api/grpc/src/handler/grpc/request/metrics/querier.rs`: requires a verified `rbac_subject` on the metrics query RPC, maps 403 errors to permission_denied, and rejects the other metrics RPCs outright while RBAC is enabled.
- `src/api/grpc/src/handler/grpc/request/otlp.rs`: adds `check_otlp_logs_ingest`, the logs-only interceptor plus the existing memory-breaker refusal.
- `src/api/grpc/src/handler/grpc/request/query_cache.rs`: rejects both query-cache RPCs with permission_denied while RBAC is enabled, since cached results are not subject-scoped.
- `src/api/grpc/src/router/grpc/ingest/logs.rs`: with RBAC enabled, the router forwards the caller's own credential instead of the internal token so the ingester re-authenticates and scopes it.
- `src/api/grpc/src/server.rs`: registers the OTLP logs service, on both ingester and router, behind the logs-only interceptor; the other OTLP services keep the deny-all interceptor.
- `src/api/http/src/handler/http/router/mod.rs`: wires the RBAC gate into the HTTP stack (canonical route names, ingestion principal extension, `rbac::authorize` after auth, RBAC routes, `route_gate`, CORS ordering) and mounts the versioned `/internal/rbac/v1/api` forwarding routes plus the proxy route table.
- `src/api/http/src/handler/http/router/openapi_coverage/excluded_routes.txt`: lists the new browser-only RBAC policy, subject, bootstrap and destination routes as excluded from the public OpenAPI contract.
- `src/api/http/src/handler/http/router/openapi_coverage/mod.rs`: folds `/internal/rbac/v1/api` mount aliases into canonical `/api` operations, rejects non-literal nest prefixes, and adds a test pinning every endpoint to its reviewed RBAC disposition in `docs/rbac/endpoints.md`.
- `src/api/http/src/handler/http/router/rbac.rs`
- `src/api/http/src/handler/http/router/rbac_destinations.rs`
- `src/api/http/src/handler/http/router/rbac_forwarding_tests.rs`
- `src/api/http/src/router/http/mod.rs`: with RBAC enabled, the router tier forwards requests to nodes under the `/internal/rbac/v1` prefix (so nodes re-authorize) and disables body-based result-cache routing; also serves the RBAC proxy routes.
- `src/api/ingest/src/request/logs/ingest.rs`: accepts the optional org ingestion principal as the ingest identity for `_json`, `_multi` and OTLP `v1/logs`, and maps authorization denials to HTTP 403.
- `src/api/ingest/src/request/metrics/ingest.rs`: uses the org ingestion principal as the ingest identity for metrics JSON and returns 403 instead of 400 when the error is an authorization denial.
- `src/api/management/src/models/alerts/requests.rs`: test only; proves a client-supplied `execution_subject` in alert create/update bodies is ignored and cannot act as alert authority.
- `src/api/management/src/request/alerts/mod.rs`: with RBAC enabled, restricts alerts to scheduled type, binds the alert's execution subject via `alerts::rbac::bind` on create/update, and filters list, detail and composite responses to alerts the caller can read.
- `src/api/management/src/request/alerts/templates.rs`: test only; asserts a template authorization denial maps to HTTP 403.
- `src/api/management/src/request/dashboards/mod.rs`: with RBAC enabled, filters the dashboard list to dashboards the caller can read and applies pagination after filtering rather than before.
- `src/api/management/src/request/dashboards/reports.rs`: with RBAC enabled, binds the scheduled report's author, renderer subject, folder and destinations (`reports::scoped::bind`) on create/update, forbids org or folder moves, and filters the report list by readable ids.
- `src/api/management/src/request/organization/ingestion_tokens.rs`: with RBAC enabled, forbids enabling or disabling default, system or writer ingestion tokens, which are not manageable credentials.
- `src/api/management/src/request/service_accounts/mod.rs`: validates the service-account token rotation target against a primary read of org membership and role before updating, and drops obsolete comments about the middleware.
- `src/api/management/src/request/stream/mod.rs`: with RBAC enabled, filters the stream list to typed stream resources the caller can read, failing closed with 403 when the policy is unavailable.
- `src/api/pipelines/src/models/pipelines.rs`: with RBAC enabled, omits historic `last_error` rows from the pipeline response model so error samples cannot leak data from unreadable streams; adds a test for both modes.
- `src/api/pipelines/src/request/pipeline.rs`: with RBAC enabled, save and update run as the verified user subject (`save_user_pipeline_as_subject` and `update_user_pipeline_as_subject`), and the pipeline list is filtered to readable pipelines.
- `src/api/search/src/promql/mod.rs`: extracts `metrics_search_error_response` so authorization denials return HTTP 403 while PromQL syntax errors stay 400; adds a test.
- `src/api/search/src/search/mod.rs`: routes field validation through `validate_query_fields_for_user` so the caller's identity is authorized against the queried typed stream resources.
- `src/api/search/src/search/multi_streams.rs`: with RBAC enabled, authorizes every query of multi-stream, multi-stream streaming and partition-multi searches (`authorize_batch`), including query functions, before any execution.
- `src/api/search/src/search/saved_view.rs`: with RBAC enabled, filters the saved-view list to saved queries the caller can read and fails closed with 403 on decision error; adds a revocation test.
- `src/api/search/src/search/search_stream.rs`: passes the verified user id into SQL parsing (`Sql::new_for_user`) for HTTP/2 streaming search so the stream resources named in the SQL are authorized.
- `src/api/search/src/search/utils.rs`: adds `validate_query_fields_for_user`, which builds the SQL with `Sql::new_for_user` so authorization is applied during field validation; the old function delegates with no user.
- `src/api/search/src/traces/list/query.rs`: with RBAC enabled, disables the trace-list time index so trace listing goes through the authorized search path.
- `src/api/search/src/traces/mod.rs`: with RBAC enabled, authorizes Query on the typed traces stream, uses the org ingestion principal for trace writes, and rejects an org header that differs from the route org.

## Rust integration in config

- `src/config/src/config.rs`: adds the `ZO_RBAC_ENABLED` and `ZO_RBAC_POLICY_CACHE_ENTRIES` settings and bumps `DB_SCHEMA_VERSION` from 157 to 160 for the three new migrations.
- `src/config/src/datafusion/request.rs`: carries `rbac_subject` (the verified subject) in the DataFusion request and maps it to and from the Flight `super_cluster_info`, with tests.
- `src/config/src/meta/alerts/alert.rs`: adds the persisted `execution_subject` field on `Alert`, the scheduled alert execution subject, including its memory-size accounting and default.
- `src/config/src/meta/dashboards/reports.rs`: adds `ReportExecutionContext` (author and renderer subject, folder, destination names) and `delivery_destinations` to `Report`; the context is never deserialized from client input.
- `src/config/src/meta/user.rs`: adds the `OrgIngestionPrincipal` type (org id and token id) that represents a verified org ingestion token.

## Rust integration in core

- `src/core/Cargo.toml`: adds `tempfile` and `web` dependencies, used for the isolated browser profile and the embedded stream worker asset in scoped report rendering.
- `src/core/src/alerts/alert.rs`: with RBAC enabled, alert evaluation and notification authorize through `alerts::rbac::authorize_execution`, resolve only approved custom-template destinations, re-check approval at dispatch, and refuse legacy recovery notifications.
- `src/core/src/alerts/derived_streams.rs`: mechanical; passes `None` for the new `execution_subject` argument of the scheduled query evaluation call.
- `src/core/src/alerts/mod.rs`: with RBAC enabled, scheduled alert queries validate the stored execution subject, authorize its SQL, and run via `grpc_search_as_subject`; realtime evaluation and hybrid caching are refused or disabled.
- `src/core/src/alerts/rbac.rs`
- `src/core/src/alerts/templates.rs`: with RBAC enabled, stops the root fallback across org boundaries, refuses updates to shared or non-custom templates, and checks foreign references before local template mutation.
- `src/core/src/dashboards/reports.rs`: with RBAC enabled, scheduled report sends require `scoped::authorize`, render in an isolated incognito browser attached to a `BrowserScope` request guard, rechecked recipients, and escaped email content.
- `src/core/src/dashboards/reports/browser_scope.rs`
- `src/core/src/dashboards/reports/scoped.rs`
- `src/core/src/http.rs`: maps `TemplateError::AuthorizationDenied` to an HTTP 403 "Access denied" response.
- `src/core/src/ingestion_tokens.rs`: with RBAC enabled, hides default, system and writer tokens from the token listing so only manageable org ingestion tokens are visible.
- `src/core/src/logs/bulk.rs`: mechanical; uses `line_str.as_ref()` in string concatenation to resolve the trait ambiguity introduced by Casbin's smartstring dependency.
- `src/core/src/logs/ingest.rs`: with RBAC enabled, `authorize_scoped_destinations` checks Ingest on the typed logs stream for a user or org ingestion token and loads only scoped pipelines before any write; derived ingestion is refused. OTLP logs share this check.
- `src/core/src/logs/otlp.rs`: with RBAC enabled, authorizes the destination and every scoped pipeline output for the verified user or org token before `check_ingestion_allowed`, and rejects pipeline failures instead of writing the source.
- `src/core/src/metrics/json.rs`: with RBAC enabled, resolves every record's destination metric stream and authorizes the whole batch for the user or org token, refusing metrics streams that have pipelines; the rest is a refactor splitting `metric_destination` out.
- `src/core/src/organization.rs`: with RBAC enabled, service-account passcode rotation requires a primary-read check that the target is a non-root member with the exact service-account role, and the service-account passcode path no longer diverts to the root-only branch.
- `src/core/src/pipeline/batch_execution.rs`: adds an optional `scoped_context` to `ExecutablePipeline` and, with RBAC enabled, validates it before execution and its outputs afterward, failing closed on task errors.
- `src/core/src/pipeline/db.rs`: adds `set_scoped` and `update_scoped` so pipeline writes persist the execution subject; the original `set` and `update` delegate with `None`.
- `src/core/src/pipeline/mod.rs`: registers `pipeline::rbac`, validates pipeline saves against the subject's authority, always treats updates as changes under RBAC, and adds `save_user_pipeline_as_subject` and `update_user_pipeline_as_subject`.
- `src/core/src/pipeline/rbac.rs`
- `src/core/src/traces/mod.rs`: with RBAC enabled, authorizes Ingest on the typed traces stream for a user or org token, rejects streams with pipelines, and skips the trace time-index write.
- `src/core/src/users.rs`: with RBAC enabled, only a verified self password change is allowed, since a password belongs to the global identity; also stops cross-org listing and role-less member listing.

## Rust integration in db

- `src/db/src/alerts/alert.rs`: mechanical; adds `execution_subject: None` to a test fixture.
- `src/db/src/alerts/templates.rs`: registers the `rbac` submodule and, with RBAC enabled, reads and lists templates from the primary store without default-org inheritance and checks cross-org references before mutation.
- `src/db/src/alerts/templates/rbac.rs`
- `src/db/src/dashboards/reports.rs`: mechanical; adds `execution_context: None` and `delivery_destinations: vec![]` to a test fixture.
- `src/db/src/system_settings.rs`: mechanical; appends `.as_str()` in a string concatenation to resolve the trait ambiguity from Casbin's smartstring dependency.

## Policy engine

- `src/extensions/rbac/Cargo.toml`
- `src/extensions/rbac/model.conf`
- `src/extensions/rbac/src/lib.rs`
- `src/extensions/rbac/tests/authorization.rs`

## Rust integration in infra

- `src/infra/Cargo.toml`: adds the `openobserve-rbac` workspace dependency so infra can host the policy store and Casbin decisions.
- `src/infra/src/db/nats.rs`: mechanical; four string concatenations now use `.as_str()` to resolve the smartstring trait ambiguity.
- `src/infra/src/errors/mod.rs`: adds `ErrorCodes::AuthorizationDenied` (code 20015, HTTP 403) so denials keep their status across RPC.
- `src/infra/src/file_list/mod.rs`: mechanical; `FileKey` key concatenation uses `.as_str()` slices to resolve the smartstring trait ambiguity.
- `src/infra/src/lib.rs`: declares the new `rbac` module.
- `src/infra/src/pipeline/execution.rs`
- `src/infra/src/pipeline/mod.rs`: declares the `execution` module and extends `PipelineTable::put` and `update` with an optional execution subject (the legacy `put` passes `None`).
- `src/infra/src/pipeline/postgres.rs`: adds the `execution_subject` column and writes it in the same transaction on pipeline put and update.
- `src/infra/src/pipeline/sqlite.rs`: adds the `execution_subject` column and writes it in the same transaction on pipeline put and update.
- `src/infra/src/rbac.rs`
- `src/infra/src/rbac/cache.rs`
- `src/infra/src/rbac/destinations.rs`
- `src/infra/src/rbac/pipelines.rs`
- `src/infra/src/rbac/tokens.rs`
- `src/infra/src/table/alerts/mod.rs`: maps `execution_subject` between the alert entity and meta model on read and update; adds a roundtrip test.
- `src/infra/src/table/entity/alerts.rs`: adds the `execution_subject` column to the alert entity.
- `src/infra/src/table/entity/reports.rs`: adds the `execution_context` text column holding the serialized report execution context.
- `src/infra/src/table/migration/m20261223_000001_add_alert_execution_subject.rs`
- `src/infra/src/table/migration/m20261224_000001_add_report_execution_context.rs`
- `src/infra/src/table/migration/m20261225_000001_add_pipeline_execution_subject.rs`
- `src/infra/src/table/migration/mod.rs`: registers three additive migrations (alert execution subject, report execution context, pipeline execution subject) and their schema versions 158 to 160.
- `src/infra/src/table/org_ingestion_tokens.rs`: adds `find_enabled_token_primary`, a primary-store lookup of enabled non-writer org tokens used for verified ingestion identity, with a rotation and row-identity test.
- `src/infra/src/table/reports/mod.rs`: persists the report `execution_context` as serialized text on create, update and update-by-id.
- `src/infra/src/table/reports/queries.rs`: deserializes the stored `execution_context` back into the report and derives `delivery_destinations` from it.

## Rust integration in ingestion_common

- `src/ingestion_common/src/lib.rs`: adds the `IngestUser::OrgToken` variant carrying the org ingestion principal, identified in audit as `org-token:<id>`.

## Rust integration in node

- `src/node/src/cluster_info.rs`: with RBAC enabled, the cluster-info RPC fails closed without a scoped execution identity.

## Rust integration in promql_service

- `src/promql_service/src/lib.rs`: declares the new `rbac` module.
- `src/promql_service/src/rbac.rs`
- `src/promql_service/src/search/grpc/mod.rs`: with RBAC enabled, metrics gRPC search requires the verified `rbac_subject`, authorizes each metric stream, rejects exemplar, data and download operations, and refuses the PromQL data RPC.
- `src/promql_service/src/search/grpc/wal.rs`: mechanical plumbing; threads `rbac_subject` into WAL context creation and the `super_cluster_info` of the WAL search request.
- `src/promql_service/src/search/mod.rs`: with RBAC enabled, resolves the user to a subject, authorizes the PromQL query, rejects exemplars and download, sets `req.rbac_subject`, and disables result caching.
- `src/promql_service/src/service.rs`: mechanical; initializes `rbac_subject: None` in the `MetricsQueryRequest` proto conversion.

## Rust integration in proto

- `src/proto/proto/cluster/metrics.proto`: adds optional `rbac_subject` (tag 16) to `MetricsQueryRequest` so the verified subject crosses nodes.
- `src/proto/proto/cluster/plan.proto`: adds optional `rbac_subject` (tag 6) to `SuperClusterInfo` for distributed query plans.
- `src/proto/proto/cluster/search.proto`: adds optional `rbac_subject` (tag 7) to `SearchRequest`.
- `src/proto/src/generated/cluster.rs`: generated prost bindings for the three new `rbac_subject` fields; mechanical.

## Rust integration in report_server

- `src/report_server/src/router.rs`: with RBAC enabled, the standalone report server rejects send requests with 403 because it has no scoped execution identity; adds a test.

## Rust integration in search

- `src/search/src/datafusion/distributed/remote_scan/node.rs`: copies `rbac_subject` into the forwarded `SuperClusterInfo` so remote scans authorize as the same subject.
- `src/search/src/datafusion/exec.rs`: with RBAC enabled, `register_udf` returns early so custom UDFs are not registered in scoped queries.
- `src/search/src/lib.rs`: declares the new `rbac` module.
- `src/search/src/rbac.rs`
- `src/search/src/sql/mod.rs`: authorizes the SQL's typed stream resources during `Sql` construction, by subject or user id, adds `new_for_user`, and also authorizes the no-identity path, which fails closed under RBAC.

## Rust integration in search_service

- `src/search_service/src/cache/mod.rs`: with RBAC enabled, authorizes the SQL, refuses query functions, forces cache bypass, and surfaces authorization errors instead of falling back to an uncached run.
- `src/search_service/src/grpc/flight/mod.rs`: with RBAC enabled, authorizes Query on the typed stream for the Flight request by `rbac_subject` or user id, failing closed without an identity.
- `src/search_service/src/grpc_search.rs`: adds `grpc_search_as_subject` and a shared identity path carrying `rbac_subject`, used by scheduled alert execution.
- `src/search_service/src/grpc_server.rs`: the search RPC executes by `rbac_subject` or authorizes the user id first, refuses query transforms, rejects table and other RPCs without a scoped identity, and maps 403 to permission_denied.
- `src/search_service/src/lib.rs`: adds `search_as_subject`, refuses query functions under RBAC, and authorizes every query in `search_multi` with `authorize_batch`.
- `src/search_service/src/partition/sql_context.rs`: threads `user_id` into partition SQL construction via `Sql::new_for_user` so partition planning authorizes the caller.
- `src/search_service/src/streaming/collect.rs`: builds the partition-mode SQL with `Sql::new_for_user` so streaming collection authorizes the verified user.
- `src/search_service/src/streaming/mod.rs`: authorizes the streaming search SQL up front (sending a denial to the client), refuses query transforms, and bypasses caches under RBAC.

## Rust integration in web

- `src/web/build.rs`: build script that finds the single hashed `streamWorker-*.js` asset and exports its name as `O2_UI_STREAM_WORKER_ASSET`, failing to empty if not unique.
- `src/web/src/lib.rs`: exposes `stream_worker_asset()` so scoped report rendering can allow exactly that worker URL.
- `src/web/src/ui.rs`: serves the embedded stream worker with a no-network CSP so the worker cannot make requests outside the report browser scope guard; adds a test.

## Web application

- `web/src/components/alerts/AddAlert.vue`: feeds the alert form the approved `deliveryDestinations` instead of all destinations and shows a help banner when delivery approval is required.
- `web/src/components/iam/RbacPolicy.spec.ts`
- `web/src/components/iam/RbacPolicy.vue`
- `web/src/composables/useAlertForm.ts`: wires `useApprovedAlertDestinations` into the form so the destination picker lists only approved destination names for the authorized scheduled SQL query.
- `web/src/composables/useApprovedAlertDestinations.spec.ts`
- `web/src/composables/useApprovedAlertDestinations.ts`
- `web/src/composables/useDashboardRbac.spec.ts`
- `web/src/composables/useDashboardRbac.ts`
- `web/src/locales/languages/en-US.json`: adds the `ossRbac` string block for the permissions editor, delivery approvals and role names.
- `web/src/services/http.ts`: shows the access-denied toast also in OSS when the response reason is `rbac_denied`.
- `web/src/services/rbac.ts`
- `web/src/views/AddAlertView.spec.ts`: tests that destinations and templates are not fetched for an enabled non-admin and that a stale organization's denial cannot clear the new organization's data.
- `web/src/views/AddAlertView.vue`: fetches destinations and templates only when RBAC is disabled or the caller can manage, and discards responses that arrive after an organization switch.
- `web/src/views/Dashboards/Dashboards.spec.ts`: mocks `useDashboardRbac` and tests that bulk mutation actions are hidden for an RBAC Viewer.
- `web/src/views/Dashboards/Dashboards.vue`: hides add, import, move, duplicate, delete and set-home controls unless `useDashboardPermissions` allows the mutation on that dashboard.
- `web/src/views/Dashboards/ViewDashboard.vue`: gates panel add, settings, JSON edit, layout edit, set-home and alert creation behind the per-dashboard permission, making the view read-only for non-mutators.
- `web/src/views/User.rbac.spec.ts`
- `web/src/views/User.vue`: embeds the `RbacPolicy` editor and shows the user list only when RBAC is disabled or the caller can manage permissions for the current organization.
