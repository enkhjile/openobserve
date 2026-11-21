# Modified files

Branch `feature/rbac` is based on `c828ccec7a43f58e98cc51e0838b745544a15789`. The extension crate owns role semantics and Casbin decisions. The infrastructure crate reads authoritative policy, membership, credentials and job definitions. Transport and execution adapters pass verified identities and resolved resources to these boundaries.

The file inventory includes additive migrations, generated protocol bindings, authorization tests, Vue components and operational guides. NATS, file-list, system settings and bulk ingestion string concatenations use explicit string slices to resolve a trait ambiguity introduced by Casbin's transitive smartstring dependency.

## Workspace configuration

- `Cargo.lock`
- `Cargo.toml`
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
- `scripts/rbac/pipeline_smoke.py`
- `scripts/rbac/report_smoke.py`
- `scripts/rbac/run_http_smoke.py`
- `scripts/rbac/template_smoke.py`
- `scripts/rbac/token_smoke.py`
- `scripts/rbac/trace_smoke.py`
- `tests/ui-testing/scripts/rbac-browser-smoke.cjs`

## Rust integration in api

- `src/api/common/src/auth/delegation.rs`
- `src/api/common/src/auth/token.rs`
- `src/api/common/src/auth/validator.rs`
- `src/api/grpc/src/handler/grpc/auth/mod.rs`
- `src/api/grpc/src/handler/grpc/request/event.rs`
- `src/api/grpc/src/handler/grpc/request/metrics/querier.rs`
- `src/api/grpc/src/handler/grpc/request/query_cache.rs`
- `src/api/http/src/handler/http/router/mod.rs`
- `src/api/http/src/handler/http/router/openapi_coverage/excluded_routes.txt`
- `src/api/http/src/handler/http/router/openapi_coverage/mod.rs`
- `src/api/http/src/handler/http/router/rbac.rs`
- `src/api/http/src/handler/http/router/rbac_destinations.rs`
- `src/api/http/src/handler/http/router/rbac_forwarding_tests.rs`
- `src/api/http/src/router/http/mod.rs`
- `src/api/ingest/src/request/logs/ingest.rs`
- `src/api/ingest/src/request/metrics/ingest.rs`
- `src/api/management/src/models/alerts/requests.rs`
- `src/api/management/src/request/alerts/mod.rs`
- `src/api/management/src/request/alerts/templates.rs`
- `src/api/management/src/request/dashboards/mod.rs`
- `src/api/management/src/request/dashboards/reports.rs`
- `src/api/management/src/request/organization/ingestion_tokens.rs`
- `src/api/management/src/request/service_accounts/mod.rs`
- `src/api/management/src/request/stream/mod.rs`
- `src/api/pipelines/src/models/pipelines.rs`
- `src/api/pipelines/src/request/pipeline.rs`
- `src/api/search/src/promql/mod.rs`
- `src/api/search/src/search/mod.rs`
- `src/api/search/src/search/multi_streams.rs`
- `src/api/search/src/search/saved_view.rs`
- `src/api/search/src/search/search_stream.rs`
- `src/api/search/src/search/utils.rs`
- `src/api/search/src/traces/list/query.rs`
- `src/api/search/src/traces/mod.rs`

## Rust integration in config

- `src/config/src/config.rs`
- `src/config/src/datafusion/request.rs`
- `src/config/src/meta/alerts/alert.rs`
- `src/config/src/meta/dashboards/reports.rs`
- `src/config/src/meta/user.rs`

## Rust integration in core

- `src/core/Cargo.toml`
- `src/core/src/alerts/alert.rs`
- `src/core/src/alerts/derived_streams.rs`
- `src/core/src/alerts/mod.rs`
- `src/core/src/alerts/rbac.rs`
- `src/core/src/alerts/templates.rs`
- `src/core/src/dashboards/reports.rs`
- `src/core/src/dashboards/reports/browser_scope.rs`
- `src/core/src/dashboards/reports/scoped.rs`
- `src/core/src/http.rs`
- `src/core/src/ingestion_tokens.rs`
- `src/core/src/logs/bulk.rs`
- `src/core/src/logs/ingest.rs`
- `src/core/src/metrics/json.rs`
- `src/core/src/organization.rs`
- `src/core/src/pipeline/batch_execution.rs`
- `src/core/src/pipeline/db.rs`
- `src/core/src/pipeline/mod.rs`
- `src/core/src/pipeline/rbac.rs`
- `src/core/src/traces/mod.rs`
- `src/core/src/users.rs`

## Rust integration in db

- `src/db/src/alerts/alert.rs`
- `src/db/src/alerts/templates.rs`
- `src/db/src/alerts/templates/rbac.rs`
- `src/db/src/dashboards/reports.rs`
- `src/db/src/system_settings.rs`

## Policy engine

- `src/extensions/rbac/Cargo.toml`
- `src/extensions/rbac/model.conf`
- `src/extensions/rbac/src/lib.rs`
- `src/extensions/rbac/tests/authorization.rs`

## Rust integration in infra

- `src/infra/Cargo.toml`
- `src/infra/src/db/nats.rs`
- `src/infra/src/errors/mod.rs`
- `src/infra/src/file_list/mod.rs`
- `src/infra/src/lib.rs`
- `src/infra/src/pipeline/execution.rs`
- `src/infra/src/pipeline/mod.rs`
- `src/infra/src/pipeline/postgres.rs`
- `src/infra/src/pipeline/sqlite.rs`
- `src/infra/src/rbac.rs`
- `src/infra/src/rbac/cache.rs`
- `src/infra/src/rbac/destinations.rs`
- `src/infra/src/rbac/pipelines.rs`
- `src/infra/src/rbac/tokens.rs`
- `src/infra/src/table/alerts/mod.rs`
- `src/infra/src/table/entity/alerts.rs`
- `src/infra/src/table/entity/reports.rs`
- `src/infra/src/table/migration/m20261223_000001_add_alert_execution_subject.rs`
- `src/infra/src/table/migration/m20261224_000001_add_report_execution_context.rs`
- `src/infra/src/table/migration/m20261225_000001_add_pipeline_execution_subject.rs`
- `src/infra/src/table/migration/mod.rs`
- `src/infra/src/table/org_ingestion_tokens.rs`
- `src/infra/src/table/reports/mod.rs`
- `src/infra/src/table/reports/queries.rs`

## Rust integration in ingestion_common

- `src/ingestion_common/src/lib.rs`

## Rust integration in node

- `src/node/src/cluster_info.rs`

## Rust integration in promql_service

- `src/promql_service/src/lib.rs`
- `src/promql_service/src/rbac.rs`
- `src/promql_service/src/search/grpc/mod.rs`
- `src/promql_service/src/search/grpc/wal.rs`
- `src/promql_service/src/search/mod.rs`
- `src/promql_service/src/service.rs`

## Rust integration in proto

- `src/proto/proto/cluster/metrics.proto`
- `src/proto/proto/cluster/plan.proto`
- `src/proto/proto/cluster/search.proto`
- `src/proto/src/generated/cluster.rs`

## Rust integration in report_server

- `src/report_server/src/router.rs`

## Rust integration in search

- `src/search/src/datafusion/distributed/remote_scan/node.rs`
- `src/search/src/datafusion/exec.rs`
- `src/search/src/lib.rs`
- `src/search/src/rbac.rs`
- `src/search/src/sql/mod.rs`

## Rust integration in search_service

- `src/search_service/src/cache/mod.rs`
- `src/search_service/src/grpc/flight/mod.rs`
- `src/search_service/src/grpc_search.rs`
- `src/search_service/src/grpc_server.rs`
- `src/search_service/src/lib.rs`
- `src/search_service/src/partition/sql_context.rs`
- `src/search_service/src/streaming/collect.rs`
- `src/search_service/src/streaming/mod.rs`

## Rust integration in web

- `src/web/build.rs`
- `src/web/src/lib.rs`
- `src/web/src/ui.rs`

## Web application

- `web/src/components/alerts/AddAlert.vue`
- `web/src/components/iam/RbacPolicy.spec.ts`
- `web/src/components/iam/RbacPolicy.vue`
- `web/src/composables/useAlertForm.ts`
- `web/src/composables/useApprovedAlertDestinations.spec.ts`
- `web/src/composables/useApprovedAlertDestinations.ts`
- `web/src/composables/useDashboardRbac.spec.ts`
- `web/src/composables/useDashboardRbac.ts`
- `web/src/locales/languages/en-US.json`
- `web/src/services/http.ts`
- `web/src/services/rbac.ts`
- `web/src/views/AddAlertView.spec.ts`
- `web/src/views/AddAlertView.vue`
- `web/src/views/Dashboards/Dashboards.spec.ts`
- `web/src/views/Dashboards/Dashboards.vue`
- `web/src/views/Dashboards/ViewDashboard.vue`
- `web/src/views/User.rbac.spec.ts`
- `web/src/views/User.vue`
