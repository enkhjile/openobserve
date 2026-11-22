# Maintaining the RBAC branch

The branch starts at upstream commit `c828ccec7a43f58e98cc51e0838b745544a15789`. Keep the fork as `origin` and OpenObserve as `upstream`, and keep the upstream AGPL-3.0 license and notices.

## Feature-owned code

| Path | Contents |
| --- | --- |
| `src/extensions/rbac` | Casbin model, roles and typed permission decisions, with engine tests |
| `src/infra/src/rbac.rs`, `src/infra/src/rbac/` | Policy storage, stable identities, the request caller, ingestion tokens, delivery approvals, pipeline checks and shared helpers |
| `src/infra/src/table/migration/m2026122*` | The three migrations that add the recorded execution identity to alerts, reports and pipelines |
| `src/infra/src/pipeline/execution.rs` | Reads pipelines with their recorded identity |
| `src/search/src/rbac.rs`, `src/promql_service/src/rbac.rs` | SQL and PromQL source authorization |
| `src/core/src/{alerts,pipeline,metrics}/rbac.rs`, `src/db/src/alerts/templates/rbac.rs` | Scheduled alerts, pipelines, metric batches and organization-local templates |
| `src/core/src/dashboards/reports/{scoped,browser_scope}.rs` | Scoped report rendering and its browser sandbox |
| `src/api/http/src/handler/http/router/rbac*.rs` | Route permissions, the RBAC management API and router-forwarding tests |
| `**/*rbac_tests.rs` | RBAC regression tests that sit beside the upstream modules they test |
| `web/src/components/iam/RbacPolicy.vue`, `web/src/composables/use{DashboardRbac,ApprovedAlertDestinations}.ts`, `web/src/services/rbac.ts` | IAM page, permission-aware UI, and their specs |
| `scripts/rbac`, `tests/ui-testing/scripts/rbac-browser-smoke.cjs` | Live smoke suites and the endpoint inventory generator |
| `vendor/chromiumoxide_types` | Browser-protocol types patched for OpenObserve's arbitrary-precision JSON setting (see its README) |
| `docs/rbac` | These docs, plus the generated [endpoints.md](endpoints.md) and [rpc.md](rpc.md) that checks read |

## Changes to upstream files

With RBAC off, every hook below leaves upstream behaviour unchanged. A file whose only change is a `mod rbac_tests;` line just declares the tests beside it.

| Upstream file | Why |
| --- | --- |
| `Cargo.toml`, `Cargo.lock`, `src/core/Cargo.toml`, `src/infra/Cargo.toml` | Add the RBAC crate and its dependencies, and point the browser-protocol types at the vendored copy. |
| `src/config/src/config.rs` | The two `ZO_RBAC_*` settings and the schema version for the new migrations. |
| `src/config/src/meta/{user,alerts/alert,dashboards/reports}.rs`, `src/ingestion_common/src/lib.rs` | Carry the verified ingestion-token identity and the recorded execution identity. |
| `src/infra/src/lib.rs`, `src/infra/src/errors/mod.rs`, `src/core/src/http.rs` | Register the RBAC module, and keep authorization denials as HTTP 403 across RPC. |
| `src/infra/src/table/{alerts,reports,entity,migration}/…`, `src/infra/src/pipeline/{mod,sqlite,postgres}.rs`, `src/core/src/pipeline/db.rs` | Store and read the recorded identity in the same transaction as the object. |
| `src/infra/src/table/org_ingestion_tokens.rs`, `src/core/src/ingestion_tokens.rs`, `src/api/management/src/request/organization/ingestion_tokens.rs` | Re-read tokens from the primary store, and keep system and feature tokens out of grants. |
| `src/api/common/src/auth/{validator,token,delegation}.rs`, `src/api/common/src/auth/validator/oidc.rs` | Resolve an org ingestion token to its own row, and stop logins, OIDC sessions included, from creating organizations while RBAC is on. |
| `src/api/http/src/handler/http/router/mod.rs`, `src/api/http/src/router/http/mod.rs`, `openapi_coverage/{mod.rs,excluded_routes.txt}` | Apply the route gate after authentication, set the request caller, mount the RBAC API and the router-forwarding path, and keep the route inventory in step. |
| `src/api/grpc/src/server.rs`, `src/api/grpc/src/handler/grpc/auth/mod.rs`, `request/{event,logs,otlp,query_cache,metrics/querier}.rs`, `src/api/grpc/src/router/grpc/ingest/logs.rs`, `src/node/src/cluster_info.rs` | Refuse RPCs that have no scoped check, and accept only the caller's own credential for OTLP log export. |
| `src/search/src/{lib.rs,sql/mod.rs,datafusion/…}`, `src/config/src/datafusion/request.rs`, `src/proto/proto/cluster/*.proto`, `src/proto/src/generated/cluster.rs` | Authorize every SQL source when a query is built, and carry the verified identity to other nodes. |
| `src/search_service/src/{lib,grpc_server,grpc_search}.rs`, `cache/mod.rs`, `grpc/flight/mod.rs`, `streaming/{mod,collect,execution}.rs` | Run searches as the verified caller, keep the caller in background search tasks, bypass the result cache, and refuse query functions. |
| `src/api/search/src/search/{multi_streams,search_stream,saved_view}.rs`, `traces/{mod,list/query,list/stream}.rs`, `promql/mod.rs` | Authorize multi-stream batches and trace and PromQL queries, keep the caller in streamed responses, and filter saved views. |
| `src/promql_service/src/{lib,service}.rs`, `search/{mod.rs,grpc/mod.rs,grpc/wal.rs}` | Authorize each named metric and carry the identity through PromQL storage reads. |
| `src/core/src/logs/{ingest,otlp,bulk}.rs`, `src/core/src/traces/mod.rs`, `src/core/src/metrics/{json,mod}.rs`, `src/api/ingest/src/request/{logs,metrics}/ingest.rs` | Authorize every destination and pipeline output before writing, and return 403 on denial. |
| `src/core/src/pipeline/{mod,batch_execution}.rs`, `src/api/pipelines/src/{request/pipeline,models/pipelines}.rs` | Save pipelines with the editor's identity, run only scoped pipelines, filter listings, and hide error samples from unreadable streams. |
| `src/core/src/alerts/{mod,alert,templates,derived_streams}.rs`, `src/db/src/alerts/{alert,templates}.rs`, `src/api/management/src/{request/alerts/{mod,templates}.rs,models/alerts/requests.rs}` | Run scheduled SQL alerts as their recorded identity, check delivery approvals before sending, keep templates organization-local, and filter alert listings. |
| `src/core/src/dashboards/reports.rs`, `src/db/src/dashboards/reports.rs`, `src/api/management/src/request/dashboards/{mod,reports}.rs`, `src/report_server/src/router.rs`, `src/web/{build.rs,src/lib.rs,src/ui.rs}` | Render scoped reports in a sandboxed browser, refuse the standalone report server, filter dashboard and report listings, and serve the report worker without network access. |
| `src/api/management/src/request/{stream,service_accounts}/mod.rs`, `src/core/src/{users,organization}.rs` | Filter stream listings, and block cross-identity password resets and service-account takeover. |
| `src/infra/src/db/nats.rs`, `src/infra/src/file_list/mod.rs`, `src/db/src/system_settings.rs` | Mechanical: string concatenations that a Casbin dependency made ambiguous. |
| `web/src/views/{User,AddAlertView,Dashboards/Dashboards,Dashboards/ViewDashboard}.vue`, `web/src/components/alerts/AddAlert.vue`, `web/src/composables/useAlertForm.ts`, `web/src/services/http.ts`, `web/src/locales/languages/en-US.json` | IAM page, permission-aware controls, approved alert destinations and the access-denied message. |

## Updating from upstream

1. Start from a clean checkout and keep a backup branch of the current release.
2. Fetch `upstream` and review its changes to the files above, especially authentication results, route registration, search and ingestion entry points, new background tasks on search paths, and the gRPC services:

   ```sh
   git diff --stat "$OLD" "$NEW" -- $(git diff --name-only c828ccec7a43f58e98cc51e0838b745544a15789 HEAD -- src web)
   ```

3. Merge the upstream release into a candidate branch (rebase only if nobody else uses the branch), resolving conflicts at the hooks.
4. Agree changes to the authentication validator or HTTP middleware with the OIDC branch owner. The authenticated identity handed to handlers is the contract between the two features.
5. Regenerate the route inventory and review every changed line. New routes appear as `Unsupported` and stay refused until you give them a permission. The check also fails if a cluster RPC was added or removed without updating [rpc.md](rpc.md).

   ```sh
   python3 scripts/rbac/endpoint_inventory.py
   git diff docs/rbac/endpoints.md
   python3 scripts/rbac/endpoint_inventory.py --check
   ```

6. If upstream added a `tokio::spawn` on a search path, use `infra::rbac::caller::spawn` there, or that search will be refused.
7. Run the [regression checks](#regression-checks), then record the upstream commit and results.

## Regression checks

In the Rust workspace:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -W clippy::too_many_lines -W clippy::cognitive_complexity -W clippy::excessive_nesting -D warnings
cargo test -p openobserve-rbac
cargo test --no-fail-fast -p infra -p search_service -p openobserve-api-http -p openobserve-api-grpc -p openobserve-core \
  -p openobserve-api-search -p openobserve-api-management -p openobserve-api-pipelines -p report_server \
  --lib -- rbac openapi_coverage handler::grpc::auth logs::otlp cache::tests
cargo build
```

`rbac_saved_view_listing_filters_metadata_and_revocation` currently fails because its fixture never adds the viewer's organization membership.

Live suites against the compiled server, each on fresh loopback servers with temporary data (install `grpcio`, have `protoc` on the path, and Docker for PostgreSQL):

```sh
python3 scripts/rbac/run_http_smoke.py --binary target/debug/openobserve --store both
python3 scripts/rbac/otlp_logs_smoke.py --binary target/debug/openobserve --store both --acknowledge-disposable-fixture
python3 scripts/rbac/alert_smoke.py --binary target/debug/openobserve --acknowledge-disposable-fixture
python3 scripts/rbac/report_smoke.py --binary "$PWD/target/debug/openobserve" --acknowledge-disposable-fixture
python3 scripts/rbac/template_smoke.py --binary target/debug/openobserve --acknowledge-disposable-fixture
```

The first runs the HTTP and gRPC suites on SQLite and PostgreSQL. It covers bootstrap, roles, cross-organization and cross-stream access, SQL joins, CTEs, subqueries and unions, downloads, streaming and trace listing, ingestion and org tokens, pipelines, revocation, and a disable/re-enable rollback. The report suite needs Google Chrome and `pdftotext`. The web suites (`npm run format:check`, `lint:ci` and the RBAC specs under `web/src`) apply after any change under `web/`.

Before disabling RBAC in production, make sure an operator can still sign in as root. Policies and recorded identities stay in the metadata store.
