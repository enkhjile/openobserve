# RBAC verification

The tests use disposable application databases and loopback services. The generated HTTP matrix in `endpoints.md` and the RPC inventory in `rpc.md` identify which operations support scoped execution. Of the 585 operations marked active in OSS by the route parser, 494 are classified as unsupported and deny access when RBAC is enabled. Consult the matrix before enabling RBAC on an installation that depends on specialist APIs.

## Current evidence

| Boundary | Result | Local run log |
| --- | --- | --- |
| SQLite application, HTTP and gRPC | 236 assertions, including current membership, mixed SQL batches, scoped downloads, streamed rows and delegated gRPC search before and after revocation | `/tmp/rbac-streaming-sqlite-final.log` |
| PostgreSQL 16 application, HTTP and gRPC | The same 236 assertions passed against a fresh PostgreSQL database | `/tmp/rbac-final-postgres-smoke.log` |
| Policy persistence | Six policy tests on each backend, including root organization discovery, concurrent updates, revoked administrators and membership removal. The SQLite infrastructure suite passed all fourteen checks. | `/tmp/rbac-infra-pipeline-focused.log`, `/tmp/rbac-policy-pg-six-final.log` |
| Route inventory | All 41 OpenAPI coverage tests passed, including canonicalization of the internal forwarding mount and the full reviewed-permission snapshot. | `/tmp/rbac-openapi-forwarding-green.log` |
| Core execution | Fifteen core RBAC regressions passed for alerts, reports, pipeline execution, credential administration and dashboard sources. | `/tmp/rbac-core-regressions-final.log` |
| Casbin engine | Ten integration tests passed. | `/tmp/rbac-casbin-final.log` |
| Scoped collections | Alert pagination, composite children, deletion conflicts and named report listings returned only permitted objects. A stream-only member saw no alerts or reports. | `/tmp/rbac-alert-scoped-final.log`, `/tmp/rbac-report-live.log` |
| Scoped dashboard reports | All 31 fixture checks passed. The manual PDF contained the authorized row and reached the approved address. The elected scheduler also delivered a PDF. Revoking Export blocked both manual delivery and the next completed scheduled claim. | `/tmp/rbac-report-live.log` |
| Build and lint | The debug application build and strict workspace Clippy passed. Five web asset tests and three scoped browser policy tests passed. | `/tmp/rbac-worker-report-build.log`, `/tmp/rbac-worker-clippy.log`, `/tmp/rbac-web-worker-test.log`, `/tmp/rbac-final-worker-csp-tests.log` |
| Scheduled SQL alerts | An approved destination received a delivery. After source revocation the scheduler completed a claim without delivery. Restoring source access restored delivery. Revoking destination approval also prevented delivery. | `/tmp/rbac-alert-scoped-final.log` |
| Scoped pipelines | A condition routed matching records to both authorized streams. Revoking either the executor or triggering caller's required grant prevented writes. | `/tmp/rbac-pipeline-postgres-smoke.log` |
| Dedicated router | A request traversed the router and downstream HTTP server under a base URI. Revocation denied subsequent access. An older downstream exposing only ordinary API routes rejected forwarded reads and writes. The CORS preflight succeeded and the subsequent unauthorized request returned 403. | `/tmp/rbac-router-complete-final.log` |
| Browser | Admin and Viewer signed in, opened dashboards and IAM, and saw the appropriate editing and user-management controls. Neither role produced an uncaught page exception. | `/tmp/rbac-browser-admin-controls.log` |
| Vue | 184 tests across eight suites, application and test type-checks, focused ESLint, repository formatting, and the production Vite build passed. | `/tmp/rbac-vue-resume-final.log`, `/tmp/rbac-vue-app-resume.log`, `/tmp/rbac-vue-resume-typecheck.log`, `/tmp/rbac-vue-format-resume.log`, `/tmp/rbac-resume-assets.log` |
| Metadata upgrades | SQLite preserved seven user IDs, eleven memberships, two policies and two dashboard IDs across three migrations. PostgreSQL preserved eight users, twelve memberships and both policies while upgrading from schema 158 to 160. | `/tmp/rbac-metadata-upgrade.log`, `/tmp/rbac-pg-upgrade-check.log` |

Transport totals exclude the scripts' summary lines. The HTTP fixture starts with RBAC disabled for provisioning and restarts with RBAC enabled. Its disabled setup exercises existing endpoints but covers only a subset of upstream behavior. Vue type-check and build used an 8 GiB Node heap. Local logs are ephemeral. The portable launcher repeated both suites, disabled RBAC and read the original metric with an existing account, then re-enabled RBAC and verified the same policy revision and renewed denial on each store. It cleaned up both fixtures (`/tmp/rbac-worker-both-stores-final.log`). The repeatable fixtures are under `scripts/rbac/` and `tests/ui-testing/scripts/`.

## Scope of the checks

- SQL checks cover ordinary reads and downloads, joins, subqueries, CTEs, unions, mixed batches and immediate revocation. The batch fixtures cover streaming, partition planning and one-shot APIs. Enabled execution rejects custom transforms, table functions and UDFs and bypasses shared result caches.
- Ingestion checks exercise logs, multiline logs, JSON metrics, HTTP OTLP traces, organization tokens and scoped pipelines. Named PromQL instant and range queries run through both GET and POST. Additional protocols listed as unsupported in the endpoint matrix are denied.
- Identity checks use two organizations, actual user and service-account credentials, credential rotation and deletion, explicit root bootstrap, and a removed member with a retained policy entry.
- The delegated gRPC SQL fixture verifies a returned row before revocation and a permission denial afterwards. Additional RPC checks exercise 17 denial cases. These use loopback servers and disposable data.
- The scoped renderer used a local Chromium installation, a disposable SMTP server and the bundled streaming decoder. The standalone report service stays blocked. The private enterprise manifest and corresponding enterprise build were unavailable in this checkout.

## Independent review

The first review found four issues. The dedicated router discarded supported routes, the authorization gate rejected CORS preflights, collection endpoints omitted named alert and report grants, and root could not discover an explicitly bootstrapped organization without a membership row. The follow-up review checked all four corrections against the source and regression fixtures. The router transport run checked the first two, alert/report fixtures checked scoped collections, and the two-store policy tests checked root organization discovery.

## Rebase verification

Regenerate the endpoint inventory and run its check, then repeat the Casbin, metadata, HTTP, SQL, gRPC, background-execution and browser suites. Review every modified integration point in `modified-files.md`. A route that retains its path can still change which identity or resources it uses. Follow `operations.md` for setup, bootstrap and rollback.
