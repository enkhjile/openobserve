# Maintaining the OIDC branch

The branch starts at upstream commit `c828ccec7a43f58e98cc51e0838b745544a15789`. Keep the fork as `origin` and OpenObserve as `upstream`, and keep the upstream AGPL-3.0 license and notices.

## Feature-owned code

| Path | Contents |
| --- | --- |
| `src/extensions/oidc` | Protocol: discovery, PKCE, token exchange and ID-token verification, with provider tests |
| `src/core/src/extensions/oidc*` | Account binding and sessions; `session_store.rs` holds the atomic session SQL |
| `src/config/src/oidc.rs` | Settings, startup validation and the shared password policy |
| `src/api/http/src/oidc.rs` | Browser endpoints |
| `src/api/common/src/auth/validator/oidc.rs` | Request validation; a child module, so it uses the validator's private helpers |
| `web/src/services/oidc.ts`, `web/src/utils/serverSignOut.ts` | Vue client and the choice of session to revoke on sign-out |
| `web/src/views/OidcCallback.vue`, `web/src/views/ConfirmSignOut.vue` | Callback page and direct-logout confirmation |
| `web/src/**/*.oidc.spec.ts`, `web/cypress/e2e/oidc.cy.js` | Vue unit tests for upstream components, and the browser spec |
| `src/core/tests/oidc_lifecycle.rs`, `tests/oidc/browser_flow.py` | Lifecycle test on SQLite, and a mock-provider flow against the compiled server |
| `deploy/oidc`, `docs/oidc` | Compose example and these docs |

## Changes to upstream files

| Upstream file | Why |
| --- | --- |
| `Cargo.lock` | Locks the protocol crate's dependencies. The root `Cargo.toml` is unchanged, since Cargo adds a path dependency inside the workspace as a member automatically. |
| `.env.example` | Shows the disabled settings and the account-link format. |
| `src/config/src/lib.rs`, `src/config/src/config.rs` | Load the OIDC settings through the normal environment loader. |
| `src/core/Cargo.toml`, `src/core/src/lib.rs` | Depend on the protocol crate and expose the core adapter. |
| `src/main.rs` | Validates provider settings before the server accepts traffic. |
| `src/db/src/user.rs`, `src/infra/src/table/org_users.rs` | Load the bound account and its memberships by immutable user ID. |
| `src/db/src/session.rs` | Keeps OIDC rows (`config::oidc::SESSION_PREFIX`) out of the native session cache. |
| `src/core/src/auth.rs` | Recognizes the session cookie in the request extractor. |
| `src/api/common/src/auth/validator.rs` | Routes requests with the session cookie to `validator/oidc.rs`, and applies OIDC-only policy to human passwords. |
| `src/api/grpc/src/handler/grpc/auth/mod.rs` | Applies OIDC-only policy to gRPC and OTLP passwords. |
| `src/api/http/src/handler/http/router/mod.rs`, `src/api/http/src/lib.rs` | Mount `oidc::routes()` and pin the public `oidc_enabled` field. The OpenAPI coverage test reads routes only from `router/mod.rs`, so the browser routes in `oidc.rs` need no exclusion. |
| `src/api/management/src/request/users/mod.rs` | Applies native login policy, and revokes the browser's OIDC session on password login (`retire_browser_session`). |
| `src/api/management/src/request/status/mod.rs` | Reports `oidc_enabled`, and folds OIDC-only policy into `native_login_enabled`. |
| `src/config/src/axum/middlewares/access_log.rs`, `src/api/http/src/server.rs` | Drop callback queries from logs and traces (`oidc::is_callback_path`), and redact Set-Cookie values in custom access logs. |
| `web/src/components/login/Login.vue` | SSO button and the generic callback error. |
| `web/src/composables/shared/router.ts`, `web/src/utils/drafts/signOutFlow.ts` | Register the callback and logout-confirmation routes, and wait for server revocation before leaving. |
| `web/src/services/users.ts` | Lets the confirmation page send native logout without the global 401 handler, so it can offer a retry. |
| `web/src/utils/auth.ts` | Never restores a profile that a confirmed sign-out failed to delete. |
| `web/src/utils/sessionServices.ts`, `web/src/utils/storage.ts` | Finish logout cleanup and navigation when browser storage throws. |
| `web/src/locales/languages/en-US.json` | SSO and error messages. |
| `web/cypress/e2e/tsconfig.json` | Points at the Vue DOM config the installed package ships, so browser specs compile. |
| `Login.spec.ts`, `signOutFlow.spec.ts`, `MainLayout.rum.spec.ts`, `MainLayout.signOutDrafts.spec.ts`, `MainLayout.signOutEditor.spec.ts` | Small stubs: the OIDC client, and the bootstrap config that sign-out reads. |
| `composables/shared/router.spec.ts` | Pins the added routes and drops tests of the replaced `/logout` redirect. |

## Updating from upstream

1. Start from a clean checkout and keep a backup branch of the current release.
2. Fetch `upstream` and review its changes to the files above, especially login paths, credential validators, route normalization, account identifiers, cookies, session expiry and Vue session restoration.
3. Merge the upstream release into a candidate branch (rebase only if nobody else uses the branch), resolving conflicts at the hooks.
4. Agree changes to the validator or HTTP middleware with the RBAC branch owner. The validated identity passed to handlers is the contract; claim verification, provisioning and cookies stay out of RBAC.
5. Regenerate `Cargo.lock` with the pinned toolchain and review dependency changes.
6. Run the [regression checks](#regression-checks), then the [Authentik acceptance test](authentik.md) before deploying.
7. Record the upstream commit and results, and back up the metadata database and configuration; bindings and sessions live with the user data.

Before disabling OIDC, make sure an operator can still sign in with local credentials. Accounts and memberships stay in the metadata store.

## Regression checks

In `web/`, after `npm ci` (build the UI before the server, so the binary embeds it):

```sh
npm run format:check
npm run lint:ci
NODE_OPTIONS="--max-old-space-size=8192" npm run build
NODE_OPTIONS="--no-experimental-webstorage" npm run test:unit -- --run components/login/ views/OidcCallback.spec.ts services/oidc.spec.ts services/users.spec.ts utils/auth.spec.ts utils/drafts/ utils/sessionServices composables/shared/router.spec.ts router/index.spec.ts layouts/
```

Browser spec, with the dev server running in another terminal (`npm run dev -- --host 127.0.0.1 --port 4173 --strictPort`); it stubs the backend:

```sh
npx cypress run --e2e --spec cypress/e2e/oidc.cy.js --config baseUrl=http://127.0.0.1:4173,supportFile=false
```

In the Rust workspace (set `PROTOC_INCLUDE` if your system needs it):

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -W clippy::too_many_lines -W clippy::cognitive_complexity -W clippy::excessive_nesting -D warnings
cargo test -p openobserve-oidc
cargo test -p openobserve-core --test oidc_lifecycle
cargo test -p config -p openobserve-api-common -p openobserve-api-http -p openobserve-core --lib oidc
cargo build
uv run tests/oidc/browser_flow.py target/debug/openobserve
```

The last command runs the compiled server in five configurations against a loopback mock provider with fresh credentials and a temporary SQLite store. It covers login, replay, overlapping tabs, the pending-login limit, cross-origin writes, a `ZO_BASE_URI` prefix, logout and expiry, account collisions, OIDC-only policy over HTTP and gRPC, and ingestion and service credentials. Set `OIDC_TEST_POSTGRES_DSN` to an empty disposable database to run it on PostgreSQL.
