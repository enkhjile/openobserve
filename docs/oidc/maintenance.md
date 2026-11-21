# Maintaining the OIDC branch

The branch starts at upstream commit `c828ccec7a43f58e98cc51e0838b745544a15789`. Keep the fork as `origin` and OpenObserve as `upstream`. Preserve the upstream AGPL-3.0 license and notices in the fork.

## Integration points

| Upstream file | Reason for the change |
| --- | --- |
| `Cargo.lock` | Lock the protocol crate's resolved dependencies. The root `Cargo.toml` is unchanged: Cargo adds a path dependency inside the workspace directory as a member automatically. |
| `.env.example` | Show the disabled configuration and operator approval format. |
| `src/config/src/lib.rs`, `src/config/src/config.rs` | Load the dedicated OIDC configuration through the normal environment loader. |
| `src/core/Cargo.toml`, `src/core/src/lib.rs` | Depend on the protocol crate by path and expose the core adapter. |
| `src/main.rs` | Validate static provider settings before the server accepts traffic. |
| `src/db/src/user.rs`, `src/infra/src/table/org_users.rs` | Load the bound account and its current memberships by immutable user ID. |
| `src/db/src/session.rs` | Exclude OIDC rows, identified by `config::oidc::SESSION_PREFIX`, when rebuilding the native session cache. |
| `src/core/src/auth.rs` | Recognize the session cookie in the OSS request extractor. |
| `src/api/common/src/auth/validator.rs` | Route a request carrying the session cookie to the child module `validator/oidc.rs`, which pins its own role refusals, and apply OIDC-only policy before accepting human passwords. |
| `src/api/grpc/src/handler/grpc/auth/mod.rs` | Apply the human-password policy to gRPC and OTLP passwords; ingestion tokens are unaffected. |
| `src/api/http/src/handler/http/router/openapi_coverage/excluded_routes.txt` | Record browser-specific non-API routes in the existing OpenAPI coverage check. |
| `src/api/http/src/lib.rs`, `src/api/http/src/handler/http/router/mod.rs` | Merge the browser authentication routes from `oidc::routes()` and pin the public bootstrap field in tests. |
| `src/api/management/src/request/users/mod.rs` | Apply native login policy, and call `retire_browser_session` so a successful password login revokes the browser's OIDC session and clears its cookies. |
| `src/api/management/src/request/status/mod.rs` | Report `oidc_enabled`, and fold OIDC-only policy into `native_login_enabled` through `Oidc::allows_native_login`. |
| `src/config/src/axum/middlewares/access_log.rs`, `src/api/http/src/server.rs` | Strip callback queries from logs and omit request spans for the callback, both through `oidc::is_callback_path`; redact Set-Cookie values in custom access logs. |
| `web/src/components/login/Login.vue` | Show SSO, the allowed native login and a generic callback failure. |
| `web/src/utils/drafts/signOutFlow.ts`, `web/src/composables/shared/router.ts` | Register the OIDC callback page, expose a confirmation page for direct logout, and wait for session revocation before leaving the application. |
| `web/src/services/users.ts` | Let the logout confirmation page send the one native logout request through the interceptor-free client in `services/oidc.ts`, so it can report a 401 or 503 and offer a retry. |
| `web/src/utils/auth.ts` | Refuse to restore a cached profile that a confirmed sign-out could not delete, so the login guard cannot loop into a revoked session. |
| `web/src/locales/languages/en-US.json` | Add SSO controls and actionable error messages. |
| `web/cypress/e2e/tsconfig.json` | Resolve the installed Vue DOM config so browser test specs compile. |
| `web/src/layouts/MainLayout.signOutDrafts.spec.ts`, `MainLayout.signOutEditor.spec.ts`, `MainLayout.rum.spec.ts` | Supply the bootstrap config response that sign-out reads to choose OIDC or native logout. |
| `web/src/utils/sessionServices.ts`, `web/src/utils/storage.ts` | Continue logout cleanup and navigation when browser storage is unavailable. |
| `components/login/Login.spec.ts`, `utils/drafts/signOutFlow.spec.ts` | One line each: stub the OIDC client, and give the test store a native-login config. |
| `composables/shared/router.spec.ts` | Pin the added routes and drop the tests of the replaced `/logout` redirect. |

New files are grouped by function: `src/extensions/oidc` contains the protocol and provider tests, `src/core/src/extensions` contains account binding and session persistence (`oidc/session_store.rs` holds the atomic session SQL), and `src/api/http/src/oidc.rs` handles browser requests. Request validation lives in `src/api/common/src/auth/validator/oidc.rs`, a child module that uses the validator's private helpers without widening upstream visibility. Configuration lives in `src/config/src/oidc.rs`. The callback page, which loads the profile from the session and purges the previous account's cached results, lives in `web/src/views/OidcCallback.vue`. The direct logout page lives in `web/src/views/ConfirmSignOut.vue`, and `web/src/utils/serverSignOut.ts` chooses which server session sign-out revokes. The Vue client and service tests live in `web/src/services/oidc*`; OIDC unit tests for upstream components live next to each component in `*.oidc.spec.ts` files. Deployment and operator material is under `deploy/oidc` and `docs/oidc`. The browser UI tests are in `web/cypress/e2e/oidc.cy.js`. The core lifecycle test uses SQLite, and `tests/oidc/browser_flow.py` exercises a compiled binary through its HTTP endpoints.

## Updating upstream

1. Start with a clean checkout and retain a named backup branch for the current release.
2. Fetch `upstream` and inspect the upstream changes in the files listed above. Pay special attention to new public login paths, alternate credential validators, route normalization, account identifiers, cookie settings, session expiry and Vue session restoration.
3. Rebase a candidate branch on the chosen upstream tag or commit. With a published branch used by multiple people, merge the upstream release into the candidate branch to preserve shared history. Resolve conflicts at the adapter boundary.
4. Coordinate with the RBAC branch owner before resolving changes in the validator or HTTP middleware. The existing validated identity passed to handlers is the integration contract. Keep claim verification, user provisioning and cookie handling outside RBAC.
5. Regenerate the Cargo lockfile using the repository's pinned toolchain and review dependency changes. Inspect the diff against the new upstream baseline to catch accidental upstream formatting or feature changes.
6. Run the checks in [Regression checks](#regression-checks), including disabled local login, ingestion credentials, session revocation, and the mock-provider browser flow. Repeat the [Authentik acceptance test](authentik.md) before deploying an upgraded release.
7. Record the new upstream commit, diff and test results. Back up the SQLite metadata and configuration before deployment. Account bindings and sessions must move with the user database.

Disabling OIDC removes interactive OIDC access. Before doing this, verify an operator can authenticate with existing local credentials under the intended policy. Existing accounts and organization memberships remain in the metadata store.

## Regression checks

Install frontend dependencies with `npm ci` in `web/`, then build the UI before compiling the server so the binary embeds the login page.

```sh
npm run format:check
npm run lint:ci
NODE_OPTIONS="--max-old-space-size=8192" npm run build
NODE_OPTIONS="--no-experimental-webstorage" npm run test:unit -- --run components/login/ views/OidcCallback.spec.ts services/oidc.spec.ts services/users.spec.ts utils/auth.spec.ts utils/drafts/ utils/sessionServices composables/shared/router.spec.ts router/index.spec.ts layouts/
```

From `web/`, start the development server in one terminal:

```sh
npm run dev -- --host 127.0.0.1 --port 4173 --strictPort
```

Run the isolated browser spec from `web/` in a second terminal. It stubs the backend endpoints. Stop the development server with Ctrl-C after the run.

```sh
npx cypress run --e2e --spec cypress/e2e/oidc.cy.js --config baseUrl=http://127.0.0.1:4173,supportFile=false
```

From the Rust workspace, set `PROTOC_INCLUDE` to the protobuf include directory if required by your system. Debug builds with `CARGO_PROFILE_DEV_DEBUG=0` and `CARGO_PROFILE_TEST_DEBUG=0` reduce disk use. Run:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -W clippy::too_many_lines -W clippy::cognitive_complexity -W clippy::excessive_nesting -D warnings
cargo test -p openobserve-oidc
cargo test -p openobserve-core --test oidc_lifecycle
cargo test -p config -p openobserve-api-common -p openobserve-api-http -p openobserve-core --lib oidc
cargo build
uv run tests/oidc/browser_flow.py target/debug/openobserve
```

The last command launches five successive configurations of the actual binary with a temporary local SQLite store and a loopback RSA-signing mock provider. It checks the browser redirects and cookies, password and token access over gRPC, overlapping login tabs, the pending-login limit, a refused cross-origin write, login under a `ZO_BASE_URI` prefix, switching from OIDC to a native account, logout, hard expiry, account collision, local-login policy, ingestion and service credentials. The script generates fresh test credentials and removes the temporary database on exit. To repeat it with PostgreSQL metadata, set `OIDC_TEST_POSTGRES_DSN` to the DSN of an empty disposable database.
