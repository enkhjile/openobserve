# Maintaining the OIDC branch

The branch starts at upstream commit `c828ccec7a43f58e98cc51e0838b745544a15789`. Keep the fork as `origin` and OpenObserve as `upstream`. Preserve the upstream AGPL-3.0 license and notices in the fork.

## Integration points

| Upstream file | Reason for the change |
| --- | --- |
| `Cargo.toml`, `Cargo.lock` | Register the protocol crate and lock the resolved dependencies. |
| `.env.example` | Show the disabled configuration and operator approval format. |
| `src/config/src/lib.rs`, `src/config/src/config.rs` | Load the dedicated OIDC configuration through the normal environment loader. |
| `src/core/Cargo.toml`, `src/core/src/lib.rs` | Make the protocol crate available to the core adapter. |
| `src/main.rs` | Validate static provider settings before the server accepts traffic. |
| `src/db/src/user.rs`, `src/infra/src/table/org_users.rs` | Load the bound account and its current memberships by immutable user ID. |
| `src/core/src/auth.rs` | Recognize the session cookie in the OSS request extractor. |
| `src/api/common/src/auth/validator.rs` | Validate a stored OIDC session, enforce existing organization scope, and apply OIDC-only policy before accepting human passwords. |
| `src/api/grpc/src/handler/grpc/auth/mod.rs` | Apply the human-password policy in the gRPC validator, which authenticates OTLP separately from HTTP. |
| `src/api/http/src/handler/http/router/openapi_coverage/excluded_routes.txt` | Record browser-specific non-API routes in the existing OpenAPI coverage check. |
| `src/api/http/src/lib.rs`, `src/api/http/src/handler/http/router/mod.rs` | Register four browser authentication endpoints and pin public bootstrap fields in tests. |
| `src/api/management/src/request/users/mod.rs` | Apply native login policy and revoke the previous OIDC session on a successful password login. |
| `src/api/management/src/request/status/mod.rs` | Expose public login capabilities to Vue at bootstrap and after login. |
| `src/config/src/axum/middlewares/access_log.rs`, `src/api/http/src/server.rs` | Strip callback queries in request and referer logs and omit request spans containing the callback URL. |
| `web/src/components/login/Login.vue`, `web/src/views/Login.vue` | Show SSO and use the session endpoint to load the authenticated profile on return. |
| `web/src/utils/drafts/signOutFlow.ts`, `web/src/composables/shared/router.ts` | Wait for local session revocation before leaving the application. |
| `web/src/locales/languages/en-US.json` | Add SSO controls and actionable error messages. |
| `web/cypress/e2e/tsconfig.json` | Resolve the installed Vue DOM config so browser test specs compile. |
| Adjacent `Login.spec.ts`, `router.spec.ts`, and `signOutFlow.spec.ts` | Exercise the changed navigation, visibility, callback and logout behavior. |

New files are grouped by function: `src/extensions/oidc` contains the protocol and provider tests, `src/core/src/extensions` contains account and session persistence, and `src/api/http/src/oidc.rs` handles browser requests. Configuration lives in `src/config/src/oidc.rs`. The Vue client and service tests live in `web/src/services/oidc*`. Deployment and operator material is under `deploy/oidc` and `docs/oidc`. The browser UI tests are in `web/cypress/e2e/oidc.cy.js`. The core lifecycle test uses SQLite, and `tests/oidc/browser_flow.py` exercises a compiled binary through its HTTP endpoints.

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
NODE_OPTIONS="--no-experimental-webstorage" npm run test:unit -- --run components/login/Login.spec.ts views/Login.spec.ts services/oidc.spec.ts utils/drafts/signOutFlow.spec.ts composables/shared/router.spec.ts layouts/MainLayout.signOutDrafts.spec.ts
```

Start the Vite development server and run the isolated Cypress OIDC spec against it. Its assertions cover rendered UI and navigation with stubbed endpoints.

From the Rust workspace, set `PROTOC_INCLUDE` to the protobuf include directory if required by your system. Debug builds with `CARGO_PROFILE_DEV_DEBUG=0` and `CARGO_PROFILE_TEST_DEBUG=0` reduce disk use. Run:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -W clippy::too_many_lines -W clippy::cognitive_complexity -W clippy::excessive_nesting -D warnings
cargo test -p openobserve-oidc
cargo test -p openobserve-core --test oidc_lifecycle
cargo test -p config -p openobserve-api-common -p openobserve-api-grpc -p openobserve-api-http -p openobserve-core --lib oidc
cargo build
uv run tests/oidc/browser_flow.py target/debug/openobserve
```

The last command launches four successive configurations of the actual binary with a temporary local SQLite store and a loopback RSA-signing mock provider. It checks the browser redirects and cookies, overlapping login tabs, switching from OIDC to a native account, logout, hard expiry, account collision, local-login policy, ingestion and service credentials. The script generates fresh test credentials and removes the temporary database on exit.
