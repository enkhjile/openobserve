# Verification record

Baseline `c828ccec7a43f58e98cc51e0838b745544a15789`, OSS configuration, macOS arm64, Rust nightly-2026-10-24. Build the Vue bundle before the server so the binary embeds the login UI. Use the repository's pinned toolchain. The tests below require no external identity provider or production secrets.

| Check | Result |
| --- | --- |
| Protocol crate | Signed mock-provider, transaction and configuration tests passed. Covered S256 PKCE, state/nonce, issuer, audience, signature, expiry, future issue time, not-before, authorized party, replay, unsupported algorithm and replacement of RSA signing keys. The final named HTTP transport also passed the multithreaded-handler check. |
| Frontend tests | 557 focused Vitest tests passed across six suites. Five Cypress Electron tests passed with mocked HTTP responses, including the no-membership state and sign-out. |
| Frontend static checks | Full format check and ESLint passed. ESLint reported seven existing warnings. Application type-check passed with an 8 GiB Node heap. |
| Vue production build | Full production build, type-check and asset copy passed. |
| SQLite lifecycle | The database-backed lifecycle integration test passed, including collision handling, row replacement, revocation and retry of pending provisioning. |
| Compose manifest | `docker compose -f deploy/oidc/compose.yaml config --quiet` passed with temporary test values. Container startup was not exercised because the local Docker daemon was unavailable. |
| Rust adapters | Nine focused tests passed across config, core and the HTTP, gRPC and shared API crates. The bootstrap-field and callback-tracing tests also passed. The macOS linker warned about the compact unwind table size in debug test binaries. |
| Rust workspace | Formatting, all-target workspace Clippy with warnings denied, and the debug build passed. |
| Whole-server mock acceptance | Passed against the compiled server in three configurations with a temporary SQLite database. Covered signed login, replay, rotation, revocation, hard expiry, provisioning, existing-account rejection, emergency access, JSON and OTLP HTTP ingestion, and service-account API access. Ruff formatting and lint checks passed. |
| Independent security review | The reviewer rechecked the fixes described in [security.md](security.md) and reported no blocking finding in the paths reviewed. |
| Authentik | Manual procedure documented in [authentik.md](authentik.md). The requested automated acceptance environment uses the local mock provider. Live Google federation and MFA were not exercised. |

Testing focused on authentication and its integration points. The full Rust and Vue test suites were not run.

## Reproduce the checks

From `web/`, install dependencies with `npm ci` and run the following. On the Node 24 host used for verification, `--no-experimental-webstorage` selected jsdom's usable localStorage implementation. An 8 GiB heap was needed for the full type-check.

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

The last command launches three successive configurations of the actual binary with a temporary local SQLite store and a loopback RSA-signing mock provider. It checks the browser redirects and cookies, signed login and logout, hard expiry, account collision, local-login policy, ingestion and service credentials. The script generates fresh test credentials and removes the temporary database on exit.
