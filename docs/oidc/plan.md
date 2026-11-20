# Modular OSS OIDC design and implementation plan

Baseline: `c828ccec7a43f58e98cc51e0838b745544a15789` from upstream main. Branch: `feature/oidc`. Tier: Feature.

## Design

Use an isolated Rust protocol crate at `src/extensions/oidc`, with thin adapters in core and HTTP. Reuse SQLite-compatible metadata for identity bindings and explicit-expiry sessions. Feed the existing authentication validator and downstream `user_id` identity contract, preserving existing membership handling. No RBAC implementation or Enterprise code is needed.

Alternatives considered: a reverse-proxy authentication service would add infrastructure; embedding provider logic throughout existing authentication would increase upgrade conflicts. The isolated crate and adapters meet the stated deployment and maintenance requirements.

Inspection: `src/core/src/auth.rs:510` extracts OSS credentials; `src/api/common/src/auth/validator.rs:203` validates them; `src/api/http/src/handler/http/router/mod.rs:353` passes the identity to handlers. `src/db/src/session.rs:122` persists sessions with explicit expiry. `src/infra/src/db/mod.rs:214` provides metadata CAS. `src/db/src/user.rs:193` inserts user records separately from memberships. `web/src/views/Login.vue:345` has a legacy token-hash callback, which the new flow must bypass.

## Numbered rules

1. OIDC is disabled by default. Existing local/API/ingestion behavior remains unchanged when disabled.
2. Use maintained `openidconnect` for discovery and authorization code + S256 PKCE, state, nonce and full signed ID-token validation. No unsigned claims or email-only trust.
3. Transactions are short-lived, browser-bound, single-use, capacity-limited and consumed before code exchange. Callback replay and login CSRF fail closed. Provider HTTP redirects are disabled; production endpoints require HTTPS; development HTTP is explicitly opted into.
4. Cache discovery/JWKS with bounded lifetime, refresh on key rotation with rate limiting, and never log codes, tokens, secrets or callback query strings through new code.
5. Persist immutable identity linkage by exact issuer+subject. Provisioning defaults to deny. Explicit operator-provided mappings may link existing accounts. Automatic provisioning refuses collisions, creates unusable passwords, grants no administrator role and does not interpret groups. New users receive no implicit organization membership.
6. Use fresh opaque session identifiers, server-side expiry, HttpOnly Secure SameSite=Lax cookies, rotation on successful login, CSRF enforcement for unsafe cookie-authenticated methods, and POST logout with error-aware revocation. Retain no provider refresh token; session expiry is bounded by verified ID token expiry and configured maximum.
7. OIDC-only denies native interactive login and human-password authentication through direct Basic/derived paths. Only an explicitly configured existing root emergency identity may use its password. Existing ingestion tokens and service authentication remain supported.
8. Adapter resolves the current persisted identity/user and returns the ordinary authentication result through existing checks; deleted/unapproved identities fail. No authorization architecture changes.
9. Frontend advertises SSO, honors native policy, bootstraps a profile from a server session, handles generic errors and awaits logout. Never consume URL tokens in the OIDC path.
10. Configuration uses ZO_OIDC_* environment variables; documentation covers Authentik, deployment, trust boundaries, every upstream modification and future rebases.

## Components and contracts

- Protocol crate: owns validated settings, provider discovery/code exchange and verified identity; I/O errors fail without issuing identity. Tests use a mock provider.
- Core adapter: owns metadata bindings, provisioning and sessions; partial storage failures issue no browser credentials, retries cannot replace an existing identity binding.
- HTTP adapter: owns browser transaction cookies, routes and CSRF; failed callbacks never issue authenticated sessions.
- Frontend adapter: displays server capabilities and restores UI-only profile after server authentication.

HTTP contract (under existing API base path): `GET /auth/oidc/login`, `GET /auth/oidc/callback`, `GET /auth/oidc/session`, `POST /auth/oidc/logout`. Callback redirects to existing web `/cb?oidc=1`. Session profile is `{email, name, given_name, family_name, exp}`. Safe config flags: `oidc_enabled`, `oidc_only`, `oidc_emergency_login_enabled`; native login is visible when policy permits or emergency login is configured. Logout is awaited and failures surfaced.

## Implementation sequence

- [ ] Protocol crate + negative-token/mock-provider tests; prove tests fail before implementation then pass.
- [ ] Metadata/session/core and HTTP adapters + bypass/provisioning/session tests.
- [ ] Minimal Vue integration + login/callback/logout tests.
- [ ] Configuration example, Authentik manual test, Compose example, security and maintenance docs.
- [ ] Rust format/build/tests/clippy, Vue format/lint/type/build/tests and browser check where runnable; record all failures accurately.
- [ ] Independent security review, confirm/fix findings, repeat review as necessary (maximum five rounds).
- [ ] Remove Rust compilation artifacts after all active builds finish.

## Verification focus

Test invalid issuer/audience/signature/nonce/state/expiry; JWKS rotation; code replay; browser mismatch; duplicate cookies; unsafe cross-origin requests; concurrent account provisioning and collision/takeover attempts; session fixation/revocation/expiry; approval withdrawal; disabled compatibility; native-password bypass and unaffected ingestion tokens. Live Authentik acceptance requires an operator-controlled provider/client and cannot be claimed from mock tests alone.

## Constraints and open dependencies

The repository references absent `web/CLAUDE.md`; use present AGENTS and UI skill rules. Maintain the shared identity contract with the independent RBAC branch. Real Authentik credentials and instance are not supplied. Enterprise builds are out of scope and inaccessible.
