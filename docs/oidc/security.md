# Authentication security review

Review scope: OIDC login on the Community Edition, from browser redirect through the validated identity supplied to OpenObserve handlers. The mock provider controls its own test signing keys. The operator controls the issuer URL, TLS trust, client registration, account mappings, root credential and database. A compromise of those authorities is outside the protection supplied by an OIDC client.

| Boundary | What the implementation checks |
| --- | --- |
| Browser to callback | A short-lived, capacity-limited server transaction binds a random state, nonce and S256 verifier to a separate HttpOnly browser cookie. Each login tab receives its own cookie. Each transaction can complete once. A browser with eight pending cookies must finish a login or wait for a cookie to expire before starting another. |
| Provider to application | Discovery starts at the configured issuer. The client uses TLS in production, disables redirects, limits response sizes and timeouts, verifies signed ID tokens, and checks issuer, audience, applicable authorized-party claims, nonce and token times. A failed verification can refresh signing keys under a rate limit. |
| Provider identity to local account | The operator approves exact issuer and subject pairs. A signed email claim alone confers no access to an existing account. Automatic provisioning requires verified email, refuses collisions and creates an account without memberships. |
| Account deletion and recreation | Each binding also records the local database row ID. Recreating the same email cannot revive an old binding. Concurrent provisioning uses a normalized email, a reserved user ID, and compare-and-swap metadata writes. |
| Local account to browser session | The server rotates a random session secret and persists a hash as its lookup key. The session expires at the earlier of the configured limit and ID-token expiry. Each request reads the session from the primary database and checks current approval and the linked local user ID, including after logout. |
| Browser to state-changing handlers | Unsafe session requests must have the expected Origin or same-origin Referer. Duplicate session cookies are rejected. Production cookies use HttpOnly, Secure, Path=/, a host-only prefix and SameSite=Lax. Logout uses POST and revokes the session before success. It also cancels outstanding callbacks identified by the browser’s transaction cookies. |
| Other credentials | OIDC-only policy is enforced in the backend. An explicitly named root may use emergency password login. Ingestion tokens and service-account tokens keep their upstream route and scope restrictions. |
| Logs and UI | The callback redirects without returning provider tokens. Access/slow logs strip the callback query and the request tracer suppresses its raw-URL span. The UI reads a display profile from the session endpoint. Generic login errors avoid returning provider exchanges to users. |

## Boundaries operators should verify

Keep the UI and API on the same HTTPS origin. Match the complete callback URL at the provider, including any base path. Protect the environment and SQLite database as credentials. Configure the reverse proxy to omit callback queries. Browsers retain the provider's own session after OpenObserve logout. An IdP logout or deactivation does not send a back-channel revocation notification to this extension; the application session has a hard expiry. For faster revocation remove the local approval or local account.

The current deployment target is a single OpenObserve process. Pending login state is in memory. Restarting during a login discards that transaction and the user starts again. The bounded signing-key cache permits rotation without a network call per API request. Key removal at the issuer takes effect at cache refresh. Use short token and local session lifetimes appropriate for your deployment.

Newly provisioned users have no organization membership. Add appropriate membership using the application's existing administration flow. The OIDC extension grants no roles from groups or other provider claims. The independent RBAC change must consume the validated application identity supplied by the normal HTTP middleware.

## Validation

The local mock-provider tests passed against the compiled OSS server. Live Authentik federation and MFA require a deployment-specific check. [Regression checks](maintenance.md#regression-checks) · [Authentik acceptance test](authentik.md)
