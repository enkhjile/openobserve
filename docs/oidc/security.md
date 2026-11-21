# Security notes

Scope: OIDC login in the Community Edition, from the browser redirect to the identity handed to OpenObserve's handlers. The operator controls the issuer URL, TLS trust, client registration, account links, root credentials and the database; a compromise of any of these is out of scope.

| Boundary | Protection |
| --- | --- |
| Browser to callback | Each login has a single-use, short-lived server transaction that binds state, nonce and an S256 PKCE verifier to its own HttpOnly cookie. A browser may hold eight pending logins; a ninth gets HTTP 429 until one completes or expires after five minutes. |
| Provider to OpenObserve | Discovery starts from the configured issuer. Provider requests use TLS, follow no redirects, and have timeouts and a 1 MiB response limit. The ID token's signature, issuer, audience, authorized party, nonce and times are verified; after a failure, signing keys are refreshed at most every ten seconds. |
| Identity to account | Only operator-linked issuer/subject pairs, or verified-email provisioning, are approved; a matching email alone never grants an existing account. Bindings record the account's internal ID, so recreating a user with the same email cannot revive one. Concurrent provisioning uses a reserved ID and compare-and-swap writes. |
| Session | A random secret in an HttpOnly cookie; the server stores only its hash. The session ends at the earlier of the configured maximum and the ID token's expiry. Every request reads the session from the primary database and rechecks approval and the bound account. |
| State-changing requests | Require the expected Origin, or a same-origin Referer; a refusal gets 403 and leaves the session valid. Duplicate session cookies are refused. Production cookies are `__Host-` prefixed, Secure, HttpOnly, Path=/ and SameSite=Lax. Logout is a POST that revokes the session, and any callback still in flight, before it succeeds. |
| Other credentials | OIDC-only mode is enforced on the server for HTTP and gRPC, except for the named emergency root. Ingestion and service-account tokens keep their usual scope. |
| Logs and browser | Callback queries are dropped from access logs and request traces, and Set-Cookie values are redacted in custom access logs. Provider tokens never reach the browser. Before loading a new identity, the UI deletes the previous account's cached query results. After a confirmed logout it never restores a profile the browser failed to delete. Login errors are generic. |

## Limits

- Pending logins live in one process's memory, so the supported deployment is a single OpenObserve node. A restart cancels logins in progress.
- Logout ends only the OpenObserve session. A provider-side logout or account deactivation is not pushed to OpenObserve; the session ends at its hard expiry. For immediate revocation, delete the local account, or remove its link and restart.
- Signing keys and discovery data are cached for up to five minutes, so a key removed at the provider stops being accepted within that time.
- Provider groups and claims grant no roles, and new accounts have no memberships. Authorization stays with OpenObserve's memberships and the separate RBAC work, which consumes the identity passed through the normal HTTP middleware.
- Treat the environment and the metadata database as credentials.
