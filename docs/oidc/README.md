# Optional OIDC authentication for OpenObserve OSS

This feature adds server-verified OpenID Connect authentication without an additional authentication service or metadata database. It is disabled by default. Existing organization memberships remain the source of application access; provider groups are not permissions.

## Configuration

Set environment variables using the existing OpenObserve configuration mechanism. A project-root `.env` overrides process environment; do not leave example secrets there in a deployment. Never commit a real client secret or approval list containing production identities.

| Variable | Default | Meaning |
| --- | --- | --- |
| `ZO_OIDC_ENABLED` | `false` | Enable the extension. |
| `ZO_OIDC_ISSUER` | empty | Exact provider issuer, including any trailing slash. |
| `ZO_OIDC_CLIENT_ID` | empty | Registered OIDC client ID. |
| `ZO_OIDC_CLIENT_SECRET` | empty | Confidential client secret, supplied through deployment secrets. |
| `ZO_OIDC_REDIRECT_URI` | empty | Exact public callback URL, e.g. `https://observe.example.com/auth/oidc/callback`. End it with `/auth/oidc/callback` without a trailing slash, after any public path prefix (see below). |
| `ZO_OIDC_SCOPES` | `openid email profile` | Space-separated requested scopes. Do not request offline access. |
| `ZO_OIDC_ACCOUNT_LINKS` | `[]` | JSON array of explicit `{ "issuer", "subject", "email" }` mappings to existing local accounts. |
| `ZO_OIDC_PROVISIONING_ENABLED` | `false` | Permit new verified identities to create non-administrator accounts without implicit organization memberships. |
| `ZO_OIDC_ONLY` | `false` | Require OIDC for human authentication, including direct password-based API requests. |
| `ZO_OIDC_EMERGENCY_USER` | empty | Exact existing root account allowed to authenticate with its password in OIDC-only mode. No automatic root creation by this setting. |
| `ZO_OIDC_SESSION_MAX_AGE` | `3600` | Maximum session lifetime in seconds, also bounded by verified ID-token expiry. |
| `ZO_OIDC_COOKIE_SECURE` | `true` | Secure browser cookies; keep enabled in production. |
| `ZO_OIDC_ALLOW_INSECURE_HTTP` | `false` | Explicit development-only HTTP opt-in. Never enable on an exposed deployment. |

Startup validates OIDC settings before serving requests. Provider discovery occurs on the first login. If discovery fails, concurrent logins share the failure and the server can retry discovery after two seconds. Confidential clients support client_secret_basic and client_secret_post. OpenObserve reads all `ZO_OIDC_*` settings at startup. If a file edit changes both an OIDC setting and a reloadable OpenObserve setting, the latter takes effect on reload. The OIDC change takes effect on the next server start. Keep deployment secrets in the platform's secret store and inject them into the process environment. The extension does not add a new secret-management service.

To serve OpenObserve under a public path prefix such as `https://example.com/observe`, set the existing `ZO_BASE_URI=/observe` and forward that prefix unchanged from the proxy. The callback then lives under the prefix, so set `ZO_OIDC_REDIRECT_URI=https://example.com/observe/auth/oidc/callback` and register exactly that URL with the provider. After login the browser returns to `/observe/web/oidc/cb`.

Example explicit mapping:

```sh
ZO_OIDC_ACCOUNT_LINKS='[{"issuer":"https://id.example.com/application/o/openobserve/","subject":"provider-stable-subject","email":"analyst@example.com"}]'
```

This is an operator authorization to link that exact identity. An identity with the same email but a different issuer or subject is not equivalent. A binding pins the local database user ID as well as its email. Reassigning the mapping, or deleting and recreating the user with the same email, invalidates access. Create the target account through existing administration first. Do not use the emergency root as a routine user.

Automatic provisioning is a separate policy. It requires verified email, refuses an existing-email collision, creates an unusable local password, and grants no implicit membership. An administrator must assign application membership through existing mechanisms. Keeping provisioning disabled supports an explicit approval list. After restart, a removed mapping no longer grants approval. Disabling automatic provisioning also withdraws approval for automatically provisioned identities after restart. Local accounts and application data are retained.

## Browser sessions

Authorization uses code flow with S256 PKCE, state and nonce. The callback validates the provider's signed ID token before creating a fresh opaque server session. Provider tokens are not returned to the browser. Login transactions are process-local and short-lived; after a restart, begin login again.

Sessions use secure HttpOnly cookies and a fixed maximum lifetime. Reauthenticate after expiry; no refresh token is stored. Choosing Sign Out in the application invalidates the local session through a CSRF-protected POST. A direct visit to `/web/logout` asks for confirmation before sending that request. It does not end the provider's own SSO session, so the next login may authenticate immediately there. Deleting the local user invalidates session use immediately. Withdrawing approval in the configuration invalidates session use after restart.

Use one application origin for UI and backend, with HTTPS terminated by the existing trusted reverse proxy. Unsafe cookie-authenticated requests must satisfy the adapter's origin checks. Avoid logging callback queries at the proxy, and do not enable credential/header debug logging.

## Deployment example

Use [compose.yaml](../../deploy/oidc/compose.yaml) with an image built from this branch, an existing TLS reverse proxy and an existing OIDC provider. An upstream stock image does not contain this extension. The only persistent application volume is `/data`; SQLite remains supported. The example deliberately binds the plaintext backend port to loopback and requires HTTPS callback settings.

Set the required variables in a protected deployment environment, then run the commands below. Leave `ZO_BASE_URI` unset unless the proxy serves OpenObserve under a path prefix; if it does, include the same prefix in `ZO_OIDC_REDIRECT_URI`.

```sh
docker compose -f deploy/oidc/compose.yaml config --quiet
docker compose -f deploy/oidc/compose.yaml up -d
```

Do not paste the output of unrestricted `docker compose config` into logs: it expands secrets.

See [Authentik setup and manual tests](authentik.md), [security review](security.md), and [maintenance and regression checks](maintenance.md).
