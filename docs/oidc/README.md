# Optional OIDC login for OpenObserve OSS

Adds server-verified OpenID Connect login to the Community Edition. It is off by default and needs no service besides the identity provider. Access still comes from existing organization memberships; provider groups and claims grant no roles.

## Configuration

All `ZO_OIDC_*` settings are read once at startup and validated before the server accepts traffic, so changing them needs a restart. Other OpenObserve settings keep their normal reload behaviour. A project-root `.env` overrides the process environment: keep secrets in your platform's secret store, and never commit a real client secret or production account links.

| Variable | Default | Meaning |
| --- | --- | --- |
| `ZO_OIDC_ENABLED` | `false` | Enable OIDC login. |
| `ZO_OIDC_ISSUER` | empty | Exact issuer from the provider's discovery document, including any trailing slash. |
| `ZO_OIDC_CLIENT_ID` | empty | Registered client ID. |
| `ZO_OIDC_CLIENT_SECRET` | empty | Client secret, sent with `client_secret_basic` or `client_secret_post`, whichever the provider supports. |
| `ZO_OIDC_REDIRECT_URI` | empty | Exact public callback URL ending in `/auth/oidc/callback` with no trailing slash, e.g. `https://observe.example.com/auth/oidc/callback`. |
| `ZO_OIDC_SCOPES` | `openid email profile` | Requested scopes. Do not request offline access. |
| `ZO_OIDC_ACCOUNT_LINKS` | `[]` | JSON array of approved identities; see [Approving accounts](#approving-accounts). |
| `ZO_OIDC_PROVISIONING_ENABLED` | `false` | Create accounts for new identities that have a verified email. |
| `ZO_OIDC_ONLY` | `false` | Refuse human password login, including Basic auth over HTTP and gRPC. Requires `ZO_OIDC_ENABLED`. |
| `ZO_OIDC_EMERGENCY_USER` | empty | Existing root account that may still use its password when `ZO_OIDC_ONLY` is set. |
| `ZO_OIDC_SESSION_MAX_AGE` | `3600` | Session lifetime in seconds (1–86400), further capped by the ID token's expiry. |
| `ZO_OIDC_COOKIE_SECURE` | `true` | Mark cookies `Secure`. Turning it off also requires `ZO_OIDC_ALLOW_INSECURE_HTTP`. |
| `ZO_OIDC_ALLOW_INSECURE_HTTP` | `false` | Development only: allow plain-HTTP provider and callback URLs. |

Discovery happens on the first login; after a failure the next login retries it after two seconds. Ingestion tokens and service accounts are unaffected by these settings.

### Serving under a path prefix

If the proxy serves OpenObserve under a prefix such as `https://example.com/observe`, set `ZO_BASE_URI=/observe`, forward the prefix unchanged, and include it in the callback: `ZO_OIDC_REDIRECT_URI=https://example.com/observe/auth/oidc/callback`. Register exactly that URL with the provider.

## Approving accounts

An identity is approved in one of two ways:

- **Explicit link.** Map the provider's issuer and subject to an existing local account, which you create first:

  ```sh
  ZO_OIDC_ACCOUNT_LINKS='[{"issuer":"https://id.example.com/application/o/openobserve/","subject":"provider-stable-subject","email":"analyst@example.com"}]'
  ```

  A matching email alone never links an account; another issuer or subject is another identity.
- **Provisioning.** With `ZO_OIDC_PROVISIONING_ENABLED=true`, a new identity with a verified email gets a new account with an unusable password and no organization membership. It is refused if the email already belongs to an account. Administrators assign memberships as usual.

The first login binds the identity to the account's internal user ID. Deleting and recreating a user with the same email, or pointing the link at another account, ends access through that binding. Removing a link, or turning provisioning off, withdraws approval at the next restart; accounts and their data stay. Don't use the emergency root for routine work.

## Sessions and logout

The callback verifies the provider's signed ID token and starts a new opaque server session in an HttpOnly cookie; provider tokens never reach the browser. Sessions are not refreshed: users sign in again when one expires. Every request rechecks the session and the bound account, so deleting the account ends access immediately.

Sign Out revokes the session on the server, and a direct visit to `/web/logout` asks for confirmation first. Logout does not end the provider's own session, so the next sign-in may complete without a prompt. Sign-ins in progress are held in server memory and must be restarted after a server restart.

## Deployment

Serve the UI and API from one HTTPS origin behind your reverse proxy. Keep callback query strings out of the proxy's logs, and rate-limit `/auth/oidc/login` per client (see [security notes](security.md#limits)). Both SQLite and PostgreSQL metadata stores work.

[compose.yaml](../../deploy/oidc/compose.yaml) is an example for an existing TLS proxy and provider. It needs an image built from this branch (stock images don't include OIDC), keeps data in one `/data` volume, binds the backend to loopback, and turns on OIDC-only mode with the root as emergency user.

```sh
docker compose -f deploy/oidc/compose.yaml config --quiet
docker compose -f deploy/oidc/compose.yaml up -d
```

Don't log the output of plain `docker compose config`; it expands secrets.

See also: [Authentik setup and acceptance test](authentik.md), [security notes](security.md), [maintenance](maintenance.md).
