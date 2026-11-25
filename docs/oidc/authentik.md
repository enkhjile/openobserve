# Authentik setup and acceptance test

OpenObserve speaks standard OIDC. Google sign-in, MFA and enrollment happen in Authentik's own flows.

## Authentik

1. Create an OAuth2/OpenID provider and an application that uses it ([provider docs](https://docs.goauthentik.io/add-secure-apps/providers/oauth2/), [scope mappings](https://docs.goauthentik.io/add-secure-apps/providers/property-mappings/)).
2. Use a confidential client, the authorization-code flow and an asymmetric signing key such as RS256. Don't enable the implicit flow or offline access.
3. Set the redirect URI to exactly the value of `ZO_OIDC_REDIRECT_URI`.
4. Map the `openid`, `profile` and `email` scopes and include their claims in the ID token.
5. Copy the issuer from `/application/o/<application_slug>/.well-known/openid-configuration`, and store the client ID and secret securely.
6. Add Google federation and MFA to the authentication flow if wanted, and restrict the application to its intended users.

## OpenObserve

Configure OpenObserve as in [README.md](README.md), starting with provisioning off. Link one existing test account with known memberships by its Authentik subject, taken from Authentik's admin UI; the subject is not the email unless Authentik makes it so. Accounts created through the OSS user API are organization administrators, so choose the test account accordingly. OpenObserve must reach Authentik's discovery, JWKS and token endpoints over trusted TLS, and both clocks must be synchronized.

## Acceptance test

Record the OpenObserve commit, Authentik version, issuer, signing algorithm, date, tester and each result. Never record tokens, secrets, cookie values or authorization codes.

1. With OIDC disabled, local login works.
2. With OIDC enabled, Login with SSO goes to Authentik and returns through the callback.
3. Google sign-in (if configured) and MFA complete, and the linked account sees its organizations and data.
4. An unlinked identity is refused even when its email belongs to an administrator, and another subject with the same email cannot take over the linked account.
5. With provisioning on (test installation only), a new verified identity gets an account with no membership or administrator rights, and can use it once an administrator adds a membership.
6. No provider token appears in browser storage or URL fragments, and the session cookie is Secure, HttpOnly and SameSite=Lax.
7. A replayed callback URL fails, as does one copied into another browser, and a failed login leaves an existing session intact.
8. A state-changing request from another origin gets 403 and the browser stays signed in; the same edit made in OpenObserve works.
9. After logout the old cookie is refused by the API. It is also refused once the session lifetime passes, and after its link is removed and the server restarted.
10. After Authentik rotates its signing key, login still works; a token signed with an unrelated key is refused.
11. With `ZO_OIDC_ONLY`, native login and Basic auth with a human password fail, except for the emergency root with its correct password. After an emergency browser login over HTTPS, its `auth_tokens` cookie is Secure and HttpOnly (the Compose example sets `ZO_COOKIE_SECURE_ONLY=true`).
12. OTLP ingestion, organization ingestion tokens and service-account API access keep working.
13. After a restart, existing sessions stay valid until they expire, and a sign-in that was in progress has to start again.
14. Login works through the production reverse proxy, including any `ZO_BASE_URI` prefix.
