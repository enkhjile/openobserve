# Authentik integration and manual acceptance test

This extension uses standard OIDC; it does not implement Google sign-in or MFA itself.

## Provider setup

Create an Authentik OAuth2/OpenID provider and associate it with an application. Use a confidential client, an asymmetric signing key (for example RSA/RS256), authorization-code flow, and an exact redirect URI matching `ZO_OIDC_REDIRECT_URI`. Configure the `openid`, `profile`, and `email` scope mappings and include their claims in ID tokens. Copy the issuer from discovery rather than guessing it; Authentik exposes discovery under `/application/o/<application_slug>/.well-known/openid-configuration`. Record the client ID and secret securely. Do not select implicit flow or request offline access for this extension. See the official [OAuth2 provider documentation](https://docs.goauthentik.io/add-secure-apps/providers/oauth2/) and [scope mapping documentation](https://docs.goauthentik.io/add-secure-apps/providers/property-mappings/).

Configure Google federation and MFA in the provider's authentication flow if desired. OpenObserve receives only the resulting standard OIDC response. Restrict access to the Authentik application to the intended users.

## OpenObserve setup

Use the configuration reference in [README.md](README.md). Keep provisioning disabled initially. Select a dedicated existing local test user with known organization memberships. On this OSS baseline the native user-creation API assigns the organization administrator role. Explicitly approve the test user’s exact issuer and subject using the operator-managed account mapping. Obtain the subject from the provider's administrative tools; do not use an email address as the subject unless the provider actually defines it that way. Preserve existing memberships.

Use HTTPS with an exact public callback URL. Match any OpenObserve API base path. Synchronize server clocks. Ensure the OpenObserve process can reach discovery, JWKS and token endpoints over trusted TLS. Keep callback query strings out of reverse-proxy access logs.

## Manual test record

Record the application commit, provider version, issuer, signing algorithm, date, tester, and each result. Never attach tokens, secrets, cookie values or authorization codes to the record.

1. Start with a clean browser profile. Verify that disabled OIDC preserves local login.
2. Enable OIDC with default-deny provisioning. Verify that Sign in with SSO redirects to the configured provider and returns through the configured callback.
3. Complete Google federation, if configured, and the provider's MFA challenge. Verify that the approved account sees its existing organizations and data.
4. Verify that a user without a mapping is denied, even when its email matches an existing administrator. Verify that a different subject with the same email cannot take over an approved account.
5. Enable provisioning in a test installation. Verify that a fresh verified identity creates no administrator privilege or implicit membership. Assign membership through the existing administration mechanism and retry.
6. Inspect browser storage: provider tokens must not appear in localStorage or URL fragments. Inspect the session cookie's Secure, HttpOnly and SameSite attributes.
7. Try a callback copied into another browser and replay the original callback. Both must fail. A failed login must not replace the existing account session.
8. Submit an unsafe authenticated request from another origin. Verify rejection. Verify that a normal same-origin edit still works.
9. Log out, then reuse the old cookie in a direct API request. Verify rejection. Also verify rejection after the configured session lifetime and after approval is removed.
10. Rotate the provider signing key. Verify that a subsequent login succeeds with the new key; verify that an unrelated signing key does not.
11. Enable OIDC-only mode. Try native login and direct Basic human-password access. Both must fail except for the explicitly configured emergency root account. Verify the emergency password must still be correct.
12. Exercise existing OTLP ingestion, organization ingestion tokens, and service-account API access with their normal credentials.
13. Restart OpenObserve and check persisted sessions and identity mappings according to the documented expiry policy. An unfinished login may need to restart because its transaction is process-local.
14. Verify callback handling behind the intended reverse proxy and under any configured base path.

Live Authentik acceptance is separate from the automated mock-provider suite. An unexecuted item is not a pass.
