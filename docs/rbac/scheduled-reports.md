# Scoped visual scheduled reports

With RBAC enabled, the standalone report server refuses all requests. The built-in browser renderer runs a report only when four things are pinned: the verified author recorded when the report was saved, a configured non-root renderer account that belongs to exactly one organization, one exact dashboard tab, and named approved email destinations.

The renderer's complete grant set must be Viewer on that dashboard plus Exporter on explicit named streams. No other dashboards, wildcard resources, organization roles or other privileges are accepted. Every stream must also have the author's current Query and Export rights and an approval binding the recipient destination's current primary configuration. Configuration does not grant permissions automatically.

The initial supported shape is a v8 dashboard with ordinary SQL charts/tables. HTML, Markdown, custom chart scripts, VRL, UDFs, annotation sources, dashboard variables, external assets/links, user-defined workers/frames and arbitrary API origins are unsupported. A fresh browser profile uses network interception before navigation, an exact same-origin route allowlist and restrictive document policy. Any denied/failed query, partial rendering, unrecognized data request, revision change or recipient drift aborts before email.

Reports saved before RBAC have no recorded author and stay denied until an authorized editor saves them again. The current report, dashboard and policy are checked before rendering and again before sending. Recipients come only from approved email destinations, and any raw recipient list must match them exactly. Disabled RBAC keeps upstream behaviour.

Deployment limitation: one configured renderer identity serves only reports compatible with its entire finite scope. Reports requiring different dashboards or source sets need separately configured renderer deployments/accounts; the application will not widen an account's grants to make a report run. The disposable report fixture verified that the rendered PDF includes the authorized row and that the scheduler stops delivering it after Export is revoked.

Configure `ZO_REPORT_SERVER_URL=` explicitly for embedded rendering (the upstream default selects a standalone server), `ZO_CHROME_ENABLED=true`, a local `ZO_CHROME_PATH`, and dedicated `ZO_REPORT_USER_NAME`/`ZO_REPORT_USER_PASSWORD`. Configure SMTP separately. The destination API uses `emails` for approved recipient addresses; each recipient must be an existing organization member. Report requests name approved destinations in `deliveryDestinations`; a `destinations` email list is still accepted but must match them exactly. Any execution identity the client sends is ignored.

Run the isolated verification with `python3 scripts/rbac/report_smoke.py --binary "$PWD/target/debug/openobserve" --acknowledge-disposable-fixture`. It starts only disposable localhost services and a local SMTP sink. A passing run must demonstrate a complete PDF plus permission-revocation denial; fixture setup alone is not proof of rendering support.

The scoped local mode supports standard PDF attachments only; PNG/CSV, inline attachment and image-preview options are refused. The delivered PDF test requires `pdftotext` and checks for the authorized fixture row, in addition to validating its MIME type and PDF signature.

Maintenance constraint: the bundled browser-protocol decoder is patched to handle fractional Chrome timestamps under OpenObserve's arbitrary-precision JSON setting. Do not disable arbitrary-precision JSON to work around browser issues.

Scoped Chrome keeps its native sandbox and TLS certificate verification enabled; deployments must provide a compatible Chrome executable and operating-system user. The unsafe Chrome sandbox/TLS bypass options from legacy report mode are not used for scoped reports. Two known missing application-branding SVG requests receive an inert local SVG during scoped rendering; optional shell settings/folder requests receive a fixed denial. These exceptions never apply to dashboard definitions, schemas or query responses.

The only script worker allowed is the dashboard's own streaming parser, and it cannot make network requests; if it cannot be identified unambiguously, rendering is refused. The page shown after sign-in is blank, so no unrelated data loads before the selected dashboard.

The isolated SQLite/Chrome/loopback-SMTP smoke passed on 2026-11-21: named report visibility, excessive renderer-scope denial, server-bound identity despite forged client context, exact approved recipients, a PDF containing the authorized row, scheduled delivery, and no delivery after revoking Export and observing a newer completed scheduler claim. This does not validate an external SMTP provider or enterprise-only reporting paths.
