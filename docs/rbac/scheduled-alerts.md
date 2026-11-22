# Scoped scheduled SQL alerts

With RBAC enabled, a scheduled SQL alert runs with the permissions of the user who last saved it. It never runs as root, as the owner's email, or as whoever ingested the data. Disabled RBAC keeps upstream behaviour. The scheduler's one-region election and shared row locks are unchanged.

## Behaviour

1. **Identity.** Creating or editing an alert records the editor's verified identity, and any ownership field the client sends is ignored. An alert saved before RBAC has no identity and does not run until an authorized editor saves it again. Editing an alert transfers it to the editor's permissions; old permissions do not carry over.
2. **Supported alerts.** Only scheduled SQL alerts with named source streams can be saved and run. Real-time alerts, custom conditions, PromQL, SLO, composite, VRL, multi-period and grouped evaluation, workflows, on-call and recovery notifications are refused.
3. **At each run.** The identity must still exist and belong to the organization. It must still hold Read and Write on the alert and Query on every source stream the SQL names. Searches run on any querier node under that same identity and skip shared result caches.
4. **Delivery.** Every source stream must be approved by an Admin for each destination, and the approval must match the destination's current configuration. This is checked when the alert is saved and again immediately before each notification is sent. A notification already sent cannot be recalled.
5. **API.** Listing and creating alerts, and reading, updating and deleting one alert, check typed alert permissions. Creating requires alert write permission across the organization. Unsupported alert routes stay denied.

## Revocation

Revoking the creator's source access, membership or delivery approval stops the next run from delivering. A run already in progress re-checks before delivery.

## Upgrade and rollback

The upgrade adds one stored field per alert. Rolling back the application leaves it unused. Upgrade every node that executes alerts before enabling RBAC.

## Verification

- Disabled RBAC is unchanged.
- Unsupported alert shapes are refused.
- The recorded identity survives storage.
- Revoking identity, source access or delivery approval stops delivery, as does a change to the destination.
- The identity reaches remote querier nodes.

These are covered by unit tests and by the loopback alert smoke (`scripts/rbac/alert_smoke.py`), which uses a local webhook instead of external delivery.
