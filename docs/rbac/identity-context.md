# Search caller identity

This describes whose permissions a search runs with when RBAC is enabled, and how that identity is kept as the search moves between tasks and nodes.

## Who a search runs as

- **HTTP API requests** run as the authenticated user or service account. A `user_id` header sent by the client never sets it.
- **Node-to-node search requests** run as the identity the sending node verified. Only the cluster's internal credential can send these.
- **Scheduled alerts** run as the user who last saved the alert. A legacy alert saved before RBAC has no identity, so it cannot run until an authorized editor saves it again.

## Behaviour rules

1. **Disabled RBAC changes nothing.** Search behaves exactly as stock OpenObserve and does no extra identity lookups.
2. **No identity, no data.** A search that reaches source authorization without a verified identity is denied. This holds for every search path, including new ones added upstream, so an unhandled path fails closed instead of returning data.
3. **Validation and planning use the caller too.** When an API checks or plans SQL without running it, for example an alert's preview query, the streams it names are authorized against the caller. Before the caller context existed this was refused outright. Saving an unsupported alert shape is still rejected by the alert rules.
4. **Every source is checked.** Each stream that the SQL names is authorized against the caller: joins, subqueries, CTEs and unions included. Downloads also require Export on every source.
5. **The identity follows the work.** Streaming searches, multi-stream searches, streamed trace listings and pattern extraction run parts of the search in background tasks; those tasks keep the caller's identity. Searches spread across querier nodes carry the identity to each node, and each node checks it again.
6. **The identity cannot change mid-request.** Work inside one request cannot switch to another user.
7. **Revocation is immediate.** Permissions are read at each decision, so a revoked grant denies the next search. A search already running is not cancelled.
8. **Query functions and caches.** With RBAC enabled, searches that use a query function (VRL) are refused, and the shared result cache is bypassed.
9. **Scope.** This covers SQL search. PromQL and ingestion have their own checks.

## How it is verified

- Running with RBAC disabled returns the same results as stock OpenObserve.
- A search with no verified identity is denied.
- A viewer reads authorized rows through one-shot, streaming, partitioned and multi-stream search, and authorized traces through both the one-shot and streamed trace listings. Restricted streams are denied, including through joins, CTEs, subqueries and unions.
- A search sent to another querier node returns authorized rows before revocation and is denied afterwards.
- A scheduled alert delivers while its creator holds access, and stops delivering after revocation.
- Revoking a grant denies the next request, streaming searches included.

The commands and fixtures are listed in `operations.md`; recorded results are in `verification.md`.
