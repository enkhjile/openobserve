# Security notes

Scope: authorization decisions inside OpenObserve once a request is authenticated. Authentication itself (passwords, tokens, OIDC) is out of scope. The operator controls the root credential, the cluster's internal token, the metadata database and the server configuration; a compromise of any of these is out of scope.

| Boundary | Protection |
| --- | --- |
| Identity | Grants name stable user IDs or ingestion-token rows, never emails or caller-supplied headers. An organization ingestion token acts only as its own row, whatever username it is sent with. A member removed from the organization loses all grants at once. |
| Policy | Each organization's policy is a versioned document in the primary metadata database. Updates are compare-and-swap, so a concurrent or stale edit is refused. A missing, malformed or unreadable policy denies. Root has no bypass after bootstrap. Role changes are themselves authorized, so a caller cannot grant itself more. |
| HTTP routes | Every route has a declared permission; undeclared routes, including ones added upstream, are refused. Org ingestion tokens are accepted only on supported ingestion routes. |
| Search | SQL is parsed and every stream it names is authorized before schemas or storage are read; table functions, unresolved sources and query functions are refused, and shared result caches are bypassed. A search with no verified caller is denied. The caller is carried into background tasks and to other querier nodes, which check it again. |
| Ingestion | Every destination and pipeline output is authorized before the first write; a single denial writes nothing. Server-side background writers, which no request can claim to be, write without grants, and pipelines do not run on their writes. |
| Cluster RPCs | The internal token proves the caller is a node, not that a request is allowed. While RBAC is on, a gate refuses every RPC outside a short allowlist of RPCs that check their own caller, so new upstream RPCs are refused by default. OTLP log export over gRPC refuses the internal token and accepts only the caller's own credential. |
| Scheduled work | Alerts, reports and pipelines run as the identity recorded when they were last saved, never as root or as whoever enables or triggers them, and re-check source access, membership and delivery approvals before acting. Delivery approvals bind each destination's exact configuration and template. Client-supplied owner or execution fields are ignored. |
| Report rendering | Reports render in a fresh browser profile with sandbox and TLS checks on. Network access is limited to the report's own dashboard and query requests, and the script worker cannot make network requests. Any denied or unexpected request aborts the report before email. |
| Accounts | While RBAC is on, organization administration cannot reset another identity's global password and logins do not create organizations. |
| UI | The UI hides controls a user cannot use. The server stays authoritative. |

## Limits

- Most specialist APIs are refused rather than scoped; see [endpoints.md](endpoints.md) and [rpc.md](rpc.md).
- Revocation applies to the next decision. A request or report already in progress is not cancelled, and an email already sent cannot be recalled.
- Disabling RBAC removes every restriction at once. It is an operator decision, not a fallback.
- Mixed-version clusters are unsupported. A node without RBAC would not enforce it.
- Treat the internal cluster token, the root credential and the metadata database as credentials.
