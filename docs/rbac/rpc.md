# OSS gRPC authorization matrix

Node services accept only the configured cluster transport credential. That credential identifies trusted infrastructure and can carry a delegated subject. It must be protected as a cluster secret. Public OTLP and Streams services authenticate callers separately. The classifications below cover the services the default OSS build registers.

While RBAC is enabled, a gate in front of both gRPC servers refuses every RPC except Search, GetLicenseUsageInfo, Metrics Query, Event SendFileList, GetClusterInfo, GetNodes, OTLP Logs Export and Flight DoGet (`src/infra/src/rbac/grpc.rs`). Any other RPC, including one added upstream later, is refused before its handler runs.

| Service | Methods | Enabled behavior |
| --- | --- | --- |
| Search | Search | Resolve SQL sources and check the delegated subject or user on every source. |
| Search | SearchMulti, SearchPartition | Refused by the gate; the handlers carry no delegated identity. |
| Search | GetTable, GetSourcemapFile | Refused by the gate before reading storage. |
| Search | GetResult, DeleteResult, QueryStatus, CancelQuery, ClusterCancelQuery | Refused by the gate; OSS handlers are unimplemented. |
| Search | TryAcquire, StartQuery, ReleaseQuery, GetWorkflowInputs | Refused by the gate; OSS handlers are unimplemented. |
| Search | GetLicenseUsageInfo | Node-only OSS license status, with no tenant records. |
| Metrics | Query | Require the delegated identity and authorize explicitly named metric sources. |
| Metrics | Data, WalMinTs | Refused by the gate. |
| Event | SendFileList | Node-only cache maintenance. Enabled nodes fetch from configured storage instead of requesting arbitrary peer files. |
| Event | GetFiles | Refused by the gate. |
| QueryCache | DeleteResultCache, PublicDashboardStatus | Refused by the gate. |
| ClusterInfoService | GetClusterInfo | Node-only aggregate compaction status. |
| ClusterInfoService | GetDeleteJobStatus | Refused by the gate. |
| NodeService | GetNodes | Cluster membership discovery restricted to node credentials. |
| Ingest | Ingest | Refused by the gate. |
| Streams | stream_stats | Refused by the gate. |
| OTLP Logs | Export | Requires the caller's own user or org ingestion token credential; the internal token is refused. Ingest on the destination and every scoped pipeline output is checked before the first write. |
| OTLP Metrics, Trace, Profiles | Export | Refused by the gate. |
| Arrow Flight | DoGet | Node-only transport. Stream scans use the identity propagated with the plan. |
| Arrow Flight | Handshake, ListFlights, GetFlightInfo, PollFlightInfo, GetSchema, DoPut, DoAction, ListActions, DoExchange | Refused by the gate; unimplemented. |

The router's OTLP Logs proxy forwards the caller's credential unchanged while RBAC is enabled. The ingester authenticates it again and re-reads org ingestion tokens from the primary store. A forwarded internal token cannot carry a scoped identity.

On rebase, compare service registrations, interceptors, every cluster protocol declaration and the actual downstream method before carrying a classification forward. Automated live checks exercise selected methods. This matrix describes implementation coverage independently of transport test coverage.
