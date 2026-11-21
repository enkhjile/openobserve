# OSS gRPC authorization matrix

Node services accept only the configured cluster transport credential. That credential identifies trusted infrastructure and can carry a delegated subject. It must be protected as a cluster secret. Public OTLP and Streams use separate interceptors. The classifications below cover the default OSS build in `src/api/grpc/src/server.rs`.

| Service | Methods | Enabled behavior |
| --- | --- | --- |
| Search | Search | Resolve SQL sources and check the delegated subject or user on every source. |
| Search | SearchMulti, SearchPartition | The RPC handlers have no delegated identity. Downstream source checks deny data access. |
| Search | GetTable, GetSourcemapFile | Deny stored file retrieval before reading storage. |
| Search | GetResult, DeleteResult, QueryStatus, CancelQuery, ClusterCancelQuery | OSS handlers return unimplemented. |
| Search | TryAcquire, StartQuery, ReleaseQuery, GetWorkflowInputs | OSS handlers return unimplemented. |
| Search | GetLicenseUsageInfo | Node-only OSS license status, with no tenant records. |
| Metrics | Query | Require the delegated identity and authorize explicitly named metric sources. |
| Metrics | Data, WalMinTs | Deny the unscoped storage query. |
| Event | SendFileList | Node-only cache maintenance. Enabled nodes fetch from configured storage instead of requesting arbitrary peer files. |
| Event | GetFiles | Deny unscoped file downloads. |
| QueryCache | DeleteResultCache, PublicDashboardStatus | Deny calls without scoped cache ownership. |
| ClusterInfoService | GetClusterInfo | Node-only aggregate compaction status. |
| ClusterInfoService | GetDeleteJobStatus | Deny per-job access without organization and subject. |
| NodeService | GetNodes | Cluster membership discovery restricted to node credentials. |
| Ingest | Ingest | Deny unscoped internal ingestion. |
| Streams | stream_stats | Deny until stream statistics can be scoped. |
| OTLP Logs, Metrics, Trace, Profiles | Export | Deny at the ingest or router interceptor. |
| Arrow Flight | DoGet | Node-only transport. Stream scans use the identity propagated with the plan. |
| Arrow Flight | Handshake, ListFlights, GetFlightInfo, PollFlightInfo, GetSchema, DoPut, DoAction, ListActions, DoExchange | Unimplemented. |

On rebase, compare service registrations, interceptors, every cluster protocol declaration and the actual downstream method before carrying a classification forward. Automated live checks exercise selected methods. This matrix describes implementation coverage independently of transport test coverage.
