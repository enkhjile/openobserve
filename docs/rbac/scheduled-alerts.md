# Scoped scheduled SQL alerts

This slice adds scheduled SQL alerts to the existing RBAC boundary. It preserves disabled behavior and the elected-region, multi-scheduler row-lock model. The alternative of running as root, an owner email, or ingestion caller is rejected because it changes authority when users change or rows arrive.

1. Persist a nullable execution subject UUID on the alert. HTTP create/update overwrites it from the verified caller; client-supplied ownership fields confer no authority. Legacy NULL rows cannot execute until an authorized edit.
2. Permit only scheduled SQL queries with named sources. Real-time, custom conditions, PromQL, SLO, composites, VRL, multi-period/group evaluation, workflows, on-call and recovery delivery remain denied.
3. At execution, verify primary identity and org membership, current Alert Read/Write permission, and Query permission on every SQL source. Carry the UUID in a distinct trusted internal RPC field, never an email/header substitution; bypass shared caches.
4. Destinations require separate Admin-managed approvals for every exact source and the current primary destination configuration. Validate before saving and again immediately before delivery. Dispatch the primary object actually authorized.
5. Keep unsupported routes denied. Expose collection create/list and individual get/update/delete with typed Alert permissions. Collection writes require wildcard Alert permission. No implicit legacy execution migration.
6. Preserve missing-context denial tests. Add shape rejection, persistence roundtrip, identity revocation, source revocation, destination drift and RPC propagation coverage, plus disposable local runtime evidence without external notification delivery.

The additive text column uses SQLite/PostgreSQL migration and schema-version registration. Rolling back the application leaves the column inert; all executing nodes must be upgraded before enabling RBAC. In-flight work rechecks authorization before delivery. Editing an alert rebinds its execution identity to the editor; it does not transfer old privileges.
