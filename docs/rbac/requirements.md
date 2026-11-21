# Task: Add Modular Casbin-RS RBAC to OpenObserve OSS

Repository: https://github.com/openobserve/openobserve

## Objective

Implement production-ready role-based access control (RBAC) for OpenObserve Community Edition using Casbin-RS.

The implementation must be independent of authentication. A separate agent is implementing OIDC, and this feature must work with existing OpenObserve authentication without that work.

**Top priority: Implement secure server-side authorization with minimal upstream modifications and easy future upstream upgrades.**

Implement the solution, not just an architectural proposal.

## 1. Inspect the repository first

Before modifying anything:

- Inspect the current Rust workspace and existing user and organization models.
- Inspect authentication middleware and how authenticated users are propagated.
- Identify the API routing architecture.
- Inventory every sensitive HTTP/gRPC endpoint and internal operation.
- Inspect search/query execution, ingestion, dashboards, alerts, streams, service accounts, exports, and background tasks.
- Identify SQLite and PostgreSQL metadata persistence abstractions.
- Identify existing authorization behavior and potential bypass paths.
- Read AGENTS.md and repository development conventions.
- Record the baseline upstream commit.

Produce a short architecture and endpoint-permission map before implementation, then proceed.

## 2. Architecture requirements

Use the official Rust Casbin implementation:

https://github.com/apache/casbin-rs

Implement RBAC in an isolated module or workspace crate, conceptually:

- `src/extensions/rbac/` — authorization engine
- `model.conf` — Casbin authorization model
- Policy persistence adapter
- Resource/action definitions
- Small adapters to existing API and query layers
- Tests
- Minimal Vue role-management integration

Adjust paths to the actual workspace structure.

Requirements:

- No external authorization server.
- No OpenFGA, Redis, or separate PostgreSQL requirement.
- Work with existing OpenObserve single-node SQLite metadata storage.
- Support PostgreSQL metadata storage when available.
- Avoid adding RBAC logic directly to unrelated business code.
- Do not copy proprietary Enterprise RBAC code.
- Keep existing installation and deployment modes functional.

## 3. Authorization design

Create a centralized authorization API.

Conceptually:

`authorize(principal, organization, action, resource) -> Result<AuthorizationDecision>`

Requirements:

- Authentication-independent.
- Use OpenObserve's existing stable internal user identity.
- Organization-scoped roles.
- Resource-level permission checking.
- Explicit default-deny behavior.
- No unconditional superuser bypass except the documented, tightly controlled root/bootstrap mechanism.
- Centralized, typed actions and resources rather than scattered string comparisons.
- Evaluate policies server-side.
- Fail closed when RBAC is enabled but policies cannot be loaded or evaluated.

Do not use email addresses as permanent authorization identifiers.

## 4. Roles

Provide built-in roles:

**Admin**
- Full organization management.
- User and permission management.
- Read/write access to organization resources.
- Manage streams, dashboards, alerts, and ingestion credentials.

**Editor**
- Read streams and queries where permitted.
- Create and edit dashboards.
- Manage permitted alerts and saved queries.
- No user/role administration.
- No unrestricted deletion of streams.

**Viewer**
- Read authorized logs, metrics, traces, and dashboards.
- No mutations.
- No ingestion access unless separately granted.

**Ingester**
- Ingest telemetry only into explicitly permitted streams.
- Cannot query, export, delete, or administer data.

Support multiple roles per user if the existing data model allows it cleanly.

Design policies to support custom roles later without a major redesign.

## 5. Organization and stream permissions

Implement organization isolation and optional per-stream restrictions.

Example:

- Alice is Viewer in organization A.
- Alice is Editor in organization B.
- Alice may query `api-logs` in A.
- Alice may not query `finance-logs` in A.
- A collector may ingest to `api-logs` but cannot read it.

Permissions must be enforced by the backend.

Organization membership alone must not grant access to all streams when stream-level restrictions are configured.

Use structured resource identities, including organization and stream type where necessary, rather than relying on ambiguous resource names.

## 6. Secure query authorization

This is a high-priority security requirement.

Users must not bypass permissions through SQL, PromQL, alternative query APIs, or query features.

Test and enforce authorization for all relevant query mechanisms, including:

- Ordinary SELECT queries
- JOINs across streams
- Subqueries
- CTEs
- UNIONs
- Aliases
- Wildcards and multi-stream operations
- Metrics and traces queries
- Search APIs
- Query exports and downloads
- Saved queries and background query execution
- Scheduled reports and alerts

Use the existing parser/query-plan abstractions where possible.

Never use regex or simple string matching as the security boundary for SQL.

Prefer authorization before query execution, based on resolved source streams, with additional downstream checks where needed.

If a query feature cannot be authorized reliably, reject it while RBAC is enabled rather than allowing a possible bypass.

## 7. API coverage

Enforce authorization for:

- Organization management
- Users and service accounts
- Streams
- Logs, metrics, and traces
- Ingestion endpoints
- Search endpoints
- Dashboards
- Alerts
- Pipelines
- Reports
- Saved queries
- Resource deletion
- Export and administrative operations
- Relevant gRPC APIs
- Background and scheduled jobs

Identify safe exceptions such as health checks and publicly intended endpoints.

Produce an endpoint inventory showing each operation and its required authorization.

Ensure newly introduced API endpoints cannot silently bypass RBAC.

Where practical, add CI tests or route-coverage checks to detect missing authorization declarations.

For asynchronous jobs, preserve the initiating user's authorization context or use an explicitly scoped service identity. Never silently execute user-created jobs with unlimited administrator access.

## 8. Policy persistence

Use OpenObserve's existing metadata storage abstraction wherever practical.

Requirements:

- SQLite compatibility.
- PostgreSQL compatibility.
- Durable policies.
- Schema migrations with safe rollback/upgrade behavior.
- Policy cache with defined invalidation behavior.
- Immediate or bounded revocation of permissions after role changes.
- Safe concurrent policy changes.
- No application startup with accidentally empty permissive policies.

Casbin must handle authorization decisions; persistence can be adapted to OpenObserve's existing infrastructure rather than requiring a separate SQLx deployment.

## 9. Bootstrap and migration

Existing OpenObserve installations must remain upgradeable.

Implement safe initialization:

- Preserve the existing root administrator.
- Provide a documented initial organization-admin assignment process.
- No automatic privilege elevation for ordinary users.
- No default Viewer role that accidentally grants access to sensitive data.
- Existing data and organization memberships are preserved.
- RBAC can initially be disabled for backward compatibility.

When RBAC is enabled, refuse unsafe or incomplete policy initialization instead of silently granting full access.

Provide an explicit migration and rollback guide.

## 10. Vue frontend

Integrate permissions with the existing UI using minimal changes.

Required features:

- Show current user's organization roles.
- Role assignment interface for authorized administrators.
- Restrict editing controls for Viewers.
- Hide resources users cannot access.
- Display meaningful 403/access-denied messages.
- Support stream permission management where implemented.

UI restrictions are usability features only. All authorization must be enforced by Rust backend checks.

## 11. Authentication independence

Do not implement OIDC, MFA, login, logout, or token validation.

Consume the existing authenticated user identity from OpenObserve.

The RBAC module must work with:

- Existing username/password authentication.
- Existing API/service-account authentication.
- A future external OIDC authentication provider.

Do not depend on Authentik group names or OIDC-specific claims.

If identity-provider group mapping is desired in the future, it should be implemented through a separate adapter.

## 12. Configuration

Follow existing OpenObserve configuration conventions.

Support:

- Enable/disable RBAC.
- Policy storage initialization.
- Policy caching/invalidation settings.
- Safe bootstrap behavior.
- Optional administrative diagnostics.

RBAC should be opt-in initially to preserve existing deployment behavior.

When enabled, never fall back to unrestricted access on errors.

## 13. Security tests

Provide automated positive and negative tests for:

- Cross-organization access.
- Cross-stream access.
- Viewer mutation attempts.
- Unauthorized ingestion.
- Ingester query attempts.
- Role escalation.
- Unauthorized role assignment.
- Direct API bypass attempts.
- Unauthorized gRPC operations.
- SQL JOIN/CTE/subquery/UNION access bypasses.
- Query/export permission bypasses.
- Background job authorization.
- Service account permissions.
- Root/bootstrap behavior.
- Stale cache after permission revocation.
- Concurrent policy updates.
- Invalid or missing policies.
- RBAC-disabled backward compatibility.

Test every relevant action through real API boundaries, not just unit tests of Casbin's `enforce()` function.

## 14. Upstream compatibility

This requirement is critical.

- Use an isolated `feature/rbac` branch.
- Keep authorization code primarily in a dedicated extension crate/module.
- Prefer narrow hooks and adapters to large changes in upstream handlers.
- Avoid changing public API contracts unnecessarily.
- Do not refactor existing authentication.
- Do not modify OIDC-specific code.
- Do not overwrite or depend on Enterprise implementation.
- Keep schema changes additive wherever possible.
- Document all modified upstream integration points.
- Add regression tests that can run after each upstream rebase.
- Preserve AGPL-3.0 notices and obligations.

If upstream architecture makes a shared central hook impossible, implement the smallest viable set of adapters and document every necessary integration point.

## 15. Deliverables

Produce:

1. Working Casbin-RS authorization implementation.
2. RBAC policy model and persistence.
3. Backend permission enforcement.
4. Stream/organization isolation.
5. Minimal Vue permissions UI.
6. Safe database migrations.
7. Detailed endpoint authorization matrix.
8. Automated authorization and security tests.
9. Configuration and deployment documentation.
10. Upstream upgrade and maintenance guide.
11. Summary of all modified upstream files.

Run the relevant Rust/Vue formatting, linting, build, and tests. Report checks that could not be completed.

## Acceptance criteria

- Admin, Editor, Viewer, and Ingester roles work.
- Users cannot access unauthorized organizations or streams.
- API, SQL/query, ingestion, and background operation bypasses are prevented.
- RBAC works with existing authentication, independently of OIDC.
- No additional authorization server is required.
- Existing OpenObserve single-node deployment remains supported.
- Changes are modular and minimize upstream merge conflicts.
- The result is production-oriented, not a superficial UI-only permission system.

Focus on secure authorization coverage, maintainability, and upstream compatibility.
