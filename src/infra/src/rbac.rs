// Copyright 2026 OpenObserve Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

mod cache;
mod destinations;
mod pipelines;
mod tokens;
use anyhow::{Context, Result, ensure};
pub use destinations::{
    DestinationApprovalRequest, authorize_alert_destinations, authorized_alert_destination,
    authorized_alert_destination_with_template, available_alert_destinations,
    replace_destination_approvals, validate_report_renderer,
};
use openobserve_rbac::Engine;
pub use openobserve_rbac::{
    Action, DestinationApproval, Grant, PolicyDocument, Resource, ResourceKind, Role,
};
pub use pipelines::authorize_pipeline_permissions;
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, FromQueryResult, QueryFilter, Statement};
pub use tokens::{allowed_ingestion_token_resources, ingestion_token_subjects};

use crate::{
    db,
    table::{
        entity::{organizations, users},
        users::get_id_by_email_with,
    },
};

pub fn enabled() -> bool {
    config::get_config().common.rbac_enabled
}

pub async fn user_subject(email: &str) -> Result<String> {
    get_id_by_email_with(db::get_orm_client_rw().await, email)
        .await?
        .context("RBAC identity does not exist")
}

pub async fn validate_subject(subject: &str, organization: &str) -> Result<()> {
    validate_subject_on(db::get_orm_client_rw().await, subject, organization).await
}

pub async fn member_subjects(org: &str) -> Result<Vec<(String, String)>> {
    let db = db::get_orm_client_rw().await;
    let members = db
        .query_all(Statement::from_sql_and_values(
            db.get_database_backend(),
            "SELECT u.id, u.email FROM users u JOIN org_users ou ON ou.email = u.email
         WHERE ou.org_id = $1 ORDER BY u.email",
            [org.into()],
        ))
        .await?;
    members
        .into_iter()
        .map(|row| Ok((row.try_get("", "id")?, row.try_get("", "email")?)))
        .collect()
}

pub async fn visible_organizations(email: &str) -> Result<Vec<organizations::Model>> {
    let db = db::get_orm_client_rw().await;
    let subject = get_id_by_email_with(db, email)
        .await?
        .context("unknown identity")?;
    visible_organizations_on(db, &subject).await
}

pub async fn authorize_user(
    email: &str,
    organization: &str,
    action: Action,
    resource: Resource,
) -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let subject = user_subject(email).await?;
    authorize_subject(&subject, organization, action, resource).await
}

pub async fn authorize_subject(
    subject: &str,
    organization: &str,
    action: Action,
    resource: Resource,
) -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    validate_subject(subject, organization).await?;
    let document = read_policy(organization).await?;
    ensure!(
        cache::engine(&document)
            .await?
            .authorize(subject, organization, action, &resource)?,
        "RBAC access denied"
    );
    Ok(())
}

/// A wildcard grant leaves the list unrestricted. Named grants must enter paginated queries by ID.
pub async fn readable_object_ids(
    email: &str,
    organization: &str,
    kind: ResourceKind,
) -> Result<Option<std::collections::BTreeSet<String>>> {
    if !enabled() {
        return Ok(None);
    }
    let subject = user_subject(email).await?;
    validate_subject(&subject, organization).await?;
    let document = read_policy(organization).await?;
    let engine = cache::engine(&document).await?;
    if engine.authorize(
        &subject,
        organization,
        Action::Read,
        &Resource::new(kind, "*"),
    )? {
        return Ok(None);
    }
    let mut ids = std::collections::BTreeSet::new();
    for resource in document
        .grants
        .iter()
        .filter(|grant| grant.subject == subject)
        .flat_map(|grant| &grant.resources)
        .filter(|resource| resource.kind == kind)
    {
        if engine.authorize(&subject, organization, Action::Read, resource)? {
            ids.insert(resource.name.clone());
        }
    }
    Ok(Some(ids))
}

pub async fn allowed_resources(
    email: &str,
    organization: &str,
    action: Action,
    resources: &[Resource],
) -> Result<Vec<bool>> {
    allowed_resource_actions(email, organization, &[action], resources).await
}

pub async fn allowed_resource_actions(
    email: &str,
    organization: &str,
    actions: &[Action],
    resources: &[Resource],
) -> Result<Vec<bool>> {
    if !enabled() {
        return Ok(vec![true; resources.len()]);
    }
    let subject = user_subject(email).await?;
    allowed_subject_resource_actions(&subject, organization, actions, resources).await
}

pub async fn allowed_subject_resource_actions(
    subject: &str,
    organization: &str,
    actions: &[Action],
    resources: &[Resource],
) -> Result<Vec<bool>> {
    if !enabled() {
        return Ok(vec![true; resources.len()]);
    }
    allowed_subject_resource_actions_on(
        db::get_orm_client_rw().await,
        subject,
        organization,
        actions,
        resources,
    )
    .await
}

pub async fn allowed_subject_resources(
    subject: &str,
    organization: &str,
    action: Action,
    resources: &[Resource],
) -> Result<Vec<bool>> {
    allowed_subject_resource_actions(subject, organization, &[action], resources).await
}

pub async fn read_policy(organization: &str) -> Result<PolicyDocument> {
    read_policy_on(db::get_orm_client_rw().await, organization).await
}

/// Concurrent revocation invalidates the write's authorization snapshot. [strong]
pub async fn replace_policy(
    email: &str,
    organization: &str,
    expected_version: u64,
    grants: Vec<Grant>,
) -> Result<PolicyDocument> {
    ensure!(enabled(), "RBAC is disabled");
    replace_policy_on(
        db::get_orm_client_rw().await,
        email,
        organization,
        expected_version,
        grants,
    )
    .await
}

/// Only a persisted root can initialize an existing organization once. [strong]
pub async fn bootstrap(email: &str, organization: &str) -> Result<PolicyDocument> {
    ensure!(enabled(), "RBAC is disabled");
    bootstrap_on(db::get_orm_client_rw().await, email, organization).await
}

async fn visible_organizations_on<C: ConnectionTrait>(
    db: &C,
    subject: &str,
) -> Result<Vec<organizations::Model>> {
    let rows = db.query_all(Statement::from_sql_and_values(db.get_database_backend(),
        "SELECT o.*, m.value AS policy FROM organizations o
         JOIN meta m ON m.module = 'rbac' AND m.key1 = o.identifier AND m.key2 = 'policy' AND m.start_dt = 0
         JOIN users u ON u.id = $1
         WHERE o.deleted_at IS NULL AND (u.is_root = true OR EXISTS (
            SELECT 1 FROM org_users ou WHERE ou.email = u.email AND ou.org_id = o.identifier))
         ORDER BY o.org_name, o.identifier", [subject.into()])).await?;
    let mut visible = Vec::new();
    for row in rows {
        let organization = organizations::Model::from_query_result(&row, "")?;
        let raw: String = row.try_get("", "policy")?;
        if let Ok(policy) = decode_policy(raw.as_bytes(), &organization.identifier)
            && policy.grants.iter().any(|grant| grant.subject == subject)
        {
            visible.push(organization);
        }
    }
    Ok(visible)
}

async fn validate_subject_on<C: ConnectionTrait>(
    client: &C,
    subject: &str,
    organization: &str,
) -> Result<()> {
    if let Some(id) = openobserve_rbac::token_subject_id(subject)? {
        return tokens::validate_token_on(client, id, organization).await;
    }
    // Root bootstrap may precede org membership; it still needs explicit policy grants.
    let row = client.query_one(Statement::from_sql_and_values(
        client.get_database_backend(),
        "SELECT users.id FROM users WHERE users.id = $1 AND (users.is_root = true OR EXISTS (SELECT 1 FROM org_users WHERE org_users.email = users.email AND org_users.org_id = $2))",
        [subject.into(), organization.into()],
    )).await?;
    ensure!(row.is_some(), "RBAC organization membership denied");
    Ok(())
}

async fn allowed_subject_resource_actions_on<C: ConnectionTrait>(
    client: &C,
    subject: &str,
    organization: &str,
    actions: &[Action],
    resources: &[Resource],
) -> Result<Vec<bool>> {
    validate_subject_on(client, subject, organization).await?;
    let document = read_policy_on(client, organization).await?;
    let engine = cache::engine(&document).await?;
    resources
        .iter()
        .map(|resource| {
            for action in actions {
                if !engine.authorize(subject, organization, *action, resource)? {
                    return Ok(false);
                }
            }
            Ok(true)
        })
        .collect()
}

async fn read_policy_on<C: ConnectionTrait>(
    client: &C,
    organization: &str,
) -> Result<PolicyDocument> {
    validate_organization(organization)?;
    let row = client
        .query_one(Statement::from_sql_and_values(
            client.get_database_backend(),
            "SELECT value FROM meta WHERE module = $1 AND key1 = $2 AND key2 = $3 AND start_dt = 0",
            ["rbac".into(), organization.into(), "policy".into()],
        ))
        .await?
        .context("RBAC policy has not been initialized")?;
    let value: String = row.try_get("", "value")?;
    decode_policy(value.as_bytes(), organization)
}

async fn replace_policy_on<C: ConnectionTrait>(
    client: &C,
    email: &str,
    organization: &str,
    expected_version: u64,
    grants: Vec<Grant>,
) -> Result<PolicyDocument> {
    let subject = get_id_by_email_with(client, email)
        .await?
        .context("unknown identity")?;
    validate_subject_on(client, &subject, organization).await?;
    let current = read_policy_on(client, organization).await?;
    ensure!(
        current.version == expected_version,
        "RBAC policy version conflict"
    );
    ensure!(
        Engine::new(&current).await?.authorize(
            &subject,
            organization,
            Action::Manage,
            &Resource::organization()
        )?,
        "RBAC policy administration denied"
    );
    let document = PolicyDocument {
        destination_approvals: current.destination_approvals.clone(),
        schema_version: 1,
        version: expected_version
            .checked_add(1)
            .context("RBAC version overflow")?,
        organization: organization.into(),
        grants,
    };
    Engine::new(&document).await?;
    for grant in &document.grants {
        validate_subject_on(client, &grant.subject, organization).await?;
    }

    ensure!(
        document.grants.iter().any(|grant| grant.role == Role::Admin
            && grant.resources.contains(&Resource::organization())),
        "policy requires an organization administrator"
    );
    write_policy_on(client, &document, Some(current)).await?;
    Ok(document)
}

async fn bootstrap_on<C: ConnectionTrait>(
    client: &C,
    email: &str,
    organization: &str,
) -> Result<PolicyDocument> {
    validate_organization(organization)?;
    let subject = get_id_by_email_with(client, email)
        .await?
        .context("unknown identity")?;
    let user = users::Entity::find_by_id(subject.clone())
        .one(client)
        .await?
        .context("unknown root")?;
    ensure!(user.is_root, "RBAC bootstrap requires root");
    ensure!(
        organizations::Entity::find()
            .filter(organizations::Column::Identifier.eq(organization))
            .one(client)
            .await?
            .is_some(),
        "unknown organization"
    );
    let document = PolicyDocument {
        destination_approvals: vec![],
        schema_version: 1,
        version: 1,
        organization: organization.into(),
        grants: vec![Grant {
            subject,
            role: Role::Admin,
            resources: vec![Resource::organization()],
        }],
    };
    Engine::new(&document).await?;
    write_policy_on(client, &document, None).await?;
    Ok(document)
}

fn validate_organization(organization: &str) -> Result<()> {
    ensure!(
        !organization.is_empty() && !organization.contains(['/', '*', '\0']),
        "invalid organization"
    );
    Ok(())
}

fn decode_policy(bytes: &[u8], organization: &str) -> Result<PolicyDocument> {
    let document: PolicyDocument = serde_json::from_slice(bytes)?;
    document.validate()?;
    ensure!(
        document.organization == organization,
        "RBAC policy organization mismatch"
    );
    Ok(document)
}

async fn write_policy_on<C: ConnectionTrait>(
    client: &C,
    document: &PolicyDocument,
    previous: Option<PolicyDocument>,
) -> Result<()> {
    let value = serde_json::to_string(document)?;
    let result = if let Some(previous) = previous {
        client.execute(Statement::from_sql_and_values(client.get_database_backend(),
            "UPDATE meta SET value = $1 WHERE module = 'rbac' AND key1 = $2 AND key2 = 'policy' AND start_dt = 0 AND value = $3",
            [value.into(),document.organization.clone().into(),serde_json::to_string(&previous)?.into()])).await?
    } else {
        client.execute(Statement::from_sql_and_values(client.get_database_backend(),
            "INSERT INTO meta (module,key1,key2,start_dt,value) VALUES ('rbac',$1,'policy',0,$2) ON CONFLICT (module,key1,key2,start_dt) DO NOTHING",
            [document.organization.clone().into(),value.into()])).await?
    };
    ensure!(result.rows_affected() == 1, "RBAC policy version conflict");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        net::IpAddr,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    use sea_orm::{ConnectOptions, Database, DatabaseBackend, DatabaseConnection, Schema};

    use super::*;

    static SCHEMA_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    async fn database() -> DatabaseConnection {
        let client = match std::env::var("O2_RBAC_TEST_POSTGRES_URL") {
            Ok(url) => postgres_fixture(url).await,
            Err(std::env::VarError::NotPresent) => {
                let mut options = ConnectOptions::new("sqlite::memory:");
                options.max_connections(1);
                Database::connect(options).await.unwrap()
            }
            Err(std::env::VarError::NotUnicode(_)) => panic!("test database URL must be UTF-8"),
        };
        let backend = client.get_database_backend();
        let schema = Schema::new(backend);
        for statement in [
            schema.create_table_from_entity(users::Entity),
            schema.create_table_from_entity(organizations::Entity),
        ] {
            client.execute(backend.build(&statement)).await.unwrap();
        }
        let identity = if backend == DatabaseBackend::Sqlite {
            "INTEGER PRIMARY KEY AUTOINCREMENT"
        } else {
            assert_eq!(backend, DatabaseBackend::Postgres);
            "BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY"
        };
        client.execute_unprepared(&format!("CREATE TABLE meta (id {identity},module TEXT NOT NULL,key1 TEXT NOT NULL,key2 TEXT NOT NULL,start_dt BIGINT NOT NULL,value TEXT NOT NULL,UNIQUE(module,key1,key2,start_dt))")).await.unwrap();
        client.execute_unprepared("INSERT INTO organizations(identifier,org_name,org_type,status,created_at,updated_at) VALUES ('org','Org',0,'active',0,0)").await.unwrap();
        for (id, email, root) in [
            ("root-id", "root@example.test", true),
            ("viewer-id", "viewer@example.test", false),
        ] {
            client.execute(Statement::from_sql_and_values(backend,
                "INSERT INTO users(id,email,first_name,last_name,password,salt,is_root,user_type,created_at,updated_at,must_reset_password) VALUES($1,$2,'','','','',$3,0,0,0,false)",
                [id.into(),email.into(),root.into()])).await.unwrap();
        }
        client
            .execute_unprepared("CREATE TABLE org_users(email TEXT, org_id TEXT)")
            .await
            .unwrap();
        client
            .execute_unprepared("INSERT INTO org_users VALUES ('viewer@example.test', 'org')")
            .await
            .unwrap();
        client
    }

    async fn postgres_fixture(value: String) -> DatabaseConnection {
        assert_eq!(
            std::env::var("O2_RBAC_TEST_DISPOSABLE").as_deref(),
            Ok("1"),
            "PostgreSQL tests require explicit disposable-fixture acknowledgement"
        );
        let parsed = url::Url::parse(&value).expect("invalid disposable PostgreSQL URL");
        let host = parsed.host_str().unwrap_or("").trim_matches(['[', ']']);
        assert!(
            matches!(parsed.scheme(), "postgres" | "postgresql")
                && host
                    .parse::<IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
                && parsed.port().is_some()
                && parsed.query().is_none()
                && parsed.fragment().is_none(),
            "PostgreSQL test URL must use an explicit numeric loopback host and port without query parameters"
        );
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let sequence = SCHEMA_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let name = format!("rbac_test_{}_{nonce}_{sequence}", std::process::id());
        let mut options = ConnectOptions::new(value);
        options.max_connections(4).sqlx_logging(false);
        let setup = Database::connect(options.clone())
            .await
            .expect("could not connect to disposable PostgreSQL fixture");
        setup
            .execute_unprepared(&format!("CREATE SCHEMA {name}"))
            .await
            .expect("could not create isolated RBAC test schema");
        setup.close().await.unwrap();
        options.set_schema_search_path(name);
        Database::connect(options)
            .await
            .expect("could not connect to isolated RBAC test schema")
    }

    #[tokio::test]
    async fn organization_switcher_requires_a_grant_even_for_root() {
        let db = database().await;
        assert!(
            visible_organizations_on(&db, "root-id")
                .await
                .unwrap()
                .is_empty()
        );
        bootstrap_on(&db, "root@example.test", "org").await.unwrap();
        let visible = visible_organizations_on(&db, "root-id").await.unwrap();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].identifier, "org");
        assert!(
            visible_organizations_on(&db, "viewer-id")
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn policy_bootstrap_requires_root_and_is_single_use() {
        let db = database().await;
        assert!(
            bootstrap_on(&db, "viewer@example.test", "org")
                .await
                .is_err()
        );
        assert!(read_policy_on(&db, "org").await.is_err());
        assert!(
            bootstrap_on(&db, "root@example.test", "missing")
                .await
                .is_err()
        );
        let policy = bootstrap_on(&db, "root@example.test", "org").await.unwrap();
        assert_eq!(policy.grants[0].subject, "root-id");
        assert!(bootstrap_on(&db, "root@example.test", "org").await.is_err());
        assert_eq!(read_policy_on(&db, "org").await.unwrap().version, 1);
    }

    #[tokio::test]
    async fn policy_membership_removal_denies_retained_grants_and_reassignment() {
        let db = database().await;
        let original = bootstrap_on(&db, "root@example.test", "org").await.unwrap();
        let mut grants = original.grants.clone();
        grants.push(Grant {
            subject: "viewer-id".into(),
            role: Role::Admin,
            resources: vec![Resource::organization()],
        });
        let policy = replace_policy_on(&db, "root@example.test", "org", 1, grants)
            .await
            .unwrap();
        validate_subject_on(&db, "viewer-id", "org").await.unwrap();
        assert_eq!(
            allowed_subject_resource_actions_on(
                &db,
                "viewer-id",
                "org",
                &[Action::Query],
                &[Resource::stream("logs", "api")]
            )
            .await
            .unwrap(),
            vec![true]
        );
        db.execute_unprepared("DELETE FROM org_users WHERE email = 'viewer@example.test'")
            .await
            .unwrap();
        assert!(validate_subject_on(&db, "viewer-id", "org").await.is_err());
        assert!(
            allowed_subject_resource_actions_on(
                &db,
                "viewer-id",
                "org",
                &[Action::Query],
                &[Resource::stream("logs", "api")]
            )
            .await
            .is_err()
        );
        assert!(
            allowed_subject_resource_actions_on(&db, "viewer-id", "org", &[Action::Read], &[])
                .await
                .is_err()
        );
        assert!(
            replace_policy_on(&db, "viewer@example.test", "org", 2, policy.grants.clone())
                .await
                .is_err()
        );
        assert!(
            replace_policy_on(&db, "root@example.test", "org", 2, policy.grants.clone())
                .await
                .is_err()
        );
        assert_eq!(read_policy_on(&db, "org").await.unwrap().version, 2);
        validate_subject_on(&db, "root-id", "org").await.unwrap();
        let mut without_root_grant = policy.clone();
        without_root_grant
            .grants
            .retain(|grant| grant.subject != "root-id");
        assert!(
            !Engine::new(&without_root_grant)
                .await
                .unwrap()
                .authorize(
                    "root-id",
                    "org",
                    Action::Query,
                    &Resource::stream("logs", "ungranted")
                )
                .unwrap()
        );
        replace_policy_on(&db, "root@example.test", "org", 2, original.grants)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn policy_updates_reject_escalation_and_stale_concurrent_writes() {
        let db = database().await;
        let policy = bootstrap_on(&db, "root@example.test", "org").await.unwrap();
        assert!(
            replace_policy_on(&db, "viewer@example.test", "org", 1, policy.grants.clone())
                .await
                .is_err()
        );
        let mut unknown = policy.grants.clone();
        unknown[0].subject = "missing-id".into();
        assert!(
            replace_policy_on(&db, "root@example.test", "org", 1, unknown)
                .await
                .is_err()
        );
        let (first, second) = tokio::join!(
            replace_policy_on(&db, "root@example.test", "org", 1, policy.grants.clone()),
            replace_policy_on(&db, "root@example.test", "org", 1, policy.grants.clone())
        );
        assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
        assert_eq!(read_policy_on(&db, "org").await.unwrap().version, 2);
    }

    #[tokio::test]
    async fn policy_revocation_and_corruption_fail_closed() {
        let db = database().await;
        let original = bootstrap_on(&db, "root@example.test", "org").await.unwrap();
        let mut grants = original.grants.clone();
        grants.push(Grant {
            subject: "viewer-id".into(),
            role: Role::Viewer,
            resources: vec![Resource::stream("logs", "api")],
        });
        replace_policy_on(&db, "root@example.test", "org", 1, grants)
            .await
            .unwrap();
        let before = read_policy_on(&db, "org").await.unwrap();
        assert!(
            Engine::new(&before)
                .await
                .unwrap()
                .authorize(
                    "viewer-id",
                    "org",
                    Action::Query,
                    &Resource::stream("logs", "api")
                )
                .unwrap()
        );
        replace_policy_on(&db, "root@example.test", "org", 2, original.grants)
            .await
            .unwrap();
        let after = read_policy_on(&db, "org").await.unwrap();
        assert!(
            !Engine::new(&after)
                .await
                .unwrap()
                .authorize(
                    "viewer-id",
                    "org",
                    Action::Query,
                    &Resource::stream("logs", "api")
                )
                .unwrap()
        );
        db.execute_unprepared("UPDATE meta SET value='not json'")
            .await
            .unwrap();
        assert!(read_policy_on(&db, "org").await.is_err());
        assert!(bootstrap_on(&db, "root@example.test", "org").await.is_err());
    }

    #[tokio::test]
    async fn policy_revoked_administrator_cannot_restore_old_snapshot() {
        let db = database().await;
        let original = bootstrap_on(&db, "root@example.test", "org").await.unwrap();
        let mut grants = original.grants.clone();
        grants.push(Grant {
            subject: "viewer-id".into(),
            role: Role::Admin,
            resources: vec![Resource::organization()],
        });
        let captured = replace_policy_on(&db, "root@example.test", "org", 1, grants)
            .await
            .unwrap();
        replace_policy_on(&db, "root@example.test", "org", 2, original.grants)
            .await
            .unwrap();
        let mut stale_update = captured.clone();
        stale_update.version = 3;
        assert!(
            write_policy_on(&db, &stale_update, Some(captured))
                .await
                .is_err()
        );
        assert!(
            replace_policy_on(&db, "viewer@example.test", "org", 3, stale_update.grants)
                .await
                .is_err()
        );
        let current = read_policy_on(&db, "org").await.unwrap();
        assert_eq!(current.version, 3);
        assert_eq!(current.grants.len(), 1);
        assert_eq!(current.grants[0].subject, "root-id");
    }
}
