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

use anyhow::{Context, Result, ensure};
use config::meta::destinations::{Destination, DestinationType, Module, Template, TemplateKind};
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, Statement};
use serde::Deserialize;

use super::{Action, DestinationApproval, Engine, PolicyDocument, Resource, ResourceKind};
use crate::{
    db,
    table::entity::{destinations, templates},
};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationApprovalRequest {
    pub destination_name: String,
    #[serde(default)]
    pub expected_target_fingerprint: Option<String>,
    pub sources: Vec<Resource>,
}

pub async fn validate_report_renderer(email: &str, org: &str) -> Result<String> {
    validate_report_renderer_on(db::get_orm_client_rw().await, email, org).await
}

pub async fn replace_destination_approvals(
    email: &str,
    org: &str,
    expected_version: u64,
    requested: Vec<DestinationApprovalRequest>,
) -> Result<PolicyDocument> {
    ensure!(super::enabled(), "RBAC is disabled");
    let client = db::get_orm_client_rw().await;
    let subject = super::user_subject(email).await?;
    super::validate_subject_on(client, &subject, org).await?;
    let current = super::read_policy_on(client, org).await?;
    ensure!(
        current.version == expected_version,
        "RBAC policy version conflict"
    );
    ensure!(
        Engine::new(&current).await?.authorize(
            &subject,
            org,
            Action::Manage,
            &Resource::organization()
        )?,
        "delivery authorization denied"
    );
    let mut next = current.clone();
    next.version = current
        .version
        .checked_add(1)
        .context("RBAC version overflow")?;
    next.destination_approvals.clear();
    for request in requested {
        let (destination, fingerprint, _) =
            destination_snapshot(org, &request.destination_name).await?;
        let id = destination
            .id
            .context("missing destination identity")?
            .to_string();
        // Keeping an approval must name the target it approved, so a changed target is not
        // re-approved.
        let approved = current
            .destination_approvals
            .iter()
            .find(|approval| {
                approval.destination_id == id || approval.destination_name == destination.name
            })
            .map(|approval| approval.target_fingerprint.as_str());
        let expected = request.expected_target_fingerprint.as_deref();
        ensure!(
            approved.is_none_or(|approved| expected == Some(approved))
                && expected.is_none_or(|expected| expected == fingerprint),
            "destination target changed; explicit reapproval required"
        );
        next.destination_approvals.push(DestinationApproval {
            destination_id: id,
            destination_name: destination.name,
            target_fingerprint: fingerprint,
            sources: request.sources,
        });
    }
    next.validate()?;
    super::write_policy_on(client, &next, Some(current)).await?;
    Ok(next)
}

pub async fn authorize_alert_destinations(
    subject: &str,
    org: &str,
    sources: &[Resource],
    names: &[String],
) -> Result<()> {
    if !super::enabled() {
        return Ok(());
    }
    ensure!(!names.is_empty(), "delivery authorization denied");
    for name in names {
        authorized_alert_destination(subject, org, sources, name).await?;
    }
    Ok(())
}

pub async fn available_alert_destinations(
    subject: &str,
    org: &str,
    alert_id: &str,
    sources: &[Resource],
) -> Result<Vec<String>> {
    ensure!(
        super::enabled() && !sources.is_empty(),
        "delivery authorization denied"
    );
    super::validate_subject(subject, org).await?;
    let policy = super::read_policy(org).await?;
    let engine = super::cache::engine(&policy).await?;
    ensure!(
        engine.authorize(
            subject,
            org,
            Action::Write,
            &Resource::new(ResourceKind::Alert, alert_id)
        )?,
        "delivery authorization denied"
    );
    for source in sources {
        ensure!(
            source.kind == ResourceKind::Stream
                && source.name != "*"
                && source.stream_type != "*"
                && engine.authorize(subject, org, Action::Query, source)?,
            "delivery authorization denied"
        );
    }
    let mut names = std::collections::BTreeSet::new();
    for approval in &policy.destination_approvals {
        if !sources
            .iter()
            .all(|source| approval.sources.contains(source))
        {
            continue;
        }
        // A deleted or changed destination drops out of the list instead of failing it.
        let Ok((destination, fingerprint, _)) =
            destination_snapshot(org, &approval.destination_name).await
        else {
            continue;
        };
        let id = destination
            .id
            .context("missing destination identity")?
            .to_string();
        if approval_matches(approval, &id, &destination.name, &fingerprint, sources) {
            names.insert(destination.name);
        }
    }
    Ok(names.into_iter().collect())
}

pub async fn authorized_alert_destination(
    subject: &str,
    org: &str,
    sources: &[Resource],
    name: &str,
) -> Result<Destination> {
    Ok(
        authorized_alert_destination_with_template(subject, org, sources, name)
            .await?
            .0,
    )
}

pub async fn authorized_alert_destination_with_template(
    subject: &str,
    org: &str,
    sources: &[Resource],
    name: &str,
) -> Result<(Destination, Option<Template>)> {
    ensure!(super::enabled(), "RBAC is disabled");
    super::validate_subject(subject, org).await?;
    let policy = super::read_policy(org).await?;
    ensure!(!sources.is_empty(), "delivery authorization denied");
    let engine = super::cache::engine(&policy).await?;
    for source in sources {
        ensure!(
            source.kind == ResourceKind::Stream && source.name != "*" && source.stream_type != "*",
            "delivery authorization denied"
        );
        ensure!(
            engine.authorize(subject, org, Action::Query, source)?,
            "delivery authorization denied"
        );
    }
    let (destination, fingerprint, template) = destination_snapshot(org, name).await?;
    let id = destination
        .id
        .as_ref()
        .context("missing destination identity")?
        .to_string();
    ensure!(
        policy
            .destination_approvals
            .iter()
            .any(|approval| approval_matches(approval, &id, name, &fingerprint, sources)),
        "delivery authorization denied"
    );
    Ok((destination, template))
}

async fn validate_report_renderer_on<C: ConnectionTrait>(
    client: &C,
    email: &str,
    org: &str,
) -> Result<String> {
    let row = client.query_one(Statement::from_sql_and_values(client.get_database_backend(),
        "SELECT users.id FROM users INNER JOIN org_users ON users.email = org_users.email WHERE LOWER(users.email) = LOWER($1) AND users.is_root = false AND org_users.org_id = $2 AND (SELECT COUNT(*) FROM org_users AS memberships WHERE memberships.email = users.email) = 1 AND (SELECT COUNT(*) FROM users AS candidates WHERE LOWER(candidates.email) = LOWER($1)) = 1",
        [email.into(), org.into()])).await?.context("report renderer authorization denied")?;
    Ok(row.try_get("", "id")?)
}

async fn destination_snapshot(
    org: &str,
    name: &str,
) -> Result<(Destination, String, Option<Template>)> {
    destination_snapshot_on(db::get_orm_client_rw().await, org, name).await
}

async fn destination_snapshot_on<C: ConnectionTrait>(
    client: &C,
    org: &str,
    name: &str,
) -> Result<(Destination, String, Option<Template>)> {
    let row = destinations::Entity::find()
        .filter(destinations::Column::Org.eq(org))
        .filter(destinations::Column::Name.eq(name))
        .one(client)
        .await?
        .context("delivery authorization denied")?;
    ensure!(row.module == "alert", "unsupported destination");
    let target: DestinationType = serde_json::from_value(row.r#type.clone())?;
    match &target {
        DestinationType::Http(endpoint) => ensure!(
            endpoint
                .destination_type
                .as_deref()
                .is_none_or(|kind| kind == "custom")
                && !endpoint.url.contains(['{', '}']),
            "unsupported destination"
        ),
        DestinationType::Email(email) => ensure!(
            !email.recipients.is_empty()
                && email
                    .recipients
                    .iter()
                    .all(|address| !address.contains(['{', '}'])),
            "unsupported destination"
        ),
        _ => anyhow::bail!("unsupported destination"),
    }
    let template = match &row.template_id {
        Some(id) => Some(
            templates::Entity::find_by_id(id)
                .one(client)
                .await?
                .context("missing template")?,
        ),
        None => None,
    };
    let template: Option<Template> = template.map(TryInto::try_into).transpose()?;
    let binding = serde_json::json!({"id": row.id, "org": row.org, "name": row.name,
        "target": row.r#type, "template": template});
    let fingerprint = sha256::digest(canonical(binding).to_string());
    ensure!(
        template
            .as_ref()
            .is_some_and(|template| template.kind == TemplateKind::Custom),
        "delivery requires an approved custom template"
    );
    Ok((
        Destination {
            id: Some(row.id.parse().context("invalid destination identity")?),
            org_id: row.org,
            name: row.name,
            module: Module::Alert {
                template: template.as_ref().map(|t| t.name.clone()),
                destination_type: target,
            },
        },
        fingerprint,
        template,
    ))
}

fn canonical(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let sorted: std::collections::BTreeMap<_, _> = map
                .into_iter()
                .map(|(key, value)| (key, canonical(value)))
                .collect();
            serde_json::Value::Object(sorted.into_iter().collect())
        }
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.into_iter().map(canonical).collect())
        }
        value => value,
    }
}

fn approval_matches(
    approval: &DestinationApproval,
    id: &str,
    name: &str,
    fingerprint: &str,
    sources: &[Resource],
) -> bool {
    approval.destination_id == id
        && approval.destination_name == name
        && approval.target_fingerprint == fingerprint
        && !sources.is_empty()
        && sources
            .iter()
            .all(|source| approval.sources.contains(source))
}

#[cfg(test)]
mod tests {
    use svix_ksuid::KsuidLike;

    use super::*;

    #[tokio::test]
    async fn report_renderer_requires_unique_nonroot_single_org_identity() {
        use sea_orm::Database;
        let mut options = sea_orm::ConnectOptions::new("sqlite::memory:");
        options.max_connections(1);
        let db = Database::connect(options).await.unwrap();
        for sql in [
            "CREATE TABLE users(id TEXT PRIMARY KEY, email TEXT, is_root BOOLEAN)",
            "CREATE TABLE org_users(email TEXT, org_id TEXT)",
            "INSERT INTO users VALUES ('renderer-id','renderer@example.test',false), ('root-id','root@example.test',true)",
            "INSERT INTO org_users VALUES ('renderer@example.test','org'), ('root@example.test','org')",
        ] {
            db.execute_unprepared(sql).await.unwrap();
        }
        assert_eq!(
            validate_report_renderer_on(&db, "renderer@example.test", "org")
                .await
                .unwrap(),
            "renderer-id"
        );
        assert!(
            validate_report_renderer_on(&db, "root@example.test", "org")
                .await
                .is_err()
        );
        assert!(
            validate_report_renderer_on(&db, "renderer@example.test", "other")
                .await
                .is_err()
        );
        db.execute_unprepared("INSERT INTO org_users VALUES ('renderer@example.test','other')")
            .await
            .unwrap();
        assert!(
            validate_report_renderer_on(&db, "renderer@example.test", "org")
                .await
                .is_err()
        );
        db.execute_unprepared("DELETE FROM org_users WHERE org_id = 'other'")
            .await
            .unwrap();
        db.execute_unprepared(
            "INSERT INTO users VALUES ('ambiguous','RENDERER@example.test',false)",
        )
        .await
        .unwrap();
        assert!(
            validate_report_renderer_on(&db, "renderer@example.test", "org")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn primary_snapshot_changes_on_target_template_or_identity_change() {
        use sea_orm::{Database, DbBackend, Schema};
        let db = Database::connect("sqlite::memory:").await.unwrap();
        let schema = Schema::new(DbBackend::Sqlite);
        for table in [
            schema.create_table_from_entity(templates::Entity),
            schema.create_table_from_entity(destinations::Entity),
        ] {
            db.execute(DbBackend::Sqlite.build(&table)).await.unwrap();
        }
        let id = svix_ksuid::Ksuid::new(None, None).to_string();
        let template_id = svix_ksuid::Ksuid::new(None, None).to_string();
        db.execute(Statement::from_sql_and_values(DbBackend::Sqlite,
            "INSERT INTO templates (id,org,name,is_default,type,body,title,kind,applies_to) VALUES ($1,'org','template',false,'http','body',NULL,'custom','[]')", [template_id.clone().into()])).await.unwrap();
        db.execute(Statement::from_sql_and_values(DbBackend::Sqlite,
            "INSERT INTO destinations (id,org,name,module,template_id,type) VALUES ($1,'org','ops','alert',$2,$3)",
            [id.into(), template_id.into(), serde_json::json!({"type":"http","url":"https://first.example"}).to_string().into()])).await.unwrap();
        let (_, original, template) = destination_snapshot_on(&db, "org", "ops").await.unwrap();
        assert_eq!(template.unwrap().body, "body");
        assert!(destination_snapshot_on(&db, "other", "ops").await.is_err());
        db.execute_unprepared("UPDATE templates SET body = 'changed'")
            .await
            .unwrap();
        let (_, changed_template, _) = destination_snapshot_on(&db, "org", "ops").await.unwrap();
        assert_ne!(original, changed_template);
        db.execute(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "UPDATE destinations SET type = $1",
            [
                serde_json::json!({"type":"http","url":"https://second.example"})
                    .to_string()
                    .into(),
            ],
        ))
        .await
        .unwrap();
        let (_, changed_target, _) = destination_snapshot_on(&db, "org", "ops").await.unwrap();
        assert_ne!(changed_template, changed_target);
        db.execute(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "UPDATE destinations SET id = $1",
            [svix_ksuid::Ksuid::new(None, None).to_string().into()],
        ))
        .await
        .unwrap();
        assert_ne!(
            changed_target,
            destination_snapshot_on(&db, "org", "ops").await.unwrap().1
        );
        db.execute_unprepared("UPDATE templates SET kind = 'content'")
            .await
            .unwrap();
        assert!(destination_snapshot_on(&db, "org", "ops").await.is_err());
    }

    #[test]
    fn approval_binds_identity_target_and_every_source() {
        let source = Resource::stream("logs", "allowed");
        let approval = DestinationApproval {
            destination_id: "id".into(),
            destination_name: "webhook".into(),
            target_fingerprint: "digest".into(),
            sources: vec![source.clone()],
        };
        assert!(approval_matches(
            &approval,
            "id",
            "webhook",
            "digest",
            std::slice::from_ref(&source)
        ));
        for (id, name, fingerprint, sources) in [
            ("replacement", "webhook", "digest", vec![source.clone()]),
            ("id", "renamed", "digest", vec![source.clone()]),
            ("id", "webhook", "changed", vec![source.clone()]),
            (
                "id",
                "webhook",
                "digest",
                vec![source, Resource::stream("logs", "secret")],
            ),
            ("id", "webhook", "digest", vec![]),
        ] {
            assert!(!approval_matches(
                &approval,
                id,
                name,
                fingerprint,
                &sources
            ));
        }
    }

    #[test]
    fn canonical_binding_ignores_object_order_but_detects_target_changes() {
        let first: serde_json::Value =
            serde_json::from_str(r#"{"url":"https://a","headers":{"b":"2","a":"1"}}"#).unwrap();
        let reordered: serde_json::Value =
            serde_json::from_str(r#"{"headers":{"a":"1","b":"2"},"url":"https://a"}"#).unwrap();
        assert_eq!(canonical(first.clone()), canonical(reordered));
        let mut changed = first.clone();
        changed["url"] = "https://b".into();
        assert_ne!(canonical(first), canonical(changed));
    }
}
