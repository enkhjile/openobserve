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

use config::meta::destinations::Template;
use infra::table::entity::templates;
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QueryOrder, Statement};

use super::TemplateError;

pub(super) async fn get_on<C: ConnectionTrait>(
    client: &C,
    org: &str,
    name: &str,
) -> Result<Option<Template>, TemplateError> {
    templates::Entity::find()
        .filter(templates::Column::Org.eq(org))
        .filter(templates::Column::Name.eq(name))
        .one(client)
        .await
        .map_err(infra::errors::Error::from)?
        .map(|row| {
            row.try_into()
                .map_err(infra::errors::Error::from)
                .map_err(TemplateError::from)
        })
        .transpose()
}

pub(super) async fn list_on<C: ConnectionTrait>(
    client: &C,
    org: &str,
) -> Result<Vec<Template>, TemplateError> {
    templates::Entity::find()
        .filter(templates::Column::Org.eq(org))
        .order_by_asc(templates::Column::Name)
        .all(client)
        .await
        .map_err(infra::errors::Error::from)?
        .into_iter()
        .map(|row| {
            row.try_into()
                .map_err(infra::errors::Error::from)
                .map_err(TemplateError::from)
        })
        .collect()
}

pub(super) async fn ensure_mutation_on<C: ConnectionTrait>(
    client: &C,
    org: &str,
    name: &str,
) -> Result<(), TemplateError> {
    if let Some(existing) = get_on(client, org, name).await? {
        let id = existing
            .id
            .ok_or(TemplateError::AuthorizationDenied)?
            .to_string();
        let foreign = client
            .query_one(Statement::from_sql_and_values(
                client.get_database_backend(),
                "SELECT id FROM destinations WHERE template_id = $1 AND org <> $2 LIMIT 1",
                [id.into(), org.into()],
            ))
            .await
            .map_err(infra::errors::Error::from)?;
        if foreign.is_some() {
            return Err(TemplateError::AuthorizationDenied);
        }
    }
    if org == config::DEFAULT_ORG {
        for (table, org_column) in [
            ("alerts", "org"),
            ("anomaly_detection_config", "org_id"),
            ("synthetics", "org_id"),
            ("oncall_policies", "org_id"),
            ("alert_composites", "org"),
        ] {
            let sql = format!(
                "SELECT template FROM {table} WHERE {org_column} <> $1 AND template = $2 LIMIT 1"
            );
            let foreign = client
                .query_one(Statement::from_sql_and_values(
                    client.get_database_backend(),
                    sql,
                    [org.into(), name.into()],
                ))
                .await
                .map_err(infra::errors::Error::from)?;
            if foreign.is_some() {
                return Err(TemplateError::AuthorizationDenied);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use config::meta::destinations::{TemplateKind, TemplateType};
    use sea_orm::{Database, DbBackend, Schema};

    use super::*;

    #[tokio::test]
    async fn primary_template_reads_do_not_inherit_default_org() {
        let mut options = sea_orm::ConnectOptions::new("sqlite::memory:");
        options.max_connections(1);
        let db = Database::connect(options).await.unwrap();
        db.execute(
            DbBackend::Sqlite.build(
                &Schema::new(DbBackend::Sqlite)
                    .create_table_from_entity(infra::table::entity::templates::Entity),
            ),
        )
        .await
        .unwrap();
        let row = Template {
            id: None,
            org_id: "default".into(),
            name: "local".into(),
            is_default: false,
            body: "private body".into(),
            template_type: TemplateType::Http,
            kind: TemplateKind::Custom,
            applies_to: vec![],
        };
        infra::table::templates::put_with(&db, row).await.unwrap();
        assert!(get_on(&db, "other", "local").await.unwrap().is_none());
        assert_eq!(
            get_on(&db, "default", "local").await.unwrap().unwrap().body,
            "private body"
        );
        assert!(list_on(&db, "other").await.unwrap().is_empty());
        for sql in [
            "CREATE TABLE destinations(id TEXT, org TEXT, template_id TEXT)",
            "CREATE TABLE alerts(org TEXT, template TEXT)",
            "CREATE TABLE anomaly_detection_config(org_id TEXT, template TEXT)",
            "CREATE TABLE synthetics(org_id TEXT, template TEXT)",
            "CREATE TABLE oncall_policies(org_id TEXT, template TEXT)",
            "CREATE TABLE alert_composites(org TEXT, template TEXT)",
        ] {
            db.execute_unprepared(sql).await.unwrap();
        }
        assert!(ensure_mutation_on(&db, "default", "local").await.is_ok());
        let mut local = get_on(&db, "default", "local").await.unwrap().unwrap();
        local.body = "edited".into();
        infra::table::templates::put_with(&db, local).await.unwrap();
        assert_eq!(
            get_on(&db, "default", "local").await.unwrap().unwrap().body,
            "edited"
        );
        db.execute_unprepared("INSERT INTO destinations SELECT 'foreign','other',id FROM templates WHERE name = 'local'").await.unwrap();
        assert!(matches!(
            ensure_mutation_on(&db, "default", "local").await,
            Err(TemplateError::AuthorizationDenied)
        ));
        db.execute_unprepared("DELETE FROM destinations")
            .await
            .unwrap();
        db.execute_unprepared("INSERT INTO alerts VALUES ('other','local')")
            .await
            .unwrap();
        assert!(matches!(
            ensure_mutation_on(&db, "default", "local").await,
            Err(TemplateError::AuthorizationDenied)
        ));
        db.execute_unprepared("DELETE FROM alerts").await.unwrap();
        assert!(ensure_mutation_on(&db, "default", "local").await.is_ok());
        assert!(
            infra::table::templates::delete_with(&db, "default", "local")
                .await
                .unwrap()
        );
        assert!(get_on(&db, "default", "local").await.unwrap().is_none());
    }
}
