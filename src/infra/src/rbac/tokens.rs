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
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter};
use serde::Serialize;

use super::{Action, Resource};
use crate::{
    db,
    table::{
        entity::org_ingestion_tokens,
        org_ingestion_tokens::{WRITER_TOKEN_CREATOR, WRITER_TOKEN_PREFIX},
    },
};

#[derive(Serialize)]
pub struct IngestionTokenSubject {
    pub subject: String,
    pub name: String,
}

pub async fn ingestion_token_subjects(org: &str) -> Result<Vec<IngestionTokenSubject>> {
    let rows = org_ingestion_tokens::Entity::find()
        .filter(org_ingestion_tokens::Column::OrgId.eq(org))
        .filter(org_ingestion_tokens::Column::Enabled.eq(true))
        .all(db::get_orm_client_rw().await)
        .await?;
    Ok(rows
        .into_iter()
        .filter(|row| {
            !row.name.starts_with(WRITER_TOKEN_PREFIX) && row.created_by != WRITER_TOKEN_CREATOR
        })
        .filter_map(|row| {
            let subject = format!("org-token:{}", row.id);
            openobserve_rbac::token_subject_id(&subject).ok()?;
            Some(IngestionTokenSubject {
                subject,
                name: row.name,
            })
        })
        .collect())
}

pub async fn allowed_ingestion_token_resources(
    org_id: &str,
    token_id: &str,
    resources: &[Resource],
) -> Result<Vec<bool>> {
    ensure!(super::enabled(), "RBAC is disabled");
    let subject = format!("org-token:{token_id}");
    super::allowed_subject_resources(&subject, org_id, Action::Ingest, resources).await
}

pub(super) async fn validate_subject_if_token(subject: &str, org: &str) -> Result<()> {
    if let Some(id) = openobserve_rbac::token_subject_id(subject)? {
        validate_token_on(db::get_orm_client_rw().await, id, org).await?;
    }
    Ok(())
}

pub(super) async fn validate_token_on<C: ConnectionTrait>(
    client: &C,
    id: &str,
    org: &str,
) -> Result<()> {
    let row = org_ingestion_tokens::Entity::find_by_id(id)
        .filter(org_ingestion_tokens::Column::OrgId.eq(org))
        .filter(org_ingestion_tokens::Column::Enabled.eq(true))
        .one(client)
        .await?
        .context("ingestion token authorization denied")?;
    ensure!(
        !row.name.starts_with(WRITER_TOKEN_PREFIX) && row.created_by != WRITER_TOKEN_CREATOR,
        "feature writer token cannot receive user policy grants"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use sea_orm::{Database, DbBackend, Schema, Statement};

    use super::*;

    #[tokio::test]
    async fn token_binding_rejects_disabled_cross_org_feature_and_recreated_rows() {
        let mut options = sea_orm::ConnectOptions::new("sqlite::memory:");
        options.max_connections(1);
        let db = Database::connect(options).await.unwrap();
        db.execute(DbBackend::Sqlite.build(
            &Schema::new(DbBackend::Sqlite).create_table_from_entity(org_ingestion_tokens::Entity),
        ))
        .await
        .unwrap();
        let id = "000000000000000000000000001";
        db.execute(Statement::from_sql_and_values(DbBackend::Sqlite,
            "INSERT INTO org_ingestion_tokens(id,org_id,name,token,description,is_default,enabled,created_by,created_at,updated_at) VALUES($1,'a','collector','secret','',false,true,'admin',0,0)",[id.into()])).await.unwrap();
        assert!(validate_token_on(&db, id, "a").await.is_ok());
        assert!(validate_token_on(&db, id, "b").await.is_err());
        db.execute_unprepared("UPDATE org_ingestion_tokens SET token = 'rotated'")
            .await
            .unwrap();
        assert!(validate_token_on(&db, id, "a").await.is_ok());
        db.execute_unprepared("UPDATE org_ingestion_tokens SET enabled = false")
            .await
            .unwrap();
        assert!(validate_token_on(&db, id, "a").await.is_err());
        db.execute_unprepared(
            "UPDATE org_ingestion_tokens SET enabled = true, name = '_o2_writer'",
        )
        .await
        .unwrap();
        assert!(validate_token_on(&db, id, "a").await.is_err());
        db.execute_unprepared(
            "UPDATE org_ingestion_tokens SET name = 'collector', created_by = 'system'",
        )
        .await
        .unwrap();
        assert!(validate_token_on(&db, id, "a").await.is_err());
        db.execute_unprepared("UPDATE org_ingestion_tokens SET created_by = 'admin', id = '000000000000000000000000002'").await.unwrap();
        assert!(validate_token_on(&db, id, "a").await.is_err());
        assert!(
            validate_token_on(&db, "000000000000000000000000002", "a")
                .await
                .is_ok()
        );
    }
}
