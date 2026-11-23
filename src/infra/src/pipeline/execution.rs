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

use config::meta::pipeline::Pipeline;
use sqlx::{FromRow, Row};

use crate::errors::Result;

const RECORD_SUBJECT: &str =
    "UPDATE pipeline SET execution_subject = $1 WHERE id = $2 AND org = $3";

#[derive(Debug, Clone, PartialEq)]
pub struct PipelineExecution {
    pub pipeline: Pipeline,
    pub subject: Option<String>,
}

pub async fn for_stream(org: &str, stream: &str) -> Result<Vec<PipelineExecution>> {
    let sql = "SELECT * FROM pipeline WHERE (org = $1 OR stream_org = $1) AND enabled = true AND source_type = 'realtime' AND stream_name = $2 AND stream_type = 'logs'";
    load(sql, org, stream).await
}

pub async fn by_id(org: &str, id: &str) -> Result<Option<PipelineExecution>> {
    Ok(
        load("SELECT * FROM pipeline WHERE org = $1 AND id = $2", org, id)
            .await?
            .pop(),
    )
}

/// Chooses insert or update from the primary store, so a lagging replica cannot pair a new
/// subject with an old definition.
pub async fn put(pipeline: &Pipeline) -> Result<()> {
    if by_id(&pipeline.org, &pipeline.id).await?.is_some() {
        super::CLIENT.update(pipeline).await
    } else {
        super::CLIENT.put(pipeline).await
    }
}

/// The identity a pipeline written now runs as: the saving request's caller, else none.
pub async fn recorded_subject() -> Option<String> {
    crate::rbac::caller::current_subject().await.ok()
}

/// Written in the transaction that writes the definition, so the two never disagree.
pub(super) async fn record_sqlite(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    pipeline: &Pipeline,
    subject: Option<String>,
) -> Result<()> {
    sqlx::query(RECORD_SUBJECT)
        .bind(subject)
        .bind(&pipeline.id)
        .bind(&pipeline.org)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

pub(super) async fn record_postgres(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    pipeline: &Pipeline,
    subject: Option<String>,
) -> Result<()> {
    sqlx::query(RECORD_SUBJECT)
        .bind(subject)
        .bind(&pipeline.id)
        .bind(&pipeline.org)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

pub async fn has_enabled_source(org: &str, stream: &str, stream_type: &str) -> Result<bool> {
    let sql = "SELECT COUNT(*) FROM pipeline WHERE enabled = true AND source_type = 'realtime' AND stream_org = $1 AND stream_name = $2 AND stream_type = $3";
    let count: i64 = if matches!(
        config::meta::meta_store::MetaStore::from(config::get_config().common.meta_store.as_str()),
        config::meta::meta_store::MetaStore::PostgreSQL
    ) {
        sqlx::query_scalar(sql)
            .bind(org)
            .bind(stream)
            .bind(stream_type)
            .fetch_one(&crate::db::postgres::CLIENT_RW.clone())
            .await?
    } else {
        sqlx::query_scalar(sql)
            .bind(org)
            .bind(stream)
            .bind(stream_type)
            .fetch_one(&crate::db::sqlite::CLIENT_RW.clone())
            .await?
    };
    Ok(count > 0)
}

async fn load(sql: &str, org: &str, key: &str) -> Result<Vec<PipelineExecution>> {
    if matches!(
        config::meta::meta_store::MetaStore::from(config::get_config().common.meta_store.as_str()),
        config::meta::meta_store::MetaStore::PostgreSQL
    ) {
        let rows = sqlx::query(sql)
            .bind(org)
            .bind(key)
            .fetch_all(&crate::db::postgres::CLIENT_RW.clone())
            .await?;
        rows.iter()
            .map(|row| {
                Ok(PipelineExecution {
                    pipeline: Pipeline::from_row(row)?,
                    subject: row.try_get("execution_subject")?,
                })
            })
            .collect()
    } else {
        let rows = sqlx::query(sql)
            .bind(org)
            .bind(key)
            .fetch_all(&crate::db::sqlite::CLIENT_RW.clone())
            .await?;
        rows.iter()
            .map(|row| {
                Ok(PipelineExecution {
                    pipeline: Pipeline::from_row(row)?,
                    subject: row.try_get("execution_subject")?,
                })
            })
            .collect()
    }
}
