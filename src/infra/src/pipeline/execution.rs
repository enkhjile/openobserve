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

pub async fn put(pipeline: &Pipeline, subject: Option<&str>) -> Result<()> {
    if by_id(&pipeline.org, &pipeline.id).await?.is_some() {
        super::CLIENT.update(pipeline, subject).await
    } else {
        super::CLIENT.put(pipeline, subject).await
    }
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
