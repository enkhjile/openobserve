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
pub(super) async fn recorded_subject() -> Option<String> {
    if !crate::rbac::enabled() {
        return None;
    }
    crate::rbac::caller::current_subject().await.ok()
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

#[cfg(test)]
mod rbac_subject_tests {
    use crate::rbac::caller::{Caller, scope};

    #[tokio::test]
    async fn a_written_pipeline_records_the_saving_caller_or_none() {
        if std::env::var_os("O2_RBAC_RECORDED_CHILD").is_none() {
            let off = scope(Caller::Subject("s".into()), super::recorded_subject());
            assert_eq!(off.await.unwrap(), None, "RBAC off records no subject");
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "pipeline::execution::rbac_subject_tests::a_written_pipeline_records_the_saving_caller_or_none",
                    "--nocapture",
                ])
                .env("O2_RBAC_RECORDED_CHILD", "1")
                .env("ZO_RBAC_ENABLED", "true")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }
        assert_eq!(
            super::recorded_subject().await,
            None,
            "no caller records none"
        );
        let delegated = scope(
            Caller::Subject("org-token:t".into()),
            super::recorded_subject(),
        );
        assert_eq!(delegated.await.unwrap().as_deref(), Some("org-token:t"));
    }
}
