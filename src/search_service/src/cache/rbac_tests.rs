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

use super::*;

#[tokio::test]
async fn rbac_cache_preparation_rejects_missing_identity() {
    if std::env::var("O2_RBAC_CACHE_CHILD").as_deref() != Ok("1") {
        let directory = std::env::temp_dir().join(format!("rbac-cache-{}", config::ider::uuid()));
        std::fs::create_dir_all(&directory).unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "rbac_cache_preparation_rejects_missing_identity",
                "--nocapture",
            ])
            .env("O2_RBAC_CACHE_CHILD", "1")
            .env("ZO_RBAC_ENABLED", "true")
            .env("ZO_LOCAL_MODE", "true")
            .env("ZO_META_STORE", "sqlite")
            .env("ZO_DATA_DIR", directory.join("data"))
            .current_dir(&directory)
            .status()
            .unwrap();
        assert!(status.success());
        std::fs::remove_dir_all(directory).unwrap();
        return;
    }
    let mut request = search::Request::default();
    request.query.sql = "SELECT _timestamp FROM t ORDER BY _timestamp ASC".into();
    assert!(
        prepare_cache_response(
            "rbac-cache",
            "org",
            StreamType::Logs,
            &mut request,
            CacheMode::Bypass,
        )
        .await
        .is_err()
    );
    verify_scoped_cache_metadata().await;
}

async fn verify_scoped_cache_metadata() {
    use arrow_schema::{DataType, Field, Schema};
    use infra::{
        rbac::{
            Grant, Resource, Role,
            caller::{self, Caller},
        },
        schema::{STREAM_SCHEMAS_LATEST, SchemaCache},
    };

    infra::db::create_table().await.unwrap();
    infra::table::create_user_tables().await.unwrap();
    infra::table::organizations::add(
        "org",
        "Cache fixture",
        config::meta::organization::OrganizationType::Default,
    )
    .await
    .unwrap();
    for (email, root) in [("root@cache.test", true), ("viewer@cache.test", false)] {
        infra::table::users::add(infra::table::users::UserRecord {
            email: email.into(),
            first_name: "".into(),
            last_name: "".into(),
            password: "".into(),
            salt: "".into(),
            is_root: root,
            password_ext: None,
            user_type: config::meta::user::UserType::Internal,
            created_at: 0,
            updated_at: 0,
            must_reset_password: false,
            password_reset_reason: None,
            flagged_at: None,
            password_updated_at: None,
        })
        .await
        .unwrap();
    }
    infra::table::org_users::add(
        "org",
        "viewer@cache.test",
        config::meta::user::UserRole::Viewer,
        "fixture-token",
        None,
    )
    .await
    .unwrap();
    let original = infra::rbac::bootstrap("root@cache.test", "org")
        .await
        .unwrap();
    let mut grants = original.grants.clone();
    grants.push(Grant {
        subject: infra::rbac::user_subject("viewer@cache.test")
            .await
            .unwrap(),
        role: Role::Viewer,
        resources: vec![Resource::stream("logs", "t")],
    });
    infra::rbac::replace_policy("root@cache.test", "org", original.version, grants)
        .await
        .unwrap();
    STREAM_SCHEMAS_LATEST.write().await.insert(
        "org/logs/t".into(),
        SchemaCache::new(Schema::new(vec![Field::new(
            TIMESTAMP_COL_NAME,
            DataType::Int64,
            false,
        )])),
    );
    for (sql, column, expected) in [
        (
            "SELECT _timestamp FROM t ORDER BY _timestamp ASC",
            "_timestamp",
            [10, 20, 30],
        ),
        (
            "SELECT histogram(_timestamp, '1 hour', '+00:00') AS ts, count(*) AS c FROM t GROUP BY ts ORDER BY ts ASC",
            "ts",
            [10, 20, 30],
        ),
        (
            "SELECT histogram(_timestamp, '1 hour', '+08:00') AS ts, count(*) AS c FROM t GROUP BY ts ORDER BY c DESC",
            "ts",
            [20, 10, 30],
        ),
    ] {
        let mut request = search::Request {
            query: search::Query {
                sql: sql.into(),
                start_time: 1_735_689_600_000_000,
                end_time: 1_735_776_000_000_000,
                size: 100,
                ..Default::default()
            },
            ..Default::default()
        };
        let (prepared, execute) = caller::scope(
            Caller::User("viewer@cache.test".into()),
            prepare_cache_response(
                "scoped",
                "org",
                StreamType::Logs,
                &mut request,
                CacheMode::Bypass,
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(execute);
        assert!(prepared.file_path.is_empty());
        assert!(!prepared.has_cached_data && !prepared.cache_query_response);
        assert_eq!(prepared.ts_column, column);
        let mut response = search::Response {
            hits: vec![
                json::json!({(column): 20, "c": 3}),
                json::json!({(column): 30, "c": 1}),
                json::json!({(column): 10, "c": 2}),
            ],
            ..Default::default()
        };
        sort_response(
            prepared.is_descending,
            &mut response,
            &prepared.ts_column,
            &prepared.order_by,
        );
        assert_eq!(
            response
                .hits
                .iter()
                .map(|hit| hit[column].as_i64().unwrap())
                .collect::<Vec<_>>(),
            expected
        );
    }
    infra::rbac::replace_policy("root@cache.test", "org", 2, original.grants)
        .await
        .unwrap();
    let mut request = search::Request::default();
    request.query.sql = "SELECT _timestamp FROM t".into();
    assert!(
        caller::scope(
            Caller::User("viewer@cache.test".into()),
            prepare_cache_response(
                "revoked",
                "org",
                StreamType::Logs,
                &mut request,
                CacheMode::Bypass,
            ),
        )
        .await
        .unwrap()
        .is_err()
    );
}
