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

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    routing::post,
};
use infra::rbac::{Grant, Resource, Role};
use serde_json::json;
use tower::ServiceExt;

const ORG: &str = "values_rbac";
const ROOT: &str = "root@values.test";
const VIEWER: &str = "viewer@values.test";

async fn values(stream: &str) -> StatusCode {
    let body = json!({"fields": ["missing_field"], "no_count": false, "stream_name": stream,
        "stream_type": "logs", "sql": ""});
    let request = Request::builder()
        .method("POST")
        .uri(format!("/{ORG}/_values_stream"))
        .header("content-type", "application/json")
        .header("user_id", VIEWER)
        .body(Body::from(body.to_string()))
        .unwrap();
    let app = Router::new().route("/{org_id}/_values_stream", post(super::values_http2_stream));
    infra::rbac::caller::scope_user(VIEWER, app.oneshot(request))
        .await
        .unwrap()
        .unwrap()
        .status()
}

async fn fixture() {
    infra::db_init().await.unwrap();
    infra::table::migrate().await.unwrap();
    let org_type = config::meta::organization::OrganizationType::Default;
    infra::table::organizations::add(ORG, "Values fixture", org_type)
        .await
        .unwrap();
    for (email, is_root) in [(ROOT, true), (VIEWER, false)] {
        infra::table::users::add(infra::table::users::UserRecord {
            email: email.into(),
            first_name: String::new(),
            last_name: String::new(),
            password: String::new(),
            salt: String::new(),
            is_root,
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
    let role = config::meta::user::UserRole::Viewer;
    infra::table::org_users::add(ORG, VIEWER, role, "fixture-token", None)
        .await
        .unwrap();
    let policy = infra::rbac::bootstrap(ROOT, ORG).await.unwrap();
    let mut grants = policy.grants;
    grants.push(Grant {
        subject: infra::rbac::user_subject(VIEWER).await.unwrap(),
        role: Role::Viewer,
        resources: vec![Resource::stream("logs", "allowed")],
    });
    infra::rbac::replace_policy(ROOT, ORG, policy.version, grants)
        .await
        .unwrap();
}

/// An unreadable stream is refused before its schema shows which fields exist.
#[tokio::test]
async fn rbac_values_stream_checks_the_stream_before_reading_its_fields() {
    if std::env::var_os("O2_VALUES_RBAC_CHILD").is_none() {
        let directory = std::env::temp_dir().join(format!("values-rbac-{}", config::ider::uuid()));
        let test = "search::search_stream::rbac_tests::rbac_values_stream_checks_the_stream_before_reading_its_fields";
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--nocapture"])
            .env("O2_VALUES_RBAC_CHILD", "1")
            .env("ZO_RBAC_ENABLED", "true")
            .env("ZO_DATA_DIR", &directory)
            .status()
            .unwrap();
        if directory.exists() {
            std::fs::remove_dir_all(directory).unwrap();
        }
        assert!(status.success());
        return;
    }
    fixture().await;
    assert_eq!(values("secret").await, StatusCode::FORBIDDEN);
    assert_eq!(values("allowed").await, StatusCode::BAD_REQUEST);
}
