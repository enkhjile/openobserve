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
    routing::{post, put},
};
use serde_json::{Value, json};
use tower::ServiceExt;

use super::*;

fn app() -> Router {
    Router::new()
        .route("/{org_id}/savedviews", post(create_view).get(get_views))
        .route(
            "/{org_id}/savedviews/{view_id}",
            put(update_view).get(get_view),
        )
}

async fn call(method: &str, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header("user_id", "viewer@example.com")
        .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
        .unwrap();
    let resp = app().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn create(org: &str, name: &str, view_type: Option<&str>) -> (StatusCode, Value) {
    let mut body = json!({"data": {"v": 1}, "view_name": name});
    if let Some(t) = view_type {
        body["view_type"] = json!(t);
    }
    call("POST", &format!("/{org}/savedviews"), Some(body)).await
}

async fn list(org: &str) -> Vec<Value> {
    let (status, body) = call("GET", &format!("/{org}/savedviews"), None).await;
    assert_eq!(status, StatusCode::OK);
    body["views"].as_array().cloned().unwrap_or_default()
}

fn new_org() -> String {
    format!("svorg{}", config::ider::uuid()).to_lowercase()
}

#[tokio::test]
async fn rbac_saved_view_listing_filters_metadata_and_revocation() {
    if std::env::var_os("O2_SAVED_VIEW_RBAC_CHILD").is_none() {
        let directory =
            std::env::temp_dir().join(format!("saved-view-rbac-{}", config::ider::uuid()));
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "search::saved_view::rbac_tests::rbac_saved_view_listing_filters_metadata_and_revocation", "--nocapture"])
            .env("O2_SAVED_VIEW_RBAC_CHILD", "1").env("ZO_RBAC_ENABLED", "true")
            .env("ZO_DATA_DIR", &directory).status().unwrap();
        if directory.exists() {
            std::fs::remove_dir_all(directory).unwrap();
        }
        assert!(status.success());
        return;
    }
    infra::db::create_table().await.unwrap();
    infra::table::create_user_tables().await.unwrap();
    let user = infra::table::users::UserRecord {
        email: "viewer@example.com".into(),
        first_name: String::new(),
        last_name: String::new(),
        password: String::new(),
        salt: String::new(),
        is_root: false,
        password_ext: None,
        user_type: config::meta::user::UserType::Internal,
        created_at: 0,
        updated_at: 0,
        must_reset_password: false,
        password_reset_reason: None,
        flagged_at: None,
        password_updated_at: None,
    };
    infra::table::users::add(user).await.unwrap();
    let org = new_org();
    infra::table::organizations::add(
        &org,
        "Saved view fixture",
        config::meta::organization::OrganizationType::Default,
    )
    .await
    .unwrap();
    infra::table::org_users::add(
        &org,
        "viewer@example.com",
        config::meta::user::UserRole::Viewer,
        "fixture-token",
        None,
    )
    .await
    .unwrap();
    let (_, allowed) = create(&org, "visible", None).await;
    let (_, hidden) = create(&org, "secret-metadata", Some("traces")).await;
    let subject = infra::rbac::user_subject("viewer@example.com")
        .await
        .unwrap();
    let mut policy = infra::rbac::PolicyDocument {
        destination_approvals: vec![],
        schema_version: 1,
        version: 1,
        organization: org.clone(),
        grants: vec![infra::rbac::Grant {
            subject,
            role: infra::rbac::Role::Viewer,
            resources: vec![infra::rbac::Resource::new(
                infra::rbac::ResourceKind::SavedQuery,
                allowed["view_id"].as_str().unwrap(),
            )],
        }],
    };
    let key = format!("/rbac/{org}/policy");
    db::put(
        &key,
        serde_json::to_vec(&policy).unwrap().into(),
        infra::db::NO_NEED_WATCH,
        None,
    )
    .await
    .unwrap();
    let (status, response) = call("GET", &format!("/{org}/savedviews"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["views"].as_array().unwrap().len(), 1);
    assert_eq!(response["views"][0]["view_id"], allowed["view_id"]);
    assert!(!response.to_string().contains("secret-metadata"));
    assert!(
        !response
            .to_string()
            .contains(hidden["view_id"].as_str().unwrap())
    );
    assert!(response.get("total").is_none());
    policy.version += 1;
    policy.grants[0].resources[0].name = "different-view".into();
    db::put(
        &key,
        serde_json::to_vec(&policy).unwrap().into(),
        infra::db::NO_NEED_WATCH,
        None,
    )
    .await
    .unwrap();
    assert!(list(&org).await.is_empty());
    db::delete(&key, false, infra::db::NO_NEED_WATCH, None)
        .await
        .unwrap();
    assert_eq!(
        call("GET", &format!("/{org}/savedviews"), None).await.0,
        StatusCode::FORBIDDEN
    );
}
