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

use std::collections::BTreeSet;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    routing::{get, patch, post},
};
use infra::rbac::{Grant, Resource, ResourceKind, Role};
use serde_json::{Value, json};
use tower::ServiceExt;

const ORG: &str = "folders_rbac";
const ROOT: &str = "root@folders.test";
const EDITOR: &str = "editor@folders.test";

fn app() -> Router {
    use crate::request::dashboards::{create_dashboard, move_dashboards};
    Router::new()
        .route(
            "/v2/{org_id}/folders/{folder_type}",
            get(super::list_folders).post(super::create_folder),
        )
        .route(
            "/v2/{org_id}/folders/{folder_type}/{folder_id}",
            get(super::get_folder),
        )
        .route(
            "/v2/{org_id}/folders/{folder_type}/name/{folder_name}",
            get(super::get_folder_by_name),
        )
        .route("/{org_id}/dashboards", post(create_dashboard))
        .route("/{org_id}/dashboards/move", patch(move_dashboards))
}

async fn call(method: &str, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header("user_id", EDITOR)
        .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
        .unwrap();
    let response = infra::rbac::caller::scope_user(EDITOR, app().oneshot(request))
        .await
        .unwrap()
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn folder(name: &str) -> String {
    let body = json!({"name": name, "description": ""});
    let (status, folder) = call("POST", &format!("/v2/{ORG}/folders/dashboards"), Some(body)).await;
    assert_eq!(status, StatusCode::OK, "{folder}");
    folder["folderId"].as_str().unwrap().to_owned()
}

async fn dashboard(folder: &str) -> String {
    let body = json!({"version": 8, "title": folder, "description": "",
        "tabs": [{"tabId": "main", "name": "Main", "panels": []}]});
    let uri = format!("/{ORG}/dashboards?folder={folder}");
    let (status, dashboard) = call("POST", &uri, Some(body)).await;
    assert_eq!(status, StatusCode::OK, "{dashboard}");
    dashboard
        .to_string()
        .split("\"dashboardId\":\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap()
        .to_owned()
}

async fn listed() -> BTreeSet<String> {
    let (status, body) = call("GET", &format!("/v2/{ORG}/folders/dashboards"), None).await;
    assert_eq!(status, StatusCode::OK);
    body["list"]
        .as_array()
        .unwrap()
        .iter()
        .map(|folder| folder["folderId"].as_str().unwrap().to_owned())
        .collect()
}

async fn grant(dashboards: &[(Role, &str)]) {
    let policy = infra::rbac::read_policy(ORG).await.unwrap();
    let mut grants: Vec<_> = policy
        .grants
        .into_iter()
        .filter(|grant| grant.role == Role::Admin)
        .collect();
    let subject = infra::rbac::user_subject(EDITOR).await.unwrap();
    for (role, id) in dashboards {
        grants.push(Grant {
            subject: subject.clone(),
            role: *role,
            resources: vec![Resource::new(ResourceKind::Dashboard, id)],
        });
    }
    infra::rbac::replace_policy(ROOT, ORG, policy.version, grants)
        .await
        .unwrap();
}

async fn fixture() {
    infra::db_init().await.unwrap();
    infra::table::migrate().await.unwrap();
    let org_type = config::meta::organization::OrganizationType::Default;
    infra::table::organizations::add(ORG, "Folders fixture", org_type)
        .await
        .unwrap();
    for (email, is_root) in [(ROOT, true), (EDITOR, false)] {
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
    let role = config::meta::user::UserRole::Editor;
    infra::table::org_users::add(ORG, EDITOR, role, "fixture-token", None)
        .await
        .unwrap();
    infra::rbac::bootstrap(ROOT, ORG).await.unwrap();
}

#[tokio::test]
async fn rbac_folders_show_only_folders_with_readable_objects() {
    if std::env::var_os("O2_FOLDERS_RBAC_CHILD").is_none() {
        let directory = std::env::temp_dir().join(format!("folders-rbac-{}", config::ider::uuid()));
        let test =
            "request::folders::rbac_tests::rbac_folders_show_only_folders_with_readable_objects";
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--nocapture"])
            .env("O2_FOLDERS_RBAC_CHILD", "1")
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
    let (team_a, team_b, team_c) = (
        folder("team-a").await,
        folder("team-b").await,
        folder("team-c").await,
    );
    let (a, b, c) = (
        dashboard(&team_a).await,
        dashboard(&team_b).await,
        dashboard(&team_c).await,
    );
    grant(&[(Role::Editor, &a), (Role::Viewer, &c)]).await;

    let visible = listed().await;
    assert!(visible.contains(&team_a) && visible.contains(&team_c));
    assert!(!visible.contains(&team_b));
    let get = |path: String| async move {
        call("GET", &format!("/v2/{ORG}/folders/{path}"), None)
            .await
            .0
    };
    assert_eq!(get(format!("dashboards/{team_a}")).await, StatusCode::OK);
    assert_eq!(
        get(format!("dashboards/{team_b}")).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        get("dashboards/name/team-b".into()).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        get("dashboards/missing".into()).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(get("workflows".into()).await, StatusCode::FORBIDDEN);

    let mv = |ids: Vec<&String>, dst: &String| {
        let body = json!({"dashboard_ids": ids, "dst_folder_id": dst});
        async move {
            call("PATCH", &format!("/{ORG}/dashboards/move"), Some(body))
                .await
                .0
        }
    };
    assert_eq!(
        mv(vec![&a], &team_b).await,
        StatusCode::FORBIDDEN,
        "hidden destination"
    );
    assert_eq!(
        mv(vec![&c], &team_a).await,
        StatusCode::FORBIDDEN,
        "read-only dashboard"
    );
    assert_eq!(
        mv(vec![&a, &b], &team_c).await,
        StatusCode::FORBIDDEN,
        "one unwritable"
    );
    assert_eq!(listed().await, visible, "a refused batch moves nothing");
    assert_eq!(mv(vec![&a], &team_c).await, StatusCode::OK);
    assert!(!listed().await.contains(&team_a));

    grant(&[(Role::Viewer, "*")]).await;
    assert!(
        listed()
            .await
            .is_superset(&BTreeSet::from([team_a, team_b, team_c]))
    );
}
