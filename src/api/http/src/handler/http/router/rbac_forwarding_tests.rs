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
    body::{Body, to_bytes},
    extract::Request,
    http::{StatusCode, header},
    middleware,
};
use config::meta::{
    cluster::{NodeStatus, Role, RoleGroup},
    user::{UserRole, UserType},
};
use tower::ServiceExt;

use super::rbac;

const PASSWORD: &str = "Router-fixture-only!123";

#[tokio::test]
async fn rbac_router_forwards_scoped_requests_only_to_enforcing_mount() {
    if std::env::var("O2_RBAC_ROUTER_CHILD").as_deref() != Ok("1") {
        let dir = std::env::temp_dir().join(format!("rbac-router-{}", config::ider::uuid()));
        std::fs::create_dir_all(&dir).unwrap();
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "rbac_router_forwards_scoped_requests_only_to_enforcing_mount",
                "--nocapture",
            ])
            .env("O2_RBAC_ROUTER_CHILD", "1")
            .env("ZO_RBAC_ENABLED", "true")
            .env("ZO_LOCAL_MODE", "true")
            .env("ZO_META_STORE", "sqlite")
            .env("ZO_NODE_ROLE", "all")
            .env("ZO_BASE_URI", "/o2")
            .env("ZO_DATA_DIR", dir.join("data"))
            .current_dir(&dir)
            .status()
            .unwrap();
        assert!(result.success());
        std::fs::remove_dir_all(dir).unwrap();
        return;
    }
    seed_identities().await;
    let backend = super::create_app_router(|_| Router::new());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, backend).await.unwrap() });
    assert_backend_preflight(address).await;
    let mut node = config::cluster::LOCAL_NODE.clone();
    node.uuid = "rbac-router-backend".into();
    node.name = node.uuid.clone();
    node.http_addr = format!("http://{address}");
    node.role = vec![Role::Ingester, Role::Querier];
    node.role_group = RoleGroup::Interactive;
    node.scheduled = true;
    node.status = NodeStatus::Online;
    infra::cluster::add_node_to_cache(node.clone()).await;

    let response = request(
        "GET",
        "/o2/api/router-org/rbac/me",
        Some("viewer@example.test"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let value: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
    assert_eq!(value["grants"][0]["resources"][0]["name"], "permitted");
    assert_eq!(
        request(
            "GET",
            "/o2/api/router-org/users",
            Some("viewer@example.test")
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(
            "POST",
            "/o2/api/router-org/_bulk",
            Some("root@example.test")
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request("GET", "/o2/api/public_dashboards/slug/data", None)
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request("GET", "/o2/api/router-org/rbac/me", None)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );

    let root = infra::rbac::read_policy("router-org").await.unwrap();
    let grants = root
        .grants
        .into_iter()
        .filter(|grant| grant.subject != value["subject"].as_str().unwrap())
        .collect();
    infra::rbac::replace_policy("root@example.test", "router-org", root.version, grants)
        .await
        .unwrap();
    assert_eq!(
        request(
            "GET",
            "/o2/api/router-org/rbac/me",
            Some("viewer@example.test")
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );

    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
    let old_listener = tokio::net::TcpListener::bind(address).await.unwrap();
    let old = Router::new().route(
        "/o2/api/router-org/rbac/me",
        axum::routing::get(|| async { "unguarded data" }),
    );
    let old = old.route(
        "/o2/api/router-org/permitted/_json",
        axum::routing::post(|| async { StatusCode::CREATED }),
    );
    let old_server = tokio::spawn(async move { axum::serve(old_listener, old).await.unwrap() });
    assert_eq!(
        request(
            "GET",
            "/o2/api/router-org/rbac/me",
            Some("root@example.test")
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        request(
            "POST",
            "/o2/api/router-org/permitted/_json",
            Some("root@example.test")
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );
    old_server.abort();
}

async fn assert_backend_preflight(address: std::net::SocketAddr) {
    let client = reqwest::Client::new();
    let origin = url::Url::parse(&config::get_config().common.web_url)
        .unwrap()
        .origin()
        .ascii_serialization();
    let url = format!("http://{address}/o2/api/router-org/future");
    let response = client
        .request(reqwest::Method::OPTIONS, &url)
        .header(header::ORIGIN, &origin)
        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
        origin
    );
    assert!(response.bytes().await.unwrap().is_empty());
    assert_eq!(
        client.post(url).send().await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
}

async fn request(method: &str, path: &str, email: Option<&str>) -> axum::response::Response {
    let app = Router::new()
        .nest("/o2", crate::router::http::create_router_routes())
        .layer(middleware::from_fn(rbac::route_gate))
        .layer(super::cors_layer());
    let mut request = Request::builder().method(method).uri(path);
    if let Some(email) = email {
        request = request.header(
            header::AUTHORIZATION,
            format!(
                "Basic {}",
                config::utils::base64::encode(&format!("{email}:{PASSWORD}"))
            ),
        );
    }
    app.oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

async fn seed_identities() {
    infra::db::create_table().await.unwrap();
    infra::table::create_user_tables().await.unwrap();
    openobserve_core::organization::check_and_create_org_without_ofga("router-org")
        .await
        .unwrap();
    for (email, root, role) in [
        ("root@example.test", true, UserRole::Root),
        ("viewer@example.test", false, UserRole::Viewer),
    ] {
        infra::table::users::add(infra::table::users::UserRecord {
            email: email.into(),
            first_name: "Router".into(),
            last_name: "Fixture".into(),
            password: openobserve_core::auth::get_hash(PASSWORD, "router-salt"),
            salt: "router-salt".into(),
            is_root: root,
            password_ext: None,
            user_type: UserType::Internal,
            created_at: 0,
            updated_at: 0,
            must_reset_password: false,
            password_reset_reason: None,
            flagged_at: None,
            password_updated_at: None,
        })
        .await
        .unwrap();
        db::org_users::add("router-org", email, role, "fixture-token", None)
            .await
            .unwrap();
    }
    let policy = infra::rbac::bootstrap("root@example.test", "router-org")
        .await
        .unwrap();
    let mut grants = policy.grants;
    grants.push(infra::rbac::Grant {
        subject: infra::rbac::user_subject("viewer@example.test")
            .await
            .unwrap(),
        role: infra::rbac::Role::Viewer,
        resources: vec![infra::rbac::Resource::stream("logs", "permitted")],
    });
    infra::rbac::replace_policy("root@example.test", "router-org", policy.version, grants)
        .await
        .unwrap();
}

#[tokio::test]
async fn rbac_cors_preflight_never_executes_protected_handler() {
    let app = Router::new()
        .route(
            "/api/{org_id}/future",
            axum::routing::get(|| async { "sensitive data" }),
        )
        .layer(middleware::from_fn(|request, next| {
            rbac::gate(true, request, next)
        }))
        .layer(super::cors_layer());
    let origin = url::Url::parse(&config::get_config().common.web_url)
        .unwrap()
        .origin()
        .ascii_serialization();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/api/org/future")
                .header(header::ORIGIN, &origin)
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
        origin
    );
    assert!(
        to_bytes(response.into_body(), 65536)
            .await
            .unwrap()
            .is_empty()
    );
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/org/future")
                .header(header::ORIGIN, origin)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn rbac_forwarding_rejects_disabled_data_node() {
    if std::env::var("O2_RBAC_DISABLED_ROUTER_CHILD").as_deref() != Ok("1") {
        let dir =
            std::env::temp_dir().join(format!("rbac-disabled-router-{}", config::ider::uuid()));
        std::fs::create_dir_all(&dir).unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["rbac_forwarding_rejects_disabled_data_node", "--nocapture"])
            .env("O2_RBAC_DISABLED_ROUTER_CHILD", "1")
            .env("ZO_RBAC_ENABLED", "false")
            .env("ZO_NODE_ROLE", "all")
            .env("ZO_BASE_URI", "")
            .env("ZO_DATA_DIR", dir.join("data"))
            .current_dir(&dir)
            .status()
            .unwrap();
        assert!(status.success());
        std::fs::remove_dir_all(dir).unwrap();
        return;
    }
    let app = super::create_app_router(|_| Router::new()).layer(middleware::from_fn(
        |request: Request, next: axum::middleware::Next| async move {
            assert!(
                request
                    .extensions()
                    .get::<axum::extract::MatchedPath>()
                    .is_none()
            );
            next.run(request).await
        },
    ));
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/internal/rbac/v1/api/org/stream/_json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let retained_mount = Router::new()
        .route("/", axum::routing::post(|| async { "write" }))
        .layer(middleware::from_fn(rbac::require_enabled_forwarding));
    let response = retained_mount
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
