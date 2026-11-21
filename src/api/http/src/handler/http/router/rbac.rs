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
    Json,
    extract::{FromRequestParts, MatchedPath, Path, RawPathParams, Request},
    http::{Method, StatusCode, request::Parts},
    middleware::Next,
    response::{IntoResponse, Response},
};
use infra::rbac::{self, Action, Resource, ResourceKind};
use serde::Deserialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Disposition {
    Public,
    Identity,
    Member,
    Query,
    MetricsQuery,
    Permission(Action, ResourceKind, &'static str),
    Unsupported,
}

#[derive(Clone)]
pub(super) struct VerifiedUser(pub String);

#[derive(Deserialize)]
pub(super) struct PolicyUpdate {
    expected_version: u64,
    grants: Vec<rbac::Grant>,
}

pub(super) fn disposition(method: &str, path: &str) -> Disposition {
    use Disposition::{Identity, Member, MetricsQuery, Permission, Public, Query, Unsupported};
    use ResourceKind::{Alert, Dashboard, Organization, Report, SavedQuery, Stream};
    match (method, path) {
        ("GET" | "HEAD", "/healthz")
        | ("GET", "/config/" | "/config")
        | ("GET" | "POST", "/auth/login")
        | ("GET", "/config/logout") => Public,
        ("POST", "/api/{org_id}/rbac/destinations/available") => Member,
        ("GET", "/api/{org_id}/rbac/me") | ("POST", "/api/{org_id}/rbac/bootstrap") => Identity,
        ("PUT", "/api/{org_id}/rbac/destinations")
        | ("GET" | "PUT", "/api/{org_id}/rbac/policy")
        | ("GET", "/api/{org_id}/rbac/subjects") => Permission(Action::Manage, Organization, ""),
        ("POST", "/api/{org_id}/_search")
        | ("POST", "/api/{org_id}/_search_multi")
        | ("POST", "/api/{org_id}/_search_stream")
        | ("POST", "/api/{org_id}/_search_multi_stream")
        | ("POST", "/api/{org_id}/_search_partition")
        | ("POST", "/api/{org_id}/_search_partition_multi") => Query,
        ("GET" | "POST", "/api/{org_id}/prometheus/api/v1/query")
        | ("GET" | "POST", "/api/{org_id}/prometheus/api/v1/query_range") => MetricsQuery,
        ("GET", "/api/organizations") => Identity,
        ("GET", "/api/{org_id}/config") => Member,
        ("GET" | "POST", "/api/{org_id}/settings")
        | ("GET" | "POST", "/api/{org_id}/users")
        | ("POST" | "PUT" | "DELETE", "/api/{org_id}/users/{email_id}")
        | ("GET", "/api/{org_id}/users/roles")
        | ("GET" | "POST", "/api/{org_id}/ingestion-tokens")
        | ("PATCH", "/api/{org_id}/ingestion-tokens/{name}")
        | ("GET" | "POST", "/api/{org_id}/alerts/templates")
        | ("GET" | "PUT" | "DELETE", "/api/{org_id}/alerts/templates/{template_name}")
        | ("GET" | "POST", "/api/{org_id}/alerts/destinations")
        | ("GET" | "PUT" | "DELETE", "/api/{org_id}/alerts/destinations/{destination_name}")
        | ("GET" | "POST", "/api/{org_id}/service_accounts")
        | ("PUT" | "DELETE", "/api/{org_id}/service_accounts/{email_id}") => {
            Permission(Action::Manage, Organization, "")
        }
        ("GET", "/api/{org_id}/streams") => Member,
        ("POST", "/api/{org_id}/ingest/metrics/_json") => Member,
        ("POST", "/api/{org_id}/v1/traces" | "/api/{org_id}/otel/v1/traces") => Member,
        ("POST", "/api/{org_id}/v1/logs") => Member,
        (
            "GET",
            "/api/{org_id}/{stream_name}/traces/latest"
            | "/api/{org_id}/{stream_name}/traces/latest_stream",
        ) => Query,
        ("POST", "/api/{org_id}/{stream_name}/_json" | "/api/{org_id}/{stream_name}/_multi") => {
            Permission(Action::Ingest, Stream, "stream_name")
        }
        ("GET", "/api/{org_id}/streams/{stream_name}/schema") => {
            Permission(Action::Read, Stream, "stream_name")
        }
        ("POST", "/api/{org_id}/streams/{stream_name}")
        | ("PUT", "/api/{org_id}/streams/{stream_name}/settings") => {
            Permission(Action::Write, Stream, "stream_name")
        }
        ("DELETE", "/api/{org_id}/streams/{stream_name}") => {
            Permission(Action::Delete, Stream, "stream_name")
        }
        ("GET", "/api/v2/{org_id}/reports") => Member,
        ("POST", "/api/v2/{org_id}/reports") => Permission(Action::Write, Report, "*"),
        ("GET", "/api/v2/{org_id}/reports/{report_id}") => {
            Permission(Action::Read, Report, "report_id")
        }
        ("PUT", "/api/v2/{org_id}/reports/{report_id}") => {
            Permission(Action::Write, Report, "report_id")
        }
        ("DELETE", "/api/v2/{org_id}/reports/{report_id}") => {
            Permission(Action::Delete, Report, "report_id")
        }
        ("PUT", "/api/v2/{org_id}/reports/{report_id}/trigger") => {
            Permission(Action::Write, Report, "report_id")
        }
        ("GET", "/api/v2/{org_id}/alerts") => Member,
        ("POST", "/api/v2/{org_id}/alerts") => Permission(Action::Write, Alert, "*"),
        ("GET", "/api/v2/{org_id}/alerts/{alert_id}") => {
            Permission(Action::Read, Alert, "alert_id")
        }
        ("PUT", "/api/v2/{org_id}/alerts/{alert_id}") => {
            Permission(Action::Write, Alert, "alert_id")
        }
        ("DELETE", "/api/v2/{org_id}/alerts/{alert_id}") => {
            Permission(Action::Delete, Alert, "alert_id")
        }
        ("GET", "/api/{org_id}/dashboards") => Member,
        ("POST", "/api/{org_id}/dashboards") => Permission(Action::Write, Dashboard, "*"),
        ("GET", "/api/{org_id}/dashboards/{dashboard_id}") => {
            Permission(Action::Read, Dashboard, "dashboard_id")
        }
        ("PUT", "/api/{org_id}/dashboards/{dashboard_id}")
        | ("POST", "/api/{org_id}/dashboards/{dashboard_id}/panels")
        | ("PUT" | "DELETE", "/api/{org_id}/dashboards/{dashboard_id}/panels/{panel_id}") => {
            Permission(Action::Write, Dashboard, "dashboard_id")
        }
        ("DELETE", "/api/{org_id}/dashboards/{dashboard_id}") => {
            Permission(Action::Delete, Dashboard, "dashboard_id")
        }
        ("GET" | "PUT", "/api/{org_id}/pipelines") => Member,
        ("POST", "/api/{org_id}/pipelines") => {
            Permission(Action::Write, ResourceKind::Pipeline, "*")
        }
        ("GET", "/api/{org_id}/pipelines/{pipeline_id}") => {
            Permission(Action::Read, ResourceKind::Pipeline, "pipeline_id")
        }
        ("DELETE", "/api/{org_id}/pipelines/{pipeline_id}") => {
            Permission(Action::Delete, ResourceKind::Pipeline, "pipeline_id")
        }
        ("GET", "/api/{org_id}/savedviews") => Member,
        ("POST", "/api/{org_id}/savedviews") => Permission(Action::Write, SavedQuery, "*"),
        ("GET", "/api/{org_id}/savedviews/{view_id}") => {
            Permission(Action::Read, SavedQuery, "view_id")
        }
        ("PUT", "/api/{org_id}/savedviews/{view_id}") => {
            Permission(Action::Write, SavedQuery, "view_id")
        }
        ("DELETE", "/api/{org_id}/savedviews/{view_id}") => {
            Permission(Action::Delete, SavedQuery, "view_id")
        }
        _ => Unsupported,
    }
}

pub(super) fn forbidden() -> Response {
    (StatusCode::FORBIDDEN, Json(serde_json::json!({
        "code": 403, "message": "Access denied by organization RBAC policy", "reason": "rbac_denied"
    }))).into_response()
}

pub(super) async fn require_enabled_forwarding(request: Request, next: Next) -> Response {
    if !rbac::enabled() {
        return forbidden();
    }
    next.run(request).await
}

pub(super) async fn route_gate(request: Request, next: Next) -> Response {
    gate(rbac::enabled(), request, next).await
}

pub(super) async fn authorize(
    parts: &mut Parts,
    email: &str,
    has_user_role: bool,
    token_name: Option<&str>,
) -> Result<(), Response> {
    if !rbac::enabled() {
        parts.extensions.insert(VerifiedUser(email.to_owned()));
        return Ok(());
    }
    authorize_enabled(parts, email, has_user_role, token_name).await
}

pub(super) async fn me(
    Path(org): Path<String>,
    axum::Extension(user): axum::Extension<VerifiedUser>,
) -> Response {
    if !rbac::enabled() {
        return Json(serde_json::json!({"enabled": false, "can_manage": false, "grants": []}))
            .into_response();
    }
    let result = async {
        let can_manage = rbac::authorize_user(&user.0, &org, Action::Manage, Resource::organization()).await.is_ok();
        let subject = rbac::user_subject(&user.0).await?;
        rbac::validate_subject(&subject, &org).await?;
        let policy = rbac::read_policy(&org).await?;
        let grants: Vec<_> = policy.grants.into_iter().filter(|grant| grant.subject == subject).collect();
        anyhow::ensure!(!grants.is_empty(), "No organization grants");
        Ok::<_, anyhow::Error>(Json(serde_json::json!({"enabled": true, "subject": subject, "version": policy.version, "grants": grants, "can_manage": can_manage})))
    }.await;
    match result {
        Ok(body) => body.into_response(),
        Err(_) => forbidden(),
    }
}

pub(super) async fn get_policy(Path(org): Path<String>) -> Response {
    if !rbac::enabled() {
        return forbidden();
    }
    match rbac::read_policy(&org).await {
        Ok(policy) => Json(policy).into_response(),
        Err(_) => forbidden(),
    }
}

pub(super) async fn put_policy(
    Path(org): Path<String>,
    axum::Extension(user): axum::Extension<VerifiedUser>,
    Json(update): Json<PolicyUpdate>,
) -> Response {
    if !rbac::enabled() {
        return forbidden();
    }
    match rbac::replace_policy(&user.0, &org, update.expected_version, update.grants).await {
        Ok(policy) => Json(policy).into_response(),
        Err(_) => forbidden(),
    }
}

pub(super) async fn bootstrap(
    Path(org): Path<String>,
    axum::Extension(user): axum::Extension<VerifiedUser>,
) -> Response {
    if !rbac::enabled() {
        return forbidden();
    }
    match rbac::bootstrap(&user.0, &org).await {
        Ok(policy) => Json(policy).into_response(),
        Err(_) => forbidden(),
    }
}

pub(super) async fn organizations(
    headers: openobserve_api_common::extractors::Headers<openobserve_core::auth::UserEmail>,
    query: axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    if !rbac::enabled() {
        return openobserve_api_management::request::organization::org::organizations(
            headers, query,
        )
        .await;
    }
    use common::meta::organization::{OrgDetails, OrgUser, OrganizationResponse, THRESHOLD};

    let email = &headers.0.user_id;
    let result = async {
        let organizations = rbac::visible_organizations(email).await?;
        let data = organizations
            .into_iter()
            .enumerate()
            .map(|(index, org)| OrgDetails {
                id: index as i64 + 1,
                identifier: org.identifier,
                name: org.org_name,
                user_email: email.clone(),
                org_type: config::meta::organization::OrganizationType::from(org.org_type)
                    .to_string(),
                created_at: org.created_at,
                user_obj: OrgUser {
                    email: email.clone(),
                    first_name: String::new(),
                    last_name: String::new(),
                },
                owner_email: String::new(),
                owner_first_name: String::new(),
                plan: 0,
                ingest_threshold: THRESHOLD,
                search_threshold: THRESHOLD,
            })
            .collect();
        Ok::<_, anyhow::Error>(Json(OrganizationResponse { data }))
    }
    .await;
    match result {
        Ok(body) => body.into_response(),
        Err(_) => forbidden(),
    }
}

pub(super) async fn subjects(Path(org): Path<String>) -> Response {
    if !rbac::enabled() {
        return forbidden();
    }
    let result = async {
        let mut subjects: Vec<_> = rbac::member_subjects(&org).await?.into_iter()
            .map(|(subject, email)| serde_json::json!({"subject": subject, "email": email})).collect();
        for token in rbac::ingestion_token_subjects(&org).await? {
            subjects.push(serde_json::json!({"subject": token.subject, "name": token.name, "kind": "ingestion_token"}));
        }
        Ok::<_, anyhow::Error>(Json(subjects))
    }
    .await;
    match result {
        Ok(body) => body.into_response(),
        Err(_) => forbidden(),
    }
}

pub(super) fn canonical_route(path: &str) -> &str {
    let base = &config::get_config().common.base_uri;
    let path = if base.is_empty() || base == "/" {
        path
    } else {
        path.strip_prefix(base.trim_end_matches('/'))
            .unwrap_or(path)
    };
    path.strip_prefix(crate::router::http::RBAC_FORWARD_PREFIX)
        .unwrap_or(path)
}

pub(super) async fn gate(enabled: bool, request: Request, next: Next) -> Response {
    if !enabled {
        return next.run(request).await;
    }
    let path = request
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str())
        .unwrap_or("");
    let path = canonical_route(path);
    let static_asset =
        request.method() == Method::GET && matches!(path, "/" | "/web" | "/web/" | "/web/{*path}");
    if !static_asset && disposition(request.method().as_str(), path) == Disposition::Unsupported {
        return forbidden();
    }
    next.run(request).await
}

async fn authorize_enabled(
    parts: &mut Parts,
    email: &str,
    has_user_role: bool,
    token_name: Option<&str>,
) -> Result<(), Response> {
    if let Some(principal) = parts
        .extensions
        .get::<config::meta::user::OrgIngestionPrincipal>()
        .cloned()
    {
        let route = parts
            .extensions
            .get::<MatchedPath>()
            .map(|path| canonical_route(path.as_str()))
            .unwrap_or("");
        if parts.method != axum::http::Method::POST
            || !matches!(
                route,
                "/api/{org_id}/{stream_name}/_json"
                    | "/api/{org_id}/{stream_name}/_multi"
                    | "/api/{org_id}/ingest/metrics/_json"
                    | "/api/{org_id}/v1/traces"
                    | "/api/{org_id}/otel/v1/traces"
                    | "/api/{org_id}/v1/logs"
            )
        {
            return Err(forbidden());
        }
        let params = RawPathParams::from_request_parts(parts, &())
            .await
            .map_err(|_| forbidden())?;
        let org = params
            .iter()
            .find(|(key, _)| *key == "org_id")
            .map(|(_, value)| value)
            .ok_or_else(forbidden)?;
        if org != principal.org_id {
            return Err(forbidden());
        }
        rbac::allowed_ingestion_token_resources(org, &principal.token_id, &[])
            .await
            .map_err(|_| forbidden())?;
        return Ok(());
    }
    if !has_user_role || token_name.is_some() {
        return Err(forbidden());
    }
    let path = parts
        .extensions
        .get::<MatchedPath>()
        .map(|p| p.as_str())
        .unwrap_or("");
    let rule = disposition(parts.method.as_str(), canonical_route(path));
    if rule == Disposition::Identity {
        parts.extensions.insert(VerifiedUser(email.to_owned()));
        return Ok(());
    }
    let params = RawPathParams::from_request_parts(parts, &())
        .await
        .map_err(|_| forbidden())?;
    let org = params
        .iter()
        .find(|(key, _)| *key == "org_id")
        .map(|(_, value)| value)
        .ok_or_else(forbidden)?;
    match rule {
        Disposition::Identity => {}
        Disposition::Member => {
            let subject = rbac::user_subject(email).await.map_err(|_| forbidden())?;
            rbac::validate_subject(&subject, org)
                .await
                .map_err(|_| forbidden())?;
            let policy = rbac::read_policy(org).await.map_err(|_| forbidden())?;
            if !policy.grants.iter().any(|grant| grant.subject == subject) {
                return Err(forbidden());
            }
        }
        Disposition::Query | Disposition::MetricsQuery => {
            // Resolved-source checks own data access; this rejects an uninitialized org before
            // parsing.
            rbac::read_policy(org).await.map_err(|_| forbidden())?;
        }
        Disposition::Permission(action, kind, parameter) => {
            let name = if parameter == "*" || parameter.is_empty() {
                parameter
            } else {
                params
                    .iter()
                    .find(|(key, _)| *key == parameter)
                    .map(|(_, value)| value)
                    .ok_or_else(forbidden)?
            };
            let resource = resource_for(parts, kind, name)?;
            rbac::authorize_user(email, org, action, resource)
                .await
                .map_err(|_| forbidden())?;
        }
        Disposition::Public | Disposition::Unsupported => return Err(forbidden()),
    }
    parts.extensions.insert(VerifiedUser(email.to_owned()));
    Ok(())
}

fn resource_for(parts: &Parts, kind: ResourceKind, name: &str) -> Result<Resource, Response> {
    if kind == ResourceKind::Organization {
        return Ok(Resource::organization());
    }
    if kind != ResourceKind::Stream {
        return Ok(Resource::new(kind, name));
    }
    if name != "*"
        && !config::get_config().common.skip_formatting_stream_name
        && config::utils::schema::format_stream_name(name.to_owned()) != name
    {
        return Err(forbidden());
    }
    let types: Vec<_> = url::form_urlencoded::parse(parts.uri.query().unwrap_or("").as_bytes())
        .filter(|(key, _)| key == "type")
        .map(|(_, value)| value.into_owned())
        .collect();
    if types.len() > 1 {
        return Err(forbidden());
    }
    let stream_type = types.first().map(String::as_str).unwrap_or("logs");
    if !matches!(stream_type, "logs" | "metrics" | "traces") {
        return Err(forbidden());
    }
    Ok(Resource::stream(stream_type, name))
}

#[cfg(test)]
mod tests {
    use axum::{Router, body::Body, middleware, routing::get};
    use tower::ServiceExt;

    use super::*;

    #[tokio::test]
    async fn ingestion_credential_cannot_be_used_as_a_user_without_an_adapted_route() {
        let request = Request::builder()
            .method("POST")
            .uri("/api/org/_search")
            .body(Body::empty())
            .unwrap();
        let (mut parts, _) = request.into_parts();
        parts
            .extensions
            .insert(config::meta::user::OrgIngestionPrincipal {
                org_id: "org".into(),
                token_id: "credential-id".into(),
            });
        assert!(
            authorize_enabled(&mut parts, "root@example.test", true, None)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn unknown_direct_api_and_alternate_auth_routes_deny() {
        for path in [
            "/api/org/future",
            "/aws/org/logs/_kinesis_firehose",
            "/api/public_dashboards/slug/data",
            "/proxy/org/target",
        ] {
            let app = Router::new()
                .route(path, get(|| async { "sensitive" }))
                .layer(middleware::from_fn(|req, next| gate(true, req, next)));
            let response = app
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .header("user_id", "root@example.com")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");
        }
    }

    #[tokio::test]
    async fn disabled_mode_and_public_health_retain_behavior() {
        for (enabled, path) in [(false, "/api/org/future"), (true, "/healthz")] {
            let app = Router::new()
                .route(path, get(|| async { "ok" }))
                .layer(middleware::from_fn(move |req, next| {
                    gate(enabled, req, next)
                }));
            let response = app
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn serving_router_denies_unsupported_operations_before_authentication() {
        for (method, path) in [
            ("POST", "/api/org/_bulk"),
            ("GET", "/api/public_dashboards/slug/data"),
            ("POST", "/api/org/prometheus/api/v1/query_exemplars"),
        ] {
            let app = super::super::create_app_router(|_| Router::new())
                .layer(middleware::from_fn(|req, next| gate(true, req, next)));
            let response = app
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .header("user_id", "root@example.com")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");
        }
    }

    #[tokio::test]
    async fn future_web_api_is_not_a_static_asset_exception() {
        let app = Router::new()
            .route("/web/admin/export", get(|| async { "secret" }))
            .layer(middleware::from_fn(|req, next| gate(true, req, next)));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/web/admin/export")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn only_scoped_promql_execution_routes_are_declared() {
        for method in ["GET", "POST"] {
            for endpoint in ["query", "query_range"] {
                assert_eq!(
                    disposition(
                        method,
                        &format!("/api/{{org_id}}/prometheus/api/v1/{endpoint}")
                    ),
                    Disposition::MetricsQuery
                );
            }
            for endpoint in [
                "query_exemplars",
                "query_data",
                "metadata",
                "series",
                "labels",
                "format_query",
                "parse_tree",
                "write",
            ] {
                assert_eq!(
                    disposition(
                        method,
                        &format!("/api/{{org_id}}/prometheus/api/v1/{endpoint}")
                    ),
                    Disposition::Unsupported
                );
            }
        }
        assert_eq!(
            disposition("POST", "/api/{org_id}/ingest/metrics/_json"),
            Disposition::Member
        );
    }

    #[test]
    fn only_otlp_log_export_is_declared_among_alternate_log_protocols() {
        assert_eq!(
            disposition("POST", "/api/{org_id}/v1/logs"),
            Disposition::Member
        );
        for path in [
            "/api/{org_id}/_bulk",
            "/api/{org_id}/_hec",
            "/api/{org_id}/loki/api/v1/push",
            "/api/{org_id}/v1/metrics",
        ] {
            assert_eq!(
                disposition("POST", path),
                Disposition::Unsupported,
                "{path}"
            );
        }
    }

    #[test]
    fn stream_type_ambiguity_and_noncanonical_names_deny() {
        let (parts, _) = Request::builder()
            .uri("/api/org/streams/logs?type=logs&type=metrics")
            .body(Body::empty())
            .unwrap()
            .into_parts();
        assert!(resource_for(&parts, ResourceKind::Stream, "logs").is_err());
        let (parts, _) = Request::builder()
            .uri("/api/org/streams/logs?type=unknown")
            .body(Body::empty())
            .unwrap()
            .into_parts();
        assert!(resource_for(&parts, ResourceKind::Stream, "logs").is_err());
    }

    #[tokio::test]
    async fn ingestion_tokens_cannot_impersonate_basic_username() {
        let (mut parts, _) = Request::new(Body::empty()).into_parts();
        assert!(
            authorize_enabled(&mut parts, "root@example.com", true, Some("collector"))
                .await
                .is_err()
        );
        assert!(
            authorize_enabled(&mut parts, "root@example.com", false, None)
                .await
                .is_err()
        );
    }
    #[test]
    fn scoped_collections_delegate_to_permission_filtered_handlers() {
        for path in [
            "/api/{org_id}/dashboards",
            "/api/{org_id}/savedviews",
            "/api/v2/{org_id}/alerts",
            "/api/v2/{org_id}/reports",
        ] {
            assert!(matches!(disposition("GET", path), Disposition::Member));
            assert!(matches!(
                disposition("POST", path),
                Disposition::Permission(Action::Write, _, "*")
            ));
        }
    }
}
