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
    Json, Router,
    extract::Query,
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use openobserve_core::extensions::oidc::{self, browser_transactions};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct Callback {
    code: Option<String>,
    state: Option<String>,
}

#[derive(Serialize)]
struct Profile {
    email: String,
    name: String,
    given_name: String,
    family_name: String,
    exp: i64,
}

/// Browser sign-in routes, mounted under `/auth` without authentication.
pub fn routes() -> Router {
    Router::new()
        .route("/oidc/login", get(login))
        .route("/oidc/callback", get(callback))
        .route("/oidc/session", get(session))
        .route("/oidc/logout", post(logout))
}

pub async fn login(headers: HeaderMap) -> Response {
    let cfg = config::get_config();
    if !cfg.oidc.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    if browser_transactions::pending_cookie_names(&headers, &cfg.oidc).len()
        >= browser_transactions::MAX_BROWSER_TRANSACTIONS
    {
        return no_store(
            (
                StatusCode::TOO_MANY_REQUESTS,
                "Too many sign-ins are open in this browser. Finish one of them, or wait up to \
                 five minutes for one to expire, then try again.",
            )
                .into_response(),
        );
    }
    let binding = oidc::random_secret();
    let result = async {
        let provider = oidc::provider().await?;
        let request = provider
            .begin(&binding)
            .await
            .map_err(|_| anyhow::anyhow!("OIDC unavailable"))?;
        browser_transactions::register(&binding).await?;
        Ok::<_, anyhow::Error>(request)
    }
    .await;
    match result {
        Ok(request) => {
            let Some(cookie_name) =
                browser_transactions::cookie_for_state(&cfg.oidc, &request.state)
            else {
                return unavailable();
            };
            let mut response = Redirect::temporary(&request.url).into_response();
            set_cookie(&mut response, &cookie_name, &binding, 300);
            no_store(response)
        }
        Err(_) => unavailable(),
    }
}

pub async fn callback(headers: HeaderMap, Query(query): Query<Callback>) -> Response {
    let cfg = config::get_config();
    if !cfg.oidc.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    let transaction_cookie = query
        .state
        .as_deref()
        .and_then(|state| browser_transactions::cookie_for_state(&cfg.oidc, state));
    let result = async {
        let name = transaction_cookie
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("invalid OIDC state"))?;
        let binding = oidc::unique_cookie(&headers, name)?
            .ok_or_else(|| anyhow::anyhow!("missing OIDC transaction"))?;
        let code = query
            .code
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("missing OIDC code"))?;
        let state = query
            .state
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("missing OIDC state"))?;
        let identity = oidc::provider()
            .await?
            .complete(code, state, binding)
            .await
            .map_err(|_| anyhow::anyhow!("OIDC verification failed"))?;
        oidc::establish(identity, &headers, &browser_transactions::marker(binding)).await
    }
    .await;
    let mut response = match result {
        Ok((secret, session)) => {
            let mut response =
                Redirect::to(&format!("{}/web/oidc/cb", cfg.common.base_uri)).into_response();
            let age = session.expires_at - chrono::Utc::now().timestamp();
            set_cookie(&mut response, oidc::cookie_name(&cfg.oidc), &secret, age);
            for name in ["auth_tokens", "auth_ext"] {
                set_cookie(&mut response, name, "", 0);
            }
            response
        }
        Err(_) => {
            Redirect::to(&format!("{}/web/login?oidc_error=1", cfg.common.base_uri)).into_response()
        }
    };
    if let Some(name) = transaction_cookie {
        set_cookie(&mut response, &name, "", 0);
    }
    no_store(response)
}

pub async fn session(headers: HeaderMap) -> Response {
    if !config::get_config().oidc.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    let (session, user) = match oidc::resolve_session_account(&headers, &Method::GET).await {
        Ok(account) => account,
        Err(err) if oidc::session_unavailable(&err) => return unavailable(),
        Err(_) => return no_store(StatusCode::UNAUTHORIZED.into_response()),
    };
    no_store(
        Json(Profile {
            email: user.email,
            name: format!("{} {}", user.first_name, user.last_name)
                .trim()
                .to_owned(),
            given_name: user.first_name,
            family_name: user.last_name,
            exp: session.expires_at,
        })
        .into_response(),
    )
}

pub async fn logout(headers: HeaderMap) -> Response {
    let cfg = config::get_config();
    if !cfg.oidc.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    if oidc::check_csrf(&headers, &Method::POST, &cfg.oidc.redirect_uri).is_err() {
        return no_store(StatusCode::FORBIDDEN.into_response());
    }
    let Ok(cleared) = oidc::retire_browser_session(&headers).await else {
        return unavailable();
    };
    let mut response = StatusCode::NO_CONTENT.into_response();
    for cookie in cleared {
        response.headers_mut().append(header::SET_COOKIE, cookie);
    }
    for name in ["auth_tokens", "auth_ext"] {
        set_cookie(&mut response, name, "", 0);
    }
    no_store(response)
}

fn set_cookie(response: &mut Response, name: &str, value: &str, age: i64) {
    let cookie = oidc::cookie_header(&config::get_config().oidc, name, value, age);
    response.headers_mut().append(header::SET_COOKIE, cookie);
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

fn unavailable() -> Response {
    no_store(
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Single sign-on is unavailable. Please try again.",
        )
            .into_response(),
    )
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    use super::*;

    #[tokio::test]
    async fn disabled_oidc_routes_do_not_issue_cookies() {
        assert!(!config::get_config().oidc.enabled);
        for (method, path) in [
            ("GET", "/login"),
            ("GET", "/session"),
            ("GET", "/callback"),
            ("POST", "/logout"),
        ] {
            let response = crate::handler::http::router::basic_routes()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(format!("/auth/oidc{path}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            assert!(!response.headers().contains_key(header::SET_COOKIE));
        }
    }
}
