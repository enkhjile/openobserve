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
    extract::Query,
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
};
use openobserve_core::extensions::oidc;
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

pub async fn login() -> Response {
    if !config::get_config().oidc.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    let binding = oidc::random_secret();
    let result = async {
        let provider = oidc::provider().await?;
        let request = provider
            .begin(&binding)
            .await
            .map_err(|_| anyhow::anyhow!("OIDC unavailable"))?;
        Ok::<_, anyhow::Error>(request)
    }
    .await;
    match result {
        Ok(request) => {
            let cfg = config::get_config();
            let mut response = Redirect::temporary(&request.url).into_response();
            if set_cookie(
                &mut response,
                oidc::transaction_cookie_name(&cfg.oidc),
                &binding,
                300,
            )
            .is_err()
            {
                return unavailable();
            }
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
    let result = async {
        let binding = oidc::unique_cookie(&headers, oidc::transaction_cookie_name(&cfg.oidc))?
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
        oidc::establish(identity, &headers).await
    }
    .await;
    let mut response = match result {
        Ok((secret, session)) => {
            let mut response =
                Redirect::to(&format!("{}/web/cb?oidc=1", cfg.common.base_uri)).into_response();
            if set_cookie(
                &mut response,
                oidc::cookie_name(&cfg.oidc),
                &secret,
                session.expires_at - chrono::Utc::now().timestamp(),
            )
            .is_err()
            {
                return unavailable();
            }
            for name in ["auth_tokens", "auth_ext"] {
                if set_cookie(&mut response, name, "", 0).is_err() {
                    return unavailable();
                }
            }
            response
        }
        Err(_) => {
            Redirect::to(&format!("{}/web/login?oidc_error=1", cfg.common.base_uri)).into_response()
        }
    };
    if set_cookie(
        &mut response,
        oidc::transaction_cookie_name(&cfg.oidc),
        "",
        0,
    )
    .is_err()
    {
        return unavailable();
    }
    no_store(response)
}

pub async fn session(headers: HeaderMap) -> Response {
    if !config::get_config().oidc.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    let result = async {
        let session = oidc::resolve_session(&headers, &Method::GET).await?;
        let user = db::user::get_user_record(&session.email).await?;
        Ok::<_, anyhow::Error>(Profile {
            email: session.email,
            name: format!("{} {}", user.first_name, user.last_name)
                .trim()
                .to_string(),
            given_name: user.first_name,
            family_name: user.last_name,
            exp: session.expires_at,
        })
    }
    .await;
    no_store(match result {
        Ok(profile) => Json(profile).into_response(),
        Err(_) => StatusCode::UNAUTHORIZED.into_response(),
    })
}

pub async fn logout(headers: HeaderMap) -> Response {
    let cfg = config::get_config();
    if !cfg.oidc.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    if oidc::check_csrf(&headers, &Method::POST, &cfg.oidc.redirect_uri).is_err() {
        return no_store(StatusCode::FORBIDDEN.into_response());
    }
    if oidc::revoke(&headers).await.is_err() {
        return unavailable();
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    for name in [
        oidc::cookie_name(&cfg.oidc),
        oidc::transaction_cookie_name(&cfg.oidc),
        "auth_tokens",
        "auth_ext",
    ] {
        if set_cookie(&mut response, name, "", 0).is_err() {
            return unavailable();
        }
    }
    no_store(response)
}

fn set_cookie(response: &mut Response, name: &str, value: &str, age: i64) -> anyhow::Result<()> {
    let secure = if config::get_config().oidc.cookie_secure {
        "; Secure"
    } else {
        ""
    };
    let value = HeaderValue::from_str(&format!(
        "{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={age}{secure}"
    ))?;
    response.headers_mut().append(header::SET_COOKIE, value);
    Ok(())
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
