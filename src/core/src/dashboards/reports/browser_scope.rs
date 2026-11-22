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

use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use anyhow::{Context, Result, ensure};
use base64::Engine;
use chromiumoxide::{
    Page,
    cdp::browser_protocol::{
        fetch::{
            self, ContinueRequestParams, EventRequestPaused, FailRequestParams,
            FulfillRequestParams, GetResponseBodyParams, HeaderEntry, RequestPattern, RequestStage,
        },
        network::{ErrorReason, SetBypassServiceWorkerParams},
    },
};
use futures::StreamExt;

use super::scoped::{self, Scope};

#[derive(Clone, Copy, PartialEq)]
enum RequestKind {
    Document,
    Asset,
    Login,
    Metadata,
    Dashboard,
    OptionalMetadata,
    CosmeticAsset,
    Landing,
    Query,
}

pub(super) struct BrowserScope {
    failed: Arc<AtomicBool>,
    pending: Arc<AtomicUsize>,
    completed: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl BrowserScope {
    pub async fn attach(page: &Page, origin: &str, base_uri: &str, scope: Scope) -> Result<Self> {
        let origin = url::Url::parse(origin)?;
        ensure!(
            matches!(origin.scheme(), "http" | "https")
                && origin.username().is_empty()
                && origin.password().is_none(),
            "Invalid report web origin"
        );
        let worker_asset =
            web::stream_worker_asset().context("Missing unique stream parser worker")?;
        let worker_url = format!(
            "{}{base_uri}/web/{worker_asset}",
            origin.origin().ascii_serialization()
        );
        let failed = Arc::new(AtomicBool::new(false));
        let pending = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(AtomicUsize::new(0));
        let mut events = page.event_listener::<EventRequestPaused>().await?;
        page.execute(SetBypassServiceWorkerParams::new(true))
            .await?;
        page.execute(
            fetch::EnableParams::builder()
                .pattern(
                    RequestPattern::builder()
                        .url_pattern("*")
                        .request_stage(RequestStage::Request)
                        .build(),
                )
                .pattern(
                    RequestPattern::builder()
                        .url_pattern("*")
                        .request_stage(RequestStage::Response)
                        .build(),
                )
                .build(),
        )
        .await?;
        let page = page.clone();
        let base_uri = base_uri.to_owned();
        let task_failed = failed.clone();
        let task_pending = pending.clone();
        let task_completed = completed.clone();
        let task = tokio::spawn(async move {
            while let Some(event) = events.next().await {
                let result = handle(
                    &page,
                    &event,
                    (&origin, &base_uri),
                    &worker_url,
                    &scope,
                    &task_pending,
                    &task_completed,
                )
                .await;
                if let Err(error) = result {
                    let path = url::Url::parse(&event.request.url)
                        .map(|url| url.path().to_owned())
                        .unwrap_or_else(|_| "invalid URL".to_owned());
                    log::warn!(
                        "Scoped report request denied: {} {}: {error}",
                        event.request.method,
                        path
                    );
                    task_failed.store(true, Ordering::SeqCst);
                    if page
                        .execute(FailRequestParams::new(
                            event.request_id.clone(),
                            ErrorReason::Aborted,
                        ))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        });
        Ok(Self {
            failed,
            pending,
            completed,
            task,
        })
    }

    pub fn complete(&self) -> Result<()> {
        ensure!(
            !self.failed.load(Ordering::SeqCst)
                && self.pending.load(Ordering::SeqCst) == 0
                && self.completed.load(Ordering::SeqCst) > 0,
            "Report rendering was incomplete or denied"
        );
        Ok(())
    }
}

impl Drop for BrowserScope {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// An isolated, cache-free browser profile for one scoped report render.
pub(super) fn launch_config(profile: &std::path::Path) -> Result<chromiumoxide::BrowserConfig> {
    let cfg = config::get_config();
    chromiumoxide::browser::BrowserConfig::builder()
        .chrome_executable(&cfg.chrome.chrome_path)
        .user_data_dir(profile)
        .incognito()
        .respect_https_errors()
        .window_size(
            cfg.chrome.chrome_window_width,
            cfg.chrome.chrome_window_height,
        )
        .enable_request_intercept()
        .disable_cache()
        .args([
            "--disable-extensions",
            "--disable-background-networking",
            "--disable-sync",
            "--no-pings",
            "--disable-quic",
            "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        ])
        .build()
        .map_err(anyhow::Error::msg)
}

/// Waits until the login form exists and the web app has stopped replacing it while starting up.
pub(super) async fn await_login_form(page: &Page) -> Result<()> {
    const STABLE_PASSWORD_INPUT: &str = "(() => { \
        const input = document.querySelector(\"input[type='password']\"); \
        const stable = input !== null && window.__o2ReportLoginInput === input; \
        window.__o2ReportLoginInput = input; \
        return stable; })()";
    for _ in 0..60 {
        // Evaluation fails while a navigation replaces the document; the next poll retries.
        let stable = page.evaluate(STABLE_PASSWORD_INPUT).await.ok();
        if stable.and_then(|result| result.into_value::<bool>().ok()) == Some(true) {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    anyhow::bail!("Report login form did not render")
}

async fn handle(
    page: &Page,
    event: &EventRequestPaused,
    location: (&url::Url, &str),
    worker_url: &str,
    scope: &Scope,
    pending: &AtomicUsize,
    completed: &AtomicUsize,
) -> Result<()> {
    let (origin, base_uri) = location;
    let request_url = url::Url::parse(&event.request.url)?;
    if request_url.path().contains("/assets/streamWorker-") {
        ensure!(
            request_url.as_str() == worker_url,
            "Unapproved stream parser worker"
        );
    }
    let kind = classify(
        &event.request.url,
        &event.request.method,
        origin,
        base_uri,
        scope,
    )?;
    if matches!(
        kind,
        RequestKind::OptionalMetadata | RequestKind::CosmeticAsset | RequestKind::Landing
    ) {
        let (status, content_type, body) = match kind {
            RequestKind::Landing => (
                200,
                "text/html",
                "<!doctype html><html><body></body></html>",
            ),
            RequestKind::CosmeticAsset => (
                200,
                "image/svg+xml",
                r#"<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"/>"#,
            ),
            _ => (
                403,
                "application/json",
                r#"{"code":403,"message":"Unavailable in scoped report"}"#,
            ),
        };
        page.execute(
            FulfillRequestParams::builder()
                .request_id(event.request_id.clone())
                .response_code(status)
                .response_header(HeaderEntry::new("Content-Type", content_type))
                .response_header(HeaderEntry::new(
                    "Content-Security-Policy",
                    "default-src 'none'",
                ))
                .body(base64::engine::general_purpose::STANDARD.encode(body))
                .build()
                .map_err(anyhow::Error::msg)?,
        )
        .await?;
        return Ok(());
    }
    ensure!(
        event.redirected_request_id.is_none() && event.response_error_reason.is_none(),
        "Redirect or failed response in scoped report"
    );
    if matches!(kind, RequestKind::Query | RequestKind::Dashboard) {
        log::debug!(
            "Scoped report data request: {} status {:?}",
            url::Url::parse(&event.request.url)?.path(),
            event.response_status_code
        );
    }
    if let Some(status) = event.response_status_code {
        ensure!(
            (200..300).contains(&status),
            "Non-success response in scoped report: HTTP {status}"
        );
        if matches!(
            kind,
            RequestKind::Document | RequestKind::Query | RequestKind::Dashboard
        ) {
            let response = page
                .execute(GetResponseBodyParams::new(event.request_id.clone()))
                .await?;
            let data = if response.result.base64_encoded {
                base64::engine::general_purpose::STANDARD.decode(response.result.body)?
            } else {
                response.result.body.into_bytes()
            };
            ensure!(
                data.len() <= 32 * 1024 * 1024,
                "Report response exceeds supported size"
            );
            if kind == RequestKind::Dashboard {
                ensure!(
                    serde_json::from_slice::<serde_json::Value>(&data)? == scope.dashboard_json,
                    "Rendered dashboard differs from authorized snapshot"
                );
            }
            if kind == RequestKind::Query {
                log::debug!("Scoped report query body received: {} bytes", data.len());
                validate_query_response(&data)?;
                pending.fetch_sub(1, Ordering::SeqCst);
                completed.fetch_add(1, Ordering::SeqCst);
            }
            let mut headers = event.response_headers.clone().unwrap_or_default();
            headers.retain(|h| {
                !matches!(
                    h.name.to_ascii_lowercase().as_str(),
                    "content-length" | "content-encoding" | "content-security-policy"
                )
            });
            if kind == RequestKind::Document {
                headers.push(HeaderEntry::new(
                    "Content-Security-Policy",
                    document_policy(origin, worker_url),
                ));
            }
            page.execute(
                FulfillRequestParams::builder()
                    .request_id(event.request_id.clone())
                    .response_code(status)
                    .response_headers(headers)
                    .body(base64::engine::general_purpose::STANDARD.encode(data))
                    .build()
                    .map_err(anyhow::Error::msg)?,
            )
            .await?;
            if kind == RequestKind::Query {
                log::debug!("Scoped report query response delivered to browser");
            }
            return Ok(());
        }
    } else if matches!(
        kind,
        RequestKind::Query | RequestKind::Metadata | RequestKind::Dashboard
    ) {
        scoped::current(scope).await?;
        if kind == RequestKind::Query {
            pending.fetch_add(1, Ordering::SeqCst);
        }
    }
    page.execute(ContinueRequestParams::new(event.request_id.clone()))
        .await?;
    Ok(())
}

fn classify(
    raw: &str,
    method: &str,
    origin: &url::Url,
    base_uri: &str,
    scope: &Scope,
) -> Result<RequestKind> {
    let url = url::Url::parse(raw)?;
    ensure!(
        url.origin() == origin.origin()
            && url.username().is_empty()
            && url.password().is_none()
            && !url.path().contains('%'),
        "Report attempted an unapproved origin or path"
    );
    let path = url
        .path()
        .strip_prefix(base_uri)
        .context("Report path outside configured base")?;
    let api = format!("/api/{}", scope.organization);
    if method == "GET" {
        if path == "/web/login" {
            return Ok(RequestKind::Document);
        }
        if path == "/web/" {
            ensure!(
                url.query_pairs()
                    .filter(|(key, _)| key == "org_identifier")
                    .all(|(_, value)| value == scope.organization),
                "Report login selected another organization"
            );
            return Ok(RequestKind::Landing);
        }
        if path == "/web/dashboards/view" {
            let parameters: Vec<_> = url.query_pairs().collect();
            ensure!(
                parameters
                    .iter()
                    .filter(|(key, _)| key == "org_identifier")
                    .map(|(_, value)| value.as_ref())
                    .collect::<Vec<_>>()
                    == [scope.organization.as_str()]
                    && parameters
                        .iter()
                        .filter(|(key, _)| key == "dashboard")
                        .map(|(_, value)| value.as_ref())
                        .collect::<Vec<_>>()
                        == [scope.dashboard_id.as_str()],
                "Report navigated to another dashboard"
            );
            for (key, expected) in [("tab", &scope.tab_id), ("folder", &scope.folder_id)] {
                ensure!(
                    parameters
                        .iter()
                        .filter(|(name, _)| name == key)
                        .map(|(_, value)| value.as_ref())
                        .collect::<Vec<_>>()
                        == [expected.as_str()],
                    "Report navigated to another tab or folder"
                );
            }
            return Ok(RequestKind::Document);
        }
        if matches!(
            path,
            "/web/src/assets/images/common/openobserve_latest_light_2.svg"
                | "/web/src/assets/images/common/ai_icon_gradient.svg"
        ) {
            return Ok(RequestKind::CosmeticAsset);
        }
        if path.starts_with("/web/assets/")
            || matches!(path, "/web/favicon.ico" | "/web/favicon.svg")
        {
            return Ok(RequestKind::Asset);
        }
        if path == format!("{api}/settings")
            || path == format!("{api}/settings/v2/home_dashboard")
            || path == format!("/api/v2/{}/folders/dashboards", scope.organization)
        {
            return Ok(RequestKind::OptionalMetadata);
        }
        if path == format!("{api}/dashboards/{}", scope.dashboard_id) {
            return Ok(RequestKind::Dashboard);
        }
        if matches!(path, "/config" | "/api/organizations")
            || path == format!("{api}/config")
            || path == format!("{api}/rbac/me")
            || path == format!("{api}/streams")
            || scope
                .sources
                .iter()
                .any(|s| path == format!("{api}/streams/{}/schema", s.name))
        {
            return Ok(RequestKind::Metadata);
        }
    }
    if method == "POST" && matches!(path, "/auth/login" | "/auth/login/") {
        return Ok(RequestKind::Login);
    }
    if method == "POST"
        && [
            "/_search",
            "/_search_stream",
            "/_search_multi",
            "/_search_multi_stream",
        ]
        .iter()
        .any(|suffix| path == format!("{api}{suffix}"))
    {
        return Ok(RequestKind::Query);
    }
    if method == "POST" && path == format!("{api}/_search_partition") {
        return Ok(RequestKind::Metadata);
    }
    anyhow::bail!("Unsupported request in scoped report")
}

fn document_policy(origin: &url::Url, worker_url: &str) -> String {
    let origin = origin.origin().ascii_serialization();
    format!(
        "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src {origin}; frame-src 'none'; worker-src {worker_url}; object-src 'none'; media-src 'none'; form-action {origin}; base-uri 'self'"
    )
}

fn validate_query_response(data: &[u8]) -> Result<()> {
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) {
        ensure!(
            value.get("hits").is_some() || value.get("results").is_some(),
            "Report query returned no results"
        );
        return check_result(&value);
    }
    let text = std::str::from_utf8(data)?;
    ensure!(
        !text
            .lines()
            .any(|line| matches!(line.trim(), "event: error" | "event: cancelled")),
        "Report query failed"
    );
    let mut saw_result = false;
    let mut completed = false;
    for line in text.lines().filter_map(|line| line.strip_prefix("data:")) {
        if line.trim() == "[[DONE]]" {
            completed = true;
            continue;
        }
        ensure!(line.trim() != "[[CANCELLED]]", "Report query was cancelled");
        let value: serde_json::Value = serde_json::from_str(line.trim())?;
        check_result(&value)?;
        saw_result |= value.get("results").is_some() || value.get("hits").is_some();
    }
    ensure!(saw_result && completed, "Report query did not complete");
    Ok(())
}

fn check_result(value: &serde_json::Value) -> Result<()> {
    if let Some(results) = value.as_array() {
        ensure!(
            !results.is_empty(),
            "Report query returned no result batches"
        );
        return results.iter().try_for_each(check_result);
    }
    ensure!(value.is_object(), "Invalid report query response");
    let result = value;
    ensure!(
        result.get("is_partial").and_then(|v| v.as_bool()) != Some(true)
            && result
                .get("function_error")
                .is_none_or(|v| v.as_str().is_some_and(str::is_empty) || v.is_null())
            && result
                .get("error")
                .is_none_or(|v| v.is_null() || v.as_str() == Some(""))
            && result
                .get("code")
                .and_then(|v| v.as_u64())
                .is_none_or(|code| code < 400),
        "Report query returned an error or partial results"
    );
    if let Some(results) = value.get("results") {
        check_result(results)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> Scope {
        Scope {
            policy_version: 1,
            organization: "org".into(),
            author: "author".into(),
            renderer: "renderer".into(),
            tab_id: "main".into(),
            folder_id: "default".into(),
            dashboard_id: "board".into(),
            sources: vec![infra::rbac::Resource::stream("logs", "allowed")],
            dashboard_json: serde_json::json!({}),
            recipients: vec!["recipient@example.test".into()],
        }
    }

    #[test]
    fn rbac_report_browser_refuses_unapproved_requests() {
        let origin = url::Url::parse("http://localhost:5080").unwrap();
        let scope = scope();
        for (method, url) in [
            ("GET", "https://attacker.example/web/assets/x.js"),
            ("GET", "http://localhost:5080/api/other/streams"),
            ("GET", "http://localhost:5080/web/?org_identifier=other"),
            ("GET", "http://localhost:5080/api/org/dashboards/other"),
            ("GET", "http://localhost:5080/api/org/streams/secret/schema"),
            ("POST", "http://localhost:5080/api/org/allowed/_json"),
            ("GET", "http://localhost:5080/web/assets/%2e%2e/private"),
            (
                "GET",
                "http://localhost:5080/web/dashboards/view?org_identifier=org&dashboard=board&tab=wrong&folder=default",
            ),
            (
                "GET",
                "http://localhost:5080/web/dashboards/view?org_identifier=org&org_identifier=other&dashboard=board&tab=main&folder=default",
            ),
        ] {
            assert!(classify(url, method, &origin, "", &scope).is_err(), "{url}");
        }
        for path in [
            "/api/org/settings",
            "/api/org/settings/v2/home_dashboard",
            "/api/v2/org/folders/dashboards",
        ] {
            let url = format!("http://localhost:5080{path}");
            assert!(matches!(
                classify(&url, "GET", &origin, "", &scope),
                Ok(RequestKind::OptionalMetadata)
            ));
            assert!(classify(&url, "POST", &origin, "", &scope).is_err());
        }
        for (method, url) in [
            ("GET", "http://localhost:5080/web/"),
            (
                "GET",
                "http://localhost:5080/web/src/assets/images/common/openobserve_latest_light_2.svg",
            ),
            ("GET", "http://localhost:5080/api/org/dashboards/board"),
            ("POST", "http://localhost:5080/api/org/_search_stream"),
            (
                "GET",
                "http://localhost:5080/web/dashboards/view?org_identifier=org&dashboard=board&tab=main&folder=default",
            ),
        ] {
            assert!(classify(url, method, &origin, "", &scope).is_ok(), "{url}");
        }
    }

    #[test]
    fn rbac_report_allows_only_the_deployed_parser_worker() {
        let origin = url::Url::parse("https://example.test").unwrap();
        let worker = "https://example.test/web/assets/streamWorker-buildhash.js";
        let policy = document_policy(&origin, worker);
        assert_eq!(
            policy
                .split(';')
                .map(str::trim)
                .find(|part| part.starts_with("worker-src")),
            Some("worker-src https://example.test/web/assets/streamWorker-buildhash.js")
        );
        assert!(!policy.contains("blob:"));
        assert!(policy.contains("frame-src 'none'"));
    }

    #[test]
    fn rbac_report_browser_refuses_partial_or_failed_query_results() {
        for body in [
            r#"{"is_partial":true,"hits":[]}"#,
            r#"{"results":{"function_error":"denied","hits":[]}}"#,
            r#"{"code":403,"error":"forbidden"}"#,
            r#"{"results":[{"hits":[],"is_partial":true}]}"#,
            r#"{"code":403,"results":{"hits":[]}}"#,
            "event: error\ndata: {\"message\":\"denied\"}\n",
            "data: [[CANCELLED]]\n",
            "event: done\n",
            "data: {\"results\":{\"hits\":[]}}\n",
            "{}",
        ] {
            assert!(validate_query_response(body.as_bytes()).is_err(), "{body}");
        }
        assert!(validate_query_response(br#"{"hits":[],"is_partial":false}"#).is_ok());
        assert!(
            validate_query_response(b"data: {\"results\":{\"hits\":[]}}\ndata: [[DONE]]\n").is_ok()
        );
    }
}
