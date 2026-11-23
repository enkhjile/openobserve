use axum::body::Body;
use tower::ServiceExt;

use super::*;

fn healthz_request() -> axum::http::Request<Body> {
    axum::http::Request::builder()
        .uri("/api/healthz")
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn rbac_rejects_standalone_report_execution() {
    if std::env::var_os("O2_REPORT_SERVER_RBAC_CHILD").is_none() {
        assert!(!config::get_config().common.rbac_enabled);
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "router::rbac_tests::rbac_rejects_standalone_report_execution",
                "--nocapture",
            ])
            .env("O2_REPORT_SERVER_RBAC_CHILD", "1")
            .env("ZO_RBAC_ENABLED", "true")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    let request = axum::http::Request::builder().method("PUT").uri("/api/org_a/reports/r1/send")
        .header(REPORT_SECRET_HEADER, "secret").header("Content-Type", "application/json")
        .body(Body::from(r#"{"dashboards":[],"email_details":{"recipients":[],"title":"","name":"","message":"","dashb_url":""}}"#)).unwrap();
    let response = router_with_secret("secret".into())
        .oneshot(request)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        router_with_secret("secret".into())
            .oneshot(healthz_request())
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
}
