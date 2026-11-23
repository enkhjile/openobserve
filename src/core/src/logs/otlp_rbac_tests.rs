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

#[test]
fn org_token_exports_are_attributed_to_the_verified_token_row() {
    let token = ingestion_common::IngestUser::OrgToken(config::meta::user::OrgIngestionPrincipal {
        org_id: "org".to_string(),
        token_id: "row-id".to_string(),
    });
    assert_eq!(
        attributed_user(Some(&token), "root@example.com"),
        "org-token:row-id"
    );
    let user = ingestion_common::IngestUser::User("collector@example.com".to_string());
    assert_eq!(
        attributed_user(Some(&user), "collector@example.com"),
        "collector@example.com"
    );
    assert_eq!(
        attributed_user(None, "basic-name@example.com"),
        "basic-name@example.com"
    );
}

#[tokio::test]
async fn rbac_rejects_a_credential_from_another_organization_before_writing() {
    if std::env::var_os("O2_OTLP_LOGS_RBAC_CHILD").is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "logs::otlp::rbac_tests::rbac_rejects_a_credential_from_another_organization_before_writing",
                "--nocapture",
            ])
            .env("O2_OTLP_LOGS_RBAC_CHILD", "1")
            .env("ZO_RBAC_ENABLED", "true")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    assert!(infra::rbac::enabled());
    let principal = config::meta::user::OrgIngestionPrincipal {
        org_id: "other-org".to_string(),
        token_id: "credential-id".to_string(),
    };
    let err = super::handle_request_as(
        0,
        "rbac-otlp-org",
        ExportLogsServiceRequest::default(),
        Some("api"),
        "collector@example.com",
        Some(&principal),
        OtlpRequestType::Grpc,
    )
    .await
    .unwrap_err();
    assert_eq!(err.http_status(), 403, "{err}");
}
