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

use config::cache_instance_id;

use super::{
    tests::{basic_request, seed_org_user},
    *,
};

#[test]
fn rbac_scoped_otlp_logs_requires_the_callers_own_credential() {
    cache_instance_id("instance");
    seed_org_user(
        "auth-otlp-rbac",
        "collector@example.com",
        "Collectorpass#123",
        "collector-token",
    );
    let internal = || {
        let mut request = org_token_request("auth-otlp-rbac", "unused");
        request
            .metadata_mut()
            .insert("authorization", get_internal_grpc_token().parse().unwrap());
        request
            .metadata_mut()
            .insert("user_id", "collector@example.com".parse().unwrap());
        request
    };
    if std::env::var_os("O2_OTLP_LOGS_RBAC_CHILD").is_none() {
        assert!(check_otlp_logs_auth(internal()).is_ok());
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "handler::grpc::auth::rbac_tests::rbac_scoped_otlp_logs_requires_the_callers_own_credential",
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
    let status = check_otlp_logs_auth(internal()).unwrap_err();
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
    let mut forged = basic_request(
        "auth-otlp-rbac",
        "collector@example.com",
        "Collectorpass#123",
    );
    forged
        .metadata_mut()
        .insert("user_id", "root@example.com".parse().unwrap());
    let verified = check_otlp_logs_auth(forged).unwrap();
    assert_eq!(user_ids(&verified), ["collector@example.com"]);
    let other = basic_request(
        "auth-otlp-rbac",
        "collector@example.com",
        "Collectorpass#123",
    );
    let status = check_otlp_auth(other).unwrap_err();
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
}

fn user_ids(request: &tonic::Request<()>) -> Vec<String> {
    request
        .metadata()
        .get_all("user_id")
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect()
}

fn org_token_request(org_id: &str, encoded_credentials: &str) -> tonic::Request<()> {
    let mut request = tonic::Request::new(());
    request.metadata_mut().insert(
        "authorization",
        format!("basic {encoded_credentials}").parse().unwrap(),
    );
    request
        .metadata_mut()
        .insert("organization", org_id.parse().unwrap());
    request
}
