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

#[tokio::test]
async fn rbac_rejects_report_execution_without_scoped_identity() {
    if std::env::var_os("O2_REPORT_RBAC_TEST_CHILD").is_none() {
        assert!(!infra::rbac::enabled());
        assert!(matches!(
            Report::default().send_subscribers().await,
            Err(SendReportError::NoDashboards)
        ));
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "dashboards::reports::rbac_tests::rbac_rejects_report_execution_without_scoped_identity", "--nocapture"])
            .env("O2_REPORT_RBAC_TEST_CHILD", "1").env("ZO_RBAC_ENABLED", "true").status().unwrap();
        assert!(status.success());
        return;
    }
    let error = Report::default().send_subscribers().await.unwrap_err();
    assert!(
        error.to_string().contains("scoped RBAC execution identity"),
        "{error}"
    );
    assert_eq!(error.delivery_attempted(), Some(false));
}
