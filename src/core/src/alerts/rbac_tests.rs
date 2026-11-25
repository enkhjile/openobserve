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

// Composite alerts rely on this: they have no recorded identity, so enabling one cannot deliver.
#[tokio::test]
async fn rbac_rejects_alert_execution_without_scoped_identity() {
    use super::alert::{AlertError, AlertExt};

    if std::env::var_os("O2_ALERT_RBAC_TEST_CHILD").is_none() {
        assert!(!infra::rbac::enabled());
        assert!(
            QueryCondition::default()
                .evaluate_realtime(None)
                .await
                .is_ok()
        );
        assert!(
            config::meta::alerts::alert::Alert::default()
                .send_notification("test", &[], 0, None, 0, None, None, None, &[], None)
                .await
                .is_ok()
        );
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "alerts::rbac_tests::rbac_rejects_alert_execution_without_scoped_identity",
                "--nocapture",
            ])
            .env("O2_ALERT_RBAC_TEST_CHILD", "1")
            .env("ZO_RBAC_ENABLED", "true")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    assert!(infra::rbac::enabled());
    let query = QueryCondition::default();
    assert!(query.evaluate_realtime(None).await.is_err());
    assert!(
        query
            .evaluate_scheduled(
                "default",
                None,
                StreamType::Logs,
                &TriggerCondition::default(),
                (None, 0),
                None,
                None,
                None,
                None,
            )
            .await
            .is_err()
    );
    let alert = config::meta::alerts::alert::Alert::default();
    assert!(alert.evaluate(None, (None, 0), None).await.is_err());
    assert!(matches!(
        alert
            .send_notification("test", &[], 0, None, 0, None, None, None, &[], None)
            .await,
        Err(AlertError::PermissionDenied)
    ));
    let recovery = serde_json::from_value(serde_json::json!({
        "org_id": "default", "alert_id": "legacy", "group_key": "",
        "episode_id": "queued", "opened_at": 0, "recovered_at": 1,
        "emitted_at": 1
    }))
    .unwrap();
    assert!(matches!(
        super::alert::send_recovery_notification(&alert, &recovery).await,
        Err(AlertError::PermissionDenied)
    ));
}
