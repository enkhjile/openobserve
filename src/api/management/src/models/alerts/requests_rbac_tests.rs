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
fn client_execution_subject_is_not_an_alert_authority() {
    let mut body: serde_json::Value =
        serde_json::from_str(&body_with_warning_value("null")).unwrap();
    body["execution_subject"] = serde_json::json!("forged-root-uuid");
    let create: CreateAlertRequestBody = serde_json::from_value(body.clone()).unwrap();
    let update: UpdateAlertRequestBody = serde_json::from_value(body).unwrap();
    assert!(meta_alerts::Alert::from(create).execution_subject.is_none());
    assert!(meta_alerts::Alert::from(update).execution_subject.is_none());
}

/// Minimal create body carrying an aggregation warning threshold.
fn body_with_warning_value(warning: &str) -> String {
    format!(
        r#"{{
            "name": "agg",
            "stream_type": "logs",
            "stream_name": "s",
            "is_real_time": false,
            "destinations": ["d"],
            "query_condition": {{
                "type": "custom",
                "conditions": [],
                "aggregation": {{
                    "group_by": ["host"],
                    "function": "avg",
                    "having": {{"column": "latency", "operator": ">=", "value": 500}},
                    "warning_value": {warning}
                }}
            }},
            "trigger_condition": {{
                "period": 1, "operator": ">=", "threshold": 1,
                "frequency": 1, "frequency_type": "minutes", "silence": 0
            }}
        }}"#
    )
}
