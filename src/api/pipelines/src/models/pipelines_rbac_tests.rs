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

use config::meta::stream::StreamParams;

use super::*;

#[test]
fn rbac_pipeline_models_do_not_expose_historic_error_rows() {
    if std::env::var_os("O2_PIPELINE_ERROR_CHILD").is_none() {
        for enabled in ["true", "false"] {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "models::pipelines::rbac_tests::rbac_pipeline_models_do_not_expose_historic_error_rows", "--nocapture"])
                .env("O2_PIPELINE_ERROR_CHILD", "1").env("ZO_RBAC_ENABLED", enabled).status().unwrap();
            assert!(status.success());
        }
        return;
    }
    let pipeline = meta_pipeline {
        id: "pipeline".into(),
        version: 1,
        enabled: true,
        org: "org".into(),
        name: "name".into(),
        description: String::new(),
        source: PipelineSource::Realtime(StreamParams::default()),
        nodes: vec![],
        edges: vec![],
        kind: PipelineKind::User,
    };
    let error = PipelineErrorInfo {
        last_error_timestamp: 1,
        error_summary: Some("private-error-row".into()),
        node_errors: Some(serde_json::json!({"sample":"private-error-row"})),
    };
    let individual = Pipeline::from(pipeline.clone(), None, Some(error.clone()));
    let list = PipelineList::from(
        vec![pipeline],
        vec![],
        HashMap::from_iter([("pipeline".into(), error)]),
    );
    for serialized in [
        serde_json::to_string(&individual).unwrap(),
        serde_json::to_string(&list).unwrap(),
    ] {
        assert_eq!(
            serialized.contains("private-error-row"),
            !infra::rbac::enabled()
        );
    }
}
