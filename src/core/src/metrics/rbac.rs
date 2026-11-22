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

use std::collections::HashSet;

use anyhow::{Result, anyhow};
use config::{
    meta::stream::{StreamParams, StreamType},
    utils::{flatten, json},
};
use infra::rbac::Resource;
use ingestion_common::IngestUser;

use super::json::metric_destination;

/// The metric streams `user` may write the whole batch to, all of them without pipelines.
pub(super) async fn authorize_batch(
    org_id: &str,
    stream_name: Option<&str>,
    records: &[json::Value],
    user: &IngestUser,
) -> infra::errors::Result<Vec<String>> {
    if !infra::rbac::enabled() {
        return Ok(Vec::new());
    }
    let resources = batch_destinations(stream_name, records).map_err(infra::rbac::denied)?;
    crate::pipeline::rbac::authorize_ingest(org_id, user, &resources)
        .await
        .map_err(infra::rbac::denied)?;
    let mut names = Vec::with_capacity(resources.len());
    for resource in resources {
        let stream = StreamParams::new(org_id, &resource.name, StreamType::Metrics);
        let stored =
            infra::pipeline::execution::has_enabled_source(org_id, &resource.name, "metrics")
                .await
                .map_err(infra::rbac::denied)?;
        if stored
            || !crate::ingestion::get_stream_executable_pipelines(&stream)
                .await
                .is_empty()
        {
            return Err(infra::rbac::denied(
                "Metrics pipelines require a scoped execution adapter",
            ));
        }
        names.push(resource.name);
    }
    Ok(names)
}

fn batch_destinations(stream_name: Option<&str>, records: &[json::Value]) -> Result<Vec<Resource>> {
    let mut names = HashSet::new();
    for record in records {
        let json::Value::Object(record) = flatten::flatten(record.clone())? else {
            return Err(anyhow!("Metric record must be an object"));
        };
        names.insert(metric_destination(stream_name, &record)?);
    }
    Ok(names
        .into_iter()
        .map(|name| Resource::stream("metrics", &name))
        .collect())
}

#[cfg(test)]
mod tests {
    use config::utils::{json::json, schema::format_stream_name};

    use super::*;

    #[test]
    fn metrics_batch_destinations_use_the_write_normalization_and_every_record() {
        let records = vec![
            json!({"__name__":"allowed.metric","value":1}),
            json!({"__name__":"secret_metric","value":2}),
            json!({"__name__":"allowed.metric","value":3}),
        ];
        let resources = batch_destinations(None, &records).unwrap();
        assert_eq!(resources.len(), 2);
        assert!(resources.iter().all(|r| r.stream_type == "metrics"));
        assert!(
            resources
                .iter()
                .any(|r| r.name == format_stream_name("allowed.metric".into()))
        );
        assert!(resources.iter().any(|r| r.name == "secret_metric"));
        let forced = batch_destinations(Some("forced.metric"), &records).unwrap();
        assert_eq!(forced.len(), 1);
        assert_eq!(forced[0].name, format_stream_name("forced.metric".into()));
        assert!(batch_destinations(None, &[json!({"value":1})]).is_err());
        assert!(batch_destinations(None, &[json!({"__name__":42,"value":1})]).is_err());
    }
}
