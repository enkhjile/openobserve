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

use anyhow::{Result, bail, ensure};
use config::meta::{
    pipeline::{
        Pipeline, PipelineKind,
        components::{NodeData, PipelineSource},
    },
    stream::{StreamParams, StreamType},
};
use infra::{
    pipeline::execution::PipelineExecution,
    rbac::{Action, Resource, ResourceKind},
};
use ingestion_common::IngestUser;

use super::batch_execution::ExecutablePipeline;

#[derive(Debug, Clone)]
pub(super) struct ScopedContext {
    pub execution: PipelineExecution,
    pub trigger: String,
}

pub fn resources(pipeline: &Pipeline) -> Result<Vec<Resource>> {
    ensure!(
        pipeline.kind == PipelineKind::User,
        "Only user pipelines have a scoped adapter"
    );
    let PipelineSource::Realtime(source) = &pipeline.source else {
        bail!("Scheduled pipelines require a scoped adapter");
    };
    ensure!(
        source.org_id == pipeline.org && source.stream_type == StreamType::Logs,
        "Only same-organization log pipelines are supported"
    );
    let mut resources = Vec::new();
    for node in &pipeline.nodes {
        match &node.data {
            NodeData::Stream(stream) => {
                ensure!(
                    !config::meta::self_reporting::usage::is_internal_rollup_stream(
                        &stream.stream_name
                    ) && !config::meta::self_reporting::protected_streams::is_read_protected_stream(
                        &stream.stream_name
                    ),
                    "Protected stream has no user pipeline adapter"
                );
                ensure!(
                    stream.org_id == pipeline.org && stream.stream_type == StreamType::Logs,
                    "Pipeline stream scope mismatch"
                );
                ensure!(
                    !stream.stream_name.contains(['{', '}', '*'])
                        && config::utils::schema::format_stream_name(
                            stream.stream_name.to_string()
                        ) == stream.stream_name.as_str(),
                    "Pipeline requires fixed normalized stream names"
                );
                let resource = Resource::stream("logs", &stream.stream_name);
                if !resources.contains(&resource) {
                    resources.push(resource);
                }
            }
            NodeData::Condition(_) => {}
            _ => bail!("Pipeline node has no scoped execution adapter"),
        }
    }
    ensure!(
        resources.contains(&Resource::stream("logs", &source.stream_name)),
        "Pipeline source is absent"
    );
    Ok(resources)
}

/// The ingest decision for each resource, for a verified user or this org's ingestion token.
pub async fn allowed_ingest(
    org: &str,
    user: &IngestUser,
    resources: &[Resource],
) -> Result<Vec<bool>> {
    match user {
        // Only server code builds a system job; reading what it writes still needs a grant.
        IngestUser::SystemJob(_) => Ok(vec![true; resources.len()]),
        IngestUser::User(email) => {
            infra::rbac::allowed_resources(email, org, Action::Ingest, resources).await
        }
        IngestUser::OrgToken(principal) if principal.org_id == org => {
            infra::rbac::allowed_ingestion_token_resources(org, &principal.token_id, resources)
                .await
        }
        _ => bail!("Scoped ingestion identity required"),
    }
}

/// Fails unless `user` may ingest into every resource.
pub async fn authorize_ingest(org: &str, user: &IngestUser, resources: &[Resource]) -> Result<()> {
    let decisions = allowed_ingest(org, user, resources).await?;
    ensure!(
        decisions.len() == resources.len() && decisions.into_iter().all(|allowed| allowed),
        "Ingestion destination access denied"
    );
    Ok(())
}

/// Authorizes a log destination and every scoped pipeline output for `user`, before any write.
pub async fn authorize_log_destinations(
    org: &str,
    stream: &str,
    user: &IngestUser,
) -> infra::errors::Result<Vec<ExecutablePipeline>> {
    authorize_ingest(org, user, &[Resource::stream("logs", stream)])
        .await
        .map_err(infra::rbac::denied)?;
    load(org, stream, user).await.map_err(infra::rbac::denied)
}

pub async fn validate_save(pipeline: &Pipeline, subject: Option<&str>) -> Result<()> {
    if !infra::rbac::enabled() {
        return Ok(());
    }
    let subject =
        subject.ok_or_else(|| anyhow::anyhow!("Pipeline requires a verified execution subject"))?;
    let execution = PipelineExecution {
        pipeline: pipeline.clone(),
        subject: Some(subject.to_owned()),
    };
    authorize(&pipeline.org, &[execution], None).await
}

pub async fn load(org: &str, stream: &str, user: &IngestUser) -> Result<Vec<ExecutablePipeline>> {
    let trigger = match user {
        // A scoped pipeline runs as a user, and a system job has none to run as.
        IngestUser::SystemJob(_) => return Ok(Vec::new()),
        IngestUser::User(email) => infra::rbac::user_subject(email).await?,
        IngestUser::OrgToken(principal) if principal.org_id == org => {
            format!("org-token:{}", principal.token_id)
        }
        _ => bail!("Pipeline requires a scoped ingestion identity"),
    };
    let executions = infra::pipeline::execution::for_stream(org, stream).await?;
    for execution in &executions {
        let mut pipeline = execution.pipeline.clone();
        pipeline.validate()?;
        ensure!(
            pipeline.source == execution.pipeline.source,
            "Stored pipeline source mismatch"
        );
        resources(&pipeline)?;
    }
    if !executions.is_empty() {
        authorize(org, &executions, Some(&trigger)).await?;
    }
    let mut result = Vec::new();
    for execution in executions {
        let mut executable = ExecutablePipeline::new(&execution.pipeline).await?;
        executable.scoped_context = Some(ScopedContext {
            execution,
            trigger: trigger.clone(),
        });
        result.push(executable);
    }
    Ok(result)
}

pub(super) async fn validate_execution(org: &str, context: &ScopedContext) -> Result<()> {
    let stored = infra::pipeline::execution::by_id(org, &context.execution.pipeline.id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Pipeline no longer exists"))?;
    ensure!(
        stored == context.execution && stored.pipeline.enabled,
        "Pipeline changed before execution"
    );
    authorize(org, &[stored], Some(&context.trigger)).await
}

pub(super) fn validate_outputs(
    context: &ScopedContext,
    outputs: impl Iterator<Item = StreamParams>,
) -> Result<()> {
    let allowed = destination_resources(&context.execution.pipeline)?;
    for output in outputs {
        ensure!(
            output.org_id == context.execution.pipeline.org
                && output.stream_type == StreamType::Logs
                && allowed.contains(&Resource::stream("logs", &output.stream_name)),
            "Unapproved pipeline output"
        );
    }
    Ok(())
}

async fn authorize(
    org: &str,
    executions: &[PipelineExecution],
    trigger: Option<&str>,
) -> Result<()> {
    let mut permissions = Vec::new();
    for execution in executions {
        let pipeline = &execution.pipeline;
        ensure!(pipeline.org == org, "Pipeline organization mismatch");
        let subject = execution
            .subject
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Legacy pipeline has no scoped execution subject"))?;
        ensure!(
            !subject.starts_with("org-token:") && !subject.is_empty(),
            "Pipeline executor must be a user"
        );
        permissions.push((
            subject.clone(),
            Action::Write,
            Resource::new(ResourceKind::Pipeline, &pipeline.id),
        ));
        let source = pipeline.get_source_stream_params();
        permissions.push((
            subject.clone(),
            Action::Query,
            Resource::stream("logs", &source.stream_name),
        ));
        for resource in resources(pipeline)? {
            if let Some(trigger) = trigger {
                permissions.push((trigger.to_owned(), Action::Ingest, resource.clone()));
            }
        }
        for resource in destination_resources(pipeline)? {
            permissions.push((subject.clone(), Action::Ingest, resource));
        }
    }
    infra::rbac::authorize_pipeline_permissions(org, &permissions).await
}

fn destination_resources(pipeline: &Pipeline) -> Result<Vec<Resource>> {
    resources(pipeline)?;
    Ok(pipeline
        .nodes
        .iter()
        .filter(|node| !pipeline.edges.iter().any(|edge| edge.source == node.id))
        .filter_map(|node| match &node.data {
            NodeData::Stream(stream) => Some(Resource::stream("logs", &stream.stream_name)),
            _ => None,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use config::meta::pipeline::components::{Edge, Node};

    use super::*;

    fn local() -> Pipeline {
        let source = StreamParams::new("org", "input", StreamType::Logs);
        let destination = StreamParams::new("org", "output", StreamType::Logs);
        Pipeline {
            id: "pipe".into(),
            version: 1,
            enabled: true,
            org: "org".into(),
            name: "routing".into(),
            description: String::new(),
            source: PipelineSource::Realtime(source.clone()),
            kind: PipelineKind::User,
            nodes: vec![
                Node::new(
                    "source".into(),
                    NodeData::Stream(source),
                    0.,
                    0.,
                    "input".into(),
                ),
                Node::new(
                    "destination".into(),
                    NodeData::Stream(destination),
                    0.,
                    0.,
                    "output".into(),
                ),
            ],
            edges: vec![Edge::new("source".into(), "destination".into())],
        }
    }

    #[tokio::test]
    async fn internal_jobs_ingest_without_grants_and_run_no_pipelines() {
        let job = IngestUser::SystemJob(ingestion_common::SystemJobType::SelfReporting);
        let streams = [
            Resource::stream("logs", "usage"),
            Resource::stream("logs", "triggers"),
        ];
        assert_eq!(
            allowed_ingest("org", &job, &streams).await.unwrap(),
            vec![true, true]
        );
        assert!(load("org", "usage", &job).await.unwrap().is_empty());
    }

    #[test]
    fn scoped_pipeline_resolves_source_and_all_fixed_outputs() {
        let mut pipeline = local();
        pipeline.validate().unwrap();
        assert_eq!(
            resources(&pipeline).unwrap(),
            vec![
                Resource::stream("logs", "input"),
                Resource::stream("logs", "output")
            ]
        );
        assert_eq!(
            destination_resources(&pipeline).unwrap(),
            vec![Resource::stream("logs", "output")]
        );
        pipeline.nodes.push(Node::new(
            "extra".into(),
            NodeData::Stream(StreamParams::new("org", "secret", StreamType::Logs)),
            0.,
            0.,
            "output".into(),
        ));
        pipeline
            .edges
            .push(Edge::new("source".into(), "extra".into()));
        assert_eq!(destination_resources(&pipeline).unwrap().len(), 2);
        let context = ScopedContext {
            execution: PipelineExecution {
                pipeline,
                subject: Some("user".into()),
            },
            trigger: "writer".into(),
        };
        assert!(
            validate_outputs(
                &context,
                [StreamParams::new("org", "unapproved", StreamType::Logs)].into_iter()
            )
            .is_err()
        );
    }

    #[test]
    fn scoped_pipeline_rejects_dynamic_cross_org_and_unsupported_nodes() {
        for stream in [
            StreamParams::new("other", "output", StreamType::Logs),
            StreamParams::new("org", "{tenant}", StreamType::Logs),
            StreamParams::new("org", "output", StreamType::Metrics),
        ] {
            let mut pipeline = local();
            pipeline.nodes[1].data = NodeData::Stream(stream);
            assert!(resources(&pipeline).is_err());
        }
        let mut pipeline = local();
        pipeline.nodes[1].data = NodeData::WorkflowTrigger;
        assert!(resources(&pipeline).is_err());
        pipeline = local();
        pipeline.kind = PipelineKind::Evaluation;
        assert!(resources(&pipeline).is_err());
    }
}
