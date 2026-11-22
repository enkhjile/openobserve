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

use anyhow::{Context, Result, ensure};
use config::meta::{
    dashboards::{
        Dashboard,
        reports::{Report, ReportDestination, ReportExecutionContext},
    },
    destinations::{DestinationType, Module},
    search::SearchEventType,
};
use infra::rbac::{Action, Resource, ResourceKind, Role};

#[derive(Clone)]
pub(super) struct Scope {
    pub policy_version: u64,
    pub organization: String,
    pub author: String,
    pub renderer: String,
    pub tab_id: String,
    pub folder_id: String,
    pub dashboard_id: String,
    pub sources: Vec<Resource>,
    pub dashboard_json: serde_json::Value,
    pub recipients: Vec<String>,
}

const UNSUPPORTED: &str = "Unsupported or unauthorized scoped report configuration";

/// Binds a new report to `org` and its author; the error is the public denial message.
pub async fn bind_new(
    report: &mut Report,
    org: &str,
    email: &str,
    folder: &str,
) -> std::result::Result<(), &'static str> {
    if !infra::rbac::enabled() {
        return Ok(());
    }
    if !report.org_id.is_empty() && report.org_id != org {
        return Err("Report organization mismatch");
    }
    report.org_id = org.to_owned();
    bind(report, email, folder).await.map_err(|_| UNSUPPORTED)
}

/// Rebinds an updated report in place; scoped reports cannot move between orgs or folders.
pub async fn bind_update(
    report: &mut Report,
    org: &str,
    report_id: &str,
    email: &str,
    new_folder: Option<&str>,
) -> std::result::Result<(), &'static str> {
    if !infra::rbac::enabled() {
        return Ok(());
    }
    let (folder, _) = super::get_by_id(org, report_id)
        .await
        .map_err(|_| "Report authorization denied")?;
    if (!report.org_id.is_empty() && report.org_id != org)
        || new_folder.is_some_and(|value| value != folder.folder_id)
    {
        return Err("Scoped report moves are unsupported");
    }
    report.org_id = org.to_owned();
    bind(report, email, &folder.folder_id)
        .await
        .map_err(|_| UNSUPPORTED)
}

pub async fn bind(report: &mut Report, email: &str, folder: &str) -> Result<()> {
    if !infra::rbac::enabled() {
        return Ok(());
    }
    let author = infra::rbac::user_subject(email).await?;
    let renderer = infra::rbac::validate_report_renderer(
        &config::get_config().common.report_user_name,
        &report.org_id,
    )
    .await?;
    report.execution_context = Some(ReportExecutionContext {
        author_subject: author,
        renderer_subject: renderer,
        folder_id: folder.to_owned(),
        destination_names: report.delivery_destinations.clone(),
    });
    snapshot(report).await?;
    Ok(())
}

pub(super) async fn authorize(report: &Report) -> Result<Scope> {
    let context = report
        .execution_context
        .as_ref()
        .context("Missing scoped report execution identity")?;
    let client = infra::db::get_orm_client_rw().await;
    let (id, current) = infra::table::reports::get_with_id_by_name(
        client,
        &report.org_id,
        &context.folder_id,
        &report.name,
    )
    .await?
    .context("Report no longer exists")?;
    ensure!(
        serde_json::to_value(&current)? == serde_json::to_value(report)?,
        "Report revision changed"
    );
    for action in [Action::Read, Action::Write] {
        infra::rbac::authorize_subject(
            &context.author_subject,
            &report.org_id,
            action,
            Resource::new(ResourceKind::Report, &id),
        )
        .await?;
    }
    snapshot(report).await
}

pub(super) async fn recheck(report: &Report, previous: &Scope) -> Result<()> {
    let current = authorize(report).await?;
    ensure!(
        current.policy_version == previous.policy_version
            && current.dashboard_json == previous.dashboard_json
            && current.recipients == previous.recipients,
        "Report authorization or content changed during rendering"
    );
    Ok(())
}

pub(super) async fn current(scope: &Scope) -> Result<()> {
    infra::rbac::validate_subject(&scope.author, &scope.organization).await?;
    ensure!(
        infra::rbac::validate_report_renderer(
            &config::get_config().common.report_user_name,
            &scope.organization
        )
        .await?
            == scope.renderer,
        "Configured renderer identity changed"
    );
    ensure!(
        infra::rbac::read_policy(&scope.organization).await?.version == scope.policy_version,
        "Report policy changed during rendering"
    );
    Ok(())
}

async fn snapshot(report: &Report) -> Result<Scope> {
    ensure!(
        config::get_config().common.report_server_url.is_empty(),
        "Standalone report mode is unsupported with RBAC"
    );
    ensure!(
        report.dashboards.len() == 1,
        "Scoped rendering supports one dashboard"
    );
    let requested = &report.dashboards[0];
    ensure!(
        requested.report_type == config::meta::dashboards::reports::ReportMediaType::Pdf
            && requested.email_attachment_type
                == config::meta::dashboards::reports::ReportEmailAttachmentType::Standard
            && !report.image_preview,
        "Scoped local rendering supports standard PDF attachments"
    );
    ensure!(
        requested.tabs.len() == 1 && requested.variables.is_empty(),
        "Scoped rendering requires one tab without runtime variables"
    );
    let context = report
        .execution_context
        .as_ref()
        .context("Missing scoped report execution identity")?;
    infra::rbac::validate_subject(&context.author_subject, &report.org_id).await?;
    let renderer = infra::rbac::validate_report_renderer(
        &config::get_config().common.report_user_name,
        &report.org_id,
    )
    .await?;
    ensure!(
        renderer == context.renderer_subject,
        "Configured renderer identity changed"
    );
    let policy = infra::rbac::read_policy(&report.org_id).await?;
    let sources = renderer_resources(&policy.grants, &renderer, &requested.dashboard)?;
    let (folder, dashboard) =
        infra::table::dashboards::get_by_id_primary(&report.org_id, &requested.dashboard)
            .await?
            .context("Dashboard no longer exists")?;
    ensure!(
        folder.folder_id == requested.folder,
        "Dashboard folder changed"
    );
    infra::rbac::authorize_subject(
        &context.author_subject,
        &report.org_id,
        Action::Read,
        Resource::new(ResourceKind::Dashboard, &requested.dashboard),
    )
    .await?;
    let queries = dashboard_queries(&dashboard, &requested.tabs[0])?;
    let mut queried_sources = Vec::new();
    for (sql, stream_type) in queries {
        let checked = search::rbac::authorize_subject_event(
            &sql,
            &report.org_id,
            stream_type,
            &context.author_subject,
            Some(SearchEventType::Reports),
        )
        .await?;
        for source in checked {
            ensure!(
                sources.contains(&source),
                "Dashboard reads outside the renderer scope"
            );
            if !queried_sources.contains(&source) {
                queried_sources.push(source);
            }
        }
    }
    ensure!(
        sources
            .iter()
            .all(|source| queried_sources.contains(source)),
        "Renderer has sources outside this dashboard"
    );
    ensure!(
        !context.destination_names.is_empty(),
        "Scoped reports require approved email destinations"
    );
    let mut recipients = Vec::new();
    for name in &context.destination_names {
        let destination = infra::rbac::authorized_alert_destination(
            &context.author_subject,
            &report.org_id,
            &sources,
            name,
        )
        .await?;
        let Module::Alert {
            destination_type: DestinationType::Email(email),
            ..
        } = destination.module
        else {
            anyhow::bail!("Scoped reports require approved email destinations");
        };
        recipients.extend(email.recipients);
    }
    recipients.sort();
    recipients.dedup();
    let mut requested_recipients: Vec<_> = report
        .destinations
        .iter()
        .map(|destination| match destination {
            ReportDestination::Email(email) => email.clone(),
        })
        .collect();
    requested_recipients.sort();
    requested_recipients.dedup();
    ensure!(
        !recipients.is_empty() && requested_recipients == recipients,
        "Report recipients differ from approved destinations"
    );
    Ok(Scope {
        policy_version: policy.version,
        organization: report.org_id.clone(),
        author: context.author_subject.clone(),
        dashboard_id: requested.dashboard.clone(),
        renderer,
        tab_id: requested.tabs[0].clone(),
        folder_id: requested.folder.clone(),
        sources,
        dashboard_json: serde_json::to_value(dashboard)?,
        recipients,
    })
}

fn renderer_resources(
    grants: &[infra::rbac::Grant],
    renderer: &str,
    dashboard: &str,
) -> Result<Vec<Resource>> {
    let mut sources = Vec::new();
    let mut dashboard_granted = false;
    for grant in grants.iter().filter(|grant| grant.subject == renderer) {
        for resource in &grant.resources {
            match (grant.role, resource.kind) {
                (Role::Viewer, ResourceKind::Dashboard) if resource.name == dashboard => {
                    dashboard_granted = true
                }
                (Role::Exporter, ResourceKind::Stream)
                    if resource.name != "*" && resource.stream_type != "*" =>
                {
                    if !sources.contains(resource) {
                        sources.push(resource.clone());
                    }
                }
                _ => anyhow::bail!("Renderer grants exceed the exact report scope"),
            }
        }
    }
    ensure!(
        dashboard_granted && !sources.is_empty(),
        "Renderer requires exact dashboard and stream grants"
    );
    Ok(sources)
}

fn dashboard_queries(
    dashboard: &Dashboard,
    tab_id: &str,
) -> Result<Vec<(String, config::meta::stream::StreamType)>> {
    let dashboard = dashboard
        .v8
        .as_ref()
        .context("Scoped rendering supports v8 dashboards")?;
    ensure!(
        dashboard
            .variables
            .as_ref()
            .is_none_or(|vars| vars.list.is_empty())
            && dashboard
                .annotation_sources
                .as_ref()
                .is_none_or(Vec::is_empty),
        "Dynamic variables and annotations are unsupported"
    );
    ensure!(
        dashboard
            .tabs
            .iter()
            .any(|tab| tab.tab_id == tab_id && !tab.panels.is_empty()),
        "Report tab is missing or empty"
    );
    let mut queries = Vec::new();
    for panel in dashboard.tabs.iter().flat_map(|tab| &tab.panels) {
        ensure!(
            matches!(
                panel.typ.as_str(),
                "line"
                    | "bar"
                    | "h-bar"
                    | "area"
                    | "scatter"
                    | "pie"
                    | "donut"
                    | "table"
                    | "metric"
            ) && panel.query_type == "sql"
                && panel
                    .html_content
                    .as_ref()
                    .is_none_or(|value| value.trim().is_empty())
                && panel
                    .markdown_content
                    .as_ref()
                    .is_none_or(|value| value.trim().is_empty())
                && panel
                    .custom_chart_content
                    .as_ref()
                    .is_none_or(|value| value.trim().is_empty()),
            "Unsupported scoped dashboard panel"
        );
        ensure!(
            !unsafe_config(&serde_json::to_value(&panel.config)?),
            "External or executable panel configuration is unsupported"
        );
        ensure!(!panel.queries.is_empty(), "Report panel has no SQL query");
        for query in &panel.queries {
            ensure!(
                query.custom_query
                    && query
                        .vrl_function_query
                        .as_ref()
                        .is_none_or(|value| value.is_empty()),
                "Only static SQL report queries are supported"
            );
            queries.push((
                query
                    .query
                    .as_ref()
                    .filter(|sql| !sql.is_empty())
                    .context("Report SQL is missing")?
                    .clone(),
                query.fields.stream_type,
            ));
        }
    }
    Ok(queries)
}

fn unsafe_config(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(fields) => fields.iter().any(|(key, value)| {
            let key = key.to_lowercase();
            let present = !value.is_null()
                && value.as_array().is_none_or(|v| !v.is_empty())
                && value.as_str().is_none_or(|v| !v.is_empty());
            (present
                && ["url", "html", "javascript", "drilldown", "iframe"]
                    .iter()
                    .any(|word| key.contains(word)))
                || unsafe_config(value)
        }),
        serde_json::Value::Array(values) => values.iter().any(unsafe_config),
        serde_json::Value::String(value) => [
            "http://",
            "https://",
            "javascript:",
            "<script",
            "<iframe",
            "url(",
        ]
        .iter()
        .any(|part| value.to_lowercase().contains(part)),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use infra::rbac::Grant;

    use super::*;

    #[test]
    fn rbac_report_renderer_requires_entire_grant_set_to_be_bounded() {
        let renderer = "renderer";
        let mut grants = vec![
            Grant {
                subject: renderer.into(),
                role: Role::Viewer,
                resources: vec![Resource::new(ResourceKind::Dashboard, "board")],
            },
            Grant {
                subject: renderer.into(),
                role: Role::Exporter,
                resources: vec![Resource::stream("logs", "allowed")],
            },
        ];
        assert!(renderer_resources(&grants, renderer, "board").is_ok());
        assert!(renderer_resources(&grants, renderer, "other").is_err());
        for (role, resource) in [
            (Role::Admin, Resource::organization()),
            (Role::Editor, Resource::stream("logs", "allowed")),
            (Role::Viewer, Resource::new(ResourceKind::Dashboard, "*")),
            (
                Role::Viewer,
                Resource::new(ResourceKind::Dashboard, "other"),
            ),
            (Role::Exporter, Resource::stream("logs", "*")),
        ] {
            grants.push(Grant {
                subject: renderer.into(),
                role,
                resources: vec![resource],
            });
            assert!(renderer_resources(&grants, renderer, "board").is_err());
            grants.pop();
        }
    }

    #[test]
    fn rbac_report_rejects_external_and_executable_configuration() {
        for value in [
            serde_json::json!({"drilldown": [{"url": "https://example.com"}]}),
            serde_json::json!({"nested": {"iframe": "content"}}),
            serde_json::json!({"label": "<script>alert(1)</script>"}),
            serde_json::json!({"style": "background:url(https://example.com)"}),
        ] {
            assert!(unsafe_config(&value));
        }
        assert!(!unsafe_config(
            &serde_json::json!({"show_legends":true,"drilldown":[],"label":"Count"})
        ));
    }
    #[test]
    fn rbac_report_rejects_unscoped_and_dynamic_dashboard_shapes() {
        let legacy = config::meta::dashboards::Dashboard::default();
        assert!(dashboard_queries(&legacy, "main").is_err());
        let value = serde_json::json!({
            "version": 8, "tabs": [{"tabId":"main","name":"Main","panels":[{
                "id":"panel", "type":"table", "title":"Rows", "description":"",
                "queryType":"sql", "config":{"show_legends":false},
                "queries":[{"query":"SELECT id FROM allowed", "customQuery":true,
                    "fields":{"stream":"allowed","stream_type":"logs","x":[],"y":[],
                        "filter":{"filterType":"group","logicalOperator":"AND","conditions":[]}},
                    "config":{"promql_legend":""}}]
            }]}]
        });
        let dashboard: config::meta::dashboards::v8::Dashboard =
            serde_json::from_value(value.clone()).unwrap();
        assert!(dashboard_queries(&dashboard.into(), "main").is_ok());
        for (field, replacement) in [
            ("type", serde_json::json!("html")),
            (
                "htmlContent",
                serde_json::json!("<iframe src='https://example.com'></iframe>"),
            ),
            (
                "customChartContent",
                serde_json::json!("fetch('https://example.com')"),
            ),
            ("queryType", serde_json::json!("promql")),
        ] {
            let mut unsafe_dashboard = value.clone();
            unsafe_dashboard["tabs"][0]["panels"][0][field] = replacement;
            let dashboard: config::meta::dashboards::v8::Dashboard =
                serde_json::from_value(unsafe_dashboard).unwrap();
            assert!(dashboard_queries(&dashboard.into(), "main").is_err());
        }
    }
}
