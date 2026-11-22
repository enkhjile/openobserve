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

use anyhow::{Result, ensure};
use config::meta::alerts::{
    QueryCondition, QueryType,
    alert::{Alert, AlertTypeFilter},
};
use infra::rbac::{Action, Resource, ResourceKind};

pub fn validate_query(query: &QueryCondition) -> Result<()> {
    ensure!(
        query.query_type == QueryType::SQL
            && query.sql.as_ref().is_some_and(|sql| !sql.trim().is_empty())
            && query.vrl_function.is_none()
            && query.multi_time_range.is_none()
            && query.search_event_type.is_none()
            && query.aggregation.is_none()
            && !query.multi_alert_enabled(),
        "Unsupported scoped alert query"
    );
    Ok(())
}

pub fn validate_shape(alert: &Alert) -> Result<()> {
    validate_query(&alert.query_condition)?;
    ensure!(
        !alert.is_real_time
            && alert.template.is_none()
            && alert.workflows.is_empty()
            && !alert.creates_incident
            && alert.oncall_team.is_none()
            && !alert.notify_on_recovery
            && alert.recovery_destinations.is_empty(),
        "Unsupported scoped alert delivery"
    );
    Ok(())
}

/// Whether RBAC permits saving an alert of this type; only scheduled alerts have an adapter.
pub fn allows_type(alert_type: Option<&AlertTypeFilter>) -> bool {
    !infra::rbac::enabled() || matches!(alert_type, None | Some(AlertTypeFilter::Scheduled))
}

pub async fn bind(alert: &mut Alert, org: &str, email: &str) -> Result<()> {
    if !infra::rbac::enabled() {
        return Ok(());
    }
    alert.org_id = org.to_owned();
    validate_shape(alert)?;
    let subject = infra::rbac::user_subject(email).await?;
    infra::rbac::validate_subject(&subject, &alert.org_id).await?;
    infra::rbac::authorize_subject(
        &subject,
        &alert.org_id,
        Action::Write,
        Resource::new(
            ResourceKind::Alert,
            &alert
                .id
                .map(|id| id.to_string())
                .unwrap_or_else(|| "*".into()),
        ),
    )
    .await?;
    let sources = search::rbac::authorize_subject(
        alert.query_condition.sql.as_deref().unwrap_or_default(),
        &alert.org_id,
        alert.stream_type,
        &subject,
    )
    .await?;
    infra::rbac::authorize_alert_destinations(
        &subject,
        &alert.org_id,
        &sources,
        &alert.destinations,
    )
    .await?;
    alert.execution_subject = Some(subject);
    Ok(())
}

pub async fn authorize_execution(alert: &Alert) -> Result<Vec<Resource>> {
    validate_shape(alert)?;
    let subject = alert
        .execution_subject
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("Missing scoped alert execution identity"))?;
    let id = alert
        .id
        .ok_or_else(|| anyhow::anyhow!("Missing alert identity"))?;
    infra::rbac::validate_subject(subject, &alert.org_id).await?;
    for action in [Action::Read, Action::Write] {
        infra::rbac::authorize_subject(
            subject,
            &alert.org_id,
            action,
            Resource::new(ResourceKind::Alert, &id.to_string()),
        )
        .await?;
    }
    let client = infra::db::get_orm_client_rw().await;
    let (_, current) = db::alerts::alert::get_by_id(client, &alert.org_id, id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Alert no longer exists"))?;
    ensure!(
        current.execution_subject == alert.execution_subject
            && current.updated_at == alert.updated_at
            && current.query_condition == alert.query_condition
            && current.destinations == alert.destinations
            && current.stream_type == alert.stream_type
            && current.stream_name == alert.stream_name,
        "Alert execution revision changed"
    );
    let sources = search::rbac::authorize_subject(
        alert.query_condition.sql.as_deref().unwrap_or_default(),
        &alert.org_id,
        alert.stream_type,
        subject,
    )
    .await?;
    infra::rbac::authorize_alert_destinations(
        subject,
        &alert.org_id,
        &sources,
        &alert.destinations,
    )
    .await?;
    Ok(sources)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn legacy_scheduled_sql_has_no_implicit_execution_authority() {
        let mut alert = Alert::default();
        alert.query_condition.query_type = QueryType::SQL;
        alert.query_condition.sql = Some("SELECT id FROM logs".into());
        let error = authorize_execution(&alert).await.unwrap_err();
        assert_eq!(error.to_string(), "Missing scoped alert execution identity");
    }

    #[test]
    fn only_scoped_scheduled_sql_shape_is_supported() {
        let mut alert = Alert::default();
        alert.query_condition.query_type = QueryType::SQL;
        alert.query_condition.sql = Some("SELECT * FROM logs".into());
        assert!(validate_shape(&alert).is_ok());
        for change in [
            |a: &mut Alert| a.is_real_time = true,
            |a: &mut Alert| a.query_condition.query_type = QueryType::PromQL,
            |a: &mut Alert| a.query_condition.vrl_function = Some(".secret".into()),
            |a: &mut Alert| a.template = Some("override".into()),
            |a: &mut Alert| a.creates_incident = true,
            |a: &mut Alert| a.notify_on_recovery = true,
            |a: &mut Alert| a.workflows.push("workflow".into()),
        ] {
            let mut unsafe_alert = alert.clone();
            change(&mut unsafe_alert);
            assert!(validate_shape(&unsafe_alert).is_err());
        }
    }
}
