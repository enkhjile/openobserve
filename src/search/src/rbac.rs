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

use std::ops::ControlFlow;

use anyhow::{Result, ensure};
use config::meta::stream::StreamType;
use datafusion::common::TableReference;
use sqlparser::{
    ast::{Expr, Statement, TableFactor, Visit, Visitor},
    dialect::PostgreSqlDialect,
    parser::Parser,
};

struct FunctionGuard<'a> {
    forbidden: &'a [String],
}

impl Visitor for FunctionGuard<'_> {
    type Break = String;
    fn pre_visit_expr(&mut self, expression: &Expr) -> ControlFlow<Self::Break> {
        if let Expr::Function(function) = expression {
            let name = function.name.to_string().replace('"', "");
            if self.forbidden.iter().any(|f| f.eq_ignore_ascii_case(&name)) {
                return ControlFlow::Break(name);
            }
        }
        ControlFlow::Continue(())
    }
}

struct SourceGuard;

impl Visitor for SourceGuard {
    type Break = ();

    fn pre_visit_table_factor(&mut self, table: &TableFactor) -> ControlFlow<Self::Break> {
        match table {
            TableFactor::Table { args: None, .. }
            | TableFactor::Derived { .. }
            | TableFactor::NestedJoin { .. } => ControlFlow::Continue(()),
            _ => ControlFlow::Break(()),
        }
    }
}

pub fn reject_custom_functions(sql: &str, forbidden: &[String]) -> Result<()> {
    let statements = Parser::parse_sql(&PostgreSqlDialect {}, sql)?;
    let mut guard = FunctionGuard { forbidden };
    if let ControlFlow::Break(name) = statements.visit(&mut guard) {
        anyhow::bail!("Custom function {name} requires a scoped RBAC adapter");
    }
    Ok(())
}

pub fn required_actions(
    event: Option<config::meta::search::SearchEventType>,
) -> &'static [infra::rbac::Action] {
    if event == Some(config::meta::search::SearchEventType::Download) {
        &[infra::rbac::Action::Query, infra::rbac::Action::Export]
    } else {
        &[infra::rbac::Action::Query]
    }
}

pub fn checked_sources(sql: &str) -> Result<Vec<TableReference>> {
    let statements = Parser::parse_sql(&PostgreSqlDialect {}, sql)?;
    ensure!(
        statements.len() == 1 && matches!(&statements[0], Statement::Query(_)),
        "RBAC requires one SELECT query"
    );
    ensure!(
        matches!(
            statements.visit(&mut SourceGuard),
            ControlFlow::Continue(())
        ),
        "RBAC requires named streams; table functions and special table sources are unsupported"
    );
    let sources = config::meta::sql::resolve_stream_names_with_type(sql)?;
    ensure!(!sources.is_empty(), "RBAC requires explicit source streams");
    for source in &sources {
        ensure!(
            source.catalog().is_none(),
            "cross-catalog queries are not authorized"
        );
        if let Some(schema) = source.schema() {
            ensure!(
                matches!(schema, "logs" | "metrics" | "traces" | "enrichment_tables"),
                "unknown stream type"
            );
        }
    }
    Ok(sources)
}

pub async fn authorize(
    sql: &str,
    org: &str,
    stream_type: StreamType,
    user: Option<&str>,
    event: Option<config::meta::search::SearchEventType>,
) -> Result<()> {
    if !infra::rbac::enabled() {
        return Ok(());
    }
    let user = user
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("RBAC execution identity required"))?;
    let subject = infra::rbac::user_subject(user).await?;
    authorize_subject_event(sql, org, stream_type, &subject, event).await?;
    Ok(())
}

pub async fn authorize_batch<'a>(
    statements: impl IntoIterator<Item = &'a str>,
    org: &str,
    stream_type: StreamType,
    user: Option<&str>,
    event: Option<config::meta::search::SearchEventType>,
    has_transform: bool,
) -> Result<()> {
    if !infra::rbac::enabled() {
        return Ok(());
    }
    ensure!(!has_transform, "Query transforms require a scoped adapter");
    let email = user
        .filter(|user| !user.is_empty())
        .ok_or_else(|| anyhow::anyhow!("RBAC execution identity required"))?;
    let subject = infra::rbac::user_subject(email).await?;
    authorize_statements(statements, org, stream_type, &subject, event).await?;
    Ok(())
}

pub async fn authorize_subject(
    sql: &str,
    org: &str,
    stream_type: StreamType,
    subject: &str,
) -> Result<Vec<infra::rbac::Resource>> {
    authorize_subject_event(sql, org, stream_type, subject, None).await
}

pub async fn authorize_subject_event(
    sql: &str,
    org: &str,
    stream_type: StreamType,
    subject: &str,
    event: Option<config::meta::search::SearchEventType>,
) -> Result<Vec<infra::rbac::Resource>> {
    authorize_statements([sql], org, stream_type, subject, event).await
}

async fn authorize_statements<'a>(
    statements: impl IntoIterator<Item = &'a str>,
    org: &str,
    stream_type: StreamType,
    subject: &str,
    event: Option<config::meta::search::SearchEventType>,
) -> Result<Vec<infra::rbac::Resource>> {
    ensure!(!subject.is_empty(), "RBAC execution identity required");
    let prefix = format!("{org}/");
    let forbidden: Vec<String> = transform::QUERY_FUNCTIONS
        .iter()
        .filter(|entry| entry.key().starts_with(&prefix))
        .map(|entry| entry.name.clone())
        .collect();
    let mut resources = Vec::new();
    for sql in statements {
        reject_custom_functions(sql, &forbidden)?;
        resources.extend(checked_sources(sql)?.iter().map(|source| {
            infra::rbac::Resource::stream(
                source.schema().unwrap_or(stream_type.as_str()),
                source.table(),
            )
        }));
    }
    ensure!(
        !resources.is_empty(),
        "RBAC requires explicit source streams"
    );
    let allowed = infra::rbac::allowed_subject_resource_actions(
        subject,
        org,
        required_actions(event),
        &resources,
    )
    .await?;
    ensure!(
        allowed.len() == resources.len() && allowed.into_iter().all(|allow| allow),
        "RBAC access denied"
    );
    Ok(resources)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_download_wire_event_requires_query_and_export() {
        let event: config::meta::search::SearchEventType =
            serde_json::from_str("\"download\"").unwrap();
        assert_eq!(
            required_actions(Some(event)),
            &[infra::rbac::Action::Query, infra::rbac::Action::Export]
        );
        assert_eq!(
            required_actions(Some(config::meta::search::SearchEventType::UI)),
            &[infra::rbac::Action::Query]
        );
        assert_eq!(required_actions(None), &[infra::rbac::Action::Query]);
    }

    #[test]
    fn custom_enrichment_functions_in_nested_queries_are_rejected() {
        let forbidden = vec!["secret_lookup".to_string()];
        for sql in [
            "SELECT secret_lookup(message) FROM public_logs",
            "WITH c AS (SELECT SECRET_LOOKUP(message) FROM public_logs) SELECT * FROM c",
            "SELECT * FROM public_logs WHERE id IN (SELECT secret_lookup(id) FROM other_logs)",
        ] {
            assert!(reject_custom_functions(sql, &forbidden).is_err());
        }
        assert!(reject_custom_functions("SELECT count(*) FROM public_logs", &forbidden).is_ok());
    }

    #[test]
    fn source_resolution_includes_nested_and_combined_streams() {
        for sql in [
            "SELECT * FROM public_logs p JOIN secret_logs s ON p.id = s.id",
            "WITH c AS (SELECT * FROM secret_logs) SELECT * FROM public_logs UNION ALL SELECT * FROM c",
            "SELECT * FROM public_logs WHERE id IN (SELECT id FROM secret_logs)",
        ] {
            let sources = checked_sources(sql).unwrap();
            assert!(sources.iter().any(|s| s.table() == "secret_logs"), "{sql}");
            assert!(sources.iter().any(|s| s.table() == "public_logs"), "{sql}");
        }
    }

    #[test]
    fn external_table_functions_cannot_hide_behind_an_authorized_stream() {
        for sql in [
            "SELECT * FROM public_logs CROSS JOIN read_parquet('/tmp/secret.parquet')",
            "SELECT * FROM public_logs CROSS JOIN LATERAL read_parquet('/tmp/secret.parquet')",
            "SELECT * FROM public_logs CROSS JOIN TABLE(read_parquet('/tmp/secret.parquet'))",
            "WITH hidden AS (SELECT * FROM read_parquet('/tmp/secret.parquet')) SELECT * FROM public_logs CROSS JOIN hidden",
            "SELECT * FROM public_logs WHERE id IN (SELECT id FROM read_parquet('/tmp/secret.parquet'))",
            "SELECT * FROM public_logs UNION ALL SELECT * FROM read_parquet('/tmp/secret.parquet')",
        ] {
            let statements = Parser::parse_sql(&PostgreSqlDialect {}, sql).unwrap();
            assert!(
                matches!(statements.visit(&mut SourceGuard), ControlFlow::Break(())),
                "{sql}"
            );
            assert!(checked_sources(sql).is_err(), "{sql}");
        }
    }

    #[test]
    fn unsupported_statement_shapes_are_rejected() {
        for sql in [
            "SELECT * FROM public_logs; SELECT * FROM secret_logs",
            "COPY public_logs TO '/tmp/output'",
            "SELECT * FROM other_org.logs.secret_logs",
            "SELECT * FROM unknown_type.secret_logs",
            "",
        ] {
            assert!(checked_sources(sql).is_err(), "{sql}");
        }
    }
}
