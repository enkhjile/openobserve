// Copyright 2026 OpenObserve Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use infra::errors::{Error, Result};
use promql::ast::{name_visitor::MetricNameVisitor, visitor::walk_expr};

pub fn sources(query: &str) -> Result<Vec<infra::rbac::Resource>> {
    let ast = promql_parser::parser::parse(query).map_err(denied)?;
    let mut visitor = MetricNameVisitor::new();
    walk_expr(&mut visitor, &ast).map_err(denied)?;
    let names = visitor.into_names();
    if names.is_empty() {
        return Err(denied("Explicit metric source required"));
    }
    Ok(names
        .into_iter()
        .map(|name| infra::rbac::Resource::stream("metrics", &name))
        .collect())
}

pub async fn authorize(subject: Option<&str>, org: &str, query: &str) -> Result<()> {
    if !infra::rbac::enabled() {
        return Ok(());
    }
    let subject = subject
        .filter(|s| !s.is_empty())
        .ok_or_else(|| denied("Metrics execution identity required"))?;
    let resources = sources(query)?;
    let decisions = infra::rbac::allowed_subject_resources(
        subject,
        org,
        infra::rbac::Action::Query,
        &resources,
    )
    .await
    .map_err(denied)?;
    if decisions.len() != resources.len() || !decisions.into_iter().all(|allow| allow) {
        return Err(denied("Metrics access denied"));
    }
    Ok(())
}

/// Authorizes a metrics query request: an explicitly named query only, never data,
/// exemplar or download operations.
pub async fn guard(req: &proto::cluster_rpc::MetricsQueryRequest) -> Result<()> {
    if !infra::rbac::enabled() {
        return Ok(());
    }
    let query = req
        .query
        .as_ref()
        .ok_or_else(|| denied("Missing metrics query"))?;
    if query.query_data || query.query_exemplars || req.search_event_type == "download" {
        return Err(denied("Metrics operation requires a scoped adapter"));
    }
    authorize(req.rbac_subject.as_deref(), &req.org_id, &query.query).await
}

pub fn denied(message: impl std::fmt::Display) -> Error {
    infra::rbac::denied(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_selector_must_resolve() {
        for query in [
            "up + {job=\"secret\"}",
            "up or {__name__=~\"secret.*\"}",
            "sum(rate({job=\"secret\"}[5m]))",
            "vector(1)",
        ] {
            assert!(sources(query).is_err(), "{query}");
        }
        let names = sources("sum(rate(up[5m])) + secret_metric").unwrap();
        assert!(names.iter().any(|r| r.name == "up"));
        assert!(names.iter().any(|r| r.name == "secret_metric"));
        assert_eq!(sources("{__name__=\"up\"}").unwrap()[0].name, "up");
    }
}
