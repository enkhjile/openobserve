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
fn every_endpoint_keeps_its_reviewed_rbac_disposition() {
    let inventory = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../docs/rbac/endpoints.md"
    ));
    let expected: BTreeSet<_> = inventory
        .lines()
        .filter(|line| {
            line.starts_with("| ") && !line.starts_with("| Method") && !line.starts_with("| ---")
        })
        .map(str::to_owned)
        .collect();
    let actual: BTreeSet<_> = parsed_routes()
        .into_iter()
        .map(|route| {
            format!(
                "| {} | `{}` | {} | {:?} |",
                route.method,
                route.path,
                route.active,
                super::super::rbac::disposition(&route.method, &route.path)
            )
        })
        .collect();
    if !cfg!(feature = "enterprise")
        && !cfg!(feature = "cloud")
        && !cfg!(feature = "cpu-profiling")
        && !cfg!(feature = "profiling")
    {
        assert_eq!(
            actual, expected,
            "Review authorization and run python3 scripts/rbac/endpoint_inventory.py after route changes"
        );
    }
}

#[test]
fn internal_rbac_mount_aliases_preserve_canonical_operation_coverage() {
    let routes = parse_router(
        r#"
fn local_routes() -> Router {
    Router::new().nest("/api", api()).nest("/internal/rbac/v1/api", api())
}
fn api() -> Router {
    Router::new().route("/{org_id}/_search", post(search))
}
#[cfg(test)]
mod tests {}
    "#,
    );
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].path, "/api/{org_id}/_search");
    assert_eq!(routes[0].method, "POST");
}

#[test]
#[should_panic(expected = "non-literal nest prefix")]
fn dynamic_mount_prefix_cannot_publish_rust_source_as_a_route() {
    parse_router(
        r#"
fn local_routes() -> Router {
    Router::new().nest(&format!("{}/api", PREFIX), api())
}
fn api() -> Router {
    Router::new().route("/{org_id}/_search", post(search))
}
#[cfg(test)]
mod tests {}
    "#,
    );
}
