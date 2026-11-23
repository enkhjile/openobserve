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

use axum::http::Method;
use config::{
    DEFAULT_ORG,
    meta::user::{DBUser, UserRole},
};
use db::user::is_root_user;
pub(super) use openobserve_core::extensions::oidc::{has_session_cookie, password_login_allowed};
use openobserve_core::{
    auth::{AuthExtractor, org_from_path, routed_path},
    authz::check_permissions,
    extensions::oidc,
};

use super::{
    AuthError, AuthValidationResult, RequestData, check_and_create_org, is_org_agnostic_path,
    is_top_level_org_route,
};

pub(super) async fn validate_session(
    req: &RequestData,
    auth: &AuthExtractor,
    path_prefix: &str,
) -> Result<AuthValidationResult, AuthError> {
    let (_, record) = oidc::resolve_session_account(&req.headers, &req.method)
        .await
        .map_err(|error| {
            if oidc::session_unavailable(&error) {
                AuthError::Unavailable("Session store unavailable".into())
            } else if oidc::cross_origin_refused(&error) {
                AuthError::Forbidden("Cross-origin request refused".into())
            } else {
                AuthError::Unauthorized("Unauthorized Access".into())
            }
        })?;
    let path = routed_path(
        req.uri
            .path()
            .strip_prefix(path_prefix)
            .unwrap_or(req.uri.path()),
    );
    let path = path.strip_suffix('/').unwrap_or(path);
    let Some(role) = oidc_role(&record, path, &req.method, is_root_user(&record.email)) else {
        return Err(AuthError::RoleRefused("Not allowed".into()));
    };
    check_and_create_org(&record.email, &req.method, path, req.route.as_deref()).await?;
    if !auth.bypass_check
        && !check_permissions(&record.email, auth.clone(), role.clone(), true).await
    {
        return Err(AuthError::RoleRefused("Unauthorized Access".into()));
    }
    Ok(AuthValidationResult {
        user_email: record.email,
        user_role: Some(role),
        is_internal_user: !record.is_external,
        token_name: None,
        ingestion_principal: None,
        delegation: None,
    })
}

fn oidc_role(record: &DBUser, path: &str, method: &Method, is_root: bool) -> Option<UserRole> {
    if is_root {
        return Some(UserRole::Root);
    }
    let columns: Vec<_> = path.split('/').collect();
    if is_top_level_org_route(&columns) {
        return record
            .organizations
            .iter()
            .find(|org| org.name == config::META_ORG_ID)
            .or_else(|| record.organizations.first())
            .map(|org| org.role.clone())
            .or_else(|| matches!(*method, Method::GET | Method::HEAD).then_some(UserRole::User));
    }
    if is_org_agnostic_path(path) {
        return Some(UserRole::User);
    }
    let org_id = if columns.len() == 1 {
        DEFAULT_ORG
    } else {
        org_from_path(&columns)
    };
    record
        .organizations
        .iter()
        .find(|org| org.name == org_id)
        .map(|org| org.role.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mirrors the parent's pin: each RoleRefused here directly follows its role check.
    #[test]
    fn role_refusals_follow_their_role_checks() {
        let source = include_str!("oidc.rs");
        let (production, _) = source.split_once("\n#[cfg(test)]\nmod tests {").unwrap();
        let refusals: Vec<usize> = production
            .match_indices("Err(AuthError::RoleRefused(")
            .map(|(at, _)| at)
            .collect();
        assert_eq!(
            refusals.len(),
            2,
            "review each RoleRefused site: it reveals the license"
        );
        for at in refusals {
            let before = &production[..at];
            let guard = ["oidc_role(&record", "check_permissions("]
                .iter()
                .filter_map(|g| before.rfind(g))
                .max()
                .expect("role check before RoleRefused");
            assert!(
                !before[guard..].contains("AuthError::"),
                "{}",
                &before[guard..]
            );
        }
    }

    #[test]
    fn oidc_clusters_uses_default_org_membership() {
        let mut record: DBUser = serde_json::from_value(serde_json::json!({
            "email": "viewer@example.com",
            "password": "",
            "organizations": [{"name": "clusters", "role": "viewer"}]
        }))
        .unwrap();
        assert_eq!(oidc_role(&record, "clusters", &Method::GET, false), None);
        record.organizations[0].name = DEFAULT_ORG.into();
        assert_eq!(
            oidc_role(&record, "clusters", &Method::GET, false),
            Some(UserRole::Viewer)
        );
    }

    #[test]
    fn oidc_without_memberships_can_only_list_its_own_organizations() {
        let record = DBUser {
            email: "pending@example.com".into(),
            first_name: String::new(),
            last_name: String::new(),
            password: String::new(),
            salt: String::new(),
            organizations: vec![],
            is_external: true,
            password_ext: None,
        };
        assert_eq!(
            oidc_role(&record, "organizations", &Method::GET, false),
            Some(UserRole::User)
        );
        assert_eq!(
            oidc_role(&record, "organizations", &Method::POST, false),
            None
        );
        assert_eq!(
            oidc_role(&record, "default/streams", &Method::GET, false),
            None
        );
        assert_eq!(
            oidc_role(&record, "v2/default/alerts", &Method::GET, false),
            None
        );
        assert_eq!(
            oidc_role(&record, "default/kv/organizations", &Method::GET, false),
            None
        );
    }
}
