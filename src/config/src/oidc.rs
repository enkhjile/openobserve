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

use dotenv_config::EnvConfig;
use serde::Serialize;

#[derive(Serialize, EnvConfig, Default, PartialEq, Eq)]
pub struct Oidc {
    #[env_config(name = "ZO_OIDC_ENABLED", default = false)]
    pub enabled: bool,
    #[env_config(name = "ZO_OIDC_ISSUER", default = "")]
    pub issuer: String,
    #[env_config(name = "ZO_OIDC_CLIENT_ID", default = "")]
    pub client_id: String,
    #[serde(skip_serializing)]
    #[env_config(name = "ZO_OIDC_CLIENT_SECRET", default = "")]
    pub client_secret: String,
    #[env_config(name = "ZO_OIDC_REDIRECT_URI", default = "")]
    pub redirect_uri: String,
    #[env_config(name = "ZO_OIDC_SCOPES", default = "openid email profile")]
    pub scopes: String,
    #[env_config(name = "ZO_OIDC_ALLOW_INSECURE_HTTP", default = false)]
    pub allow_insecure_http: bool,
    #[env_config(name = "ZO_OIDC_PROVISIONING_ENABLED", default = false)]
    pub provisioning_enabled: bool,
    #[serde(skip_serializing)]
    #[env_config(name = "ZO_OIDC_ACCOUNT_LINKS", default = "[]")]
    pub account_links: String,
    #[env_config(name = "ZO_OIDC_ONLY", default = false)]
    pub only: bool,
    #[env_config(name = "ZO_OIDC_EMERGENCY_USER", default = "")]
    pub emergency_user: String,
    #[env_config(name = "ZO_OIDC_SESSION_MAX_AGE", default = 3600)]
    pub session_max_age: i64,
    #[env_config(name = "ZO_OIDC_COOKIE_SECURE", default = true)]
    pub cookie_secure: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_oidc_settings_are_not_serialized_but_are_compared_on_reload() {
        let old = Oidc::default();
        let new = Oidc {
            client_secret: "private-client-secret".into(),
            account_links: "private-account-links".into(),
            ..Default::default()
        };
        assert!(old != new);
        let value = serde_json::to_value(new).unwrap();
        assert!(value.get("client_secret").is_none());
        assert!(value.get("account_links").is_none());
        assert_eq!(value.get("enabled"), Some(&serde_json::json!(false)));
    }
}
