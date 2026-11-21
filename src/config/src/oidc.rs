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

use std::{collections::HashMap, ops::Deref, sync::LazyLock};

use dotenv_config::EnvConfig;
use serde::Serialize;

#[derive(Serialize, EnvConfig, Default)]
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

/// Application startup loads dotenv before constructing Config. Every subsequent config reload
/// receives the same OIDC settings, including the policy used to validate existing sessions.
#[derive(Serialize)]
#[serde(transparent)]
pub struct StartupOidc(&'static Oidc);

impl StartupOidc {
    pub(crate) fn init() -> Result<Self, &'static str> {
        static SETTINGS: LazyLock<Oidc> = LazyLock::new(|| {
            let settings = Oidc::init().expect("invalid OIDC configuration");
            settings
                .validate_startup()
                .expect("invalid OIDC configuration");
            settings
        });
        Ok(Self(&SETTINGS))
    }

    pub(crate) fn get_help() -> HashMap<String, (String, Option<String>)> {
        Oidc::get_help()
    }
}

impl Default for StartupOidc {
    fn default() -> Self {
        static DEFAULT: LazyLock<Oidc> = LazyLock::new(Oidc::default);
        Self(&DEFAULT)
    }
}

impl Deref for StartupOidc {
    type Target = Oidc;

    fn deref(&self) -> &Oidc {
        self.0
    }
}

pub const CALLBACK_PATH: &str = "/auth/oidc/callback";

impl Oidc {
    /// Whether human password login stays available, so the login page can offer it.
    pub fn allows_native_login(&self) -> bool {
        !self.enabled || !self.only || !self.emergency_user.is_empty()
    }

    fn validate_startup(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !(cfg!(feature = "enterprise") && self.enabled),
            "OSS OIDC is not supported in Enterprise builds"
        );
        anyhow::ensure!(
            !self.only || self.enabled,
            "ZO_OIDC_ONLY requires ZO_OIDC_ENABLED"
        );
        if self.enabled {
            self.validate_callback_path()?;
        }
        Ok(())
    }

    fn validate_callback_path(&self) -> anyhow::Result<()> {
        let uri = url::Url::parse(&self.redirect_uri)?;
        anyhow::ensure!(
            uri.path().ends_with(CALLBACK_PATH),
            "ZO_OIDC_REDIRECT_URI must end with {CALLBACK_PATH}"
        );
        Ok(())
    }
}

/// Whether a path or URL path is the callback, whose query carries the authorization code.
pub fn is_callback_path(path: &str) -> bool {
    path.trim_end_matches('/').ends_with(CALLBACK_PATH)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callback_path_detection_tolerates_prefixes_and_trailing_slashes() {
        for prefix in ["", "/observe", "https://example.test/observe"] {
            for suffix in ["", "/", "//"] {
                assert!(is_callback_path(&format!(
                    "{prefix}/auth/oidc/callback{suffix}"
                )));
            }
        }
        assert!(!is_callback_path("/auth/oidc/callback/extra"));
        assert!(!is_callback_path("/auth/oidc/login"));
    }

    #[test]
    fn callback_path_allows_proxy_prefixes_and_requires_the_exact_route() {
        for (path, valid) in [
            ("/auth/oidc/callback", true),
            ("/observe/auth/oidc/callback", true),
            ("/auth/oidc/callback/", false),
            ("/another/callback", false),
        ] {
            let cfg = Oidc {
                redirect_uri: format!("https://observe.example{path}"),
                ..Default::default()
            };
            assert_eq!(cfg.validate_callback_path().is_ok(), valid);
        }
    }

    #[test]
    fn private_oidc_settings_are_not_serialized() {
        let new = Oidc {
            client_secret: "private-client-secret".into(),
            account_links: "private-account-links".into(),
            ..Default::default()
        };
        let value = serde_json::to_value(new).unwrap();
        assert!(value.get("client_secret").is_none());
        assert!(value.get("account_links").is_none());
        assert_eq!(value.get("enabled"), Some(&serde_json::json!(false)));
    }
}
