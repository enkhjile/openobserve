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
use bytes::Bytes;
use config::oidc::Oidc;
use http::{HeaderMap, Method, header};
use infra::table::entity::users::{self, Entity as Users};
pub use openobserve_oidc::random_secret;
use openobserve_oidc::{OidcProvider, ProviderSettings, VerifiedIdentity};
use sea_orm::{
    EntityTrait, QueryFilter, Set,
    sea_query::{Expr, Func},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::OnceCell;
use url::Url;

static PROVIDER: OnceCell<OidcProvider> = OnceCell::const_new();

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AccountLink {
    pub issuer: String,
    pub subject: String,
    pub email: String,
}

#[derive(Deserialize, Serialize)]
struct Binding {
    identity: AccountLink,
    provisioned: bool,
    user_id: String,
    pending: bool,
}

#[derive(Deserialize, Serialize)]
pub struct Session {
    pub issuer: String,
    pub subject: String,
    pub email: String,
    pub expires_at: i64,
    pub user_id: String,
}

pub async fn provider() -> Result<&'static OidcProvider> {
    PROVIDER
        .get_or_try_init(|| async {
            let cfg = config::get_config();
            validate_settings(&cfg.oidc)?;
            OidcProvider::new(ProviderSettings {
                issuer: cfg.oidc.issuer.clone(),
                client_id: cfg.oidc.client_id.clone(),
                client_secret: (!cfg.oidc.client_secret.is_empty())
                    .then(|| cfg.oidc.client_secret.clone()),
                redirect_uri: cfg.oidc.redirect_uri.clone(),
                scopes: cfg
                    .oidc
                    .scopes
                    .split_whitespace()
                    .map(str::to_owned)
                    .collect(),
                allow_insecure_http: cfg.oidc.allow_insecure_http,
            })
            .map_err(|_| anyhow::anyhow!("OIDC provider configuration failed"))
        })
        .await
}

pub fn validate_settings(cfg: &Oidc) -> Result<()> {
    ensure!(cfg.enabled, "OIDC disabled");
    ensure!(
        cfg.session_max_age > 0 && cfg.session_max_age <= 86400,
        "invalid OIDC session lifetime"
    );
    ensure!(
        cfg.cookie_secure || cfg.allow_insecure_http,
        "insecure OIDC cookies require development opt-in"
    );
    let links: Vec<AccountLink> =
        serde_json::from_str(&cfg.account_links).context("invalid OIDC account links")?;
    let mut identities = std::collections::HashSet::new();
    for link in links {
        ensure!(
            !link.subject.is_empty() && !link.email.is_empty() && link.issuer == cfg.issuer,
            "invalid OIDC account link"
        );
        ensure!(
            identities.insert((link.issuer, link.subject)),
            "duplicate OIDC account link"
        );
    }
    Ok(())
}

pub fn password_allowed(cfg: &Oidc, email: &str, is_root: bool) -> bool {
    !cfg.enabled
        || !cfg.only
        || (is_root && !cfg.emergency_user.is_empty() && cfg.emergency_user == email)
}

pub fn cookie_name(cfg: &Oidc) -> &'static str {
    if cfg.cookie_secure {
        "__Host-o2_oidc"
    } else {
        "o2_oidc_dev"
    }
}

pub fn transaction_cookie_name(cfg: &Oidc) -> &'static str {
    if cfg.cookie_secure {
        "__Host-o2_oidc_tx"
    } else {
        "o2_oidc_tx_dev"
    }
}

pub fn unique_cookie<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>> {
    let mut found = None;
    for line in headers.get_all(header::COOKIE) {
        for part in line.to_str()?.split(';') {
            if let Some((key, value)) = part.trim().split_once('=')
                && key == name
            {
                ensure!(found.is_none(), "duplicate OIDC cookie");
                ensure!(!value.is_empty(), "empty OIDC cookie");
                found = Some(value);
            }
        }
    }
    Ok(found)
}

pub fn has_session_cookie(headers: &HeaderMap) -> bool {
    let cfg = config::get_config();
    cfg.oidc.enabled && !matches!(unique_cookie(headers, cookie_name(&cfg.oidc)), Ok(None))
}

pub fn check_csrf(headers: &HeaderMap, method: &Method, redirect_uri: &str) -> Result<()> {
    if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return Ok(());
    }
    let expected = Url::parse(redirect_uri)?.origin();
    let actual = match headers.get(header::ORIGIN) {
        Some(origin) => Url::parse(origin.to_str()?)?,
        None => Url::parse(
            headers
                .get(header::REFERER)
                .context("missing request origin")?
                .to_str()?,
        )?,
    };
    ensure!(actual.origin() == expected, "cross-origin OIDC request");
    Ok(())
}

pub async fn resolve_session(headers: &HeaderMap, method: &Method) -> Result<Session> {
    let cfg = config::get_config();
    ensure!(cfg.oidc.enabled, "OIDC disabled");
    check_csrf(headers, method, &cfg.oidc.redirect_uri)?;
    let secret = unique_cookie(headers, cookie_name(&cfg.oidc))?.context("no OIDC session")?;
    // A cache miss racing logout must never revive a revoked session from cache.
    let stored = infra::table::entity::sessions::Entity::find_by_id(session_key(secret))
        .one(infra::db::get_orm_client_rw().await)
        .await?
        .context("missing OIDC session")?;
    ensure!(
        stored.expires_at > chrono::Utc::now().timestamp_micros(),
        "expired OIDC session"
    );
    let session: Session = serde_json::from_str(&stored.access_token)?;
    ensure!(
        session.expires_at > chrono::Utc::now().timestamp(),
        "expired OIDC session"
    );
    ensure!(session.issuer == cfg.oidc.issuer, "OIDC issuer changed");
    let binding = load_binding(&session.issuer, &session.subject)
        .await?
        .context("unlinked OIDC identity")?;
    ensure!(
        binding.identity.email == session.email && binding_allowed(&cfg.oidc, &binding)?,
        "unapproved OIDC identity"
    );
    ensure_human_account(&session.email).await?;
    let user = lookup_user(&session.email)
        .await?
        .context("deleted OIDC account")?;
    ensure!(
        user.id == binding.user_id && user.id == session.user_id && !binding.pending,
        "OIDC account replaced"
    );
    Ok(session)
}

pub async fn establish(
    identity: VerifiedIdentity,
    headers: &HeaderMap,
) -> Result<(String, Session)> {
    let cfg = config::get_config();
    validate_settings(&cfg.oidc)?;
    ensure!(
        identity.expires_at > chrono::Utc::now().timestamp(),
        "expired OIDC identity"
    );
    let binding = resolve_identity(&cfg.oidc, &identity).await?;
    let expires_at = identity
        .expires_at
        .min(chrono::Utc::now().timestamp() + cfg.oidc.session_max_age);
    ensure!(
        expires_at > chrono::Utc::now().timestamp(),
        "expired OIDC identity"
    );
    let session = Session {
        issuer: identity.issuer,
        subject: identity.subject,
        email: binding.identity.email,
        expires_at,
        user_id: binding.user_id,
    };
    // Revoke first; a failed rotation must not leave a second live browser credential.
    revoke(headers).await?;
    let secret = random_secret();
    db::session::set_with_expiry(
        &session_key(&secret),
        &serde_json::to_string(&session)?,
        expires_at * 1_000_000,
    )
    .await?;
    Ok((secret, session))
}

pub async fn revoke(headers: &HeaderMap) -> Result<()> {
    let cfg = config::get_config();
    if let Some(secret) = unique_cookie(headers, cookie_name(&cfg.oidc))? {
        db::session::delete(&session_key(secret)).await?;
    }
    Ok(())
}

fn session_key(secret: &str) -> String {
    format!("oidc_{:x}", Sha256::digest(secret.as_bytes()))
}

fn binding_key(issuer: &str, subject: &str) -> Result<String> {
    Ok(format!(
        "/oidc/identities/{:x}",
        Sha256::digest(serde_json::to_vec(&(issuer, subject))?)
    ))
}

async fn load_binding(issuer: &str, subject: &str) -> Result<Option<Binding>> {
    infra::db::get_db()
        .await
        .get_if_exists(&binding_key(issuer, subject)?)
        .await?
        .map(|bytes| serde_json::from_slice(&bytes).map_err(Into::into))
        .transpose()
}

fn configured_link(cfg: &Oidc, issuer: &str, subject: &str) -> Result<Option<AccountLink>> {
    let links: Vec<AccountLink> = serde_json::from_str(&cfg.account_links)?;
    Ok(links
        .into_iter()
        .find(|link| link.issuer == issuer && link.subject == subject))
}

fn binding_allowed(cfg: &Oidc, binding: &Binding) -> Result<bool> {
    let link = configured_link(cfg, &binding.identity.issuer, &binding.identity.subject)?;
    Ok(match link {
        Some(link) => link == binding.identity,
        None => binding.provisioned && cfg.provisioning_enabled,
    })
}

async fn ensure_human_account(email: &str) -> Result<()> {
    let user = db::user::get_db_user(email).await?;
    ensure!(
        !user
            .organizations
            .iter()
            .any(|org| org.role.is_service_account()),
        "service accounts cannot use interactive OIDC"
    );
    Ok(())
}

async fn lookup_user(email: &str) -> Result<Option<users::Model>> {
    let mut matches = Users::find()
        .filter(Expr::expr(Func::lower(Expr::col(users::Column::Email))).eq(email.to_lowercase()))
        .all(infra::db::get_orm_client_rw().await)
        .await?;
    ensure!(matches.len() <= 1, "ambiguous OIDC account email");
    Ok(matches.pop())
}

async fn resolve_identity(cfg: &Oidc, identity: &VerifiedIdentity) -> Result<Binding> {
    ensure!(
        identity.issuer == cfg.issuer && !identity.subject.is_empty(),
        "invalid OIDC identity"
    );
    let key = binding_key(&identity.issuer, &identity.subject)?;
    let store = infra::db::get_db().await;
    if load_binding(&identity.issuer, &identity.subject)
        .await?
        .is_none()
    {
        let binding = initial_binding(cfg, identity).await?;
        // A concurrent callback owns the same immutable reservation if this CAS loses.
        store
            .put_if_revision(&key, Bytes::from(serde_json::to_vec(&binding)?), None)
            .await?;
    }
    let (bytes, revision) = store
        .get_with_revision(&key)
        .await?
        .context("missing OIDC reservation")?;
    let mut binding: Binding = serde_json::from_slice(&bytes)?;
    ensure!(
        binding.identity.issuer == identity.issuer
            && binding.identity.subject == identity.subject
            && binding_allowed(cfg, &binding)?,
        "unapproved OIDC identity"
    );
    if binding.pending {
        complete_provisioning(&binding, identity).await?;
        infra::db::put_into_db_coordinator(
            &format!("{}{}", db::user::USER_RECORD_KEY, binding.identity.email),
            Bytes::new(),
            true,
            None,
        )
        .await?;
        binding.pending = false;
        store
            .put_if_revision(
                &key,
                Bytes::from(serde_json::to_vec(&binding)?),
                Some(revision),
            )
            .await?;
        let current = load_binding(&identity.issuer, &identity.subject)
            .await?
            .context("missing OIDC binding")?;
        ensure!(
            !current.pending && current.user_id == binding.user_id,
            "OIDC binding changed"
        );
    }
    let user = lookup_user(&binding.identity.email)
        .await?
        .context("deleted OIDC account")?;
    ensure!(user.id == binding.user_id, "OIDC account replaced");
    ensure_human_account(&binding.identity.email).await?;
    Ok(binding)
}

async fn initial_binding(cfg: &Oidc, identity: &VerifiedIdentity) -> Result<Binding> {
    if let Some(link) = configured_link(cfg, &identity.issuer, &identity.subject)? {
        let user = lookup_user(&link.email)
            .await?
            .context("linked account missing")?;
        return Ok(Binding {
            identity: link,
            provisioned: false,
            user_id: user.id,
            pending: false,
        });
    }
    ensure!(
        cfg.provisioning_enabled && identity.email_verified,
        "OIDC provisioning denied"
    );
    let email = identity
        .email
        .as_ref()
        .context("OIDC email missing")?
        .trim()
        .to_lowercase();
    ensure!(
        config::utils::str::is_valid_email(&email),
        "invalid OIDC email"
    );
    ensure!(
        lookup_user(&email).await?.is_none(),
        "OIDC account collision"
    );
    Ok(Binding {
        identity: AccountLink {
            issuer: identity.issuer.clone(),
            subject: identity.subject.clone(),
            email: email.clone(),
        },
        provisioned: true,
        user_id: config::ider::uuid(),
        pending: true,
    })
}

async fn complete_provisioning(binding: &Binding, identity: &VerifiedIdentity) -> Result<()> {
    ensure!(binding.provisioned, "invalid OIDC reservation");
    if let Some(user) = lookup_user(&binding.identity.email).await? {
        ensure!(user.id == binding.user_id, "OIDC account collision");
        return Ok(());
    }
    let now = chrono::Utc::now().timestamp_micros();
    let record = users::ActiveModel {
        id: Set(binding.user_id.clone()),
        email: Set(binding.identity.email.clone()),
        first_name: Set(identity.given_name.clone().unwrap_or_default()),
        last_name: Set(identity.family_name.clone().unwrap_or_default()),
        password: Set("!oidc-disabled-password!".into()),
        salt: Set(random_secret()),
        is_root: Set(false),
        password_ext: Set(None),
        user_type: Set(config::meta::user::UserType::External.into()),
        created_at: Set(now),
        updated_at: Set(now),
        must_reset_password: Set(false),
        password_reset_reason: Set(None),
        flagged_at: Set(None),
        password_updated_at: Set(Some(now)),
    };
    match Users::insert(record)
        .exec(infra::db::get_orm_client_rw().await)
        .await
    {
        Ok(_) => Ok(()),
        Err(error) => {
            let user = lookup_user(&binding.identity.email)
                .await?
                .context("OIDC user insert failed")?;
            if user.id != binding.user_id {
                return Err(error.into());
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_policy_preserves_disabled_and_requires_exact_root() {
        let mut cfg = Oidc {
            only: true,
            ..Default::default()
        };
        assert!(password_allowed(&cfg, "human@example.com", false));
        cfg.enabled = true;
        cfg.emergency_user = "root@example.com".into();
        assert!(!password_allowed(&cfg, "human@example.com", false));
        assert!(!password_allowed(&cfg, "root@example.com", false));
        assert!(password_allowed(&cfg, "root@example.com", true));
        assert!(!password_allowed(&cfg, "other@example.com", true));
    }

    #[test]
    fn csrf_rejects_cross_origin_and_missing_origin() {
        let mut headers = HeaderMap::new();
        let expected = "https://observe.example/auth/oidc/callback";
        assert!(check_csrf(&headers, &Method::POST, expected).is_err());
        headers.insert(header::ORIGIN, "https://evil.example".parse().unwrap());
        assert!(check_csrf(&headers, &Method::POST, expected).is_err());
        headers.insert(header::ORIGIN, "https://observe.example".parse().unwrap());
        assert!(check_csrf(&headers, &Method::POST, expected).is_ok());
    }

    #[test]
    fn duplicate_cookie_and_ambiguous_binding_fail() {
        let mut headers = HeaderMap::new();
        headers.append(header::COOKIE, "x=1; x=2".parse().unwrap());
        assert!(unique_cookie(&headers, "x").is_err());
        assert_ne!(
            binding_key("ab", "c").unwrap(),
            binding_key("a", "bc").unwrap()
        );
        assert!(!session_key("secret").contains("secret"));
    }

    #[test]
    fn withdrawn_approval_and_email_takeover_are_rejected() {
        let mut cfg = Oidc::default();
        let binding = Binding {
            identity: AccountLink {
                issuer: "https://issuer".into(),
                subject: "subject".into(),
                email: "user@example.com".into(),
            },
            provisioned: false,
            user_id: "immutable-id".into(),
            pending: false,
        };
        cfg.account_links = serde_json::to_string(&vec![binding.identity.clone()]).unwrap();
        assert!(binding_allowed(&cfg, &binding).unwrap());
        cfg.account_links = "[]".into();
        assert!(!binding_allowed(&cfg, &binding).unwrap());
        cfg.account_links =
            r#"[{"issuer":"https://issuer","subject":"attacker","email":"user@example.com"}]"#
                .into();
        assert!(!binding_allowed(&cfg, &binding).unwrap());
    }
}
