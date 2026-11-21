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

pub mod browser_transactions;
pub mod session_store;

use std::collections::HashMap;

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use config::{meta::user::DBUser, oidc::Oidc};
use http::{HeaderMap, HeaderValue, Method, header};
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

struct Runtime {
    provider: OidcProvider,
    // All configured links belong to the configured issuer.
    links: HashMap<String, AccountLink>,
}

static RUNTIME: OnceCell<Runtime> = OnceCell::const_new();

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
    Ok(&runtime().await?.provider)
}

async fn runtime() -> Result<&'static Runtime> {
    RUNTIME
        .get_or_try_init(|| async {
            let cfg = config::get_config();
            let links = validated_links(&cfg.oidc)?;
            let provider = OidcProvider::new(ProviderSettings {
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
            .context("OIDC provider configuration failed")?;
            Ok(Runtime { provider, links })
        })
        .await
}

fn validated_links(cfg: &Oidc) -> Result<HashMap<String, AccountLink>> {
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
    let mut identities = HashMap::new();
    for link in links {
        ensure!(
            !link.subject.is_empty()
                && config::utils::str::is_valid_email(&link.email)
                && link.issuer == cfg.issuer,
            "invalid OIDC account link"
        );
        ensure!(
            identities.insert(link.subject.clone(), link).is_none(),
            "duplicate OIDC account link"
        );
    }
    Ok(identities)
}

pub fn password_allowed(cfg: &Oidc, email: &str, is_root: bool) -> bool {
    !cfg.enabled
        || !cfg.only
        || (is_root && !cfg.emergency_user.is_empty() && cfg.emergency_user == email)
}

/// `password_allowed` under the running configuration, for credential checks in upstream code.
pub fn password_login_allowed(email: &str, is_root: bool) -> bool {
    password_allowed(&config::get_config().oidc, email, is_root)
}

pub fn cookie_name(cfg: &Oidc) -> &'static str {
    if cfg.cookie_secure {
        "__Host-o2_oidc"
    } else {
        "o2_oidc_dev"
    }
}

/// Formats an OIDC browser cookie; an age of zero clears it.
pub fn cookie_header(cfg: &Oidc, name: &str, value: &str, age: i64) -> HeaderValue {
    let secure = if cfg.cookie_secure { "; Secure" } else { "" };
    // Names are constants or validated states, and values are base64url secrets or empty.
    HeaderValue::from_str(&format!(
        "{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={age}{secure}"
    ))
    .expect("OIDC cookies are visible ASCII")
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

#[derive(Debug)]
struct SessionUnavailable;

impl std::fmt::Display for SessionUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OIDC session store unavailable")
    }
}

#[derive(Debug)]
struct CrossOriginRequest;

impl std::fmt::Display for CrossOriginRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("cross-origin OIDC request")
    }
}

pub fn session_unavailable(error: &anyhow::Error) -> bool {
    error.is::<SessionUnavailable>()
}

pub fn cross_origin_refused(error: &anyhow::Error) -> bool {
    error.is::<CrossOriginRequest>()
}

pub async fn resolve_session(headers: &HeaderMap, method: &Method) -> Result<Session> {
    Ok(resolve_session_account(headers, method).await?.0)
}

pub async fn resolve_session_account(
    headers: &HeaderMap,
    method: &Method,
) -> Result<(Session, DBUser)> {
    let cfg = config::get_config();
    ensure!(cfg.oidc.enabled, "OIDC disabled");
    check_csrf(headers, method, &cfg.oidc.redirect_uri).context(CrossOriginRequest)?;
    let secret = unique_cookie(headers, cookie_name(&cfg.oidc))?.context("no OIDC session")?;
    // A cache miss racing logout must never revive a revoked session from cache.
    let stored = infra::table::entity::sessions::Entity::find_by_id(session_key(secret))
        .one(infra::db::get_orm_client_rw().await)
        .await
        .context(SessionUnavailable)?
        .context("missing OIDC session")?;
    ensure!(
        stored.expires_at > chrono::Utc::now().timestamp_micros(),
        "expired OIDC session"
    );
    let session: Session =
        serde_json::from_str(&stored.access_token).context(SessionUnavailable)?;
    ensure!(
        session.expires_at > chrono::Utc::now().timestamp(),
        "expired OIDC session"
    );
    ensure!(session.issuer == cfg.oidc.issuer, "OIDC issuer changed");
    let binding = load_binding(&session.issuer, &session.subject)
        .await
        .context(SessionUnavailable)?
        .context("unlinked OIDC identity")?;
    ensure!(
        binding.identity.issuer == session.issuer
            && binding.identity.subject == session.subject
            && binding.identity.email == session.email
            && binding_allowed(
                &cfg.oidc,
                &runtime().await.context(SessionUnavailable)?.links,
                &binding
            ),
        "unapproved OIDC identity"
    );
    ensure!(
        binding.user_id == session.user_id && !binding.pending,
        "OIDC account replaced"
    );
    let user = bound_account(&binding).await?;
    Ok((session, user))
}

pub async fn establish(
    identity: VerifiedIdentity,
    headers: &HeaderMap,
    marker: &str,
) -> Result<(String, Session)> {
    let cfg = config::get_config();
    let links = &runtime().await?.links;
    ensure!(
        identity.expires_at > chrono::Utc::now().timestamp(),
        "expired OIDC identity"
    );
    let binding = resolve_identity(&cfg.oidc, links, &identity).await?;
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
    let previous_id = unique_cookie(headers, cookie_name(&cfg.oidc))?.map(session_key);
    let secret = format!("v1.{}", random_secret());
    session_store::rotate(
        marker,
        previous_id.as_deref(),
        &session_key(&secret),
        &serde_json::to_string(&session)?,
        expires_at * 1_000_000,
    )
    .await?;
    Ok((secret, session))
}

pub async fn revoke(headers: &HeaderMap) -> Result<()> {
    let cfg = config::get_config();
    let current = unique_cookie(headers, cookie_name(&cfg.oidc))?.map(session_key);
    let markers = browser_transactions::pending_markers(headers, &cfg.oidc);
    session_store::revoke(markers, current).await
}

/// Revokes the browser's OIDC session before a native login and returns the cookies that clear it.
pub async fn retire_browser_session(headers: &HeaderMap) -> Result<Vec<HeaderValue>> {
    let cfg = config::get_config();
    if !cfg.oidc.enabled {
        return Ok(Vec::new());
    }
    revoke(headers).await?;
    Ok(std::iter::once(cookie_name(&cfg.oidc))
        .chain(browser_transactions::pending_cookie_names(
            headers, &cfg.oidc,
        ))
        .map(|name| cookie_header(&cfg.oidc, name, "", 0))
        .collect())
}

fn session_key(secret: &str) -> String {
    if secret.starts_with("v1.") {
        return compact_key("oidc_s_", secret);
    }
    // Sessions issued before compact keys used the full hex digest on SQLite.
    format!(
        "{}{:x}",
        db::session::OIDC_SESSION_PREFIX,
        Sha256::digest(secret.as_bytes())
    )
}

fn compact_key(prefix: &str, secret: &str) -> String {
    // 168 bits encode to 28 characters, leaving room for the namespace in VARCHAR(36).
    let digest = Sha256::digest(secret.as_bytes());
    format!("{prefix}{}", URL_SAFE_NO_PAD.encode(&digest[..21]))
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

fn binding_allowed(cfg: &Oidc, links: &HashMap<String, AccountLink>, binding: &Binding) -> bool {
    match links.get(&binding.identity.subject) {
        Some(link) => link == &binding.identity,
        None => binding.provisioned && cfg.provisioning_enabled,
    }
}

async fn bound_account(binding: &Binding) -> Result<DBUser> {
    let user = db::user::get_db_user_by_id(&binding.user_id)
        .await
        .context(SessionUnavailable)?
        .context("deleted OIDC account")?;
    ensure!(
        user.email.to_lowercase() == binding.identity.email.to_lowercase(),
        "OIDC account renamed"
    );
    ensure!(
        !user
            .organizations
            .iter()
            .any(|org| org.role.is_service_account()),
        "service accounts cannot use interactive OIDC"
    );
    Ok(user)
}

async fn lookup_user(email: &str) -> Result<Option<users::Model>> {
    let mut matches = Users::find()
        .filter(Expr::expr(Func::lower(Expr::col(users::Column::Email))).eq(email.to_lowercase()))
        .all(infra::db::get_orm_client_rw().await)
        .await?;
    ensure!(matches.len() <= 1, "ambiguous OIDC account email");
    Ok(matches.pop())
}

async fn resolve_identity(
    cfg: &Oidc,
    links: &HashMap<String, AccountLink>,
    identity: &VerifiedIdentity,
) -> Result<Binding> {
    ensure!(
        identity.issuer == cfg.issuer && !identity.subject.is_empty(),
        "invalid OIDC identity"
    );
    let key = binding_key(&identity.issuer, &identity.subject)?;
    let store = infra::db::get_db().await;
    let (bytes, revision) = match store.get_with_revision(&key).await? {
        Some(existing) => existing,
        None => {
            let binding = initial_binding(cfg, links, identity).await?;
            // A concurrent callback owns the same immutable reservation if this CAS loses.
            store
                .put_if_revision(&key, Bytes::from(serde_json::to_vec(&binding)?), None)
                .await?;
            store
                .get_with_revision(&key)
                .await?
                .context("missing OIDC reservation")?
        }
    };
    let mut binding: Binding = serde_json::from_slice(&bytes)?;
    ensure!(
        binding.identity.issuer == identity.issuer
            && binding.identity.subject == identity.subject
            && binding_allowed(cfg, links, &binding),
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
        if !store
            .put_if_revision(
                &key,
                Bytes::from(serde_json::to_vec(&binding)?),
                Some(revision),
            )
            .await?
        {
            let current = load_binding(&identity.issuer, &identity.subject)
                .await?
                .context("missing OIDC binding")?;
            ensure!(
                !current.pending
                    && current.user_id == binding.user_id
                    && current.identity == binding.identity,
                "OIDC binding changed"
            );
        }
    }
    bound_account(&binding).await?;
    Ok(binding)
}

async fn initial_binding(
    cfg: &Oidc,
    links: &HashMap<String, AccountLink>,
    identity: &VerifiedIdentity,
) -> Result<Binding> {
    if let Some(link) = links.get(&identity.subject) {
        let user = lookup_user(&link.email)
            .await?
            .context("linked account missing")?;
        return Ok(Binding {
            identity: link.clone(),
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
    fn startup_rejects_invalid_session_settings_and_links() {
        let mut cfg = Oidc {
            enabled: true,
            issuer: "https://issuer".into(),
            cookie_secure: true,
            account_links: "[]".into(),
            ..Default::default()
        };
        assert!(validated_links(&cfg).is_err());
        cfg.session_max_age = 3600;
        cfg.cookie_secure = false;
        assert!(validated_links(&cfg).is_err());
        cfg.allow_insecure_http = true;
        assert!(validated_links(&cfg).is_ok());
        cfg.account_links = "invalid".into();
        assert!(validated_links(&cfg).is_err());
        let link = r#"{"issuer":"https://issuer","subject":"a","email":"a@example.com"}"#;
        cfg.account_links = format!("[{link},{link}]");
        assert!(validated_links(&cfg).is_err());
    }

    #[test]
    fn withdrawn_approval_and_email_takeover_are_rejected() {
        let mut cfg = Oidc {
            enabled: true,
            issuer: "https://issuer".into(),
            session_max_age: 3600,
            cookie_secure: true,
            ..Default::default()
        };
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
        assert!(binding_allowed(
            &cfg,
            &validated_links(&cfg).unwrap(),
            &binding
        ));
        cfg.account_links = "[]".into();
        assert!(!binding_allowed(
            &cfg,
            &validated_links(&cfg).unwrap(),
            &binding
        ));
        cfg.account_links =
            r#"[{"issuer":"https://issuer","subject":"attacker","email":"user@example.com"}]"#
                .into();
        assert!(!binding_allowed(
            &cfg,
            &validated_links(&cfg).unwrap(),
            &binding
        ));
    }
}
