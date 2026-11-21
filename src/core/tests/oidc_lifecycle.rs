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

use config::meta::{organization::OrganizationType, user::UserRole};
use http::{HeaderMap, Method, header};
use infra::table::{org_users, organizations};
use openobserve_core::extensions::oidc;
use openobserve_oidc::VerifiedIdentity;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use sha2::{Digest, Sha256};

fn env(key: &str, value: &str) {
    // This binary has one test and sets configuration before starting any worker.
    unsafe { std::env::set_var(key, value) };
}

fn identity(subject: &str, email: &str) -> VerifiedIdentity {
    VerifiedIdentity {
        issuer: "https://issuer.example".into(),
        subject: subject.into(),
        email: Some(email.into()),
        email_verified: true,
        given_name: Some("OIDC".into()),
        family_name: Some("Test".into()),
        expires_at: chrono::Utc::now().timestamp() + 300,
    }
}

fn cookie(secret: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        format!("__Host-o2_oidc={secret}").parse().unwrap(),
    );
    headers.insert(header::ORIGIN, "https://observe.example".parse().unwrap());
    headers
}

#[tokio::test]
async fn oidc_sessions_and_account_bindings_fail_closed() {
    let dir = std::env::temp_dir().join(format!("o2-oidc-lifecycle-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("db")).unwrap();
    let env_file = dir.join("empty.env");
    std::fs::write(&env_file, "").unwrap();
    config::config_path_manager::set_config_file_path(env_file.clone()).unwrap();
    env("ZO_LOCAL_MODE", "true");
    env("ZO_META_STORE", "sqlite");
    env("ZO_DATA_DIR", &format!("{}/", dir.display()));
    env("ZO_DATA_DB_DIR", &format!("{}/db/", dir.display()));
    env("ZO_OIDC_ENABLED", "true");
    env("ZO_OIDC_CLIENT_ID", "test-client");
    env("ZO_OIDC_ISSUER", "https://issuer.example");
    env(
        "ZO_OIDC_REDIRECT_URI",
        "https://observe.example/auth/oidc/callback",
    );
    env("ZO_OIDC_PROVISIONING_ENABLED", "true");
    assert!(config::get_config().oidc.enabled);
    let before_enabled = std::env::var_os("ZO_OIDC_ENABLED");
    let before_only = std::env::var_os("ZO_OIDC_ONLY");
    let before_secure = std::env::var_os("ZO_OIDC_COOKIE_SECURE");
    let new_key = "O2_TEST_RELOAD_TRANSIENT";
    assert!(std::env::var_os(new_key).is_none());
    env("O2_TEST_RELOAD_BASE", "original");
    for invalid in [
        "ZO_OIDC_ENABLED=false\nZO_OIDC_ONLY=true",
        "ZO_OIDC_ONLY=true",
        "ZO_ROUTE_STRATEGY=invalid",
        "ZO_OIDC_COOKIE_SECURE=invalid",
        "bad dotenv line",
    ] {
        std::fs::write(
            &env_file,
            format!("O2_TEST_RELOAD_BASE=first\nO2_TEST_RELOAD_BASE=second\n{new_key}=candidate\n{invalid}\n"),
        ).unwrap();
        assert!(config::config::refresh_config().is_err());
        assert_eq!(std::env::var("O2_TEST_RELOAD_BASE").unwrap(), "original");
        assert!(std::env::var_os(new_key).is_none());
        assert_eq!(std::env::var_os("ZO_OIDC_ENABLED"), before_enabled);
        assert_eq!(std::env::var_os("ZO_OIDC_ONLY"), before_only);
        assert_eq!(std::env::var_os("ZO_OIDC_COOKIE_SECURE"), before_secure);
        assert!(config::get_config().oidc.enabled);
        assert!(!config::get_config().oidc.only);
    }
    std::fs::write(
        &env_file,
        format!("\u{feff}O2_TEST_RELOAD_BASE=first\n{new_key}=${{O2_TEST_RELOAD_BASE}}\nO2_TEST_RELOAD_BASE=last\n"),
    ).unwrap();
    config::config::refresh_config().unwrap();
    assert_eq!(std::env::var(new_key).unwrap(), "first");
    assert_eq!(std::env::var("O2_TEST_RELOAD_BASE").unwrap(), "last");
    infra::db::create_table().await.unwrap();
    infra::db_init().await.unwrap();
    infra::table::migrate().await.unwrap();

    let (secret, first) = oidc::establish(identity("one", "one@example.com"), &HeaderMap::new())
        .await
        .unwrap();
    let headers = cookie(&secret);
    assert_eq!(
        oidc::resolve_session(&headers, &Method::GET)
            .await
            .unwrap()
            .user_id,
        first.user_id
    );
    let (_, db_user) = oidc::resolve_session_account(&headers, &Method::GET)
        .await
        .unwrap();
    assert_eq!(db_user.email, "one@example.com");
    assert!(db_user.organizations.is_empty());
    assert!(db_user.password_ext.is_none());
    assert!(!db_user.password.is_empty());
    organizations::add("team", "Team", OrganizationType::Custom)
        .await
        .unwrap();
    org_users::add("team", &db_user.email, UserRole::Viewer, "fixture", None)
        .await
        .unwrap();
    let (_, member) = oidc::resolve_session_account(&headers, &Method::GET)
        .await
        .unwrap();
    assert_eq!(member.organizations.len(), 1);
    assert_eq!(member.organizations[0].role, UserRole::Viewer);
    org_users::remove("team", &db_user.email).await.unwrap();
    org_users::add(
        "team",
        &db_user.email,
        UserRole::ServiceAccount,
        "fixture",
        None,
    )
    .await
    .unwrap();
    assert!(
        oidc::resolve_session_account(&headers, &Method::GET)
            .await
            .is_err()
    );
    org_users::remove("team", &db_user.email).await.unwrap();
    assert!(
        oidc::establish(identity("attacker", "ONE@example.com"), &HeaderMap::new())
            .await
            .is_err()
    );
    let mut bad = cookie(&secret);
    bad.insert(header::ORIGIN, "https://evil.example".parse().unwrap());
    assert!(oidc::resolve_session(&bad, &Method::POST).await.is_err());
    let mut bad = cookie(&secret);
    bad.append(
        header::COOKIE,
        format!("__Host-o2_oidc={secret}").parse().unwrap(),
    );
    assert!(oidc::resolve_session(&bad, &Method::GET).await.is_err());

    let (rotated, _) = oidc::establish(identity("one", "one@example.com"), &headers)
        .await
        .unwrap();
    assert_ne!(secret, rotated);
    assert!(oidc::resolve_session(&headers, &Method::GET).await.is_err());
    let headers = cookie(&rotated);
    oidc::revoke(&headers).await.unwrap();
    let revoked_key = format!("oidc_{:x}", Sha256::digest(rotated.as_bytes()));
    common::infra::config::USER_SESSIONS
        .insert(revoked_key.clone(), serde_json::to_string(&first).unwrap());
    common::infra::config::USER_SESSIONS_EXPIRY.insert(
        revoked_key,
        (chrono::Utc::now().timestamp() + 3600) * 1_000_000,
    );
    assert!(oidc::resolve_session(&headers, &Method::GET).await.is_err());
    let mut expired = identity("one", "one@example.com");
    expired.expires_at = chrono::Utc::now().timestamp() - 1;
    assert!(oidc::establish(expired, &HeaderMap::new()).await.is_err());

    let (abandoned, session) =
        oidc::establish(identity("one", "one@example.com"), &HeaderMap::new())
            .await
            .unwrap();
    let key = format!("oidc_{:x}", Sha256::digest(abandoned.as_bytes()));
    db::session::cache().await.unwrap();
    assert!(!common::infra::config::USER_SESSIONS.contains_key(&key));
    assert!(!common::infra::config::USER_SESSIONS_EXPIRY.contains_key(&key));
    infra::table::sessions::set_with_expiry(
        &key,
        &serde_json::to_string(&session).unwrap(),
        chrono::Utc::now().timestamp_micros() - 1,
    )
    .await
    .unwrap();
    assert!(
        oidc::resolve_session(&cookie(&abandoned), &Method::GET)
            .await
            .is_err()
    );
    infra::table::sessions::delete_expired().await.unwrap();
    assert!(infra::table::sessions::get(&key).await.unwrap().is_none());

    let broken_key = format!("oidc_{:x}", Sha256::digest(b"broken"));
    db::session::set_with_expiry(
        &broken_key,
        "malformed",
        (chrono::Utc::now().timestamp() + 300) * 1_000_000,
    )
    .await
    .unwrap();
    let error = oidc::resolve_session(&cookie("broken"), &Method::GET)
        .await
        .err()
        .unwrap();
    assert!(oidc::session_unavailable(&error));
    let error = oidc::resolve_session(&cookie("absent"), &Method::GET)
        .await
        .err()
        .unwrap();
    assert!(!oidc::session_unavailable(&error));

    let empty = HeaderMap::new();
    let (upper, lower) = tokio::join!(
        oidc::establish(identity("case-upper", " Race@Example.com "), &empty),
        oidc::establish(identity("case-lower", "race@example.com"), &empty),
    );
    assert_ne!(upper.is_ok(), lower.is_ok());
    let rows = infra::table::entity::users::Entity::find()
        .filter(infra::table::entity::users::Column::Email.eq("race@example.com"))
        .all(infra::db::get_orm_client_rw().await)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert!(
        oidc::establish(identity("bad-email", "invalid-address"), &empty)
            .await
            .is_err()
    );

    let reserved_id = config::ider::uuid();
    let binding_key = format!(
        "/oidc/identities/{:x}",
        Sha256::digest(serde_json::to_vec(&("https://issuer.example", "pending")).unwrap())
    );
    let reservation = serde_json::json!({"identity":{"issuer":"https://issuer.example","subject":"pending","email":"pending@example.com"},"provisioned":true,"user_id":reserved_id,"pending":true});
    infra::db::get_db()
        .await
        .put(
            &binding_key,
            serde_json::to_vec(&reservation).unwrap().into(),
            false,
            None,
        )
        .await
        .unwrap();
    let (_, recovered) = oidc::establish(
        identity("pending", "pending@example.com"),
        &HeaderMap::new(),
    )
    .await
    .unwrap();
    assert_eq!(recovered.user_id, reserved_id);
    infra::db::get_db()
        .await
        .put(
            &binding_key,
            serde_json::to_vec(&reservation).unwrap().into(),
            false,
            None,
        )
        .await
        .unwrap();
    let (_, recovered_again) = oidc::establish(
        identity("pending", "pending@example.com"),
        &HeaderMap::new(),
    )
    .await
    .unwrap();
    assert_eq!(recovered_again.user_id, reserved_id);

    let (secret, _) = oidc::establish(identity("one", "one@example.com"), &HeaderMap::new())
        .await
        .unwrap();
    let user = db::user::get_user_record("one@example.com").await.unwrap();
    use infra::table::entity::users;
    users::Entity::delete_many()
        .filter(users::Column::Email.eq("one@example.com"))
        .exec(infra::db::get_orm_client_rw().await)
        .await
        .unwrap();
    db::user::add_record(user).await.unwrap();
    assert!(
        oidc::resolve_session(&cookie(&secret), &Method::GET)
            .await
            .is_err()
    );
    assert!(
        oidc::establish(identity("one", "one@example.com"), &HeaderMap::new())
            .await
            .is_err()
    );
}
