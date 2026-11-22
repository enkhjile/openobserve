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

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use config::meta::{organization::OrganizationType, user::UserRole};
use http::{HeaderMap, Method, header};
use infra::table::{org_users, organizations};
use openobserve_core::extensions::oidc;
use openobserve_oidc::VerifiedIdentity;
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter};
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

fn compact_session_key(secret: &str) -> String {
    assert!(secret.starts_with("v1."));
    format!(
        "oidc_s_{}",
        URL_SAFE_NO_PAD.encode(&Sha256::digest(secret.as_bytes())[..21])
    )
}

async fn users_with_email(email: &str) -> usize {
    infra::table::entity::users::Entity::find()
        .filter(infra::table::entity::users::Column::Email.eq(email))
        .all(infra::db::get_orm_client_rw().await)
        .await
        .unwrap()
        .len()
}

async fn establish(
    identity: VerifiedIdentity,
    headers: &HeaderMap,
) -> anyhow::Result<(String, oidc::Session)> {
    let binding = oidc::random_secret();
    oidc::browser_transactions::register(&binding).await?;
    oidc::establish(
        identity,
        headers,
        &oidc::browser_transactions::marker(&binding),
    )
    .await
}

#[tokio::test]
async fn oidc_sessions_and_account_bindings_fail_closed() {
    let dir = std::env::temp_dir().join(format!("o2-oidc-lifecycle-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("db")).unwrap();
    let env_file = dir.join("empty.env");
    let account_links =
        r#"[{"issuer":"https://issuer.example","subject":"linked","email":"linked@example.com"}]"#;
    std::fs::write(
        &env_file,
        format!("ZO_OIDC_ACCOUNT_LINKS='{account_links}'\nZO_ROUTE_TIMEOUT=601\n"),
    )
    .unwrap();
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
    let startup = config::get_config();
    assert_eq!(startup.route.timeout, 601);
    assert!(startup.oidc.enabled);
    assert_eq!(startup.oidc.account_links, account_links);

    // A normal edit takes effect alongside valid changes to startup-only settings.
    std::fs::write(
        &env_file,
        "ZO_ROUTE_TIMEOUT=602\nZO_OIDC_ENABLED=false\nZO_OIDC_CLIENT_ID=next-client\nZO_OIDC_ACCOUNT_LINKS=[]\n",
    ).unwrap();
    config::refresh_config().unwrap();
    let mixed = config::get_config();
    assert_eq!(mixed.route.timeout, 602);
    assert!(mixed.oidc.enabled);
    assert_eq!(mixed.oidc.client_id, "test-client");
    assert_eq!(mixed.oidc.account_links, account_links);

    // Removing the mapping and leaving a malformed next-start flag cannot stall another reload.
    std::fs::write(
        &env_file,
        "ZO_ROUTE_TIMEOUT=603\nZO_OIDC_COOKIE_SECURE=invalid\n",
    )
    .unwrap();
    config::refresh_config().unwrap();
    let malformed = config::get_config();
    assert_eq!(malformed.route.timeout, 603);
    assert!(malformed.oidc.cookie_secure);
    assert_eq!(malformed.oidc.account_links, account_links);

    std::fs::write(&env_file, "ZO_ROUTE_TIMEOUT=604\n").unwrap();
    config::refresh_config().unwrap();
    let ordinary = config::get_config();
    assert_eq!(ordinary.route.timeout, 604);
    assert_eq!(ordinary.oidc.account_links, account_links);
    infra::db::create_table().await.unwrap();
    infra::db_init().await.unwrap();
    infra::table::migrate().await.unwrap();

    let (secret, first) = establish(identity("one", "one@example.com"), &HeaderMap::new())
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
        establish(identity("attacker", "ONE@example.com"), &HeaderMap::new())
            .await
            .is_err()
    );
    let mut bad = cookie(&secret);
    bad.insert(header::ORIGIN, "https://evil.example".parse().unwrap());
    let error = oidc::resolve_session(&bad, &Method::POST)
        .await
        .err()
        .unwrap();
    assert!(oidc::cross_origin_refused(&error) && !oidc::session_unavailable(&error));
    assert!(oidc::resolve_session(&bad, &Method::GET).await.is_ok());
    let mut bad = cookie(&secret);
    bad.append(
        header::COOKIE,
        format!("__Host-o2_oidc={secret}").parse().unwrap(),
    );
    assert!(oidc::resolve_session(&bad, &Method::GET).await.is_err());

    let connection = infra::db::get_orm_client_rw().await;
    connection
        .execute_unprepared(
            "CREATE TRIGGER reject_session_insert BEFORE INSERT ON sessions WHEN NEW.access_token != ''
             BEGIN SELECT RAISE(ABORT, 'test session insert failure'); END",
        )
        .await
        .unwrap();
    let result = establish(identity("one", "one@example.com"), &headers).await;
    connection
        .execute_unprepared("DROP TRIGGER reject_session_insert")
        .await
        .unwrap();
    assert!(result.is_err());
    assert!(oidc::resolve_session(&headers, &Method::GET).await.is_ok());

    let (rotated, _) = establish(identity("one", "one@example.com"), &headers)
        .await
        .unwrap();
    assert_ne!(secret, rotated);
    assert!(oidc::resolve_session(&headers, &Method::GET).await.is_err());
    let headers = cookie(&rotated);
    oidc::revoke(&headers).await.unwrap();
    let revoked_key = compact_session_key(&rotated);
    common::infra::config::USER_SESSIONS
        .insert(revoked_key.clone(), serde_json::to_string(&first).unwrap());
    common::infra::config::USER_SESSIONS_EXPIRY.insert(
        revoked_key,
        (chrono::Utc::now().timestamp() + 3600) * 1_000_000,
    );
    assert!(oidc::resolve_session(&headers, &Method::GET).await.is_err());
    let mut expired = identity("one", "one@example.com");
    expired.expires_at = chrono::Utc::now().timestamp() - 1;
    assert!(establish(expired, &HeaderMap::new()).await.is_err());

    let (abandoned, session) = establish(identity("one", "one@example.com"), &HeaderMap::new())
        .await
        .unwrap();
    let key = compact_session_key(&abandoned);
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

    let legacy_secret = oidc::random_secret();
    let legacy_key = format!("oidc_{:x}", Sha256::digest(legacy_secret.as_bytes()));
    infra::table::sessions::set_with_expiry(
        &legacy_key,
        &serde_json::to_string(&session).unwrap(),
        session.expires_at * 1_000_000,
    )
    .await
    .unwrap();
    let legacy_headers = cookie(&legacy_secret);
    assert!(
        oidc::resolve_session(&legacy_headers, &Method::GET)
            .await
            .is_ok()
    );
    oidc::revoke(&legacy_headers).await.unwrap();
    assert!(
        infra::table::sessions::get(&legacy_key)
            .await
            .unwrap()
            .is_none()
    );

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
    assert!(!oidc::session_unavailable(&error) && !oidc::cross_origin_refused(&error));

    let empty = HeaderMap::new();
    let (upper, lower) = tokio::join!(
        establish(identity("case-upper", " Race@Example.com "), &empty),
        establish(identity("case-lower", "race@example.com"), &empty),
    );
    assert_ne!(upper.is_ok(), lower.is_ok());
    assert_eq!(users_with_email("race@example.com").await, 1);
    assert!(
        establish(identity("bad-email", "invalid-address"), &empty)
            .await
            .is_err()
    );
    // Both callbacks of one new identity must share a reservation; repeated since timing varies.
    for round in 0..4 {
        let subject = format!("same-{round}");
        let email = format!("{subject}@example.com");
        let (first, second) = tokio::join!(
            establish(identity(&subject, &email), &empty),
            establish(identity(&subject, &email), &empty),
        );
        let ((first_secret, first), (second_secret, second)) = (first.unwrap(), second.unwrap());
        assert_eq!(first.user_id, second.user_id);
        for secret in [first_secret, second_secret] {
            let resolved = oidc::resolve_session(&cookie(&secret), &Method::GET).await;
            assert_eq!(resolved.unwrap().user_id, first.user_id);
        }
        assert_eq!(users_with_email(&email).await, 1);
    }

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
    let (_, recovered) = establish(
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
    let (_, recovered_again) = establish(
        identity("pending", "pending@example.com"),
        &HeaderMap::new(),
    )
    .await
    .unwrap();
    assert_eq!(recovered_again.user_id, reserved_id);

    let (secret, _) = establish(identity("one", "one@example.com"), &HeaderMap::new())
        .await
        .unwrap();
    let state = oidc::random_secret();
    let browser_binding = oidc::random_secret();
    oidc::browser_transactions::register(&browser_binding)
        .await
        .unwrap();
    let marker = oidc::browser_transactions::marker(&browser_binding);
    let mut logout_headers = cookie(&secret);
    logout_headers.append(
        http::header::COOKIE,
        format!(
            "{}={browser_binding}",
            oidc::browser_transactions::cookie_for_state(&config::get_config().oidc, &state)
                .unwrap()
        )
        .parse()
        .unwrap(),
    );
    let (successor, _) = oidc::establish(
        identity("one", "one@example.com"),
        &cookie(&secret),
        &marker,
    )
    .await
    .unwrap();
    connection
        .execute_unprepared(
            "CREATE TRIGGER reject_oidc_cancel BEFORE DELETE ON sessions WHEN OLD.session_id NOT GLOB 'oidc_tx_*'
             BEGIN SELECT RAISE(ABORT, 'test cancellation failure'); END",
        )
        .await
        .unwrap();
    assert!(oidc::revoke(&logout_headers).await.is_err());
    connection
        .execute_unprepared("DROP TRIGGER reject_oidc_cancel")
        .await
        .unwrap();
    assert!(
        oidc::resolve_session(&cookie(&successor), &Method::GET)
            .await
            .is_ok()
    );
    assert!(
        infra::table::sessions::get(&marker)
            .await
            .unwrap()
            .is_some()
    );
    // Logout carries the old session and transaction cookies captured before callback publication.
    oidc::revoke(&logout_headers).await.unwrap();
    assert!(
        oidc::resolve_session(&cookie(&successor), &Method::GET)
            .await
            .is_err()
    );
    assert!(
        oidc::establish(
            identity("one", "one@example.com"),
            &HeaderMap::new(),
            &marker
        )
        .await
        .is_err()
    );

    let (secret, _) = establish(identity("one", "one@example.com"), &HeaderMap::new())
        .await
        .unwrap();
    let binding = oidc::random_secret();
    oidc::browser_transactions::register(&binding)
        .await
        .unwrap();
    let previous_id = compact_session_key(&secret);
    assert!(
        oidc::session_store::rotate(
            &oidc::browser_transactions::marker(&binding),
            Some(&previous_id),
            "oidc_expired_replacement",
            "{}",
            chrono::Utc::now().timestamp_micros() - 1,
        )
        .await
        .is_err()
    );
    let expired_marker = oidc::browser_transactions::marker(&oidc::random_secret());
    oidc::session_store::start_transaction(
        &expired_marker,
        chrono::Utc::now().timestamp_micros() - 1,
    )
    .await
    .unwrap();
    assert!(
        oidc::establish(
            identity("one", "one@example.com"),
            &cookie(&secret),
            &expired_marker
        )
        .await
        .is_err()
    );
    assert!(
        oidc::resolve_session(&cookie(&secret), &Method::GET)
            .await
            .is_ok()
    );
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
        establish(identity("one", "one@example.com"), &HeaderMap::new())
            .await
            .is_err()
    );
}
