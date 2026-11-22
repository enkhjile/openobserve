use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use axum::{
    Json, Router,
    extract::{Form, State},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use openobserve_oidc::{OidcProvider, ProviderSettings, random_secret};
use rsa::{RsaPrivateKey, pkcs1::EncodeRsaPrivateKey, rand_core::OsRng, traits::PublicKeyParts};
use serde_json::{Value, json};

fn signing_key(kid: &str) -> (EncodingKey, Value) {
    let key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
    let jwk = json!({
        "kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig",
        "n": URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()),
        "e": URL_SAFE_NO_PAD.encode(key.e().to_bytes_be()),
    });
    (
        EncodingKey::from_rsa_der(key.to_pkcs1_der().unwrap().as_bytes()),
        jwk,
    )
}

#[derive(Clone)]
struct Mock {
    issuer: String,
    initial_key: EncodingKey,
    rotated_key: EncodingKey,
    claims: Arc<Mutex<Value>>,
    mode: Arc<Mutex<String>>,
    jwks: Arc<Mutex<Value>>,
}
async fn discovery(State(s): State<Mock>) -> Json<Value> {
    Json(
        json!({"issuer":s.issuer,"authorization_endpoint":format!("{}/authorize",s.issuer),"token_endpoint":format!("{}/token",s.issuer),"jwks_uri":format!("{}/jwks",s.issuer),"response_types_supported":["code"],"subject_types_supported":["public"],"token_endpoint_auth_methods_supported":["client_secret_post"],"id_token_signing_alg_values_supported":["RS256"]}),
    )
}
async fn token(State(s): State<Mock>, Form(form): Form<HashMap<String, String>>) -> Json<Value> {
    assert!(form.contains_key("code_verifier"));
    assert_eq!(form.get("client_id").map(String::as_str), Some("client"));
    assert_eq!(
        form.get("client_secret").map(String::as_str),
        Some("secret")
    );
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key".into());
    let mode = s.mode.lock().unwrap().clone();
    if mode == "unknown-kid" {
        header.kid = Some("unknown".into());
    }
    if !matches!(mode.as_str(), "valid" | "unknown-kid" | "retired-key") {
        header.kid = Some("rotated".into());
    }
    if mode == "algorithm" {
        header.alg = Algorithm::RS512;
    }
    let signing_key = if matches!(mode.as_str(), "valid" | "retired-key") {
        &s.initial_key
    } else {
        &s.rotated_key
    };
    let mut token = jsonwebtoken::encode(&header, &*s.claims.lock().unwrap(), signing_key).unwrap();
    if mode == "signature" {
        let offset = token.rfind('.').unwrap() + 1;
        token.replace_range(
            offset..offset + 1,
            if &token[offset..offset + 1] == "A" {
                "B"
            } else {
                "A"
            },
        );
    }
    Json(json!({"access_token":"access","token_type":"Bearer","id_token":token}))
}
#[tokio::test]
async fn signed_login_claim_rejections_and_replay() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}", listener.local_addr().unwrap());
    let (initial_key, initial_jwk) = signing_key("test-key");
    let (rotated_key, rotated_jwk) = signing_key("rotated");
    let state = Mock {
        initial_key,
        rotated_key,
        issuer: issuer.clone(),
        claims: Arc::new(Mutex::new(json!({}))),
        mode: Arc::new(Mutex::new(String::new())),
        jwks: Arc::new(Mutex::new(json!({"keys": [initial_jwk]}))),
    };
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route(
            "/jwks",
            get(|State(s): State<Mock>| async move { Json(s.jwks.lock().unwrap().clone()) }),
        )
        .route("/token", post(token))
        .with_state(state.clone());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let provider = OidcProvider::new(ProviderSettings {
        issuer: issuer.clone(),
        client_id: "client".into(),
        client_secret: Some("secret".into()),
        redirect_uri: "http://localhost/callback".into(),
        scopes: vec!["openid".into()],
        allow_insecure_http: true,
    })
    .unwrap();
    for case in [
        "valid",
        "rotation",
        "retired-key",
        "signature",
        "unknown-kid",
        "algorithm",
        "nbf",
        "issuer",
        "audience",
        "nonce",
        "expiry",
        "future",
        "azp",
    ] {
        let binding = random_secret();
        let begin = provider.begin(&binding).await.unwrap();
        let url = url::Url::parse(&begin.url).unwrap();
        let params: HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(params["code_challenge_method"], "S256");
        let now = chrono::Utc::now().timestamp();
        let mut claims = json!({"iss":issuer,"sub":"subject","aud":"client","iat":now,"exp":now+300,"nonce":params["nonce"],"email":"user@example.test","email_verified":true});
        match case {
            "nbf" => claims["nbf"] = json!(now + 120),
            "issuer" => claims["iss"] = json!("http://wrong"),
            "audience" => claims["aud"] = json!("other"),
            "nonce" => claims["nonce"] = json!("wrong"),
            "expiry" => claims["exp"] = json!(now - 1),
            "future" => claims["iat"] = json!(now + 120),
            "azp" => claims["azp"] = json!("other"),
            _ => {}
        }
        *state.claims.lock().unwrap() = claims;
        *state.mode.lock().unwrap() = case.into();
        if case == "rotation" {
            *state.jwks.lock().unwrap() = json!({"keys": [rotated_jwk]});
        }

        let result = provider.complete("code", &begin.state, &binding).await;
        assert_eq!(
            result.is_ok(),
            matches!(case, "valid" | "rotation"),
            "{case}: {result:?}"
        );
        assert!(
            provider
                .complete("code", &begin.state, &binding)
                .await
                .is_err()
        );
    }
    server.abort();
}

#[tokio::test]
async fn concurrent_discovery_outage_is_cached_and_recovers() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use axum::{http::StatusCode, response::IntoResponse};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(AtomicUsize::new(0));
    let healthy = Arc::new(AtomicBool::new(false));
    let app = Router::new()
        .route("/.well-known/openid-configuration", get({
            let requests = requests.clone();
            let healthy = healthy.clone();
            let issuer = issuer.clone();
            move || {
                let requests = requests.clone();
                let healthy = healthy.clone();
                let issuer = issuer.clone();
                async move {
                    requests.fetch_add(1, Ordering::SeqCst);
                    if !healthy.load(Ordering::SeqCst) { return StatusCode::SERVICE_UNAVAILABLE.into_response(); }
                    Json(json!({"issuer":issuer,"authorization_endpoint":format!("{issuer}/authorize"),"token_endpoint":format!("{issuer}/token"),"jwks_uri":format!("{issuer}/jwks"),"response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"]})).into_response()
                }
            }
        }))
        .route("/jwks", get(|| async { Json(json!({"keys":[]})) }));
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let provider = Arc::new(
        OidcProvider::new(ProviderSettings {
            issuer,
            client_id: "client".into(),
            client_secret: None,
            redirect_uri: "http://localhost/callback".into(),
            scopes: vec!["openid".into()],
            allow_insecure_http: true,
        })
        .unwrap(),
    );
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..20 {
        let provider = provider.clone();
        tasks.spawn(async move { provider.begin(&random_secret()).await.is_err() });
    }
    while let Some(result) = tasks.join_next().await {
        assert!(result.unwrap());
    }
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    healthy.store(true, Ordering::SeqCst);
    assert!(provider.begin(&random_secret()).await.is_err());
    tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
    assert!(provider.begin(&random_secret()).await.is_ok());
    assert_eq!(requests.load(Ordering::SeqCst), 2);
    server.abort();
}
