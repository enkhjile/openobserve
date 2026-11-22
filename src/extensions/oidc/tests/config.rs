use openobserve_oidc::{OidcProvider, ProviderSettings, random_secret};

fn settings() -> ProviderSettings {
    ProviderSettings {
        issuer: "https://id.example.test/application/o/openobserve/".into(),
        client_id: "openobserve".into(),
        client_secret: Some("secret".into()),
        redirect_uri: "https://observe.example.test/auth/oidc/callback".into(),
        scopes: vec!["openid".into(), "profile".into(), "email".into()],
        allow_insecure_http: false,
    }
}

#[test]
fn production_configuration_rejects_unsafe_urls() {
    assert!(OidcProvider::new(settings()).is_ok());
    for bad in [
        "http://id.example.test",
        "https://user:pass@id.example.test",
        "https://id.example.test/#fragment",
        "https://id.example.test/?query=1",
    ] {
        let mut config = settings();
        config.issuer = bad.into();
        assert!(OidcProvider::new(config).is_err(), "{bad}");
    }
    let mut config = settings();
    config.redirect_uri = "http://observe.example.test/callback".into();
    assert!(OidcProvider::new(config).is_err());
}

#[test]
fn development_http_requires_explicit_opt_in() {
    let mut config = settings();
    config.issuer = "http://127.0.0.1:8000".into();
    config.redirect_uri = "http://127.0.0.1:5080/auth/oidc/callback".into();
    config.allow_insecure_http = true;
    assert!(OidcProvider::new(config).is_ok());
}

#[test]
fn secret_has_cryptographic_entropy_and_is_distinct() {
    let first = random_secret();
    assert!(first.len() >= 43);
    assert_ne!(first, random_secret());
}

#[test]
fn requests_can_run_in_multithreaded_http_handlers() {
    fn requires_send<T: Send>(_: T) {}
    let provider = OidcProvider::new(settings()).unwrap();
    requires_send(provider.begin("browser"));
    requires_send(provider.complete("code", "state", "browser"));
}
