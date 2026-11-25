use std::{
    future::Future,
    io,
    pin::Pin,
    time::{Duration, Instant},
};

use openidconnect::{
    AccessTokenHash, AuthType, AuthorizationCode, AuthorizationCodeHash, ClientId, ClientSecret,
    CsrfToken, EndpointMaybeSet, EndpointNotSet, EndpointSet, HttpRequest, HttpResponse, IssuerUrl,
    Nonce, OAuth2TokenResponse, PkceCodeChallenge, RedirectUrl, Scope, TokenResponse,
    core::{
        CoreAuthenticationFlow, CoreClient, CoreClientAuthMethod, CoreProviderMetadata,
        CoreTokenResponse,
    },
    reqwest,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use url::Url;

use crate::{Error, transactions::Transactions};

const DISCOVERY_FAILURE_TTL: Duration = Duration::from_secs(2);
const METADATA_TTL: Duration = Duration::from_secs(300);
const ROTATION_INTERVAL: Duration = Duration::from_secs(10);
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

type DiscoveredClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

#[derive(Clone)]
pub struct ProviderSettings {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub allow_insecure_http: bool,
}

impl ProviderSettings {
    fn validate(&self) -> Result<(), Error> {
        validate_url(&self.issuer, self.allow_insecure_http, false)?;
        validate_url(&self.redirect_uri, self.allow_insecure_http, false)?;
        if self.client_id.trim().is_empty()
            || self
                .scopes
                .iter()
                .any(|scope| scope.trim().is_empty() || scope.chars().any(char::is_whitespace))
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }
}

pub struct OidcProvider {
    settings: ProviderSettings,
    http: Transport,
    metadata: Mutex<MetadataCache>,
    transactions: Transactions,
}

impl OidcProvider {
    pub fn new(settings: ProviderSettings) -> Result<Self, Error> {
        settings.validate()?;
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .https_only(!settings.allow_insecure_http)
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|_| Error::Configuration)?;
        let transport = Transport {
            client: http,
            allow_http: settings.allow_insecure_http,
        };
        Ok(Self {
            settings,
            http: transport,
            metadata: Mutex::new(MetadataCache::default()),
            transactions: Transactions::default(),
        })
    }

    pub async fn begin(&self, browser_binding: &str) -> Result<AuthorizationRequest, Error> {
        let client = self.client(self.metadata(false).await?)?;
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let mut request = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .set_pkce_challenge(challenge);
        for scope in &self.settings.scopes {
            if scope != "openid" {
                request = request.add_scope(Scope::new(scope.clone()));
            }
        }
        let (url, state, nonce) = request.url();
        self.transactions.insert(
            state.secret(),
            browser_binding,
            nonce,
            verifier,
            Instant::now(),
        )?;
        Ok(AuthorizationRequest {
            url: url.to_string(),
            state: state.secret().to_owned(),
        })
    }

    pub async fn complete(
        &self,
        code: &str,
        state: &str,
        browser_binding: &str,
    ) -> Result<VerifiedIdentity, Error> {
        let transaction = self
            .transactions
            .take(state, browser_binding, Instant::now())?;
        if code.is_empty() || code.len() > 8192 {
            return Err(Error::InvalidResponse);
        }
        let client = self.client(self.metadata(false).await?)?;
        let response = client
            .exchange_code(AuthorizationCode::new(code.to_owned()))
            .map_err(|_| Error::InvalidResponse)?
            .set_pkce_verifier(transaction.pkce)
            .request_async(&self.http)
            .await
            .map_err(|_| Error::InvalidResponse)?;
        if let Ok(identity) = self.verify(&response, &transaction.nonce, code, &client) {
            return Ok(identity);
        }
        // Retry verification with rotated keys, never replay the already consumed authorization
        // code.
        let refreshed = self.client(self.metadata(true).await?)?;
        self.verify(&response, &transaction.nonce, code, &refreshed)
    }

    fn client(&self, metadata: CoreProviderMetadata) -> Result<DiscoveredClient, Error> {
        let auth_type = token_auth_type(
            self.settings.client_secret.is_some(),
            metadata
                .token_endpoint_auth_methods_supported()
                .map(Vec::as_slice),
        )?;
        Ok(CoreClient::from_provider_metadata(
            metadata,
            ClientId::new(self.settings.client_id.clone()),
            self.settings.client_secret.clone().map(ClientSecret::new),
        )
        .set_auth_type(auth_type)
        .set_redirect_uri(
            RedirectUrl::new(self.settings.redirect_uri.clone())
                .map_err(|_| Error::Configuration)?,
        ))
    }

    fn verify(
        &self,
        response: &CoreTokenResponse,
        nonce: &Nonce,
        code: &str,
        client: &DiscoveredClient,
    ) -> Result<VerifiedIdentity, Error> {
        let verifier = client
            .id_token_verifier()
            .set_issue_time_verifier_fn(|issued| {
                if issued > chrono::Utc::now() + chrono::Duration::seconds(60) {
                    Err("future issue time".into())
                } else {
                    Ok(())
                }
            });
        let token: openidconnect::IdToken<
            TemporalClaims,
            openidconnect::core::CoreGenderClaim,
            openidconnect::core::CoreJweContentEncryptionAlgorithm,
            openidconnect::core::CoreJwsSigningAlgorithm,
        > = response
            .id_token()
            .ok_or(Error::InvalidResponse)?
            .to_string()
            .parse()
            .map_err(|_| Error::InvalidResponse)?;
        let claims = token
            .claims(&verifier, nonce)
            .map_err(|_| Error::InvalidResponse)?;
        if claims
            .additional_claims()
            .nbf
            .is_some_and(|nbf| nbf > chrono::Utc::now().timestamp())
        {
            return Err(Error::InvalidResponse);
        }
        if claims.subject().as_str().is_empty()
            || claims.issue_time() >= claims.expiration()
            || claims
                .authorized_party()
                .is_some_and(|party| party.as_str() != self.settings.client_id)
            || (claims.audiences().len() > 1 && claims.authorized_party().is_none())
        {
            return Err(Error::InvalidResponse);
        }
        let algorithm = token.signing_alg().map_err(|_| Error::InvalidResponse)?;
        let key = token
            .signing_key(&verifier)
            .map_err(|_| Error::InvalidResponse)?;
        if let Some(expected) = claims.access_token_hash() {
            let actual = AccessTokenHash::from_token(response.access_token(), algorithm, key)
                .map_err(|_| Error::InvalidResponse)?;
            if actual != *expected {
                return Err(Error::InvalidResponse);
            }
        }
        if let Some(expected) = claims.code_hash() {
            let actual = AuthorizationCodeHash::from_code(
                &AuthorizationCode::new(code.to_owned()),
                algorithm,
                key,
            )
            .map_err(|_| Error::InvalidResponse)?;
            if actual != *expected {
                return Err(Error::InvalidResponse);
            }
        }
        Ok(VerifiedIdentity {
            issuer: claims.issuer().as_str().to_owned(),
            subject: claims.subject().as_str().to_owned(),
            email: claims.email().map(|value| value.as_str().to_owned()),
            email_verified: claims.email_verified().unwrap_or(false),
            given_name: claims
                .given_name()
                .and_then(|value| value.get(None))
                .map(|value| value.as_str().to_owned()),
            family_name: claims
                .family_name()
                .and_then(|value| value.get(None))
                .map(|value| value.as_str().to_owned()),
            expires_at: claims.expiration().timestamp(),
        })
    }

    async fn metadata(&self, force: bool) -> Result<CoreProviderMetadata, Error> {
        let mut cache = self.metadata.lock().await;
        let now = Instant::now();
        if !force
            && let Some((loaded, value)) = &cache.value
            && now.duration_since(*loaded) < METADATA_TTL
        {
            return Ok(value.clone());
        }
        if cache
            .failed_at
            .is_some_and(|failed| now.duration_since(failed) < DISCOVERY_FAILURE_TTL)
        {
            return Err(Error::ProviderUnavailable);
        }
        if force {
            if cache
                .last_rotation
                .is_some_and(|last| now.duration_since(last) < ROTATION_INTERVAL)
            {
                return cache
                    .value
                    .as_ref()
                    .filter(|(loaded, _)| now.duration_since(*loaded) < METADATA_TTL)
                    .map(|(_, value)| value.clone())
                    .ok_or(Error::ProviderUnavailable);
            }
            cache.last_rotation = Some(now);
        }
        let metadata = match self.discover_metadata().await {
            Ok(metadata) => {
                cache.failed_at = None;
                metadata
            }
            Err(error) => {
                cache.failed_at = Some(Instant::now());
                return Err(error);
            }
        };
        cache.value = Some((now, metadata.clone()));
        Ok(metadata)
    }
    async fn discover_metadata(&self) -> Result<CoreProviderMetadata, Error> {
        let metadata = CoreProviderMetadata::discover_async(
            IssuerUrl::new(self.settings.issuer.clone()).map_err(|_| Error::Configuration)?,
            &self.http,
        )
        .await
        .map_err(|_| Error::ProviderUnavailable)?;
        validate_url(
            metadata.authorization_endpoint().as_str(),
            self.settings.allow_insecure_http,
            true,
        )?;
        let token_endpoint = metadata.token_endpoint().ok_or(Error::InvalidResponse)?;
        validate_url(
            token_endpoint.as_str(),
            self.settings.allow_insecure_http,
            true,
        )?;
        Ok(metadata)
    }
}

struct Transport {
    client: reqwest::Client,
    allow_http: bool,
}

impl<'c> openidconnect::AsyncHttpClient<'c> for Transport {
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<HttpResponse, Self::Error>> + Send + 'c>>;

    fn call(&'c self, request: HttpRequest) -> Self::Future {
        Box::pin(self.http_request(request))
    }
}

impl Transport {
    async fn http_request(&self, request: HttpRequest) -> Result<HttpResponse, io::Error> {
        validate_url(&request.uri().to_string(), self.allow_http, true)
            .map_err(|_| io::Error::other("OIDC endpoint rejected"))?;
        let mut response = self
            .client
            .request(request.method().clone(), request.uri().to_string())
            .headers(request.headers().clone())
            .body(request.body().clone())
            .send()
            .await
            .map_err(|_| io::Error::other("OIDC request failed"))?;
        let mut builder = openidconnect::http::Response::builder().status(response.status());
        for (name, value) in response.headers() {
            builder = builder.header(name, value);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| io::Error::other("OIDC response failed"))?
        {
            if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(io::Error::other("OIDC response too large"));
            }
            body.extend_from_slice(&chunk);
        }
        builder
            .body(body)
            .map_err(|_| io::Error::other("OIDC response rejected"))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TemporalClaims {
    nbf: Option<i64>,
}
impl openidconnect::AdditionalClaims for TemporalClaims {}

#[derive(Default)]
struct MetadataCache {
    value: Option<(Instant, CoreProviderMetadata)>,
    last_rotation: Option<Instant>,
    failed_at: Option<Instant>,
}

pub struct AuthorizationRequest {
    pub url: String,
    pub state: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifiedIdentity {
    pub issuer: String,
    pub subject: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub expires_at: i64,
}

fn token_auth_type(
    confidential: bool,
    methods: Option<&[CoreClientAuthMethod]>,
) -> Result<AuthType, Error> {
    if !confidential {
        return Ok(AuthType::RequestBody);
    }
    // Discovery defaults to client_secret_basic when the provider omits this field.
    match methods {
        None => Ok(AuthType::BasicAuth),
        Some(supported) if supported.contains(&CoreClientAuthMethod::ClientSecretBasic) => {
            Ok(AuthType::BasicAuth)
        }
        Some(supported) if supported.contains(&CoreClientAuthMethod::ClientSecretPost) => {
            Ok(AuthType::RequestBody)
        }
        Some(_) => Err(Error::Configuration),
    }
}

fn validate_url(value: &str, allow_http: bool, allow_query: bool) -> Result<(), Error> {
    let url = Url::parse(value).map_err(|_| Error::Configuration)?;
    if !(url.scheme() == "https" || (allow_http && url.scheme() == "http"))
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || (!allow_query && url.query().is_some())
    {
        return Err(Error::Configuration);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn failed_rotation_preserves_fresh_metadata_only() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let provider = OidcProvider::new(ProviderSettings {
            issuer: issuer.clone(),
            client_id: "client".into(),
            client_secret: None,
            redirect_uri: "http://localhost/callback".into(),
            scopes: vec![],
            allow_insecure_http: true,
        })
        .unwrap();
        let metadata = serde_json::from_value(serde_json::json!({
            "issuer": issuer, "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"), "jwks_uri": format!("{issuer}/jwks"),
            "response_types_supported": ["code"], "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"]
        }))
        .unwrap();
        provider.metadata.lock().await.value = Some((Instant::now(), metadata));
        assert!(provider.metadata(true).await.is_err());
        assert!(provider.begin(&crate::random_secret()).await.is_ok());
        provider.metadata.lock().await.value.as_mut().unwrap().0 = Instant::now() - METADATA_TTL;
        assert!(provider.begin(&crate::random_secret()).await.is_err());
        provider.metadata.lock().await.failed_at = Some(Instant::now() - DISCOVERY_FAILURE_TTL);
        assert!(provider.metadata(true).await.is_err());
    }

    #[test]
    fn token_auth_uses_discovered_methods() {
        use CoreClientAuthMethod::{ClientSecretBasic, ClientSecretPost, PrivateKeyJwt};
        assert!(matches!(
            token_auth_type(true, None),
            Ok(AuthType::BasicAuth)
        ));
        assert!(matches!(
            token_auth_type(true, Some(&[ClientSecretPost, ClientSecretBasic])),
            Ok(AuthType::BasicAuth)
        ));
        assert!(matches!(
            token_auth_type(true, Some(&[ClientSecretPost])),
            Ok(AuthType::RequestBody)
        ));
        assert!(matches!(
            token_auth_type(true, Some(&[PrivateKeyJwt])),
            Err(Error::Configuration)
        ));
        assert!(matches!(
            token_auth_type(false, None),
            Ok(AuthType::RequestBody)
        ));
    }
}
