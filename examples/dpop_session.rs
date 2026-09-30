//! A persisted Secure Enclave DPoP session using a real device authorization grant.
//!
//! See docs/guide/dpop_session.md for configuration and signing instructions.

use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt as _, path::PathBuf, sync::Arc};

use http::{HeaderMap, Method, StatusCode, Uri};
use huskarl::{
    authorizer::{HttpAuthorizer, dpop_resend_advised, parse_challenges},
    cache::{
        GrantTokenSource, InMemoryRefreshTokenStore, InMemoryTokenCache, NoSource, Recovery,
        RefreshTokenStore,
    },
    grant::device_authorization::{DeviceAuthorizationGrant, StartInput},
    token::RefreshToken,
};
use huskarl_apple::{
    Es256PrivateKey,
    keychain::{KeychainRefreshTokenStore, KeychainSecretStore, SecretAccessPolicy},
    policy::Authentication,
};
use huskarl_core::{
    Error, OAuthErrorCode, client_auth::NoAuth, crypto::signer::AsymmetricJwsSigner as _,
    dpop::DPoP, platform::MaybeSendBoxFuture, server_metadata::AuthorizationServerMetadata,
};
use huskarl_reqwest::ReqwestClient;

// All refreshes go through one cache/source while the process holds session.lock.
// Reads use session memory. Keep rotations in memory even if persistence fails.
struct SessionRefreshTokens {
    disk: KeychainRefreshTokenStore,
    memory: InMemoryRefreshTokenStore,
}

impl RefreshTokenStore for SessionRefreshTokens {
    fn get(&self) -> MaybeSendBoxFuture<'_, Result<Option<RefreshToken>, Error>> {
        self.memory.get()
    }

    fn set<'a>(&'a self, token: &'a RefreshToken) -> MaybeSendBoxFuture<'a, Result<(), Error>> {
        Box::pin(async move {
            // The server may already have invalidated the previous token.
            self.memory.set(token).await?;
            self.disk.set(token).await.inspect_err(|_| {
                eprintln!(
                    "Could not persist the refresh token; this session may not survive restart."
                );
            })
        })
    }

    fn clear(&self) -> MaybeSendBoxFuture<'_, Result<(), Error>> {
        Box::pin(async move {
            self.memory.clear().await?;
            self.disk.clear().await.inspect_err(|_| {
                eprintln!(
                    "Could not clear the persisted refresh token; Keychain cleanup needs retry."
                );
            })
        })
    }
}

type Source = GrantTokenSource<DeviceAuthorizationGrant, SessionRefreshTokens>;
type AppError = Box<dyn std::error::Error>;

#[tokio::main]
async fn main() -> Result<(), AppError> {
    let issuer = std::env::var("ISSUER")?;
    let client_id = std::env::var("CLIENT_ID")?;
    let resource_url = std::env::var("RESOURCE_URL")?;
    let uri: Uri = resource_url.parse()?;
    if uri.scheme_str() != Some("https") {
        return Err("RESOURCE_URL must be an HTTPS URL".into());
    }
    let access_group = std::env::var("HUSKARL_ACCESS_GROUP")?;
    // Reserve a distinct account and directory for each issuer/client/user session.
    let account = std::env::var("HUSKARL_ACCOUNT")?;
    let state_dir = PathBuf::from(std::env::var("HUSKARL_STATE_DIR")?);
    let scope: Vec<String> = std::env::var("SCOPE")?
        .split_whitespace()
        .map(str::to_owned)
        .collect();

    // The directory must already exist and be private to this application/user.
    // Keep the lock file: replacing it would let two processes lock different files.
    let session_lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(state_dir.join("session.lock"))?;
    session_lock.try_lock()?; // Refuse a second rotation owner rather than waiting.

    let disk = KeychainRefreshTokenStore::builder()
        .storage(
            KeychainSecretStore::builder()
                .service("io.example.huskarl.dpop-session")
                .account(&account)
                .access_group(&access_group)
                .access_policy(
                    SecretAccessPolicy::builder()
                        .authentication(Authentication::UserPresence)
                        .build(),
                )
                .build(),
        )
        .build();
    // Authenticate when restoring the session. Access failures are propagated.
    let restored = disk.get().await?;
    let key = blocking::unblock(move || {
        Es256PrivateKey::load_or_generate()
            .label(&format!("io.example.huskarl.dpop-session/{account}"))
            .access_group(access_group)
            .lock_path(&state_dir.join("key.lock"))
            .call() // Default policy: device-only, unlocked, no presence on signing.
    })
    .await?;
    let thumbprint = key.public_key_jwk().thumbprint();
    let memory = InMemoryRefreshTokenStore::default();
    if let Some(token) = restored {
        if token.dpop_jkt() == Some(thumbprint.as_str()) {
            memory.set(&token).await?;
            println!("Restored the session; the first request will refresh its access token.");
        } else {
            // A new device/key cannot use a token bound to the old key.
            disk.clear().await?;
            println!("This session needs a new sign-in because its key binding changed.");
        }
    }

    let requests = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    let http_client = ReqwestClient::from(requests.clone());
    let metadata = AuthorizationServerMetadata::fetch()
        .issuer(issuer)
        .http_client(&http_client)
        .call()
        .await?;
    let grant = DeviceAuthorizationGrant::builder_from_metadata(&metadata)?
        .client_id(client_id)
        .client_auth(NoAuth)
        .http_client(http_client)
        .dpop(DPoP::builder().signer(key).build())
        .build();
    let source = Arc::new(
        GrantTokenSource::builder()
            .grant(grant.clone())
            .grant_parameters(NoSource) // Interactive login is handled below.
            .refresh_store(SessionRefreshTokens { disk, memory })
            .build(),
    );
    let cache = InMemoryTokenCache::builder().source(source.clone()).build();
    let authorizer = HttpAuthorizer::builder().cache(cache).build();

    // Reusing this authorizer reuses the access token but signs a fresh proof.
    for _ in 0..2 {
        let headers = request_headers(&authorizer, &source, &grant, &scope, &uri).await?;
        let mut response = requests.get(&resource_url).headers(headers).send().await?;
        authorizer.process_response(&uri, response.headers());
        let invalid_token = response.status() == StatusCode::UNAUTHORIZED
            && parse_challenges(response.headers())
                .iter()
                .any(|challenge| challenge.error() == Some(OAuthErrorCode::InvalidToken));
        if invalid_token || dpop_resend_advised(response.status(), response.headers()) {
            // Repeat this GET once, with newly built headers and the recorded nonce.
            let headers = request_headers(&authorizer, &source, &grant, &scope, &uri).await?;
            response = requests.get(&resource_url).headers(headers).send().await?;
            authorizer.process_response(&uri, response.headers());
        }
        response.error_for_status_ref()?;
        if response.status().is_redirection() {
            return Err("set RESOURCE_URL to the final URL; redirects are disabled".into());
        }
        println!("Authenticated GET: {}", response.status());
    }
    // Keep the persisted key and refresh token for the next launch.
    // The process-lifetime lock is released here, after the session finishes.
    drop(session_lock);
    Ok(())
}

async fn sign_in(
    grant: &DeviceAuthorizationGrant,
    source: &Source,
    scope: &[String],
) -> Result<(), AppError> {
    let start = grant.start(StartInput::scope(scope.to_vec())).await?;
    println!(
        "Sign in at {} with code {}",
        start.verification_uri, start.user_code
    );
    let remaining = start
        .expires_at
        .duration_since(std::time::SystemTime::now())?;
    let mut pending = start.pending_state;
    let token =
        tokio::time::timeout(remaining, grant.poll_to_completion(&mut pending, None)).await??;
    // Require a DPoP-enabled server; do not silently accept a bearer-only session.
    if token.access_token().dpop_jkt().is_none() {
        return Err("the authorization server did not issue a DPoP-bound access token".into());
    }
    if token.refresh_token().is_none() {
        return Err(
            "the server did not issue a refresh token; check its client/scopes configuration"
                .into(),
        );
    }
    source.prime(token).await?; // Persists the refresh token and its DPoP binding.
    Ok(())
}

async fn request_headers(
    authorizer: &HttpAuthorizer,
    source: &Source,
    grant: &DeviceAuthorizationGrant,
    scope: &[String],
    uri: &Uri,
) -> Result<HeaderMap, AppError> {
    let headers = match authorizer.get_headers(&Method::GET, uri).await {
        Ok(headers) => headers,
        Err(error) if error.recovery() == Recovery::Reauthenticate => {
            sign_in(grant, source, scope).await?;
            authorizer.get_headers(&Method::GET, uri).await?
        }
        // Retryable failures, denied Keychain access, and bad configuration are
        // surfaced without discarding credentials or starting a sign-in loop.
        Err(error) => return Err(error.into()),
    };
    if !headers.contains_key("dpop") {
        return Err("refusing to send an API request without a DPoP proof".into());
    }
    Ok(headers)
}
