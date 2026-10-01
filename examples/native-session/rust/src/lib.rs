//! Main-thread C bridge for a complete macOS OAuth/DPoP session example.
mod diagnostics;
mod storage;

use std::{
    cell::{Cell, RefCell},
    ffi::{CString, c_char},
    fs::{File, OpenOptions},
    future::{Future, poll_fn},
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
    pin::Pin,
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::Poll,
};

use bytes::Bytes;
use diagnostics::{TracedClient, failure, milestone};
use http::{Method, Request, StatusCode, Uri};
use huskarl::{
    authorizer::{HttpAuthorizer, dpop_resend_advised, parse_challenges},
    cache::{
        GrantTokenSource, InMemoryRefreshTokenStore, InMemoryTokenCache, NoSource, Recovery,
        RefreshTokenStore, TokenSource,
    },
    grant::authorization_code::{AuthorizationCodeGrant, StartInput},
};
use huskarl_apple::{
    Es256PrivateKey,
    keychain::{DataProtectionKeychain, KeychainRefreshTokenStore, SecretAccessPolicy},
    policy::Authentication,
    urlsession::UrlSessionClient,
    web_authentication::{PresentationAnchor, WebAuthenticationError, WebAuthenticationSession},
};
use huskarl_core::{
    OAuthErrorCode,
    client_auth::NoAuth,
    crypto::signer::AsymmetricJwsSigner,
    dpop::DPoP,
    http::{HttpClient, Idempotency},
    server_metadata::AuthorizationServerMetadata,
};
use objc2::{MainThreadMarker, rc::Retained};
use storage::SessionRefreshTokens;

type Source =
    GrantTokenSource<AuthorizationCodeGrant, SessionRefreshTokens<KeychainRefreshTokenStore>>;
type Task = Pin<Box<dyn Future<Output = Result<String, String>>>>;

thread_local! {
    static TASK: RefCell<Option<Task>> = RefCell::new(None);
    static BROWSER: RefCell<Option<WebAuthenticationSession>> = const { RefCell::new(None) };
    static SESSION: RefCell<Option<Rc<Session>>> = const { RefCell::new(None) };
    static STATUS: RefCell<CString> = RefCell::new(CString::new("Restoring session…").unwrap());
    static RUNTIME: Result<tokio::runtime::Runtime, std::io::Error> =
        tokio::runtime::Builder::new_current_thread().enable_time().build();
}

struct Session {
    grant: AuthorizationCodeGrant,
    source: Arc<Source>,
    cache: Arc<InMemoryTokenCache<Arc<Source>>>,
    authorizer: HttpAuthorizer,
    client: TracedClient<UrlSessionClient>,
    resource: Uri,
    scopes: Vec<String>,
    thumbprint: String,
    authenticated: Cell<bool>,
    cleanup_pending: Cell<bool>,
    persistence_failed: Arc<AtomicBool>,
    // Kept until all session operations/handles are gone, including shutdown.
    _owner: File,
}

fn required(name: &str) -> Result<String, String> {
    std::env::var(name)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| format!("Set {name} before launching the example."))
}

fn https(value: &str) -> bool {
    url::Url::parse(value).is_ok_and(|u| {
        u.scheme() == "https"
            && u.host_str().is_some()
            && u.username().is_empty()
            && u.password().is_none()
            && u.fragment().is_none()
    })
}

fn saved_storage(
    session_id: &str,
    group: &str,
    state_dir: &std::path::Path,
) -> Result<(File, KeychainRefreshTokenStore), String> {
    let owner = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(state_dir.join("session.lock"))
        .map_err(|error| {
            failure(
                "Open session ownership lock",
                &error,
                "Create a private HUSKARL_STATE_DIR before launch.",
            )
        })?;
    owner.try_lock().map_err(|error| {
        failure(
            "Acquire session ownership lock",
            &error,
            "Another process owns this session. Quit it before restoring.",
        )
    })?;
    let disk = KeychainRefreshTokenStore::new(
        DataProtectionKeychain::new(group)
            .map_err(|error| error.to_string())?
            .secret("io.huskarl.native-session.refresh", session_id)
            .map_err(|error| error.to_string())?
            .store()
            .creation_policy(
                SecretAccessPolicy::builder()
                    .authentication(Authentication::UserPresence)
                    .build(),
            )
            .build(),
    );
    Ok((owner, disk))
}

impl Session {
    async fn restore() -> Result<(Rc<Self>, String), String> {
        let issuer = required("ISSUER")?;
        let resource = required("RESOURCE_URL")?;
        if !https(&issuer) || !https(&resource) {
            return Err(
                "ISSUER and RESOURCE_URL must be HTTPS URLs without credentials or fragments."
                    .into(),
            );
        }
        let client_id = required("CLIENT_ID")?;
        let group = required("HUSKARL_ACCESS_GROUP")?;
        let session_id = required("HUSKARL_SESSION_ID")?;
        let state_dir = PathBuf::from(required("HUSKARL_STATE_DIR")?);
        let scopes: Vec<String> = required("SCOPE")?
            .split_whitespace()
            .map(str::to_owned)
            .collect();
        if scopes.iter().any(|s| s == "openid") {
            return Err(
                "This OAuth API example does not validate ID tokens; omit openid from SCOPE."
                    .into(),
            );
        }
        let (owner, disk) = saved_storage(&session_id, &group, &state_dir)?;
        let restored = disk.get().await.map_err(|error| failure("Read saved refresh token", &error, "Could not restore Keychain credentials. Unlock or authorize access, then retry; credentials were preserved."))?;
        let key = Es256PrivateKey::load_or_generate()
            .label(&format!("io.huskarl.native-session/{session_id}"))
            .access_group(group).lock_path(&state_dir.join("key.lock")).load_or_generate().await.map_err(|error| failure("Load or create Secure Enclave key", &error, "Could not provision the Secure Enclave key. Check hardware, signing, access group, and unlock state."))?;
        let thumbprint = key.public_key_jwk().thumbprint();
        let memory = InMemoryRefreshTokenStore::default();
        let mut authenticated = false;
        let mut message = "No saved session. Sign in to continue.";
        if let Some(token) = restored {
            if token.dpop_jkt() == Some(thumbprint.as_str()) {
                memory.set(&token).await.map_err(|error| {
                    failure(
                        "Restore session memory",
                        &error,
                        "Could not restore session memory.",
                    )
                })?;
                authenticated = true;
                message = "Session restored. Make a request to refresh the access token.";
            } else {
                disk.clear().await.map_err(|error| failure("Remove token with obsolete key binding", &error, "Saved session has a different key; could not remove its unusable token. Retry restore."))?;
                message = "The saved key binding changed. Sign in again on this device.";
            }
        }
        milestone("Configuring native networking and discovering provider endpoints");
        let client = TracedClient::new(UrlSessionClient::builder().build().map_err(|error| {
            failure(
                "Configure URLSession",
                &error,
                "Could not configure native networking.",
            )
        })?);
        let metadata = AuthorizationServerMetadata::oidc_fetch()
            .issuer(issuer)
            .http_client(&client)
            .call()
            .await
            .map_err(|error| failure("Discover provider endpoints", &error, "Discovery failed. Check issuer, network, and OIDC discovery support, then retry."))?;
        let grant = AuthorizationCodeGrant::builder_from_metadata(&metadata)
            .map_err(|error| {
                failure(
                    "Configure grant from provider metadata",
                    &error,
                    "Provider metadata does not support this authorization-code flow.",
                )
            })?
            .client_id(client_id)
            .client_auth(NoAuth)
            .http_client(client.clone())
            .redirect_uri(required("REDIRECT_URI")?)
            .oidc(false)
            .dpop(DPoP::builder().signer(key).build())
            .build()
            .await
            .map_err(|error| {
                failure(
                    "Build authorization-code grant",
                    &error,
                    "Could not configure OAuth. Check redirect URI and provider capabilities.",
                )
            })?;
        let persistence_failed = Arc::new(AtomicBool::new(false));
        let source = Arc::new(
            GrantTokenSource::builder()
                .grant(grant.clone())
                .grant_parameters(NoSource)
                .refresh_store(SessionRefreshTokens {
                    disk,
                    memory,
                    persistence_failed: persistence_failed.clone(),
                })
                .build(),
        );
        let cache = Arc::new(InMemoryTokenCache::builder().source(source.clone()).build());
        let authorizer = HttpAuthorizer::builder().cache(cache.clone()).build();
        Ok((
            Rc::new(Self {
                grant,
                source,
                cache,
                authorizer,
                client,
                resource: resource.parse().map_err(|error| {
                    failure("Parse RESOURCE_URL", &error, "Invalid RESOURCE_URL.")
                })?,
                scopes,
                thumbprint,
                authenticated: Cell::new(authenticated),
                cleanup_pending: Cell::new(false),
                persistence_failed,
                _owner: owner,
            }),
            message.into(),
        ))
    }

    async fn login(&self, window: &PresentationAnchor, ephemeral: bool) -> Result<String, String> {
        if self.authenticated.get() || self.cleanup_pending.get() {
            return Err("Complete logout before starting another sign-in.".into());
        }
        milestone("OAuth start: preparing authorization request");
        let attempts = self.client.attempts();
        let started = self
            .grant
            .start(StartInput::builder().scope(self.scopes.clone()).build())
            .await
            .map_err(|error| {
                let attempted = self.client.attempts() - attempts;
                let recovery = if attempted == 0 {
                    "No HTTP request was attempted during OAuth start. Fix the reported local configuration, serialization, or signing cause, then retry Sign in."
                } else {
                    "A pushed authorization request was attempted before browser presentation. Check the reported signing, transport, or provider rejection cause, then retry Sign in."
                };
                failure("Start OAuth", &error, recovery)
            })?;
        milestone("OAuth start completed; presenting authentication browser");
        let browser = WebAuthenticationSession::start()
            .authorization_url(&started.authorization_url.to_string())
            .redirect_uri(&started.pending_state.redirect_uri)
            .window(window)
            .prefers_ephemeral(ephemeral)
            .call()
            .map_err(|error| {
                failure(
                    "Present authentication browser",
                    &error,
                    "Could not present login. Check foreground window and redirect configuration.",
                )
            })?;
        BROWSER.with(|slot| *slot.borrow_mut() = Some(browser));
        let callback = poll_fn(|cx| {
            BROWSER.with(|slot| {
                slot.borrow_mut()
                    .as_mut()
                    .map_or(Poll::Ready(Err(WebAuthenticationError::Cancelled)), |b| {
                        Pin::new(b).poll(cx)
                    })
            })
        })
        .await;
        BROWSER.with(|slot| slot.borrow_mut().take());
        let callback = callback.map_err(|e| {
            match e {
                WebAuthenticationError::Cancelled => "Sign-in cancelled. You can try again.",
                _ => return failure("Receive browser callback", &e, "Check the reported presentation or callback mismatch cause and retry Sign in."),
            }
            .to_owned()
        })?;
        let completed = self.grant.complete(&started.pending_state,
            callback.parse().map_err(|error| failure("Parse callback", &error, "Invalid callback."))?).await
            .map_err(|error| failure("Complete authorization-code flow", &error, "OAuth completion failed: state, PKCE, provider response, or token exchange was rejected."))?;
        let token = completed.token_response;
        if token.access_token().dpop_jkt() != Some(self.thumbprint.as_str())
            || token
                .refresh_token()
                .is_none_or(|t| t.dpop_jkt() != Some(self.thumbprint.as_str()))
        {
            return Err(
                "Provider must issue a DPoP-bound access token and refresh token for this key."
                    .into(),
            );
        }
        self.source.prime(token).await.map_err(|error| {
            failure(
                "Persist new session",
                &error,
                "Could not persist sign-in. Authorize Keychain access and sign in again.",
            )
        })?;
        self.cache.invalidate();
        self.authenticated.set(true);
        Ok("Signed in. Credentials saved; make an authenticated request.".into())
    }

    async fn request(&self) -> Result<String, String> {
        let result = self.request_inner().await;
        if !self.persistence_failed.load(Ordering::Relaxed) {
            return result;
        }
        // Report rotation persistence failure even if the subsequent API
        // request failed before receiving a response.
        let append = |message: String| {
            format!(
                "{message} Refresh-token persistence failed; this session may not survive restart."
            )
        };
        result.map(append).map_err(append)
    }

    async fn request_inner(&self) -> Result<String, String> {
        if !self.authenticated.get() || self.cleanup_pending.get() {
            return Err("Sign in before making a request.".into());
        }
        for attempt in 0..2 {
            let headers = self.authorizer.get_headers(&Method::GET, &self.resource).await.map_err(|error| {
                if error.recovery() == Recovery::Reauthenticate {
                    self.authenticated.set(false);
                    failure("Authorize API request", &error, "Session expired. Sign in again.")
                } else {
                    failure("Authorize API request", &error, "Credentials were preserved. Resolve the reported cause, then retry Make request.")
                }
            })?;
            if !headers.contains_key("dpop") {
                return Err("Refusing to send a request without a DPoP proof.".into());
            }
            let mut request = Request::builder()
                .method(Method::GET)
                .uri(&self.resource)
                .body(Bytes::new())
                .map_err(|error| failure("Build API request", &error, "Invalid API request."))?;
            *request.headers_mut() = headers;
            let response = self
                .client
                .execute(request, Idempotency::Idempotent)
                .await
                .map_err(|error| failure("Send authenticated API request", &error, "API request failed. Credentials were preserved; check the network and retry."))?;
            self.authorizer
                .process_response(&self.resource, &response.headers);
            let invalid_token = response.status == StatusCode::UNAUTHORIZED
                && parse_challenges(&response.headers)
                    .iter()
                    .any(|c| c.error() == Some(OAuthErrorCode::InvalidToken));
            if attempt == 0
                && (invalid_token || dpop_resend_advised(response.status, &response.headers))
            {
                continue; // One retry, fresh headers, GET only.
            }
            return if response.status.is_success() {
                Ok(format!(
                    "Authenticated GET: {} ({} response bytes).",
                    response.status,
                    response.body.len()
                ))
            } else {
                Err(format!(
                    "API returned HTTP {}. Redirects are disabled.",
                    response.status.as_u16()
                ))
            };
        }
        Err("API challenge retry exhausted.".into())
    }

    async fn logout(&self) -> Result<String, String> {
        // One UI task at a time means no request or rotation can race logout.
        self.authenticated.set(false);
        self.cleanup_pending.set(true);
        self.cache.clear().await.map_err(|error| failure("Delete saved refresh token during logout", &error, "Logged out of memory, but Keychain cleanup failed. Retry Log out before quitting; a saved credential may remain."))?;
        self.cleanup_pending.set(false);
        Ok(
            "Logged out. Saved refresh token removed. Browser/provider cookies are unchanged."
                .into(),
        )
    }
}

fn main_thread() {
    assert!(
        MainThreadMarker::new().is_some(),
        "Bridge requires the main thread"
    );
}
fn status(message: &str) {
    let message = message.replace('\0', "�");
    STATUS.with(|s| *s.borrow_mut() = CString::new(message).expect("Status contains no NUL"));
}

/// Starts one operation; a busy operation is never replaced.
/// # Safety
/// The caller supplies a live NSWindow and calls on the main thread.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn huskarl_native_start(
    window: *mut PresentationAnchor,
    action: i32,
    ephemeral: i32,
) {
    main_thread();
    if TASK.with(|t| t.borrow().is_some()) {
        return;
    }
    let Some(window) = (unsafe { Retained::retain(window) }) else {
        status("No presentation window.");
        return;
    };
    milestone(match action {
        0 => "Restore session started",
        1 => "Sign-in started",
        2 => "API request started",
        3 => "Logout started",
        _ => "Unknown action",
    });
    status(match action {
        0 => "Restoring session…",
        1 => "Waiting for browser sign-in…",
        2 => "Making authenticated request…",
        _ => "Removing saved session…",
    });
    TASK.with(|t| {
        *t.borrow_mut() = Some(Box::pin(async move {
            if action == 0 {
                if SESSION.with(|s| s.borrow().is_some()) {
                    return Err("Session already initialized.".into());
                }
                let (session, message) = Session::restore().await?;
                SESSION.with(|s| *s.borrow_mut() = Some(session));
                return Ok(message);
            }
            let session = SESSION.with(|s| s.borrow().clone());
            if action == 3 && session.is_none() {
                // Local cleanup remains possible when discovery or key loading
                // failed. Take ownership without reading the token or networking.
                let (owner, disk) = saved_storage(
                    &required("HUSKARL_SESSION_ID")?,
                    &required("HUSKARL_ACCESS_GROUP")?,
                    &PathBuf::from(required("HUSKARL_STATE_DIR")?),
                )?;
                let result = disk.clear().await;
                drop(owner);
                result.map_err(|error| failure("Delete saved refresh token after initialization failure", &error, "Could not remove the saved token. Authorize Keychain access and retry Log out."))?;
                return Ok("Saved refresh token removed. Retry restore before signing in.".into());
            }
            let session = session.ok_or("Restore the session first.")?;
            match action {
                1 => session.login(&window, ephemeral != 0).await,
                2 => session.request().await,
                3 => session.logout().await,
                _ => Err("Unknown operation.".into()),
            }
        }))
    });
}

/// Poll once and immediately return to AppKit; 1=pending, 2=success, 3=failure.
#[unsafe(no_mangle)]
pub extern "C" fn huskarl_native_poll() -> i32 {
    main_thread();
    TASK.with(|t| {
        let mut task = t.borrow_mut();
        let Some(future) = task.as_mut() else {
            return 0;
        };
        let result = RUNTIME.with(|rt| match rt {
            Ok(rt) => rt.block_on(poll_fn(|cx| Poll::Ready(future.as_mut().poll(cx)))),
            Err(_) => Poll::Ready(Err("Could not initialize the UI executor.".into())),
        });
        match result {
            Poll::Pending => 1,
            Poll::Ready(result) => {
                task.take();
                BROWSER.with(|b| b.borrow_mut().take());
                let code = if result.is_ok() { 2 } else { 3 };
                status(&result.unwrap_or_else(|e| e));
                code
            }
        }
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn huskarl_native_cancel() {
    main_thread();
    BROWSER.with(|b| {
        if let Some(browser) = b.borrow_mut().as_mut() {
            browser.cancel();
        }
    });
}

#[unsafe(no_mangle)]
pub extern "C" fn huskarl_native_shutdown() {
    main_thread();
    TASK.with(|t| t.borrow_mut().take());
    BROWSER.with(|b| b.borrow_mut().take());
    SESSION.with(|s| s.borrow_mut().take());
}

#[unsafe(no_mangle)]
pub extern "C" fn huskarl_native_status() -> *const c_char {
    main_thread();
    STATUS.with(|s| s.borrow().as_ptr())
}
