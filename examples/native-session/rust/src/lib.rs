//! Main-thread C bridge for a complete macOS OAuth/DPoP session example.
mod diagnostics;
mod executor;

use std::{
    cell::{Cell, RefCell},
    ffi::{CString, c_char},
    fs::{File, OpenOptions},
    future::{Future, poll_fn},
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
    rc::Rc,
};

use bytes::Bytes;
use diagnostics::{TracedClient, failure, milestone};
use executor::MainThreadExecutor;
use http::{Method, Request, StatusCode, Uri};
use huskarl::{
    authorizer::{dpop_resend_advised, parse_challenges},
    cache::RefreshTokenStore,
    grant::authorization_code::{AuthorizationCodeGrant, StartInput},
};
use huskarl_apple::{
    Es256PrivateKey,
    keychain::{DataProtectionKeychain, KeychainRefreshTokenStore, SecretAccessPolicy},
    policy::Authentication,
    session::{AppleSession, PersistenceState, SessionPhase, SignInOptions},
    urlsession::UrlSessionClient,
    web_authentication::PresentationAnchor,
};
use huskarl_core::{
    OAuthErrorCode,
    client_auth::NoAuth,
    dpop::DPoP,
    http::{HttpClient, Idempotency},
    server_metadata::AuthorizationServerMetadata,
};
use objc2::{MainThreadMarker, rc::Retained};

thread_local! {
    static ACTIVE: Cell<bool> = const { Cell::new(false) };
    static CLOSING: Cell<bool> = const { Cell::new(false) };
    static SESSION: RefCell<Option<Rc<AppState>>> = const { RefCell::new(None) };
    static STATUS: RefCell<CString> = RefCell::new(CString::new("Restoring session…").unwrap());
    static EXECUTOR: MainThreadExecutor = MainThreadExecutor::new(
        MainThreadMarker::new().expect("Executor requires the main thread"));
    // The background runtime drives timers even while AppKit is idle. Local
    // futures only enter its context; they are still polled on the main thread.
    static RUNTIME: Result<tokio::runtime::Runtime, std::io::Error> =
        tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_time().build();
}

fn spawn(future: impl Future<Output = ()> + 'static) -> Result<(), String> {
    let handle = RUNTIME.with(|runtime| {
        runtime
            .as_ref()
            .map(|runtime| runtime.handle().clone())
            .map_err(|_| "Could not initialize the timer runtime.".to_owned())
    })?;
    let mut future = Box::pin(future);
    EXECUTOR.with(|executor| {
        executor.spawn_local(poll_fn(move |cx| {
            let _entered = handle.enter();
            future.as_mut().poll(cx)
        }))
    });
    Ok(())
}

// Only application configuration, transport and presentation live here.
// The library owns all token, browser and session lifecycle state.
struct AppState {
    controller: AppleSession,
    driver_done: RefCell<Option<futures_channel::oneshot::Receiver<()>>>,
    client: TracedClient<UrlSessionClient>,
    resource: Uri,
    scopes: Vec<String>,
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

impl AppState {
    async fn configure() -> Result<Rc<Self>, String> {
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
        let key = Es256PrivateKey::load_or_generate()
            .label(&format!("io.huskarl.native-session/{session_id}"))
            .access_group(group).lock_path(&state_dir.join("key.lock")).load_or_generate().await.map_err(|error| failure("Load or create Secure Enclave key", &error, "Could not provision the Secure Enclave key. Check hardware, signing, access group, and unlock state."))?;
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
        let resource = resource
            .parse()
            .map_err(|error| failure("Parse RESOURCE_URL", &error, "Invalid RESOURCE_URL."))?;
        let (controller, driver) = AppleSession::builder()
            .grant(grant)
            .refresh_store(disk)
            .main_thread(MainThreadMarker::new().ok_or("Main thread required")?)
            .build();
        let (finished, driver_done) = futures_channel::oneshot::channel();
        spawn(async move {
            // Keep exclusive persisted-session ownership until all work settles.
            driver.run().await;
            drop(owner);
            let _ = finished.send(());
        })?;
        Ok(Rc::new(Self {
            controller,
            driver_done: RefCell::new(Some(driver_done)),
            client,
            resource,
            scopes,
        }))
    }

    async fn restore(&self) -> Result<String, String> {
        let state = self.controller.restore().await.map_err(|error| failure(
            "Restore session", &error,
            "Retry after resolving access failures; for an obsolete key binding, Log out before signing in again.",
        ))?;
        Ok(if state.phase == SessionPhase::Ready {
            "Session restored. Make a request to refresh the access token."
        } else {
            "No saved session. Sign in to continue."
        }
        .into())
    }

    async fn login(&self, window: &PresentationAnchor, ephemeral: bool) -> Result<String, String> {
        self.controller
            .sign_in(
                window,
                StartInput::builder().scope(self.scopes.clone()).build(),
                SignInOptions {
                    prefers_ephemeral: ephemeral,
                    ..SignInOptions::default()
                },
            )
            .await
            .map_err(|error| {
                failure(
                    "Sign in",
                    &error,
                    "Resolve the reported cause and retry. If cleanup is required, retry Log out.",
                )
            })?;
        Ok(
            if self.controller.snapshot().persistence == PersistenceState::Saved {
                "Signed in. Credentials saved; make an authenticated request."
            } else {
                "Signed in for this run. The provider did not issue a refresh token."
            }
            .into(),
        )
    }

    async fn request(&self) -> Result<String, String> {
        let result = self.request_inner().await;
        if self.controller.snapshot().persistence != PersistenceState::UnsavedChanges {
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
        let access = self.controller.access().map_err(|error| {
            failure("Access session", &error, "Sign in before making a request.")
        })?;
        for attempt in 0..2 {
            let headers = access
                .get_headers(&Method::GET, &self.resource)
                .await
                .map_err(|error| {
                    failure(
                        "Authorize API request",
                        &error,
                        "Check session state and the reported recovery cause before retrying.",
                    )
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
            access
                .process_response(&self.resource, &response.headers)
                .await
                .map_err(|error| {
                    failure(
                        "Process API response",
                        &error,
                        "Session changed while requesting.",
                    )
                })?;
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
        self.controller.logout().await.map_err(|error| {
            failure(
                "Log out",
                &error,
                "Retry Log out to finish saved-credential cleanup.",
            )
        })?;
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
    completion: extern "C" fn(i32),
) {
    main_thread();
    if ACTIVE.get() || CLOSING.get() {
        completion(3);
        return;
    }
    let Some(window) = (unsafe { Retained::retain(window) }) else {
        status("No presentation window.");
        completion(3);
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
    ACTIVE.set(true);
    let operation = async move {
        if action == 0 {
            let existing = SESSION.with(|s| s.borrow().clone());
            let session = if let Some(session) = existing {
                session
            } else {
                let session = AppState::configure().await?;
                SESSION.with(|s| *s.borrow_mut() = Some(session.clone()));
                session
            };
            return session.restore().await;
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
    };
    if let Err(error) = spawn(async move {
        let result = operation.await;
        let code = if result.is_ok() { 2 } else { 3 };
        status(&result.unwrap_or_else(|error| error));
        ACTIVE.set(false);
        completion(code);
    }) {
        ACTIVE.set(false);
        status(&error);
        completion(3);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn huskarl_native_cancel() {
    main_thread();
    SESSION.with(|s| {
        if let Some(session) = s.borrow().as_ref() {
            session.controller.cancel_sign_in();
        }
    });
}

#[unsafe(no_mangle)]
pub extern "C" fn huskarl_native_shutdown(completion: extern "C" fn(i32)) {
    main_thread();
    // AppKit defers termination until this callback. Continue driving both the
    // session and this task until the driver has released the storage lock.
    if ACTIVE.get() || CLOSING.replace(true) {
        completion(3);
        return;
    }
    let session = SESSION.with(|s| s.borrow().clone());
    if let Err(error) = spawn(async move {
        let result = async {
            if let Some(session) = session {
                session
                    .controller
                    .shutdown()
                    .await
                    .map_err(|error| error.to_string())?;
                let done = session.driver_done.borrow_mut().take();
                if let Some(done) = done {
                    done.await
                        .map_err(|_| "Session driver stopped unexpectedly.".to_owned())?;
                }
            }
            Ok::<_, String>(())
        }
        .await;
        if let Err(error) = &result {
            status(error);
            CLOSING.set(false);
        } else {
            SESSION.with(|s| s.borrow_mut().take());
        }
        completion(if result.is_ok() { 2 } else { 3 });
    }) {
        CLOSING.set(false);
        status(&error);
        completion(3);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn huskarl_native_status() -> *const c_char {
    main_thread();
    STATUS.with(|s| s.borrow().as_ptr())
}

/// Credential-free presentation state for the example UI.
#[repr(C)]
pub struct HuskarlSessionState {
    phase: i32,
    persistence: i32,
}

#[unsafe(no_mangle)]
pub extern "C" fn huskarl_native_state() -> HuskarlSessionState {
    main_thread();
    SESSION.with(|session| {
        let session = session.borrow();
        let Some(session) = session.as_ref() else {
            return HuskarlSessionState {
                phase: 0,
                persistence: 0,
            };
        };
        let state = session.controller.snapshot();
        HuskarlSessionState {
            phase: match state.phase {
                SessionPhase::SignedOut | SessionPhase::ReauthenticationRequired => 1,
                SessionPhase::Ready => 2,
                SessionPhase::CleanupRequired => 3,
                SessionPhase::Locked | SessionPhase::Closed => 4,
                _ => 5,
            },
            persistence: match state.persistence {
                PersistenceState::Absent => 1,
                PersistenceState::Saved => 2,
                PersistenceState::UnsavedChanges => 3,
                _ => 0,
            },
        }
    })
}
