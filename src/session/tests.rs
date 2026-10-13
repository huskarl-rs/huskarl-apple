#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use bytes::Bytes;
use futures_util::{FutureExt, pin_mut, poll};
use huskarl::{cache::InMemoryRefreshTokenStore, token::RefreshToken};
use huskarl_core::{
    RetryAdvice,
    client_auth::NoAuth,
    http::{HttpClient, HttpResponse, Idempotency},
    platform::MaybeSendBoxFuture,
    secrets::SecretString,
};

use super::*;

#[derive(Clone, Default)]
struct Disk {
    memory: Arc<InMemoryRefreshTokenStore>,
    write_gate: Arc<Mutex<Option<oneshot::Receiver<()>>>>,
    writing: Arc<AtomicBool>,
    fail_write: Arc<AtomicBool>,
    fail_clear: Arc<AtomicBool>,
}

fn storage_error() -> Error {
    Error::new(
        RetryAdvice::No,
        std::io::Error::other("test storage failure"),
    )
}

impl RefreshTokenStore for Disk {
    fn get(&self) -> MaybeSendBoxFuture<'_, Result<Option<RefreshToken>, Error>> {
        self.memory.get()
    }
    fn set<'a>(&'a self, token: &'a RefreshToken) -> MaybeSendBoxFuture<'a, Result<(), Error>> {
        Box::pin(async move {
            let gate = self.write_gate.lock().unwrap().take();
            self.writing.store(true, Ordering::Relaxed);
            if let Some(gate) = gate {
                gate.await.unwrap();
            }
            if self.fail_write.load(Ordering::Relaxed) {
                return Err(storage_error());
            }
            self.memory.set(token).await
        })
    }
    fn clear(&self) -> MaybeSendBoxFuture<'_, Result<(), Error>> {
        Box::pin(async move {
            if self.fail_clear.load(Ordering::Relaxed) {
                return Err(storage_error());
            }
            self.memory.clear().await
        })
    }
}

#[derive(Clone, Default)]
struct Http {
    calls: Arc<AtomicUsize>,
    invalid_grant: Arc<AtomicBool>,
    dpop: Arc<AtomicBool>,
    no_refresh: Arc<AtomicBool>,
}
impl HttpClient for Http {
    fn execute(
        &self,
        _request: http::Request<Bytes>,
        _idempotency: Idempotency,
    ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let invalid = self.invalid_grant.load(Ordering::Relaxed);
        let dpop = self.dpop.load(Ordering::Relaxed);
        let no_refresh = self.no_refresh.load(Ordering::Relaxed);
        Box::pin(async move {
            Ok(HttpResponse {
                status: if invalid {
                    http::StatusCode::BAD_REQUEST
                } else {
                    http::StatusCode::OK
                },
                headers: HeaderMap::from_iter([(
                    http::header::CONTENT_TYPE,
                    http::HeaderValue::from_static("application/json"),
                )]),
                body: Bytes::from_static(if invalid {
                    br#"{"error":"invalid_grant"}"#
                } else if no_refresh {
                    br#"{"access_token":"access","token_type":"Bearer","expires_in":3600}"#
                } else if dpop {
                    br#"{"access_token":"access","token_type":"DPoP","expires_in":3600,"refresh_token":"rotated"}"#
                } else {
                    br#"{"access_token":"access","token_type":"Bearer","expires_in":3600,"refresh_token":"rotated"}"#
                }),
            })
        })
    }
}

async fn grant(http: Http) -> AuthorizationCodeGrant {
    AuthorizationCodeGrant::builder()
        .client_id("client")
        .client_auth(NoAuth)
        .http_client(http)
        .authorization_endpoint("https://issuer.example/authorize".parse().unwrap())
        .token_endpoint("https://issuer.example/token".parse().unwrap())
        .redirect_uri("io.huskarl.test:/callback")
        .oidc(false)
        .build()
        .await
        .unwrap()
}

async fn seeded() -> (AppleSession, SessionDriver<Disk>, Disk, Http) {
    let disk = Disk::default();
    disk.memory
        .set(&RefreshToken::new(SecretString::new("saved"), None))
        .await
        .unwrap();
    let http = Http::default();
    let (session, driver) = AppleSession::create(grant(http.clone()).await, disk.clone());
    (session, driver, disk, http)
}

async fn completed(grant: AuthorizationCodeGrant) -> Result<CompleteOutput, SessionError> {
    let started = grant
        .start(StartInput::builder().scope(vec!["read".into()]).build())
        .await?;
    let input = CompleteInput::builder()
        .code("code")
        .state(started.pending_state.state.clone())
        .build();
    Ok(grant.complete(&started.pending_state, input).await?)
}

type LoginAttempt = (
    u64,
    oneshot::Receiver<()>,
    Reply<SignInOutcome>,
    oneshot::Receiver<Result<SignInOutcome, SessionError>>,
);

fn begin_login(session: &AppleSession) -> LoginAttempt {
    let generation = session.shared.advance();
    session
        .shared
        .publish(SessionPhase::SigningIn, PersistenceState::Absent);
    let (cancel, cancelled) = oneshot::channel();
    *session.shared.cancel.borrow_mut() = Some(cancel);
    let (reply, receiver) = oneshot::channel();
    (generation, cancelled, reply, receiver)
}

#[tokio::test]
async fn restore_refresh_lock_and_restore_revoke_old_handles() {
    let (session, driver, disk, http) = seeded().await;
    let run = driver.run();
    pin_mut!(run);
    let restoring = session.restore();
    assert!(poll!(&mut run).is_pending());
    assert_eq!(restoring.await.unwrap().phase, SessionPhase::Ready);
    let access = session.access().unwrap();
    let uri = "https://api.example/profile".parse().unwrap();
    let headers = access.get_headers(&Method::GET, &uri);
    assert!(poll!(&mut run).is_pending());
    assert_eq!(
        headers.await.unwrap()[http::header::AUTHORIZATION],
        "Bearer access"
    );
    assert_eq!(http.calls.load(Ordering::Relaxed), 1);
    assert_eq!(
        disk.get().await.unwrap().unwrap(),
        RefreshToken::new(SecretString::new("rotated"), None)
    );
    let locking = session.lock();
    assert!(session.access().is_err());
    assert!(poll!(&mut run).is_pending());
    locking.await.unwrap();
    let restoring = session.restore();
    assert!(poll!(&mut run).is_pending());
    restoring.await.unwrap();
    let stale = access.process_response(&uri, &HeaderMap::new());
    assert!(poll!(&mut run).is_pending());
    assert!(matches!(stale.await, Err(SessionError::Superseded)));
    let shutdown = session.shutdown();
    run.await;
    shutdown.await.unwrap();
}

#[tokio::test]
async fn logout_waits_for_rotation_even_when_request_waiter_is_dropped() {
    let (session, driver, disk, _) = seeded().await;
    let run = driver.run();
    pin_mut!(run);
    let restoring = session.restore();
    assert!(poll!(&mut run).is_pending());
    restoring.await.unwrap();
    let (release, gate) = oneshot::channel();
    *disk.write_gate.lock().unwrap() = Some(gate);
    let access = session.access().unwrap();
    let headers = access.get_headers(&Method::GET, &"https://api.example/".parse().unwrap());
    assert!(poll!(&mut run).is_pending());
    assert!(disk.writing.load(Ordering::Relaxed));
    drop(headers);
    let logout = session.logout();
    pin_mut!(logout);
    assert_eq!(session.snapshot().phase, SessionPhase::LoggingOut);
    assert!(poll!(&mut logout).is_pending());
    release.send(()).unwrap();
    assert!(poll!(&mut run).is_pending());
    logout.await.unwrap();
    assert!(disk.get().await.unwrap().is_none());
    assert_eq!(session.snapshot().phase, SessionPhase::SignedOut);
    let shutdown = session.shutdown();
    run.await;
    shutdown.await.unwrap();
}

#[tokio::test]
async fn failed_logout_gates_access_until_retry() {
    let (session, driver, disk, _) = seeded().await;
    let run = driver.run();
    pin_mut!(run);
    let restoring = session.restore();
    assert!(poll!(&mut run).is_pending());
    restoring.await.unwrap();
    disk.fail_clear.store(true, Ordering::Relaxed);
    let logout = session.logout();
    assert!(poll!(&mut run).is_pending());
    assert!(logout.await.is_err());
    assert_eq!(session.snapshot().phase, SessionPhase::CleanupRequired);
    assert!(session.access().is_err());
    assert!(session.restore().await.is_err());
    assert!(session.lock().await.is_err());
    disk.fail_clear.store(false, Ordering::Relaxed);
    let logout = session.logout();
    assert!(poll!(&mut run).is_pending());
    logout.await.unwrap();
    assert!(disk.get().await.unwrap().is_none());
    let shutdown = session.shutdown();
    run.await;
    shutdown.await.unwrap();
}

#[tokio::test]
async fn mismatched_binding_preserves_credentials_until_explicit_logout() {
    let (session, driver, disk, _) = seeded().await;
    disk.memory
        .set(&RefreshToken::new(
            SecretString::new("bound"),
            Some("other-key".into()),
        ))
        .await
        .unwrap();
    let run = driver.run();
    pin_mut!(run);
    let restoring = session.restore();
    assert!(poll!(&mut run).is_pending());
    assert!(matches!(
        restoring.await,
        Err(SessionError::BindingMismatch)
    ));
    assert!(disk.get().await.unwrap().is_some());
    assert_eq!(session.snapshot().phase, SessionPhase::CleanupRequired);
    let shutdown = session.shutdown();
    run.await;
    shutdown.await.unwrap();
}

#[tokio::test]
async fn rotation_write_failure_keeps_memory_and_publishes_warning() {
    let (session, driver, disk, http) = seeded().await;
    let run = driver.run();
    pin_mut!(run);
    let restoring = session.restore();
    assert!(poll!(&mut run).is_pending());
    restoring.await.unwrap();
    disk.fail_write.store(true, Ordering::Relaxed);
    let access = session.access().unwrap();
    let uri = "https://api.example/".parse().unwrap();
    let headers = access.get_headers(&Method::GET, &uri);
    assert!(poll!(&mut run).is_pending());
    headers.await.unwrap();
    assert_eq!(
        session.snapshot(),
        SessionSnapshot {
            phase: SessionPhase::Ready,
            persistence: PersistenceState::UnsavedChanges
        }
    );
    let headers = access.get_headers(&Method::GET, &uri);
    assert!(poll!(&mut run).is_pending());
    headers.await.unwrap();
    assert_eq!(http.calls.load(Ordering::Relaxed), 1);
    let shutdown = session.shutdown();
    run.await;
    shutdown.await.unwrap();
}

#[tokio::test]
async fn cancelled_login_settles_write_then_removes_credentials() {
    let disk = Disk::default();
    let (session, mut driver) = AppleSession::create(grant(Http::default()).await, disk.clone());
    let (generation, cancelled, mut reply, _receiver) = begin_login(&session);
    let (release, gate) = oneshot::channel();
    *disk.write_gate.lock().unwrap() = Some(gate);
    let flow = completed(driver.engine.grant.clone());
    let login = driver.login_flow(generation, flow, cancelled, &mut reply);
    pin_mut!(login);
    assert!(poll!(&mut login).is_pending());
    assert!(disk.writing.load(Ordering::Relaxed));
    session.cancel_sign_in();
    assert!(poll!(&mut login).is_pending());
    release.send(()).unwrap();
    assert!(matches!(login.await, Err(SessionError::Cancelled)));
    assert!(disk.get().await.unwrap().is_none());
    assert_eq!(session.snapshot().phase, SessionPhase::SignedOut);
}

#[tokio::test]
async fn dropped_login_waiter_cancels_exchange_without_persisting() {
    let disk = Disk::default();
    let (session, mut driver) = AppleSession::create(grant(Http::default()).await, disk.clone());
    let (generation, cancelled, mut reply, receiver) = begin_login(&session);
    let login = driver.login_flow(generation, std::future::pending(), cancelled, &mut reply);
    pin_mut!(login);
    assert!(poll!(&mut login).is_pending());
    drop(receiver);
    assert!(matches!(login.await, Err(SessionError::Cancelled)));
    assert!(!disk.writing.load(Ordering::Relaxed));
    assert_eq!(session.snapshot().phase, SessionPhase::SignedOut);
}

#[tokio::test]
async fn login_success_and_cleanup_failure_are_observable() {
    let disk = Disk::default();
    let (session, mut driver) = AppleSession::create(grant(Http::default()).await, disk.clone());
    let mut changes = session.subscribe();
    assert_eq!(changes.next().await.unwrap().phase, SessionPhase::SignedOut);
    let (generation, cancelled, mut reply, _receiver) = begin_login(&session);
    let flow = completed(driver.engine.grant.clone());
    driver
        .login_flow(generation, flow, cancelled, &mut reply)
        .await
        .unwrap();
    assert_eq!(
        changes.next().await.unwrap(),
        SessionSnapshot {
            phase: SessionPhase::Ready,
            persistence: PersistenceState::Saved
        }
    );
    assert!(session.access().is_ok());
    // A failed initial prime, followed by failed cleanup, must never look ready.
    let (generation, cancelled, mut reply, _receiver) = begin_login(&session);
    disk.fail_write.store(true, Ordering::Relaxed);
    disk.fail_clear.store(true, Ordering::Relaxed);
    let flow = completed(driver.engine.grant.clone());
    assert!(
        driver
            .login_flow(generation, flow, cancelled, &mut reply)
            .await
            .is_err()
    );
    assert_eq!(
        changes.next().await.unwrap().phase,
        SessionPhase::CleanupRequired
    );
    assert!(changes.next().now_or_never().is_none());
    drop(driver);
    assert_eq!(changes.next().await.unwrap().phase, SessionPhase::Closed);
    assert!(changes.next().await.is_none());
}

#[tokio::test]
async fn rejected_refresh_requires_interactive_reauthentication() {
    let (session, driver, _, http) = seeded().await;
    let run = driver.run();
    pin_mut!(run);
    let restoring = session.restore();
    assert!(poll!(&mut run).is_pending());
    restoring.await.unwrap();
    http.invalid_grant.store(true, Ordering::Relaxed);
    let headers = session
        .access()
        .unwrap()
        .get_headers(&Method::GET, &"https://api.example/".parse().unwrap());
    assert!(poll!(&mut run).is_pending());
    assert!(headers.await.is_err());
    assert_eq!(
        session.snapshot().phase,
        SessionPhase::ReauthenticationRequired
    );
    let shutdown = session.shutdown();
    run.await;
    shutdown.await.unwrap();
}

#[tokio::test]
async fn dpop_refresh_produces_proofs_and_rejects_bearer_downgrade() {
    use huskarl_core::dpop::DPoP;
    use huskarl_crypto_native::asymmetric::signer::{GenerateAlgorithm, PrivateKey};
    let http = Http::default();
    http.dpop.store(true, Ordering::Relaxed);
    let key = PrivateKey::generate(GenerateAlgorithm::Es256, None).unwrap();
    let grant = AuthorizationCodeGrant::builder()
        .client_id("client")
        .client_auth(NoAuth)
        .http_client(http.clone())
        .authorization_endpoint("https://issuer.example/authorize".parse().unwrap())
        .token_endpoint("https://issuer.example/token".parse().unwrap())
        .redirect_uri("io.huskarl.test:/callback")
        .oidc(false)
        .dpop(DPoP::builder().signer(key).build())
        .build()
        .await
        .unwrap();
    let disk = Disk::default();
    disk.memory
        .set(&RefreshToken::new(
            SecretString::new("saved"),
            grant.dpop().get_current_thumbprint().await,
        ))
        .await
        .unwrap();
    let (session, driver) = AppleSession::create(grant, disk);
    let run = driver.run();
    pin_mut!(run);
    let restoring = session.restore();
    assert!(poll!(&mut run).is_pending());
    restoring.await.unwrap();
    let access = session.access().unwrap();
    let uri = "https://api.example/".parse().unwrap();
    let headers = access.get_headers(&Method::GET, &uri);
    assert!(poll!(&mut run).is_pending());
    let headers = headers.await.unwrap();
    assert!(headers.contains_key("dpop"));
    assert_eq!(headers[http::header::AUTHORIZATION], "DPoP access");
    let challenge = HeaderMap::from_iter([(
        http::header::WWW_AUTHENTICATE,
        http::HeaderValue::from_static("DPoP error=\"invalid_token\""),
    )]);
    let processed = access.process_response(&uri, &challenge);
    assert!(poll!(&mut run).is_pending());
    processed.await.unwrap();
    http.dpop.store(false, Ordering::Relaxed);
    let headers = access.get_headers(&Method::GET, &uri);
    assert!(poll!(&mut run).is_pending());
    assert!(matches!(headers.await, Err(SessionError::BindingMismatch)));
    assert_eq!(
        session.snapshot().phase,
        SessionPhase::ReauthenticationRequired
    );
    let shutdown = session.shutdown();
    run.await;
    shutdown.await.unwrap();
}

#[tokio::test]
async fn lock_cannot_hide_cancelled_login_cleanup_failure() {
    let disk = Disk::default();
    let (session, mut driver) = AppleSession::create(grant(Http::default()).await, disk.clone());
    let (generation, cancelled, mut reply, _receiver) = begin_login(&session);
    let (release, gate) = oneshot::channel();
    *disk.write_gate.lock().unwrap() = Some(gate);
    let locking;
    {
        let flow = completed(driver.engine.grant.clone());
        let login = driver.login_flow(generation, flow, cancelled, &mut reply);
        pin_mut!(login);
        assert!(poll!(&mut login).is_pending());
        locking = session.lock();
        disk.fail_clear.store(true, Ordering::Relaxed);
        release.send(()).unwrap();
        assert!(login.await.is_err());
    }
    let run = driver.run();
    pin_mut!(run);
    assert!(poll!(&mut run).is_pending());
    assert!(locking.await.is_err());
    assert_eq!(session.snapshot().phase, SessionPhase::CleanupRequired);
    assert!(session.restore().await.is_err());
    disk.fail_clear.store(false, Ordering::Relaxed);
    let logout = session.logout();
    assert!(poll!(&mut run).is_pending());
    logout.await.unwrap();
    assert!(disk.get().await.unwrap().is_none());
    let shutdown = session.shutdown();
    run.await;
    shutdown.await.unwrap();
}

#[tokio::test]
async fn access_only_login_removes_an_older_saved_credential() {
    let (session, mut driver, disk, http) = seeded().await;
    http.no_refresh.store(true, Ordering::Relaxed);
    let (generation, cancelled, mut reply, _receiver) = begin_login(&session);
    let flow = completed(driver.engine.grant.clone());
    driver
        .login_flow(generation, flow, cancelled, &mut reply)
        .await
        .unwrap();
    assert_eq!(
        session.snapshot(),
        SessionSnapshot {
            phase: SessionPhase::Ready,
            persistence: PersistenceState::Absent
        }
    );
    assert!(disk.get().await.unwrap().is_none());
    let access = session.access().unwrap();
    let run = driver.run();
    pin_mut!(run);
    let headers = access.get_headers(&Method::GET, &"https://api.example/".parse().unwrap());
    assert!(poll!(&mut run).is_pending());
    headers.await.unwrap();
    assert_eq!(http.calls.load(Ordering::Relaxed), 1);
    let shutdown = session.shutdown();
    run.await;
    shutdown.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn background_access_authorizes_and_old_handles_stay_revoked() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<SessionAccess>();

    let (session, driver, _, http) = seeded().await;
    let exercise = async {
        session.restore().await.unwrap();
        let access = session.access().unwrap();
        let stale = tokio::spawn(async move {
            let uri = "https://api.example/profile".parse().unwrap();
            let headers = access.get_headers(&Method::GET, &uri).await.unwrap();
            assert_eq!(headers[http::header::AUTHORIZATION], "Bearer access");
            access
                .process_response(&uri, &HeaderMap::new())
                .await
                .unwrap();
            access
        })
        .await
        .unwrap();
        assert_eq!(http.calls.load(Ordering::Relaxed), 1);
        session.lock().await.unwrap();
        session.restore().await.unwrap();
        tokio::spawn(async move {
            let uri = "https://api.example/profile".parse().unwrap();
            assert!(matches!(
                stale.get_headers(&Method::GET, &uri).await,
                Err(SessionError::Superseded)
            ));
            assert!(matches!(
                stale.process_response(&uri, &HeaderMap::new()).await,
                Err(SessionError::Superseded)
            ));
        })
        .await
        .unwrap();
        session.shutdown().await.unwrap();
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        futures_util::join!(driver.run(), exercise);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn background_access_reports_closed_when_driver_drops() {
    let (session, driver, _, _) = seeded().await;
    // Restore before retaining the driver so it can be dropped with work queued.
    let restoring = session.restore();
    let run = driver.run();
    let mut run = Box::pin(run);
    assert!(poll!(&mut run).is_pending());
    restoring.await.unwrap();
    let access = session.access().unwrap();
    let uri = "https://api.example/profile".parse().unwrap();
    let pending = access.get_headers(&Method::GET, &uri);
    drop(run);
    tokio::spawn(async move {
        assert!(matches!(pending.await, Err(SessionError::Closed)));
        assert!(matches!(
            access.get_headers(&Method::GET, &uri).await,
            Err(SessionError::Closed)
        ));
        assert!(matches!(
            access.process_response(&uri, &HeaderMap::new()).await,
            Err(SessionError::Closed)
        ));
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn background_access_keeps_driver_alive_until_last_handle_drops() {
    let (session, driver, _, _) = seeded().await;
    let exercise = async move {
        session.restore().await.unwrap();
        let access = session.access().unwrap();
        drop(session);
        tokio::spawn(async move {
            let uri = "https://api.example/profile".parse().unwrap();
            access.get_headers(&Method::GET, &uri).await.unwrap();
            access
                .process_response(&uri, &HeaderMap::new())
                .await
                .unwrap();
        })
        .await
        .unwrap();
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        futures_util::join!(driver.run(), exercise);
    })
    .await
    .unwrap();
}
