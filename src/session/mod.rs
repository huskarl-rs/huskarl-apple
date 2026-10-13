//! A UI-independent owner for native authorization-code sessions.
//!
//! Enable `session`. Build with an existing grant and a dedicated refresh-token
//! store, then continuously drive [`SessionDriver::run`] on the application's
//! main-thread executor. The driver owns credential mutations even if a caller
//! drops its operation future. Do not abort the driver during an operation;
//! await [`AppleSession::shutdown`] before stopping the executor.
//!
//! Request authorization is serialized; HTTP requests themselves remain outside
//! the controller and may run concurrently. Already-issued headers and requests
//! cannot be revoked locally. A store must have exactly one session owner across
//! processes; this API does not acquire a cross-process lock. Grant/store clones
//! must not be used to mutate this session outside the controller.
//!
//! Keychain access policies and optional authentication contexts are configured
//! on the supplied store/key. `lock` drops token memory, but does not invalidate
//! externally owned `LAContext`s or promise a fresh biometric prompt. Native
//! presentation still requires a foreground window and a running UI event loop.

mod storage;

use std::{
    cell::{Cell, RefCell},
    future::Future,
    pin::Pin,
    rc::{Rc, Weak},
    sync::Arc,
    task::{Context, Poll, Waker},
};

use futures_channel::{mpsc, oneshot};
use futures_util::{Stream, StreamExt, future::Either};
use http::{HeaderMap, Method, Uri};
use huskarl::{
    authorizer::HttpAuthorizer,
    cache::{
        GrantTokenSource, InMemoryTokenCache, NoSource, Recovery, RefreshTokenStore, TokenError,
    },
    grant::{
        authorization_code::{
            AuthorizationCodeGrant, CompleteInput, CompleteOutput, ParseCallbackError, StartInput,
        },
        core::OAuth2ExchangeGrant,
    },
    token::id_token::IdTokenClaims,
};
use huskarl_core::{Error, jwt::validator::ValidatedJwt};
use objc2::{MainThreadMarker, Message, rc::Retained};
use snafu::Snafu;
use storage::SessionStore;

use crate::web_authentication::{
    PresentationAnchor, WebAuthenticationError, WebAuthenticationSession,
};

/// The current local session lifecycle, independent of network reachability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionPhase {
    /// No usable in-memory session. Storage has not necessarily been inspected.
    SignedOut,
    /// Reading saved credentials and checking their binding.
    Restoring,
    /// An interactive login is in progress.
    SigningIn,
    /// Credentials are available; the server may still reject them on use.
    Ready,
    /// Access is gated while outstanding work settles.
    Locking,
    /// In-memory credentials have been discarded.
    Locked,
    /// A new interactive login is needed.
    ReauthenticationRequired,
    /// Access is gated while saved credentials are removed.
    LoggingOut,
    /// Credential cleanup failed; retry logout before signing in.
    CleanupRequired,
    /// The driver has stopped and this handle cannot be reused.
    Closed,
}

/// Whether the current credentials can survive process restart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PersistenceState {
    /// Storage has not been inspected successfully.
    Unknown,
    /// No refresh token is saved (an access-only session may still be ready).
    Absent,
    /// The last credential write/read succeeded.
    Saved,
    /// A write or deletion failed; durable state may differ from memory.
    UnsavedChanges,
}

/// A secret-free snapshot suitable for rendering application UI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionSnapshot {
    /// Local lifecycle state.
    pub phase: SessionPhase,
    /// Last known persistence state.
    pub persistence: PersistenceState,
}

/// Native browser and token-exchange options for one login attempt.
#[derive(Clone, Debug, Default)]
pub struct SignInOptions {
    /// Request an isolated browser session. This is not provider logout.
    pub prefers_ephemeral: bool,
    /// Optional token-endpoint resource indicators. Authorization-endpoint
    /// parameters remain in the supplied `StartInput`.
    pub completion_resource: Option<Vec<String>>,
}

/// Verified identity returned by login; raw access/refresh tokens stay inside
/// the controller. Restoring a refresh token does not restore this identity.
pub struct SignInOutcome {
    /// Present only when the configured grant validated an ID token.
    pub id_token: Option<ValidatedJwt<IdTokenClaims>>,
}

/// Session errors preserve the underlying protocol/storage recovery information.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum SessionError {
    /// The main-thread driver is no longer available.
    Closed,
    /// The requested lifecycle transition is not allowed in the current state.
    InvalidState,
    /// This operation or access handle belongs to an ended session generation.
    Superseded,
    /// The caller cancelled this login attempt.
    Cancelled,
    /// Saved/received credentials do not match the configured grant's `DPoP` key.
    BindingMismatch,
    /// A protocol, signing, or storage operation failed.
    Operation {
        /// Original error with its retry classification.
        source: Error,
    },
    /// Token acquisition or request authorization failed.
    Authorization {
        /// Original error with its recovery classification.
        source: TokenError,
    },
    /// Apple's authentication browser failed.
    Browser {
        /// Original native browser error.
        source: WebAuthenticationError,
    },
    /// The browser callback could not be parsed.
    Callback {
        /// Original callback error.
        source: ParseCallbackError,
    },
}

impl From<Error> for SessionError {
    fn from(source: Error) -> Self {
        Self::Operation { source }
    }
}

type Reply<T> = oneshot::Sender<Result<T, SessionError>>;
type Observer = Rc<RefCell<Option<Waker>>>;

struct Shared {
    snapshot: Cell<SessionSnapshot>,
    generation: Cell<u64>,
    revision: Cell<u64>,
    observers: RefCell<Vec<Weak<RefCell<Option<Waker>>>>>,
    cancel: RefCell<Option<oneshot::Sender<()>>>,
}

impl Shared {
    fn publish(&self, phase: SessionPhase, persistence: PersistenceState) {
        let snapshot = SessionSnapshot { phase, persistence };
        if self.snapshot.replace(snapshot) == snapshot {
            return;
        }
        self.revision.set(self.revision.get().wrapping_add(1));
        // Wake outside the borrow: an executor may immediately inspect state.
        let mut wakes = Vec::new();
        self.observers.borrow_mut().retain(|weak| {
            let Some(observer) = weak.upgrade() else {
                return false;
            };
            if let Some(waker) = observer.borrow_mut().take() {
                wakes.push(waker);
            }
            true
        });
        for waker in wakes {
            waker.wake();
        }
    }

    fn phase(&self, phase: SessionPhase) {
        self.publish(phase, self.snapshot.get().persistence);
    }

    fn advance(&self) -> u64 {
        let generation = self.generation.get().wrapping_add(1);
        self.generation.set(generation);
        let cancel = self.cancel.borrow_mut().take();
        if let Some(cancel) = cancel {
            let _ = cancel.send(());
        }
        generation
    }

    fn check(&self, generation: u64) -> Result<(), SessionError> {
        if self.snapshot.get().phase == SessionPhase::Closed {
            return Err(SessionError::Closed);
        }
        if generation != self.generation.get() {
            return Err(SessionError::Superseded);
        }
        Ok(())
    }
}

/// Coalescing snapshot stream. Slow consumers receive the latest state rather
/// than an unbounded event history. The first item is the current snapshot.
pub struct SessionChanges {
    shared: Rc<Shared>,
    observer: Observer,
    seen: Option<u64>,
}

impl Stream for SessionChanges {
    type Item = SessionSnapshot;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let revision = this.shared.revision.get();
        if this.seen != Some(revision) {
            this.seen = Some(revision);
            return Poll::Ready(Some(this.shared.snapshot.get()));
        }
        if this.shared.snapshot.get().phase == SessionPhase::Closed {
            return Poll::Ready(None);
        }
        *this.observer.borrow_mut() = Some(cx.waker().clone());
        Poll::Pending
    }
}

enum Command {
    Restore(u64, Reply<SessionSnapshot>),
    Login {
        generation: u64,
        window: Retained<PresentationAnchor>,
        input: StartInput,
        options: SignInOptions,
        cancel: oneshot::Receiver<()>,
        reply: Reply<SignInOutcome>,
    },
    Lock(u64, Reply<()>),
    Logout(u64, Reply<()>),
    Headers(u64, Method, Uri, Reply<HeaderMap>),
    Response(u64, Uri, HeaderMap, Reply<()>),
    Shutdown(Reply<()>),
}

// Only request data crosses threads; native windows and lifecycle state stay local.
enum AccessCommand {
    Headers(u64, Method, Uri, Reply<HeaderMap>),
    Response(u64, Uri, HeaderMap, Reply<()>),
}

impl From<AccessCommand> for Command {
    fn from(command: AccessCommand) -> Self {
        match command {
            AccessCommand::Headers(generation, method, uri, reply) => {
                Self::Headers(generation, method, uri, reply)
            }
            AccessCommand::Response(generation, uri, headers, reply) => {
                Self::Response(generation, uri, headers, reply)
            }
        }
    }
}

type CommandReceiver = futures_util::stream::Select<
    mpsc::UnboundedReceiver<Command>,
    futures_util::stream::Map<mpsc::UnboundedReceiver<AccessCommand>, fn(AccessCommand) -> Command>,
>;

/// Cloneable main-thread controller. Clones share one lifecycle and driver.
#[derive(Clone)]
pub struct AppleSession {
    shared: Rc<Shared>,
    commands: mpsc::UnboundedSender<Command>,
    access_commands: mpsc::UnboundedSender<AccessCommand>,
}

async fn receive<T>(
    receiver: oneshot::Receiver<Result<T, SessionError>>,
) -> Result<T, SessionError> {
    receiver.await.unwrap_or(Err(SessionError::Closed))
}

#[bon::bon]
impl AppleSession {
    /// Creates a controller and its driver on the main thread. The grant is
    /// reused for both initial login and refresh. Supply a dedicated store and
    /// retain any cross-process ownership lock until the driver finishes.
    #[builder]
    pub fn new<S: RefreshTokenStore + 'static>(
        grant: AuthorizationCodeGrant,
        refresh_store: S,
        main_thread: MainThreadMarker,
    ) -> (Self, SessionDriver<S>) {
        let _ = main_thread;
        Self::create(grant, refresh_store)
    }

    fn create<S: RefreshTokenStore + 'static>(
        grant: AuthorizationCodeGrant,
        refresh_store: S,
    ) -> (Self, SessionDriver<S>) {
        let (commands, receiver) = mpsc::unbounded();
        let (access_commands, access_receiver) = mpsc::unbounded();
        let receiver = futures_util::stream::select(
            receiver,
            access_receiver.map(Command::from as fn(AccessCommand) -> Command),
        );
        let shared = Rc::new(Shared {
            snapshot: Cell::new(SessionSnapshot {
                phase: SessionPhase::SignedOut,
                persistence: PersistenceState::Unknown,
            }),
            generation: Cell::new(0),
            revision: Cell::new(0),
            observers: RefCell::new(Vec::new()),
            cancel: RefCell::new(None),
        });
        let engine = Engine {
            grant,
            disk: Arc::new(refresh_store),
            active: None,
            cleanup_pending: false,
        };
        (
            Self {
                shared: shared.clone(),
                commands,
                access_commands,
            },
            SessionDriver {
                shared,
                receiver,
                engine,
            },
        )
    }

    /// Returns the current local snapshot without accessing Keychain or network.
    #[must_use]
    pub fn snapshot(&self) -> SessionSnapshot {
        self.shared.snapshot.get()
    }

    /// Observes the current snapshot and subsequent changes.
    #[must_use]
    pub fn subscribe(&self) -> SessionChanges {
        let observer = Rc::new(RefCell::new(None));
        self.shared
            .observers
            .borrow_mut()
            .push(Rc::downgrade(&observer));
        SessionChanges {
            shared: self.shared.clone(),
            observer,
            seen: None,
        }
    }

    /// Restores saved credentials without opening a browser. Keychain may prompt.
    /// Does not contact the provider to validate the saved refresh token.
    /// # Errors
    /// Returns state, storage, or key-binding errors. Existing credentials are
    /// preserved on failure; a binding mismatch requires explicit logout.
    pub fn restore(&self) -> impl Future<Output = Result<SessionSnapshot, SessionError>> + use<> {
        let (reply, receiver) = oneshot::channel();
        if matches!(
            self.snapshot().phase,
            SessionPhase::SignedOut | SessionPhase::Locked
        ) {
            let generation = self.shared.advance();
            self.shared.phase(SessionPhase::Restoring);
            self.send(Command::Restore(generation, reply));
        } else {
            let _ = reply.send(Err(SessionError::InvalidState));
        }
        receive(receiver)
    }

    /// Runs the supplied authorization attempt through Apple's browser, then
    /// validates and persists its result. Call `restore` first so an existing
    /// saved session cannot be accidentally overwritten. The driver retains the window.
    /// Dropping the returned future cancels the attempt; persistence already
    /// underway is settled and cleaned up by the driver before it accepts login.
    /// # Errors
    /// Returns browser, OAuth, persistence, cancellation, or lifecycle errors.
    pub fn sign_in(
        &self,
        window: &PresentationAnchor,
        input: StartInput,
        options: SignInOptions,
    ) -> impl Future<Output = Result<SignInOutcome, SessionError>> + use<> {
        let (reply, receiver) = oneshot::channel();
        if !matches!(
            self.snapshot().phase,
            SessionPhase::SignedOut | SessionPhase::ReauthenticationRequired
        ) || self.snapshot().persistence == PersistenceState::Unknown
        {
            let _ = reply.send(Err(SessionError::InvalidState));
        } else {
            let generation = self.shared.advance();
            let (cancel, cancelled) = oneshot::channel();
            *self.shared.cancel.borrow_mut() = Some(cancel);
            self.shared.phase(SessionPhase::SigningIn);
            self.send(Command::Login {
                generation,
                window: window.retain(),
                input,
                options,
                cancel: cancelled,
                reply,
            });
        }
        receive(receiver)
    }

    /// Cancels login at any stage. New login is allowed once the driver settles
    /// the attempt; a pending credential write is not abandoned.
    pub fn cancel_sign_in(&self) {
        if self.snapshot().phase == SessionPhase::SigningIn {
            let cancel = self.shared.cancel.borrow_mut().take();
            if let Some(cancel) = cancel {
                let _ = cancel.send(());
            }
        }
    }

    /// Immediately gates access; the driver then drops token memory after
    /// outstanding credential operations settle. Saved credentials are retained.
    /// # Errors
    /// Returns an error if cleanup is pending or the driver has stopped.
    pub fn lock(&self) -> impl Future<Output = Result<(), SessionError>> + use<> {
        let (reply, receiver) = oneshot::channel();
        if matches!(
            self.snapshot().phase,
            SessionPhase::LoggingOut | SessionPhase::CleanupRequired | SessionPhase::Closed
        ) {
            let _ = reply.send(Err(SessionError::InvalidState));
        } else {
            let generation = self.shared.advance();
            self.shared.phase(SessionPhase::Locking);
            self.send(Command::Lock(generation, reply));
        }
        receive(receiver)
    }

    /// Immediately gates access, then clears memory and saved credentials.
    /// Does not revoke server tokens, delete the signing key, or clear cookies.
    /// Dropping the returned future does not cancel cleanup.
    /// # Errors
    /// Failed deletion leaves `CleanupRequired`; retry logout to finish.
    pub fn logout(&self) -> impl Future<Output = Result<(), SessionError>> + use<> {
        let (reply, receiver) = oneshot::channel();
        if self.snapshot().phase == SessionPhase::Closed {
            let _ = reply.send(Err(SessionError::Closed));
        } else {
            let generation = self.shared.advance();
            self.shared.phase(SessionPhase::LoggingOut);
            self.send(Command::Logout(generation, reply));
        }
        receive(receiver)
    }

    /// Obtains a revocable request handle for this ready session generation.
    /// # Errors
    /// Fails unless the session is ready.
    pub fn access(&self) -> Result<SessionAccess, SessionError> {
        if self.snapshot().phase != SessionPhase::Ready {
            return Err(SessionError::InvalidState);
        }
        Ok(SessionAccess {
            commands: self.access_commands.clone(),
            generation: self.shared.generation.get(),
        })
    }

    /// Gates access and drains outstanding mutations before stopping the driver.
    /// Retains saved credentials. Call logout first when they must be removed.
    /// # Errors
    /// Returns an error if the driver was already stopped.
    pub fn shutdown(&self) -> impl Future<Output = Result<(), SessionError>> + use<> {
        let (reply, receiver) = oneshot::channel();
        self.shared.advance();
        self.shared.phase(SessionPhase::Closed);
        self.send(Command::Shutdown(reply));
        receive(receiver)
    }

    fn send(&self, command: Command) {
        if self.commands.unbounded_send(command).is_err() {
            self.shared.phase(SessionPhase::Closed);
        }
    }
}

/// A generation-bound, `Send + Sync` authorization facade.
///
/// Move or clone this handle into background tasks to authorize requests and
/// process responses. Its methods return `Send` futures without borrowing the
/// handle. Work is queued to the main-thread driver, which must remain running.
/// Lock, logout, and a new login revoke old handles even across threads.
/// It never exposes the token cache; already-issued headers cannot be revoked.
#[derive(Clone)]
pub struct SessionAccess {
    commands: mpsc::UnboundedSender<AccessCommand>,
    generation: u64,
}

impl SessionAccess {
    /// Obtains fresh request headers. HTTP execution remains the caller's job.
    /// # Errors
    /// Fails after lock/logout, or when token acquisition/signing fails.
    pub fn get_headers(
        &self,
        method: &Method,
        uri: &Uri,
    ) -> impl Future<Output = Result<HeaderMap, SessionError>> + Send + use<> {
        let (reply, receiver) = oneshot::channel();
        let _ = self.commands.unbounded_send(AccessCommand::Headers(
            self.generation,
            method.clone(),
            uri.clone(),
            reply,
        ));
        receive(receiver)
    }

    /// Processes response challenges/nonces without retrying the HTTP request.
    /// Responses from an ended generation cannot affect a newer session.
    /// # Errors
    /// Fails if the handle is stale or the driver has stopped.
    pub fn process_response(
        &self,
        uri: &Uri,
        headers: &HeaderMap,
    ) -> impl Future<Output = Result<(), SessionError>> + Send + use<> {
        let (reply, receiver) = oneshot::channel();
        let _ = self.commands.unbounded_send(AccessCommand::Response(
            self.generation,
            uri.clone(),
            headers.clone(),
            reply,
        ));
        receive(receiver)
    }
}

type Source<S> = GrantTokenSource<AuthorizationCodeGrant, SessionStore<S>>;
struct Active<S: RefreshTokenStore> {
    source: Arc<Source<S>>,
    authorizer: HttpAuthorizer,
    store: SessionStore<S>,
}
struct Engine<S: RefreshTokenStore> {
    grant: AuthorizationCodeGrant,
    disk: Arc<S>,
    active: Option<Active<S>>,
    cleanup_pending: bool,
}

impl<S: RefreshTokenStore + 'static> Engine<S> {
    async fn prime(&mut self, completed: CompleteOutput) -> Result<SignInOutcome, SessionError> {
        let store = SessionStore::new(self.disk.clone());
        self.activate(store);
        // An access-only replacement must not leave an older account's
        // refresh token available on the next launch.
        if completed.token_response.refresh_token().is_none() {
            self.disk.clear().await?;
        }
        self.active
            .as_ref()
            .ok_or(SessionError::InvalidState)?
            .source
            .prime(completed.token_response)
            .await?;
        Ok(SignInOutcome {
            id_token: completed.id_token,
        })
    }

    fn activate(&mut self, store: SessionStore<S>) {
        let source = Arc::new(
            GrantTokenSource::builder()
                .grant(self.grant.clone())
                .grant_parameters(NoSource)
                .refresh_store(store.clone())
                .build(),
        );
        let cache = InMemoryTokenCache::builder().source(source.clone()).build();
        self.active = Some(Active {
            source,
            authorizer: HttpAuthorizer::builder().cache(cache).build(),
            store,
        });
    }

    async fn restore(&mut self) -> Result<SessionSnapshot, SessionError> {
        let token = self.disk.get().await?;
        let Some(token) = token else {
            self.active = None;
            return Ok(SessionSnapshot {
                phase: SessionPhase::SignedOut,
                persistence: PersistenceState::Absent,
            });
        };
        if token.dpop_jkt() != self.grant.dpop().get_current_thumbprint().await.as_deref() {
            return Err(SessionError::BindingMismatch);
        }
        let store = SessionStore::new(self.disk.clone());
        store.restore(token).await?;
        self.activate(store);
        Ok(SessionSnapshot {
            phase: SessionPhase::Ready,
            persistence: PersistenceState::Saved,
        })
    }
}

/// Executor-independent main-thread worker. Run exactly once and keep it alive
/// until `shutdown` completes. No Tokio runtime is created by this module.
pub struct SessionDriver<S: RefreshTokenStore> {
    shared: Rc<Shared>,
    receiver: CommandReceiver,
    engine: Engine<S>,
}

impl<S: RefreshTokenStore> Drop for SessionDriver<S> {
    fn drop(&mut self) {
        self.shared.advance();
        self.shared.phase(SessionPhase::Closed);
    }
}

impl<S: RefreshTokenStore + 'static> SessionDriver<S> {
    /// Services commands until shutdown or all controller/access handles drop.
    /// Must run on the main thread alongside the native event loop. Do not abort
    /// this future while storage operations are outstanding.
    pub async fn run(mut self) {
        while let Some(command) = self.receiver.next().await {
            match command {
                Command::Restore(generation, reply) => {
                    let result = match self.shared.check(generation) {
                        Ok(()) => self.engine.restore().await,
                        Err(error) => Err(error),
                    };
                    if self.shared.check(generation).is_ok() {
                        match &result {
                            Ok(state) => self.shared.publish(state.phase, state.persistence),
                            Err(SessionError::BindingMismatch) => {
                                self.shared.phase(SessionPhase::CleanupRequired);
                            }
                            Err(_) => self.shared.phase(SessionPhase::SignedOut),
                        }
                    }
                    let _ = reply.send(self.shared.check(generation).and(result));
                }
                Command::Login {
                    generation,
                    window,
                    input,
                    options,
                    cancel,
                    mut reply,
                } => {
                    let result = self
                        .login(generation, &window, input, options, cancel, &mut reply)
                        .await;
                    let _ = reply.send(result);
                }
                Command::Lock(generation, reply) => {
                    let persistence = self
                        .engine
                        .active
                        .take()
                        .map_or(self.shared.snapshot.get().persistence, |active| {
                            active.store.persistence()
                        });
                    let mut result = self.shared.check(generation);
                    if result.is_ok() {
                        if self.engine.cleanup_pending {
                            self.shared.publish(
                                SessionPhase::CleanupRequired,
                                PersistenceState::UnsavedChanges,
                            );
                            result = Err(SessionError::InvalidState);
                        } else {
                            self.shared.publish(SessionPhase::Locked, persistence);
                        }
                    }
                    let _ = reply.send(result);
                }
                Command::Logout(generation, reply) => {
                    self.engine.active = None;
                    let result = self.engine.disk.clear().await.map_err(SessionError::from);
                    self.engine.cleanup_pending = result.is_err();
                    if self.shared.check(generation).is_ok() {
                        if result.is_ok() {
                            self.shared
                                .publish(SessionPhase::SignedOut, PersistenceState::Absent);
                        } else {
                            self.shared.publish(
                                SessionPhase::CleanupRequired,
                                PersistenceState::UnsavedChanges,
                            );
                        }
                    }
                    let _ = reply.send(result);
                }
                Command::Headers(generation, method, uri, reply) => {
                    let result = self.headers(generation, &method, &uri).await;
                    let _ = reply.send(result);
                }
                Command::Response(generation, uri, headers, reply) => {
                    let result = self
                        .check_access(generation)
                        .map(|active| active.authorizer.process_response(&uri, &headers));
                    let _ = reply.send(result);
                }
                Command::Shutdown(reply) => {
                    self.engine.active = None;
                    let _ = reply.send(Ok(()));
                    break;
                }
            }
        }
    }

    fn check_access(&self, generation: u64) -> Result<&Active<S>, SessionError> {
        self.shared.check(generation)?;
        if self.shared.snapshot.get().phase != SessionPhase::Ready {
            return Err(SessionError::InvalidState);
        }
        self.engine
            .active
            .as_ref()
            .ok_or(SessionError::InvalidState)
    }

    async fn headers(
        &self,
        generation: u64,
        method: &Method,
        uri: &Uri,
    ) -> Result<HeaderMap, SessionError> {
        let active = self.check_access(generation)?;
        let result = active.authorizer.get_headers(method, uri).await;
        let bound = self
            .engine
            .grant
            .dpop()
            .get_current_thumbprint()
            .await
            .is_some();
        let binding_mismatch = result
            .as_ref()
            .is_ok_and(|headers| headers.contains_key("dpop") != bound);
        if self.shared.snapshot.get().phase != SessionPhase::Closed {
            self.shared
                .publish(self.shared.snapshot.get().phase, active.store.persistence());
        }
        self.shared.check(generation)?;
        let phase = if binding_mismatch
            || result
                .as_ref()
                .is_err_and(|error| matches!(error.recovery(), Recovery::Reauthenticate))
        {
            SessionPhase::ReauthenticationRequired
        } else {
            SessionPhase::Ready
        };
        self.shared.publish(phase, active.store.persistence());
        if binding_mismatch {
            return Err(SessionError::BindingMismatch);
        }
        result.map_err(|source| SessionError::Authorization { source })
    }

    async fn login(
        &mut self,
        generation: u64,
        window: &PresentationAnchor,
        input: StartInput,
        options: SignInOptions,
        cancel: oneshot::Receiver<()>,
        reply: &mut Reply<SignInOutcome>,
    ) -> Result<SignInOutcome, SessionError> {
        let grant = self.engine.grant.clone();
        let flow = async move {
            let started = grant.start(input).await?;
            let browser = WebAuthenticationSession::start()
                .authorization_url(&started.authorization_url.to_string())
                .redirect_uri(&started.pending_state.redirect_uri)
                .window(window)
                .prefers_ephemeral(options.prefers_ephemeral)
                .call()
                .map_err(|source| SessionError::Browser { source })?;
            let callback = browser
                .await
                .map_err(|source| SessionError::Browser { source })?;
            let completion = CompleteInput::builder_from_callback(&callback)
                .map_err(|source| SessionError::Callback { source })?
                .maybe_resource(options.completion_resource)
                .build();
            grant
                .complete(&started.pending_state, completion)
                .await
                .map_err(SessionError::from)
        };
        self.login_flow(generation, flow, cancel, reply).await
    }

    async fn login_flow(
        &mut self,
        generation: u64,
        flow: impl Future<Output = Result<CompleteOutput, SessionError>>,
        cancel: oneshot::Receiver<()>,
        reply: &mut Reply<SignInOutcome>,
    ) -> Result<SignInOutcome, SessionError> {
        self.shared.check(generation)?;
        let previous = self.shared.snapshot.get();
        // Network/browser work is cancellable. Persistence is deliberately not.
        let cancelled = async {
            futures_util::future::select(cancel, reply.cancellation()).await;
        };
        let result = match futures_util::future::select(Box::pin(cancelled), Box::pin(flow)).await {
            Either::Right((result, _)) => result,
            Either::Left(_) => Err(SessionError::Cancelled),
        };
        let mut primed = false;
        let result = match result {
            Ok(completed) => {
                let expected = self.engine.grant.dpop().get_current_thumbprint().await;
                let token = &completed.token_response;
                if token.access_token().dpop_jkt() != expected.as_deref()
                    || token
                        .refresh_token()
                        .is_some_and(|refresh| refresh.dpop_jkt() != expected.as_deref())
                {
                    Err(SessionError::BindingMismatch)
                } else if self.shared.check(generation).is_err()
                    || reply.is_canceled()
                    || self.shared.cancel.borrow().is_none()
                {
                    Err(SessionError::Cancelled)
                } else {
                    primed = true;
                    // The driver retains ownership until the write finishes.
                    self.engine.prime(completed).await
                }
            }
            Err(error) => Err(error),
        };
        let cancelled = self.shared.check(generation).is_err()
            || reply.is_canceled()
            || self.shared.cancel.borrow().is_none();
        if result.is_ok() && !cancelled {
            if let Some(active) = &self.engine.active {
                self.shared
                    .publish(SessionPhase::Ready, active.store.persistence());
            }
        } else {
            // A failed/cancelled prime can have written credentials. Remove them
            // before allowing another login; preserve explicit cleanup failures.
            if primed {
                self.engine.active = None;
                if let Err(error) = self.engine.disk.clear().await {
                    self.engine.cleanup_pending = true;
                    if self.shared.check(generation).is_ok() {
                        self.shared.publish(
                            SessionPhase::CleanupRequired,
                            PersistenceState::UnsavedChanges,
                        );
                    }
                    return Err(error.into());
                }
                if self.shared.snapshot.get().phase != SessionPhase::Closed {
                    self.shared
                        .publish(self.shared.snapshot.get().phase, PersistenceState::Absent);
                }
            }
            if self.shared.check(generation).is_ok() {
                let phase = if self.engine.active.is_some() {
                    SessionPhase::ReauthenticationRequired
                } else {
                    SessionPhase::SignedOut
                };
                self.shared.publish(
                    phase,
                    if primed {
                        PersistenceState::Absent
                    } else {
                        previous.persistence
                    },
                );
            }
        }
        if self.shared.check(generation).is_ok() {
            self.shared.cancel.borrow_mut().take();
        }
        if cancelled {
            Err(SessionError::Cancelled)
        } else {
            result
        }
    }
}

#[cfg(test)]
mod tests;
