//! The Objective-C session delegate and its `URLSession` bindings.
//!
//! `URLSession` calls the delegate on its own serial operation queue. Per-task
//! state lives in [`Shared`], keyed by task identifier, and each completed
//! task delivers its result through a oneshot channel.
#![allow(unsafe_code)]

use std::{
    collections::HashMap,
    ptr,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

use block2::DynBlock;
use bytes::Bytes;
use core_foundation::{array::CFArray, base::TCFType as _};
use futures_channel::oneshot;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use huskarl_core::http::HttpResponse;
use objc2::{
    AllocAnyThread as _, ClassType as _, DefinedClass as _, define_class, msg_send,
    rc::Retained,
    runtime::{NSObject, NSObjectProtocol, ProtocolObject},
};
use objc2_foundation::{
    NSArray, NSData, NSError, NSHTTPURLResponse, NSString, NSURLAuthenticationChallenge,
    NSURLAuthenticationMethodClientCertificate, NSURLAuthenticationMethodServerTrust,
    NSURLCredential, NSURLCredentialPersistence, NSURLRequest, NSURLResponse, NSURLSession,
    NSURLSessionAuthChallengeDisposition, NSURLSessionConfiguration, NSURLSessionDataDelegate,
    NSURLSessionDataTask, NSURLSessionDelegate, NSURLSessionResponseDisposition, NSURLSessionTask,
    NSURLSessionTaskDelegate,
};
use security_framework::{certificate::SecCertificate, trust::SecTrust};

use super::{ClientIdentity, UrlSessionError};
use crate::PlatformError;

type Completion = oneshot::Sender<Result<HttpResponse, UrlSessionError>>;

/// Configuration and in-flight task state shared by the client and delegate.
#[derive(Debug)]
pub(super) struct Shared {
    tasks: Mutex<HashMap<usize, TaskState>>,
    client_identity: Option<ClientIdentity>,
    trust_anchors: Option<Vec<SecCertificate>>,
}

#[derive(Debug)]
struct TaskState {
    completion: Completion,
    max_response_bytes: usize,
    head: Option<(StatusCode, HeaderMap)>,
    body: Vec<u8>,
    // Set by a delegate callback that cancels the task, so completion reports
    // the cause rather than URLSession's generic cancellation error.
    failure: Option<UrlSessionError>,
}

impl Shared {
    pub(super) fn new(
        client_identity: Option<ClientIdentity>,
        trust_anchors: Option<Vec<SecCertificate>>,
    ) -> Self {
        Self {
            tasks: Mutex::default(),
            client_identity,
            trust_anchors,
        }
    }

    pub(super) fn uses_mtls(&self) -> bool {
        self.client_identity.is_some()
    }

    /// Registers a task before it is resumed, so no callback can miss it.
    pub(super) fn register(
        &self,
        task: &NSURLSessionTask,
        completion: Completion,
        max_response_bytes: usize,
    ) {
        self.tasks().insert(
            task.taskIdentifier(),
            TaskState {
                completion,
                max_response_bytes,
                head: None,
                body: Vec::new(),
                failure: None,
            },
        );
    }

    fn tasks(&self) -> MutexGuard<'_, HashMap<usize, TaskState>> {
        // No code panics while holding the lock, and the map stays consistent
        // even if one did, so recover rather than propagate poisoning.
        self.tasks.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn fail(&self, task: &NSURLSessionTask, failure: UrlSessionError) {
        if let Some(state) = self.tasks().get_mut(&task.taskIdentifier()) {
            state.failure.get_or_insert(failure);
        }
    }

    fn response(
        &self,
        task: &NSURLSessionTask,
        response: &NSURLResponse,
    ) -> NSURLSessionResponseDisposition {
        let mut tasks = self.tasks();
        let Some(state) = tasks.get_mut(&task.taskIdentifier()) else {
            return NSURLSessionResponseDisposition::Cancel;
        };
        // Enforce the size limit on received data. Content-Length can describe
        // a representation without a body, as with HEAD and 304 responses.
        if let Some(head) = response.downcast_ref::<NSHTTPURLResponse>().and_then(head) {
            state.head = Some(head);
            NSURLSessionResponseDisposition::Allow
        } else {
            state.failure = Some(UrlSessionError::MissingResponse);
            NSURLSessionResponseDisposition::Cancel
        }
    }

    fn data(&self, task: &NSURLSessionTask, data: &NSData) {
        let mut tasks = self.tasks();
        let Some(state) = tasks.get_mut(&task.taskIdentifier()) else {
            return;
        };
        if state.failure.is_some() {
            return;
        }
        if state.body.len() + data.length() > state.max_response_bytes {
            state.failure = Some(UrlSessionError::ResponseTooLarge {
                max: state.max_response_bytes,
            });
            state.body = Vec::new();
            drop(tasks);
            task.cancel();
            return;
        }
        // Reserve first so the allocator is not called while the bytes are
        // borrowed, as `NSData::to_vec` does, then copy once.
        state.body.reserve(data.length());
        // SAFETY: URLSession hands the delegate immutable data and does not
        // mutate it during this callback.
        state
            .body
            .extend_from_slice(unsafe { data.as_bytes_unchecked() });
    }

    fn complete(&self, task: &NSURLSessionTask, error: Option<&NSError>) {
        let Some(state) = self.tasks().remove(&task.taskIdentifier()) else {
            return;
        };
        let result = if let Some(failure) = state.failure {
            Err(failure)
        } else if let Some(error) = error {
            Err(UrlSessionError::Transport {
                source: platform_error(error),
            })
        } else if let Some((status, headers)) = state.head {
            Ok(HttpResponse {
                status,
                headers,
                body: Bytes::from(state.body),
            })
        } else {
            Err(UrlSessionError::MissingResponse)
        };
        // A closed channel means the caller stopped waiting.
        let _ = state.completion.send(result);
    }

    fn challenge(
        &self,
        task: &NSURLSessionTask,
        challenge: &NSURLAuthenticationChallenge,
    ) -> (
        NSURLSessionAuthChallengeDisposition,
        Option<Retained<NSURLCredential>>,
    ) {
        let space = challenge.protectionSpace();
        let method = space.authenticationMethod();
        // SAFETY: Foundation initializes these constants before any delegate
        // callback can run.
        let (server_trust, client_certificate) = unsafe {
            (
                NSURLAuthenticationMethodServerTrust,
                NSURLAuthenticationMethodClientCertificate,
            )
        };
        if *method == *server_trust {
            let Some(anchors) = &self.trust_anchors else {
                return (
                    NSURLSessionAuthChallengeDisposition::PerformDefaultHandling,
                    None,
                );
            };
            // SAFETY: `serverTrust` returns a borrowed SecTrustRef, or nil, for
            // a server-trust protection space. objc2-foundation omits it
            // because it uses a Security framework type.
            let raw: *mut objc2_security::SecTrust = unsafe { msg_send![&*space, serverTrust] };
            if raw.is_null() {
                return (
                    NSURLSessionAuthChallengeDisposition::CancelAuthenticationChallenge,
                    None,
                );
            }
            // SAFETY: `raw` is a live SecTrustRef; the get rule retains it.
            let mut trust = unsafe { SecTrust::wrap_under_get_rule(raw.cast()) };
            match evaluate(&mut trust, anchors) {
                Ok(()) => {
                    // SAFETY: `credentialForTrust:` accepts any valid SecTrustRef.
                    let credential: Retained<NSURLCredential> =
                        unsafe { msg_send![NSURLCredential::class(), credentialForTrust: raw] };
                    (
                        NSURLSessionAuthChallengeDisposition::UseCredential,
                        Some(credential),
                    )
                }
                Err(source) => {
                    self.fail(task, UrlSessionError::ServerTrust { source });
                    (
                        NSURLSessionAuthChallengeDisposition::CancelAuthenticationChallenge,
                        None,
                    )
                }
            }
        } else if *method == *client_certificate {
            let Some(identity) = &self.client_identity else {
                return (
                    NSURLSessionAuthChallengeDisposition::PerformDefaultHandling,
                    None,
                );
            };
            let raw = identity
                .identity
                .as_concrete_TypeRef()
                .cast::<objc2_security::SecIdentity>();
            let intermediates = CFArray::from_CFTypes(&identity.intermediates);
            let certificates = if identity.intermediates.is_empty() {
                ptr::null()
            } else {
                intermediates.as_concrete_TypeRef().cast::<NSArray>()
            };
            // SAFETY: `raw` is a SecIdentityRef kept alive by `self`, and
            // CFArray is toll-free bridged to NSArray. The array retains its
            // SecCertificateRefs and lives through this call. An empty chain
            // is passed as nil; NSURLCredential retains a supplied chain.
            let credential: Retained<NSURLCredential> = unsafe {
                msg_send![
                    NSURLCredential::class(),
                    credentialWithIdentity: raw,
                    certificates: certificates,
                    persistence: NSURLCredentialPersistence::None
                ]
            };
            (
                NSURLSessionAuthChallengeDisposition::UseCredential,
                Some(credential),
            )
        } else {
            (
                NSURLSessionAuthChallengeDisposition::PerformDefaultHandling,
                None,
            )
        }
    }
}

define_class!(
    // SAFETY: NSObject has no subclassing requirements, and this class does
    // not implement Drop.
    #[unsafe(super(NSObject))]
    #[name = "HuskarlAppleURLSessionDelegate"]
    #[ivars = Arc<Shared>]
    struct SessionDelegate;

    unsafe impl NSObjectProtocol for SessionDelegate {}

    // Connection-level challenges (server trust and client certificates) go
    // to the task method below because the session-level one is absent.
    unsafe impl NSURLSessionDelegate for SessionDelegate {}

    unsafe impl NSURLSessionTaskDelegate for SessionDelegate {
        #[unsafe(method(URLSession:task:willPerformHTTPRedirection:newRequest:completionHandler:))]
        fn will_redirect(
            &self,
            _session: &NSURLSession,
            _task: &NSURLSessionTask,
            _response: &NSHTTPURLResponse,
            _request: &NSURLRequest,
            completion: &DynBlock<dyn Fn(*mut NSURLRequest)>,
        ) {
            // A nil request delivers the redirect response itself.
            completion.call((ptr::null_mut(),));
        }

        #[unsafe(method(URLSession:task:didReceiveChallenge:completionHandler:))]
        fn did_receive_challenge(
            &self,
            _session: &NSURLSession,
            task: &NSURLSessionTask,
            challenge: &NSURLAuthenticationChallenge,
            completion: &DynBlock<
                dyn Fn(NSURLSessionAuthChallengeDisposition, *mut NSURLCredential),
            >,
        ) {
            let (disposition, credential) = self.ivars().challenge(task, challenge);
            let credential = credential
                .as_ref()
                .map_or(ptr::null_mut(), |c| Retained::as_ptr(c).cast_mut());
            completion.call((disposition, credential));
        }

        #[unsafe(method(URLSession:task:didCompleteWithError:))]
        fn did_complete(
            &self,
            _session: &NSURLSession,
            task: &NSURLSessionTask,
            error: Option<&NSError>,
        ) {
            self.ivars().complete(task, error);
        }
    }

    unsafe impl NSURLSessionDataDelegate for SessionDelegate {
        #[unsafe(method(URLSession:dataTask:didReceiveResponse:completionHandler:))]
        fn did_receive_response(
            &self,
            _session: &NSURLSession,
            task: &NSURLSessionDataTask,
            response: &NSURLResponse,
            completion: &DynBlock<dyn Fn(NSURLSessionResponseDisposition)>,
        ) {
            completion.call((self.ivars().response(task, response),));
        }

        #[unsafe(method(URLSession:dataTask:didReceiveData:))]
        fn did_receive_data(
            &self,
            _session: &NSURLSession,
            task: &NSURLSessionDataTask,
            data: &NSData,
        ) {
            self.ivars().data(task, data);
        }
    }
);

/// Creates a session whose delegate reports into `shared`.
pub(super) fn session(
    configuration: &NSURLSessionConfiguration,
    shared: Arc<Shared>,
) -> Retained<NSURLSession> {
    let delegate = SessionDelegate::alloc().set_ivars(shared);
    // SAFETY: NSObject's `init` is valid for a freshly allocated subclass.
    let delegate: Retained<SessionDelegate> = unsafe { msg_send![super(delegate), init] };
    // SAFETY: the delegate implements the protocol methods it declares, and a
    // nil queue makes URLSession create a serial delegate queue.
    unsafe {
        NSURLSession::sessionWithConfiguration_delegate_delegateQueue(
            configuration,
            Some(ProtocolObject::from_ref(&*delegate)),
            None,
        )
    }
}

fn head(response: &NSHTTPURLResponse) -> Option<(StatusCode, HeaderMap)> {
    let status = StatusCode::from_u16(u16::try_from(response.statusCode()).ok()?).ok()?;
    let (names, values) = response.allHeaderFields().to_vecs();
    let mut headers = HeaderMap::with_capacity(names.len());
    for (name, value) in names.iter().zip(&values) {
        // URLSession already joined repeated fields with ", ". Fields that
        // are not valid HTTP tokens and values are skipped, not fatal.
        let (Some(name), Some(value)) = (
            name.downcast_ref::<NSString>(),
            value.downcast_ref::<NSString>(),
        ) else {
            continue;
        };
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.to_string().as_bytes()),
            HeaderValue::from_str(&value.to_string()),
        ) {
            headers.append(name, value);
        }
    }
    Some((status, headers))
}

fn evaluate(trust: &mut SecTrust, anchors: &[SecCertificate]) -> Result<(), PlatformError> {
    trust
        .set_anchor_certificates(anchors)
        .and_then(|()| trust.set_trust_anchor_certificates_only(true))
        .map_err(|status| PlatformError {
            domain: "NSOSStatusErrorDomain".into(),
            code: status.code() as isize,
            message: status.to_string(),
        })?;
    trust.evaluate_with_error().map_err(PlatformError::from)
}

fn platform_error(error: &NSError) -> PlatformError {
    PlatformError {
        domain: error.domain().to_string(),
        code: error.code(),
        message: error.localizedDescription().to_string(),
    }
}
