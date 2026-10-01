//! Objective-C ownership and main-thread presentation boundary.
#![allow(unsafe_code)]

use std::sync::{Arc, Mutex, PoisonError, Weak};

use block2::RcBlock;
use futures_channel::oneshot;
use objc2::{
    AllocAnyThread as _, DefinedClass as _, MainThreadOnly as _, Message as _, define_class,
    msg_send,
    rc::Retained,
    runtime::{NSObject, NSObjectProtocol, ProtocolObject},
};
use objc2_authentication_services::{
    ASWebAuthenticationPresentationContextProviding, ASWebAuthenticationSession,
    ASWebAuthenticationSessionCallback, ASWebAuthenticationSessionErrorCode,
    ASWebAuthenticationSessionErrorDomain,
};
use objc2_foundation::{NSError, NSString, NSURL};

use super::{PresentationAnchor, SessionUrls, WebAuthenticationError, validate_callback};
use crate::PlatformError;

type Response = Result<String, WebAuthenticationError>;
type Sender = oneshot::Sender<Response>;

#[derive(Default)]
struct Completion(Mutex<Option<Sender>>);

impl Completion {
    fn finish(&self, result: Response) {
        let sender = self.0.lock().unwrap_or_else(PoisonError::into_inner).take();
        // Release the lock before waking an executor or calling native code.
        if let Some(sender) = sender {
            let _ = sender.send(result);
        }
    }
}

define_class!(
    // SAFETY: NSObject has no subclassing requirements. The retained window
    // and all provider methods are confined to the main thread.
    #[unsafe(super(NSObject))]
    #[name = "HuskarlWebAuthenticationPresentationProvider"]
    #[thread_kind = objc2::MainThreadOnly]
    #[ivars = Retained<PresentationAnchor>]
    struct PresentationProvider;

    unsafe impl NSObjectProtocol for PresentationProvider {}
    unsafe impl ASWebAuthenticationPresentationContextProviding for PresentationProvider {
        // Implement inside the protocol block so objc2 registers the required
        // selector before checking conformance, including on iOS.
        #[unsafe(method_id(presentationAnchorForWebAuthenticationSession:))]
        fn anchor(&self, _session: &ASWebAuthenticationSession) -> Retained<NSObject> {
            #[cfg(target_os = "macos")]
            { self.ivars().clone().into_super().into_super() }
            #[cfg(target_os = "ios")]
            { self.ivars().clone().into_super().into_super().into_super() }
        }
    }
);

pub(super) struct Session {
    browser: Retained<ASWebAuthenticationSession>,
    // Apple holds its presentation provider weakly.
    provider: Retained<PresentationProvider>,
    completion: Weak<Completion>,
}

impl Session {
    pub(super) fn start(
        urls: &SessionUrls,
        window: &PresentationAnchor,
        ephemeral: bool,
        sender: Sender,
    ) -> Result<Self, WebAuthenticationError> {
        let mtm = window.mtm();
        let provider = PresentationProvider::alloc(mtm).set_ivars(window.retain());
        // SAFETY: Initializes our NSObject subclass after installing its ivars.
        let provider: Retained<PresentationProvider> = unsafe { msg_send![super(provider), init] };
        let completion = Arc::new(Completion(Mutex::new(Some(sender))));
        let captured = completion.clone();
        let expected = urls.redirect.clone();
        let handler = RcBlock::new(move |url: *mut NSURL, error: *mut NSError| {
            // SAFETY: Apple supplies nullable objects valid for this callback.
            let result =
                unsafe { callback_result(url.as_ref(), error.as_ref()) }.and_then(|callback| {
                    validate_callback(&expected, &callback)?;
                    Ok(callback)
                });
            captured.finish(result);
        });
        let url = NSURL::URLWithString(&NSString::from_str(urls.authorization.as_str()))
            .ok_or(WebAuthenticationError::InvalidAuthorizationUrl)?;
        let scheme = NSString::from_str(urls.redirect.scheme());
        // SAFETY: On the main thread, using live objects and a heap block that
        // the initializer copies. New APIs are protected by an availability check.
        let session = unsafe {
            if objc2::available!(macos = 14.4, ios = 17.4, ..) {
                let callback = if urls.redirect.scheme() == "https" {
                    let host = urls
                        .redirect
                        .host_str()
                        .ok_or(WebAuthenticationError::InvalidRedirectUrl)?;
                    ASWebAuthenticationSessionCallback::callbackWithHTTPSHost_path(
                        &NSString::from_str(host),
                        &NSString::from_str(urls.redirect.path()),
                    )
                } else {
                    ASWebAuthenticationSessionCallback::callbackWithCustomScheme(&scheme)
                };
                ASWebAuthenticationSession::initWithURL_callback_completionHandler(
                    ASWebAuthenticationSession::alloc(),
                    &url,
                    &callback,
                    RcBlock::as_ptr(&handler),
                )
            } else {
                if urls.redirect.scheme() == "https" {
                    return Err(WebAuthenticationError::HttpsCallbackUnavailable);
                }
                #[allow(deprecated)]
                ASWebAuthenticationSession::initWithURL_callbackURLScheme_completionHandler(
                    ASWebAuthenticationSession::alloc(),
                    &url,
                    Some(&scheme),
                    RcBlock::as_ptr(&handler),
                )
            }
        };
        let native = Self {
            browser: session,
            provider,
            completion: Arc::downgrade(&completion),
        };
        // SAFETY: Main-thread presentation; the provider is retained by `native`.
        unsafe {
            native
                .browser
                .setPresentationContextProvider(Some(ProtocolObject::from_ref(&*native.provider)));
            native
                .browser
                .setPrefersEphemeralWebBrowserSession(ephemeral);
            if !native.browser.start() {
                native.cancel();
                return Err(WebAuthenticationError::StartFailed);
            }
        }
        Ok(native)
    }

    pub(super) fn cancel(&self) {
        if let Some(completion) = self.completion.upgrade() {
            completion.finish(Err(WebAuthenticationError::Cancelled));
        }
        // SAFETY: Session is confined to the main thread, including destruction.
        unsafe { self.browser.cancel() };
    }
}

fn callback_result(url: Option<&NSURL>, error: Option<&NSError>) -> Response {
    if let Some(error) = error {
        // SAFETY: Framework constant is available on all supported OS versions.
        if *error.domain() == *unsafe { ASWebAuthenticationSessionErrorDomain }
            && error.code() == ASWebAuthenticationSessionErrorCode::CanceledLogin.0
        {
            return Err(WebAuthenticationError::Cancelled);
        }
        return Err(WebAuthenticationError::Platform {
            source: PlatformError {
                domain: error.domain().to_string(),
                code: error.code(),
                message: error.localizedDescription().to_string(),
            },
        });
    }
    url.and_then(NSURL::absoluteString)
        .map(|url| url.to_string())
        .ok_or(WebAuthenticationError::MissingCallback)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presentation_provider_registers_required_protocol_method() {
        use objc2::{ClassType as _, sel};
        assert!(
            PresentationProvider::class()
                .instance_method(sel!(presentationAnchorForWebAuthenticationSession:))
                .is_some()
        );
    }

    #[test]
    fn cancellation_does_not_replace_an_arrived_callback() {
        let (sender, mut receiver) = oneshot::channel();
        let completion = Completion(Mutex::new(Some(sender)));
        completion.finish(Ok("app:/callback?code=secret".into()));
        completion.finish(Err(WebAuthenticationError::Cancelled));
        assert!(matches!(receiver.try_recv(), Ok(Some(Ok(_)))));
    }

    #[test]
    fn missing_callback_and_native_errors_are_distinct() {
        assert!(matches!(
            callback_result(None, None),
            Err(WebAuthenticationError::MissingCallback)
        ));
        // SAFETY: Read-only framework constant.
        let domain = unsafe { ASWebAuthenticationSessionErrorDomain };
        let cancelled = unsafe { NSError::errorWithDomain_code_userInfo(domain, 1, None) };
        assert!(matches!(
            callback_result(None, Some(&cancelled)),
            Err(WebAuthenticationError::Cancelled)
        ));
        let presentation = unsafe { NSError::errorWithDomain_code_userInfo(domain, 3, None) };
        assert!(matches!(
            callback_result(None, Some(&presentation)),
            Err(WebAuthenticationError::Platform { .. })
        ));
        let unrelated = unsafe {
            NSError::errorWithDomain_code_userInfo(&NSString::from_str("other"), 1, None)
        };
        assert!(matches!(
            callback_result(None, Some(&unrelated)),
            Err(WebAuthenticationError::Platform { .. })
        ));
    }
}
