//! Native OAuth browser sessions for Apple applications.
//!
//! Enable `web-authentication` and call [`WebAuthenticationSession::start`] from
//! the application's main thread, supplying its visible window. Await the returned
//! session on a main-thread executor while the application's event loop runs.
//! Dropping a pending session dismisses the browser. This is not a browser launcher
//! for headless tools or a replacement for OAuth state validation and PKCE.
//!
//! See the [browser login guide](crate::_docs::guide::browser_login) for integration.

mod native;

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use bon::bon;
use futures_channel::oneshot;
/// The application's window used to present authentication.
#[cfg(target_os = "macos")]
pub use objc2_app_kit::NSWindow as PresentationAnchor;
/// The application's foreground-scene window used to present authentication.
#[cfg(target_os = "ios")]
pub use objc2_ui_kit::UIWindow as PresentationAnchor;
use snafu::Snafu;
use url::Url;

use crate::PlatformError;

/// Errors presenting authentication or receiving its callback.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum WebAuthenticationError {
    /// The authorization URL must use HTTPS (or HTTP to a loopback IP) without credentials.
    InvalidAuthorizationUrl,
    /// The redirect must be a custom-scheme or HTTPS URL without credentials,
    /// a query, or a fragment. HTTPS redirects must use the default port.
    InvalidRedirectUrl,
    /// HTTPS callbacks require macOS 14.4+ or iOS 17.4+.
    HttpsCallbackUnavailable,
    /// Apple declined to start the session, for example because presentation
    /// is unavailable. Start a fresh session from a foreground window.
    StartFailed,
    /// The user or caller cancelled authentication.
    Cancelled,
    /// Apple reported a presentation or authentication-session error.
    Platform {
        /// The framework error, preserved for diagnosis.
        source: PlatformError,
    },
    /// Apple completed the session without a URL or an error.
    MissingCallback,
    /// The callback did not match the configured redirect's scheme, host,
    /// port, and path, or contained a fragment or credentials.
    CallbackMismatch,
    /// The native completion handler was released without delivering a result.
    CompletionLost,
}

/// An in-flight authentication browser session and its callback future.
///
/// The session retains its presentation window. It is deliberately not `Send`:
/// creation, polling, cancellation, and destruction stay on the main thread.
/// Keep the application's UI event loop running; do not use a blocking executor.
/// Dropping the future before completion cancels the native session.
#[must_use = "await the session; dropping it cancels authentication"]
pub struct WebAuthenticationSession {
    native: native::Session,
    receiver: oneshot::Receiver<Result<String, WebAuthenticationError>>,
    finished: bool,
}

impl std::fmt::Debug for WebAuthenticationSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Do not include authorization URLs, callback codes, or state.
        f.debug_struct("WebAuthenticationSession")
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

#[bon]
impl WebAuthenticationSession {
    /// Presents an OAuth authorization URL in Apple's authentication browser.
    ///
    /// `redirect_uri` must equal the redirect URI supplied to the authorization
    /// code flow. Custom schemes work on macOS 10.15+ and iOS 13+; HTTPS callbacks
    /// require macOS 14.4+ or iOS 17.4+ and a configured associated web credentials
    /// domain. Redirects with fixed query parameters are not supported.
    ///
    /// `prefers_ephemeral` asks the browser not to share its normal cookies;
    /// it defaults to false, allowing existing browser sign-in to be reused.
    ///
    /// # Errors
    /// Returns an error for invalid URLs, unavailable HTTPS callback support,
    /// or a session that cannot start. User cancellation and callback failures
    /// are returned when awaiting the session.
    #[builder]
    pub fn start(
        authorization_url: &str,
        redirect_uri: &str,
        window: &PresentationAnchor,
        #[builder(default)] prefers_ephemeral: bool,
    ) -> Result<Self, WebAuthenticationError> {
        let urls = SessionUrls::new(authorization_url, redirect_uri)?;
        let (sender, receiver) = oneshot::channel();
        let native = native::Session::start(&urls, window, prefers_ephemeral, sender)?;
        Ok(Self {
            native,
            receiver,
            finished: false,
        })
    }

    /// Dismisses the browser and resolves a pending session as cancelled.
    /// Does not overwrite a callback that has already arrived.
    pub fn cancel(&mut self) {
        if !self.finished {
            self.native.cancel();
        }
    }
}

impl Future for WebAuthenticationSession {
    type Output = Result<String, WebAuthenticationError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match Pin::new(&mut this.receiver).poll(cx) {
            Poll::Ready(result) => {
                this.finished = true;
                Poll::Ready(result.unwrap_or(Err(WebAuthenticationError::CompletionLost)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for WebAuthenticationSession {
    fn drop(&mut self) {
        if !self.finished {
            self.native.cancel();
        }
    }
}

struct SessionUrls {
    authorization: Url,
    redirect: Url,
}

impl SessionUrls {
    fn new(authorization: &str, redirect: &str) -> Result<Self, WebAuthenticationError> {
        let authorization = Url::parse(authorization)
            .map_err(|_| WebAuthenticationError::InvalidAuthorizationUrl)?;
        let loopback_http = authorization.scheme() == "http"
            && authorization.host_str().is_some_and(|host| {
                host.trim_start_matches('[')
                    .trim_end_matches(']')
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
            });
        if (authorization.scheme() != "https" && !loopback_http)
            || authorization.host_str().is_none()
            || has_credentials(&authorization)
            || authorization.fragment().is_some()
        {
            return Err(WebAuthenticationError::InvalidAuthorizationUrl);
        }
        let redirect =
            Url::parse(redirect).map_err(|_| WebAuthenticationError::InvalidRedirectUrl)?;
        if redirect.cannot_be_a_base()
            || has_credentials(&redirect)
            || redirect.query().is_some()
            || redirect.fragment().is_some()
            || matches!(redirect.scheme(), "http" | "file" | "ftp" | "ws" | "wss")
            || (redirect.scheme() == "https"
                && (redirect.host_str().is_none() || redirect.port().is_some()))
        {
            return Err(WebAuthenticationError::InvalidRedirectUrl);
        }
        Ok(Self {
            authorization,
            redirect,
        })
    }
}

fn has_credentials(url: &Url) -> bool {
    !url.username().is_empty() || url.password().is_some()
}

fn validate_callback(expected: &Url, callback: &str) -> Result<(), WebAuthenticationError> {
    let mut actual = Url::parse(callback).map_err(|_| WebAuthenticationError::CallbackMismatch)?;
    if has_credentials(&actual) || actual.fragment().is_some() {
        return Err(WebAuthenticationError::CallbackMismatch);
    }
    actual.set_query(None);
    if actual != *expected {
        return Err(WebAuthenticationError::CallbackMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
