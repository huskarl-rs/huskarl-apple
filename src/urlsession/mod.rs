//! An [`HttpClient`] backed by Apple's `URLSession`.
//!
//! [`UrlSessionClient`] sends requests through the operating system's HTTP
//! stack, so it follows system proxy, VPN, and network-path policy. TLS client
//! authentication uses a Keychain [`ClientIdentity`], whose private key may be
//! a non-exportable Secure Enclave key; see
//! [`Es256PrivateKey::install_client_identity`](crate::Es256PrivateKey::install_client_identity).
//!
//! The session is ephemeral: it has no URL cache, cookie storage, or
//! credential storage, and it never follows redirects. Response bodies are
//! limited to 1 MiB by default, checked as data arrives. A `Content-Length`
//! header on a bodyless response does not count toward this limit.
//!
//! Enable the `urlsession` Cargo feature to use this module. To authenticate
//! with a Secure Enclave key, obtain a DER-encoded X.509 certificate for its
//! public key from your certificate authority, then build a client:
//!
//! ```no_run
//! use huskarl_apple::{Es256PrivateKey, urlsession::UrlSessionClient};
//!
//! # async fn example(key: &Es256PrivateKey, certificate_der: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
//! let identity = key.install_client_identity(certificate_der).await?;
//! let client = UrlSessionClient::builder()
//!     .client_identity(identity)
//!     .build()?;
//! # Ok(())
//! # }
//! ```
//!
//! If the certificate was issued by an intermediate CA, use
//! [`install_client_identity_with`](crate::Es256PrivateKey::install_client_identity_with) to
//! supply the chain:
//!
//! ```no_run
//! # use huskarl_apple::Es256PrivateKey;
//! # async fn example(key: &Es256PrivateKey, leaf_der: &[u8], issuing_ca_der: Vec<u8>, parent_ca_der: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
//! let identity = key
//!     .install_client_identity_with()
//!     .certificate_der(leaf_der)
//!     .intermediates([issuing_ca_der, parent_ca_der])
//!     .install().await?;
//! # Ok(())
//! # }
//! ```
//!
//! Order intermediates from the leaf's issuer toward the root, excluding the
//! leaf and root certificates. They are kept in memory and sent during client
//! authentication; they are not stored in the Keychain. All certificates are
//! parsed before installation, but chain construction and automatic downloads
//! are not performed. The server decides whether to trust the supplied chain.
//!
//! The client uses system trust roots unless `trust_anchors` is set. Custom
//! anchors replace those roots; server host names are still verified.
//! These anchors authenticate servers and are separate from the intermediates
//! sent with a client identity.
//! Installing an identity requires Keychain access and persists the certificate.
//! Dropping the client or identity does not delete it; deleting the private
//! key does. Use
//! [`ClientIdentity::remove_certificates`] to remove certificates installed for
//! that key, including older renewals, without deleting the private key.
//! Existing duplicate certificates are reused only under this library's label
//! for the key. A certificate stored under another label is rejected with
//! [`ClientIdentityError::CertificateOwnershipConflict`] and left untouched.

mod delegate;
mod identity;

use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use futures_channel::oneshot;
use http::{Request, header::USER_AGENT};
use huskarl_core::{
    Error, RetryAdvice,
    http::{HttpClient, HttpResponse, Idempotency},
    platform::MaybeSendBoxFuture,
};
pub(crate) use identity::install as install_identity;
pub use identity::{ClientIdentity, ClientIdentityError};
use objc2::rc::Retained;
use objc2_foundation::{
    NSData, NSMutableURLRequest, NSString, NSURL, NSURLErrorCannotConnectToHost,
    NSURLErrorCannotFindHost, NSURLErrorDNSLookupFailed, NSURLErrorNetworkConnectionLost,
    NSURLErrorNotConnectedToInternet, NSURLErrorTimedOut, NSURLRequestCachePolicy, NSURLSession,
    NSURLSessionConfiguration, NSURLSessionDataTask,
};
use security_framework::certificate::SecCertificate;
use snafu::prelude::*;

use crate::PlatformError;

/// Default response-body limit, matching the other huskarl HTTP clients.
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 1024 * 1024;

const DEFAULT_USER_AGENT: &str = concat!("huskarl-apple/", env!("CARGO_PKG_VERSION"));

/// Errors configuring the client or executing a request.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum UrlSessionError {
    /// A configured trust anchor is not a DER-encoded X.509 certificate.
    InvalidTrustAnchor,
    /// The request cannot be represented as an `NSURLRequest`.
    #[snafu(display("invalid request: {reason}"))]
    InvalidRequest {
        /// Why the request was rejected.
        reason: &'static str,
    },
    /// The response body exceeded the configured limit.
    #[snafu(display("response body exceeds {max} bytes"))]
    ResponseTooLarge {
        /// The configured limit.
        max: usize,
    },
    /// The server certificate did not chain to a configured trust anchor.
    #[snafu(display("server certificate rejected: {source}"))]
    ServerTrust {
        /// The trust evaluation failure.
        source: PlatformError,
    },
    /// `URLSession` reported a transport failure.
    #[snafu(display("URLSession transport failure: {source}"))]
    Transport {
        /// The `NSError` reported by `URLSession`.
        source: PlatformError,
    },
    /// The task completed without an HTTP response.
    MissingResponse,
    /// The session was invalidated before the task completed.
    SessionClosed,
}

/// An [`HttpClient`] that sends requests through `URLSession`.
///
/// Clones share one session. The session is invalidated, cancelling any
/// outstanding tasks, when the last clone is dropped.
#[derive(Debug, Clone)]
pub struct UrlSessionClient {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    session: Retained<NSURLSession>,
    shared: Arc<delegate::Shared>,
    user_agent: Option<String>,
    max_response_bytes: usize,
}

// The session strongly retains its delegate until invalidated, so
// invalidation is also what releases the delegate and its shared state.
impl Drop for Inner {
    fn drop(&mut self) {
        self.session.invalidateAndCancel();
    }
}

#[bon::bon]
impl UrlSessionClient {
    /// Creates a client with its own ephemeral session.
    ///
    /// # Errors
    /// Returns [`UrlSessionError::InvalidTrustAnchor`] if a trust anchor is not
    /// a DER-encoded certificate.
    #[builder]
    pub fn new(
        /// Certificate and private key to present when a server requests TLS
        /// client authentication.
        client_identity: Option<ClientIdentity>,
        /// DER-encoded certificates to trust instead of the system roots.
        ///
        /// When set, server certificates must chain to one of these anchors;
        /// host name validation still applies.
        trust_anchors: Option<Vec<Vec<u8>>>,
        /// Maximum number of response-body bytes to retain. Defaults to 1 MiB.
        /// Checked as data arrives, including when the server omits its length.
        #[builder(default = DEFAULT_MAX_RESPONSE_BYTES)]
        max_response_bytes: usize,
        /// Limit on the whole request, including retries `URLSession` performs
        /// internally. Defaults to 60 seconds.
        #[builder(default = Duration::from_secs(60))]
        timeout: Duration,
        /// Sent when a request has no `User-Agent`. `None` leaves `URLSession`'s default.
        #[builder(required, into, default = Some(DEFAULT_USER_AGENT.to_owned()))]
        user_agent: Option<String>,
    ) -> Result<Self, UrlSessionError> {
        let trust_anchors = trust_anchors
            .map(|anchors| {
                anchors
                    .iter()
                    .map(|der| SecCertificate::from_der(der).ok())
                    .collect::<Option<Vec<_>>>()
                    .context(InvalidTrustAnchorSnafu)
            })
            .transpose()?;

        let configuration = NSURLSessionConfiguration::ephemeralSessionConfiguration();
        configuration.setURLCache(None);
        configuration.setHTTPCookieStorage(None);
        configuration.setHTTPShouldSetCookies(false);
        configuration.setURLCredentialStorage(None);
        configuration.setRequestCachePolicy(NSURLRequestCachePolicy::ReloadIgnoringLocalCacheData);
        configuration.setTimeoutIntervalForResource(timeout.as_secs_f64());

        let shared = Arc::new(delegate::Shared::new(client_identity, trust_anchors));
        let session = delegate::session(&configuration, shared.clone());
        Ok(Self {
            inner: Arc::new(Inner {
                session,
                shared,
                user_agent,
                max_response_bytes,
            }),
        })
    }
}

impl UrlSessionClient {
    fn url_request(
        &self,
        request: Request<Bytes>,
    ) -> Result<Retained<NSMutableURLRequest>, UrlSessionError> {
        let (parts, body) = request.into_parts();
        let url = NSURL::URLWithString(&NSString::from_str(&parts.uri.to_string())).context(
            InvalidRequestSnafu {
                reason: "URI is not a valid URL",
            },
        )?;
        let url_request = NSMutableURLRequest::requestWithURL(&url);
        url_request.setHTTPMethod(&NSString::from_str(parts.method.as_str()));
        for (name, value) in &parts.headers {
            let value = value.to_str().ok().context(InvalidRequestSnafu {
                reason: "header value is not visible ASCII",
            })?;
            url_request.addValue_forHTTPHeaderField(
                &NSString::from_str(value),
                &NSString::from_str(name.as_str()),
            );
        }
        if let Some(user_agent) = &self.inner.user_agent
            && !parts.headers.contains_key(USER_AGENT)
        {
            url_request.setValue_forHTTPHeaderField(
                Some(&NSString::from_str(user_agent)),
                &NSString::from_str(USER_AGENT.as_str()),
            );
        }
        if !body.is_empty() {
            url_request.setHTTPBody(Some(&NSData::with_bytes(&body)));
        }
        Ok(url_request)
    }
}

impl HttpClient for UrlSessionClient {
    fn uses_mtls(&self) -> bool {
        self.inner.shared.uses_mtls()
    }

    fn execute(
        &self,
        request: Request<Bytes>,
        idempotency: Idempotency,
    ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
        Box::pin(async move {
            let (sender, receiver) = oneshot::channel();
            // Scope the request object: it is not Send and must not live
            // across the await below.
            let task = {
                let url_request = self
                    .url_request(request)
                    .map_err(|error| classify(error, idempotency))?;
                self.inner.session.dataTaskWithRequest(&url_request)
            };
            self.inner
                .shared
                .register(&task, sender, self.inner.max_response_bytes);
            let task = CancelOnDrop(task);
            task.0.resume();
            match receiver.await {
                Ok(result) => result.map_err(|error| classify(error, idempotency)),
                Err(oneshot::Canceled) => {
                    Err(classify(UrlSessionError::SessionClosed, idempotency))
                }
            }
        })
    }
}

// Cancels the task if the caller drops the future before completion.
// Cancelling a completed task has no effect.
struct CancelOnDrop(Retained<NSURLSessionDataTask>);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

fn classify(error: UrlSessionError, idempotency: Idempotency) -> Error {
    let advice = match &error {
        UrlSessionError::Transport { source } => transport_advice(source, idempotency),
        _ => RetryAdvice::No,
    };
    Error::new(advice, error)
}

// Mirrors huskarl-reqwest: connection failures never reached the server, so
// they are always safe to retry; a timeout or dropped connection may have been
// processed, so only idempotent requests retry. TLS and trust failures do not.
fn transport_advice(error: &PlatformError, idempotency: Idempotency) -> RetryAdvice {
    if error.domain != "NSURLErrorDomain" {
        return RetryAdvice::No;
    }
    let not_sent = [
        NSURLErrorCannotFindHost,
        NSURLErrorCannotConnectToHost,
        NSURLErrorDNSLookupFailed,
        NSURLErrorNotConnectedToInternet,
    ]
    .contains(&error.code);
    let uncertain = [NSURLErrorTimedOut, NSURLErrorNetworkConnectionLost].contains(&error.code);
    RetryAdvice::retry_if(not_sent || (uncertain && idempotency == Idempotency::Idempotent))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::{
        io::{Read as _, Write as _},
        net::TcpListener,
    };

    use http::StatusCode;

    use super::*;

    /// Serves one canned HTTP/1.1 response on loopback and returns its URL.
    /// Plain HTTP to an IP literal is exempt from App Transport Security.
    fn serve_once(response: Vec<u8>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buffer = [0; 1024];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                let read = stream.read(&mut buffer).unwrap();
                if read == 0 {
                    return;
                }
                request.extend_from_slice(&buffer[..read]);
            }
            // The client may abort mid-body; that is what some tests check.
            let _ = stream.write_all(&response);
        });
        format!("http://{address}/")
    }

    fn get(url: &str) -> Request<Bytes> {
        Request::get(url).body(Bytes::new()).unwrap()
    }

    fn client(max_response_bytes: usize) -> UrlSessionClient {
        UrlSessionClient::builder()
            .max_response_bytes(max_response_bytes)
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn returns_status_headers_and_body() {
        let url = serve_once(
            b"HTTP/1.1 201 Created\r\nContent-Length: 5\r\nDPoP-Nonce: abc\r\n\r\nhello".to_vec(),
        );
        let response = client(DEFAULT_MAX_RESPONSE_BYTES)
            .execute(get(&url), Idempotency::Idempotent)
            .await
            .unwrap();
        assert_eq!(response.status, StatusCode::CREATED);
        assert_eq!(response.headers["dpop-nonce"], "abc");
        assert_eq!(response.body, "hello");
    }

    #[tokio::test]
    async fn does_not_follow_redirects() {
        let url = serve_once(
            b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9/\r\nContent-Length: 0\r\n\r\n"
                .to_vec(),
        );
        let response = client(DEFAULT_MAX_RESPONSE_BYTES)
            .execute(get(&url), Idempotency::Idempotent)
            .await
            .unwrap();
        assert_eq!(response.status, StatusCode::FOUND);
        assert_eq!(response.headers["location"], "http://127.0.0.1:9/");
    }

    #[tokio::test]
    async fn bodyless_responses_allow_large_content_lengths() {
        for (method, status) in [
            (http::Method::HEAD, StatusCode::OK),
            (http::Method::GET, StatusCode::NOT_MODIFIED),
        ] {
            let url = serve_once(
                format!(
                    "HTTP/1.1 {status}\r\nContent-Length: 2000000\r\nConnection: close\r\n\r\n"
                )
                .into_bytes(),
            );
            let request = Request::builder()
                .method(method)
                .uri(url)
                .body(Bytes::new())
                .unwrap();
            let response = client(0)
                .execute(request, Idempotency::Idempotent)
                .await
                .unwrap();
            assert_eq!(response.status, status);
            assert!(response.body.is_empty());
        }
    }

    #[tokio::test]
    async fn rejects_oversized_bodies_with_and_without_content_length() {
        let body = vec![b'x'; 64 * 1024];
        let declared = [
            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes(),
            body.clone(),
        ]
        .concat();
        let streamed = [
            b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_vec(),
            body,
        ]
        .concat();
        for response in [declared, streamed] {
            let url = serve_once(response);
            let error = client(1024)
                .execute(get(&url), Idempotency::Idempotent)
                .await
                .unwrap_err();
            assert!(matches!(error.retry_advice(), RetryAdvice::No));
            assert!(
                error.to_string().contains("exceeds 1024 bytes"),
                "unexpected error: {error}"
            );
        }
    }

    #[tokio::test]
    async fn refused_connections_are_retryable() {
        // Bind then drop to find a port with no listener.
        let address = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let error = client(DEFAULT_MAX_RESPONSE_BYTES)
            .execute(get(&format!("http://{address}/")), Idempotency::Unknown)
            .await
            .unwrap_err();
        assert!(
            matches!(error.retry_advice(), RetryAdvice::Retry { .. }),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn uncertain_delivery_retries_only_when_idempotent() {
        let error = |code| PlatformError {
            domain: "NSURLErrorDomain".into(),
            code,
            message: "test".into(),
        };
        for code in [NSURLErrorTimedOut, NSURLErrorNetworkConnectionLost] {
            assert!(matches!(
                transport_advice(&error(code), Idempotency::Idempotent),
                RetryAdvice::Retry { .. }
            ));
            assert!(matches!(
                transport_advice(&error(code), Idempotency::Unknown),
                RetryAdvice::No
            ));
        }
        // Server trust failure.
        assert!(matches!(
            transport_advice(&error(-1202), Idempotency::Idempotent),
            RetryAdvice::No
        ));
    }

    #[test]
    fn invalid_trust_anchors_are_rejected() {
        assert!(matches!(
            UrlSessionClient::builder()
                .trust_anchors(vec![b"not a certificate".to_vec()])
                .build(),
            Err(UrlSessionError::InvalidTrustAnchor)
        ));
    }
}
