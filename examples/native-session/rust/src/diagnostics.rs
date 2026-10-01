//! Diagnostics omit request bodies, headers, callback URLs, and provider payloads.
use std::{
    error::Error as StdError,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use bytes::Bytes;
use http::Request;
use huskarl_apple::{PlatformError, SetupError, keychain::SecretError};
use huskarl_core::{
    Error, RetryAdvice,
    http::{HttpClient, HttpResponse, Idempotency},
    platform::MaybeSendBoxFuture,
};

pub fn milestone(message: &str) {
    eprintln!("NATIVE_SESSION {message}");
}

pub fn failure(operation: &str, error: &(dyn StdError + 'static), recovery: &str) -> String {
    let mut chain = Vec::new();
    let mut current = Some(error);
    while let Some(cause) = current {
        chain.push(cause);
        current = cause.source();
    }
    // A provider's error description and a parser's input excerpt can contain
    // credentials. Use the OAuth verdict or parser location instead.
    let verdict = chain
        .iter()
        .find_map(|cause| cause.downcast_ref::<Error>().and_then(Error::verdict));
    let json = chain
        .iter()
        .find_map(|cause| cause.downcast_ref::<serde_json::Error>());
    let mut detail = if let Some(verdict) = verdict {
        format!("OAuth provider returned {}", verdict.code())
    } else if let Some(json) = json {
        format!(
            "JSON {:?} error at line {}, column {}",
            json.classify(),
            json.line(),
            json.column()
        )
    } else {
        let mut parts = Vec::new();
        for cause in &chain {
            // Core Error repeats its cause's Display; preserve each cause once.
            if cause.downcast_ref::<Error>().is_some() {
                continue;
            }
            let message = if let Some(platform) = cause.downcast_ref::<PlatformError>() {
                format!("{} ({})", platform.domain, platform.code)
            } else {
                cause.to_string()
            };
            if parts.last() != Some(&message) {
                parts.push(message);
            }
        }
        parts.join(" → ")
    };
    if let Some(core) = chain.iter().find_map(|cause| cause.downcast_ref::<Error>()) {
        match core.retry_advice() {
            RetryAdvice::Retry { after: Some(delay) } => {
                detail.push_str(&format!(" (retry after {delay:?})"))
            }
            RetryAdvice::Retry { after: None } => detail.push_str(" (may succeed after recovery)"),
            _ => {}
        }
    }
    let hint = chain
        .iter()
        .find_map(|cause| {
            if let Some(platform) = cause.downcast_ref::<PlatformError>() {
                return platform_hint(&platform.domain, platform.code);
            }
            let code = if let Some(secret) = cause.downcast_ref::<SecretError>() {
                match secret {
                    SecretError::Access { source }
                    | SecretError::Write { source }
                    | SecretError::Delete { source }
                    | SecretError::AccessControl { source }
                    | SecretError::OpenKeychain { source } => Some(source.code()),
                    _ => None,
                }
            } else if let Some(setup) = cause.downcast_ref::<SetupError>() {
                match setup {
                    SetupError::AccessControl { source }
                    | SetupError::KeychainSearch { source }
                    | SetupError::KeyDeletion { source } => Some(source.code()),
                    _ => None,
                }
            } else {
                None
            };
            code.and_then(|code| platform_hint("NSOSStatusErrorDomain", code as isize))
        })
        .unwrap_or(recovery);
    let message =
        format!("{operation} failed.\nCause: {detail}\nRecovery: {hint}").replace('\0', "�");
    milestone(&message);
    message
}

fn platform_hint(domain: &str, code: isize) -> Option<&'static str> {
    match (domain, code) {
        ("NSOSStatusErrorDomain", -34018) => Some(
            "Check the signed app's keychain-access-groups entitlement against its embedded provisioning profile. Rebuild and run the signed bundle.",
        ),
        ("NSOSStatusErrorDomain", -25308) => Some(
            "Unlock the device and retry from the foreground app; authentication interaction is currently unavailable. Saved credentials were preserved.",
        ),
        ("NSOSStatusErrorDomain", -128) => {
            Some("Authentication was cancelled. Retry the operation when ready.")
        }
        ("NSOSStatusErrorDomain", -25293) => {
            Some("Authentication was denied. Retry and authorize the requested Keychain operation.")
        }
        ("NSURLErrorDomain", -1200 | -1202 | -1203) => Some(
            "TLS trust failed. Check the server certificate and, when using Proxyman, its certificate trust configuration. Retry after fixing trust.",
        ),
        ("NSURLErrorDomain", -1009) => {
            Some("The network is offline. Reconnect and retry; saved credentials were preserved.")
        }
        ("NSURLErrorDomain", -1001) => {
            Some("The request timed out. Check provider reachability and retry.")
        }
        _ => None,
    }
}

#[derive(Clone)]
pub struct TracedClient<C> {
    inner: C,
    attempts: Arc<AtomicUsize>,
}

impl<C> TracedClient<C> {
    pub fn new(inner: C) -> Self {
        Self {
            inner,
            attempts: Arc::new(AtomicUsize::new(0)),
        }
    }
    pub fn attempts(&self) -> usize {
        self.attempts.load(Ordering::Relaxed)
    }
}

impl<C: HttpClient> HttpClient for TracedClient<C> {
    fn execute(
        &self,
        request: Request<Bytes>,
        idempotency: Idempotency,
    ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
        Box::pin(async move {
            let attempt = self.attempts.fetch_add(1, Ordering::Relaxed) + 1;
            let origin = url::Url::parse(&request.uri().to_string())
                .ok()
                .map(|url| url.origin().ascii_serialization())
                .unwrap_or_else(|| "invalid origin".into());
            milestone(&format!(
                "HTTP #{attempt} dispatch {} to {origin}",
                request.method()
            ));
            let response = self.inner.execute(request, idempotency).await;
            match &response {
                Ok(response) => {
                    milestone(&format!("HTTP #{attempt} completed: {}", response.status))
                }
                Err(error) => {
                    failure(
                        &format!("HTTP #{attempt} transport"),
                        error,
                        "Check the reported transport cause and retry after resolving it.",
                    );
                }
            }
            response
        })
    }
    fn uses_mtls(&self) -> bool {
        self.inner.uses_mtls()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_underlying_cause_and_recovery() {
        let error = Error::new(RetryAdvice::No, std::io::Error::other("specific cause"));
        let message = failure("Start OAuth", &error, "Fix configuration.");
        assert!(message.contains("specific cause"));
        assert!(message.contains("Fix configuration."));
    }

    #[test]
    fn apple_status_selects_actionable_recovery() {
        let error = PlatformError {
            domain: "NSOSStatusErrorDomain".into(),
            code: -34018,
            message: "framework error".into(),
        };
        let message = failure("Sign proof", &error, "Fallback.");
        assert!(message.contains("-34018"));
        assert!(message.contains("keychain-access-groups"));
    }

    #[test]
    fn provider_descriptions_are_not_exposed() {
        let error = huskarl_core::http::FailedResponse::new(
            http::StatusCode::BAD_REQUEST,
            &http::HeaderMap::new(),
        )
        .unwrap()
        .into_error(
            Some(
                huskarl_core::OAuthError::new("invalid_client")
                    .with_description(Some("sensitive-payload".into())),
            ),
            std::io::Error::other("rejected"),
        );
        let message = failure("Start OAuth", &error, "Check client registration.");
        assert!(message.contains("invalid_client"));
        assert!(!message.contains("sensitive-payload"));
    }
}
