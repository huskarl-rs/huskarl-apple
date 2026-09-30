use core_foundation::error::CFError;
use huskarl_core::RetryAdvice;
use snafu::Snafu;

/// An owned, thread-safe snapshot of an Apple framework error.
///
/// Keeps the domain and numeric code for diagnosis without transferring
/// a Core Foundation error object between threads.
#[derive(Debug, Snafu)]
#[snafu(display("{domain} ({code}): {message}"))]
pub struct PlatformError {
    /// The Apple error domain.
    pub domain: String,
    /// The error code within that domain.
    pub code: isize,
    /// The framework's description of the failure.
    pub message: String,
}

impl PlatformError {
    /// Whether a later attempt may succeed after availability changes.
    ///
    /// `errSecInteractionNotAllowed` is potentially recoverable after unlock
    /// or a change to the authentication context. It does not imply that time
    /// alone will help. Callers should use bounded backoff or wait for an
    /// appropriate lifecycle event rather than continuously retrying.
    #[must_use]
    pub fn retry_advice(&self) -> RetryAdvice {
        if self.domain == "NSOSStatusErrorDomain" {
            i32::try_from(self.code).map_or(RetryAdvice::No, status_retry_advice)
        } else {
            RetryAdvice::No
        }
    }
}

// errSecInteractionNotAllowed, not exported by security-framework-sys.
pub(crate) const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;

pub(crate) fn status_retry_advice(status: i32) -> RetryAdvice {
    // Authentication cancellation, denial, and missing entitlements deliberately
    // remain nonretryable. There is no OS-supplied time until the next unlock.
    RetryAdvice::retry_if(status == ERR_SEC_INTERACTION_NOT_ALLOWED)
}

impl From<CFError> for PlatformError {
    fn from(error: CFError) -> Self {
        Self {
            domain: error.domain().to_string(),
            code: error.code(),
            message: error.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use huskarl_core::{Error, crypto::cipher::DecryptError};

    use super::*;
    use crate::{SetupError, SigningError, keychain::SecretError, secure_enclave::SealingError};

    fn apple_error(domain: &str, code: isize) -> PlatformError {
        PlatformError {
            domain: domain.into(),
            code,
            message: "test status".into(),
        }
    }

    #[test]
    fn unavailable_interaction_survives_all_error_wrappers() {
        let status = security_framework::base::Error::from_code(ERR_SEC_INTERACTION_NOT_ALLOWED);
        let errors: [Error; 10] = [
            SetupError::KeychainSearch { source: status }.into(),
            SetupError::KeyDeletion { source: status }.into(),
            SetupError::AccessControl { source: status }.into(),
            SetupError::KeyGeneration {
                source: apple_error(
                    "NSOSStatusErrorDomain",
                    ERR_SEC_INTERACTION_NOT_ALLOWED as isize,
                ),
            }
            .into(),
            SecretError::Access { source: status }.into(),
            SecretError::AccessControl { source: status }.into(),
            SecretError::Write { source: status }.into(),
            SecretError::Delete { source: status }.into(),
            SigningError::Signing {
                source: apple_error(
                    "NSOSStatusErrorDomain",
                    ERR_SEC_INTERACTION_NOT_ALLOWED as isize,
                ),
            }
            .into(),
            SealingError::Encryption {
                source: apple_error(
                    "NSOSStatusErrorDomain",
                    ERR_SEC_INTERACTION_NOT_ALLOWED as isize,
                ),
            }
            .into(),
        ];
        for error in errors {
            assert!(matches!(
                error.retry_advice(),
                RetryAdvice::Retry { after: None }
            ));
        }
        let decryption = DecryptError::Other {
            source: SealingError::Decryption {
                source: apple_error(
                    "NSOSStatusErrorDomain",
                    ERR_SEC_INTERACTION_NOT_ALLOWED as isize,
                ),
            }
            .into(),
        };
        assert!(matches!(
            decryption.retry_advice(),
            RetryAdvice::Retry { after: None }
        ));
    }

    #[test]
    fn authentication_failures_and_other_domains_do_not_retry() {
        // Cancellation, failed authentication, missing entitlements, missing item.
        for code in [-128, -25293, -34018, -25300] {
            assert!(matches!(status_retry_advice(code), RetryAdvice::No));
            assert!(matches!(
                apple_error("NSOSStatusErrorDomain", code as isize).retry_advice(),
                RetryAdvice::No
            ));
        }
        assert!(matches!(
            apple_error("another.domain", ERR_SEC_INTERACTION_NOT_ALLOWED as isize).retry_advice(),
            RetryAdvice::No
        ));
        assert!(matches!(
            Error::from(SealingError::InvalidPayload).retry_advice(),
            RetryAdvice::No
        ));
        assert!(matches!(
            Error::from(SetupError::KeyPurposeMismatch).retry_advice(),
            RetryAdvice::No
        ));
    }
}
