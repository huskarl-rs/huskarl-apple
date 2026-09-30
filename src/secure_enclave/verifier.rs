use bon::bon;
use huskarl_core::{
    crypto::{
        KeyMatchStrength,
        verifier::{JwsVerifier, KeyMatch, VerifyError},
    },
    platform::MaybeSendBoxFuture,
};
use p256::ecdsa::{Signature, signature::Verifier as _};
use security_framework::key::SecKey;
use snafu::prelude::*;

use super::{InvalidPublicKeySnafu, PublicKeyExtractionSnafu, SetupError};

/// A public-only ES256 verifier. Verification requires no Keychain access.
#[derive(Debug, Clone)]
pub struct VerifyingKey {
    key: p256::ecdsa::VerifyingKey,
    key_id: Option<String>,
}

#[bon]
impl VerifyingKey {
    /// Import a SEC1-encoded P-256 public key.
    ///
    /// # Errors
    /// Returns an error if the bytes are not a valid P-256 public key.
    #[builder]
    pub fn new(
        sec1_bytes: &[u8],
        #[builder(into)] key_id: Option<String>,
    ) -> Result<Self, SetupError> {
        let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(sec1_bytes)
            .context(InvalidPublicKeySnafu)?;
        Ok(Self { key, key_id })
    }

    pub(super) fn from_key(key: &SecKey, key_id: Option<String>) -> Result<Self, SetupError> {
        let public = key.public_key().context(PublicKeyExtractionSnafu)?;
        let bytes = public
            .external_representation()
            .context(PublicKeyExtractionSnafu)?;
        Self::builder()
            .sec1_bytes(&bytes)
            .maybe_key_id(key_id)
            .build()
    }
}

impl JwsVerifier for VerifyingKey {
    fn key_match(&self, criteria: &KeyMatch<'_>) -> Option<KeyMatchStrength> {
        criteria.strength_for(&["ES256"], self.key_id.as_deref())
    }

    fn verify<'a>(
        &'a self,
        input: &'a [u8],
        signature: &'a [u8],
        criteria: &'a KeyMatch<'a>,
    ) -> MaybeSendBoxFuture<'a, Result<(), VerifyError>> {
        Box::pin(async move {
            if self.key_match(criteria).is_none() {
                return Err(VerifyError::NoMatchingKey);
            }
            let signature = Signature::from_slice(signature).map_err(|source| {
                VerifyError::MalformedSignature {
                    source: Box::new(source),
                }
            })?;
            self.key
                .verify(input, &signature)
                .map_err(|_| VerifyError::SignatureMismatch)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_input_reports_an_import_error() {
        for bytes in [b"".as_slice(), &[4; 65]] {
            assert!(matches!(
                VerifyingKey::builder().sec1_bytes(bytes).build(),
                Err(SetupError::InvalidPublicKey { .. })
            ));
        }
    }
}
