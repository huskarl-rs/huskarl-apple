use std::{borrow::Cow, sync::Arc};

use core_foundation::error::CFError;
use huskarl_core::{
    crypto::signer::{
        AsymmetricJwsSigner, AsymmetricJwsSignerSelector, JwsSigner, JwsSignerSelector,
    },
    jwk::{KeyUse, PublicJwk},
    platform::MaybeSendBoxFuture,
};
use p256::ecdsa::signature;
use security_framework::key::SecKey;
use snafu::prelude::*;

use super::{
    KeyAccessPolicy, KeyPurpose, PublicKeyExtractionSnafu, SetupError, generate_key, load_key,
    verifier::VerifyingKey,
};
use crate::PlatformError;

/// Errors that can occur when signing data.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum SigningError {
    /// Signing operation failed.
    #[snafu(display("Signing operation failed: {source}"))]
    Signing {
        /// The underlying Apple framework error.
        #[snafu(source(from(CFError, PlatformError::from)))]
        source: PlatformError,
    },
    /// Failed to convert ECDSA signature from DER to fixed format.
    SignatureConversion {
        /// The underlying signature conversion error.
        source: signature::Error,
    },
}

impl From<SigningError> for huskarl_core::Error {
    fn from(value: SigningError) -> Self {
        let advice = match &value {
            SigningError::Signing { source } => source.retry_advice(),
            SigningError::SignatureConversion { .. } => huskarl_core::RetryAdvice::No,
        };
        huskarl_core::Error::new(advice, value)
    }
}

/// An ES256 private key backed by the macOS Secure Enclave.
///
/// The private key never leaves the hardware and cannot be extracted.
/// Signing is performed by the Secure Enclave via the Security framework.
#[derive(Debug, Clone)]
pub struct Es256PrivateKey {
    inner: Arc<Es256PrivateKeyInner>,
}

#[derive(Debug)]
struct Es256PrivateKeyInner {
    key: SecKey,
    access_group: Option<String>,
    // `jwk` carries the canonical `kid`, so `key_id()` and the published JWK
    // can't diverge.
    jwk: PublicJwk,
    thumbprint: String,
}

#[bon::bon]
impl Es256PrivateKey {
    /// Generate and persist a key using an explicit access policy.
    ///
    /// Defaults to device-only access while unlocked, without additional
    /// user-presence authentication. Use a unique label for each key version.
    ///
    /// # Errors
    /// Returns an error if policy creation, key generation, or extraction fails.
    #[builder(start_fn = generate_with, finish_fn = generate)]
    pub fn generate_configured(
        label: &str,
        #[builder(default)] access_policy: KeyAccessPolicy,
        #[builder(into)] access_group: Option<String>,
    ) -> Result<Self, SetupError> {
        let key = generate_key(
            label,
            KeyPurpose::Signing,
            access_policy,
            access_group.as_deref(),
        )?;
        Self::from_key(key, access_group)
    }

    /// Generate a new ES256 key in the Secure Enclave.
    ///
    /// The private key never leaves the hardware and cannot be extracted.
    /// Requires code signing with keychain-access-groups entitlement.
    /// See [signing an app](crate::_docs::guide::signing_an_app) for setup instructions.
    ///
    /// # Errors
    ///
    /// Returns an error if the key could not be generated or the public
    /// key could not be extracted.
    pub fn generate(label: &str) -> Result<Self, SetupError> {
        Self::generate_with().label(label).generate()
    }

    /// Load an existing ES256 key from the Secure Enclave by label.
    /// The persisted access policy is retained; this does not configure or
    /// remove user-presence requirements. Signing may prompt accordingly.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is not found or could not be loaded.
    pub fn load(label: &str) -> Result<Self, SetupError> {
        Self::load_with().label(label).load()
    }

    /// Load from an optional entitled access group.
    ///
    /// If omitted, all accessible groups are searched and ambiguous matches
    /// are rejected. This never falls back to a different group when specified.
    ///
    /// # Errors
    /// Returns an error for missing, ambiguous, incorrectly tagged, or inaccessible keys.
    #[builder(start_fn = load_with, finish_fn = load)]
    pub fn load_configured(
        label: &str,
        #[builder(into)] access_group: Option<String>,
    ) -> Result<Self, SetupError> {
        let key = load_key(label, KeyPurpose::Signing, access_group.as_deref())?;
        Self::from_key(key, access_group)
    }

    /// Load an existing key, or generate only after a definite not-found result.
    ///
    /// All cooperating creators must use the same persistent lock file in a
    /// trusted local directory (an app-group container for multiple apps).
    /// The parent directory must exist. Never remove or replace the lock file
    /// while callers may use it. The file contains no key material.
    ///
    /// This synchronous operation waits for an exclusive OS lock. The lock is
    /// released on return or process exit. Direct `generate` calls and external
    /// writers do not participate; do not race them against this operation.
    /// Existing keys retain their policy; `access_policy` applies only to creation.
    ///
    /// # Errors
    /// Returns lock, lookup, validation, generation, or extraction errors.
    /// Authorization failures and malformed results never trigger creation.
    #[builder(finish_fn = call)]
    pub fn load_or_generate(
        label: &str,
        #[builder(into)] access_group: String,
        lock_path: &std::path::Path,
        #[builder(default)] access_policy: KeyAccessPolicy,
    ) -> Result<Self, SetupError> {
        let key = super::provision::load_or_generate(
            label,
            KeyPurpose::Signing,
            &access_group,
            access_policy,
            lock_path,
        )?;
        Self::from_key(key, Some(access_group))
    }

    fn from_key(key: SecKey, access_group: Option<String>) -> Result<Self, SetupError> {
        let public = key.public_key().context(PublicKeyExtractionSnafu)?;
        let mut jwk = super::public_key::extract(&public)?;
        jwk.algorithm = Some("ES256".into());
        jwk.key_use = Some(KeyUse::Sign);
        let thumbprint = jwk.thumbprint();

        Ok(Self {
            inner: Arc::new(Es256PrivateKeyInner {
                key,
                access_group,
                jwk,
                thumbprint,
            }),
        })
    }

    /// Obtain a public-only verifier, independent of subsequent Keychain access.
    ///
    /// # Errors
    /// Returns an error if the public key cannot be extracted.
    pub fn verifier(&self) -> Result<VerifyingKey, SetupError> {
        VerifyingKey::from_key(&self.inner.key, self.inner.jwk.kid.clone())
    }

    /// Delete this exact persisted key. All clones refer to the same key.
    ///
    /// # Errors
    /// Returns an error if Keychain deletion fails.
    pub fn delete(&self) -> Result<(), SetupError> {
        super::delete_key(&self.inner.key, self.inner.access_group.as_deref())
    }

    /// Set the key ID for this key.
    ///
    /// The key ID is used in the JWT `kid` header parameter and carried in
    /// the public JWK.
    #[must_use]
    pub fn with_key_id(self, key_id: impl Into<String>) -> Self {
        let mut jwk = self.inner.jwk.clone();
        jwk.kid = Some(key_id.into());
        Self {
            inner: Arc::new(Es256PrivateKeyInner {
                key: self.inner.key.clone(),
                access_group: self.inner.access_group.clone(),
                jwk,
                thumbprint: self.inner.thumbprint.clone(),
            }),
        }
    }
}

// The signer traits are implemented on the shared inner so the selectors can
// hand out the existing `Arc` (a refcount bump, no allocation).
impl JwsSigner for Es256PrivateKeyInner {
    fn jws_algorithm(&self) -> Cow<'_, str> {
        Cow::Borrowed("ES256")
    }

    fn key_id(&self) -> Option<Cow<'_, str>> {
        self.jwk.kid.as_deref().map(Cow::Borrowed)
    }

    fn sign<'a>(
        &'a self,
        input: &'a [u8],
    ) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, huskarl_core::Error>> {
        let key = self.key.clone();
        let input = input.to_vec();
        Box::pin(async move {
            blocking::unblock(move || {
                let der_signature = key
                    .create_signature(
                        security_framework::key::Algorithm::ECDSASignatureMessageX962SHA256,
                        &input,
                    )
                    .context(SigningSnafu)?;
                let signature = p256::ecdsa::Signature::from_der(&der_signature)
                    .context(SignatureConversionSnafu)?;
                Ok(signature.to_bytes().to_vec())
            })
            .await
        })
    }
}

impl AsymmetricJwsSigner for Es256PrivateKeyInner {
    fn public_key_jwk(&self) -> Cow<'_, PublicJwk> {
        Cow::Borrowed(&self.jwk)
    }
}

impl JwsSigner for Es256PrivateKey {
    fn jws_algorithm(&self) -> Cow<'_, str> {
        self.inner.jws_algorithm()
    }

    fn key_id(&self) -> Option<Cow<'_, str>> {
        self.inner.key_id()
    }

    fn sign<'a>(
        &'a self,
        input: &'a [u8],
    ) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, huskarl_core::Error>> {
        self.inner.sign(input)
    }
}

impl AsymmetricJwsSigner for Es256PrivateKey {
    fn public_key_jwk(&self) -> Cow<'_, PublicJwk> {
        self.inner.public_key_jwk()
    }
}

impl JwsSignerSelector for Es256PrivateKey {
    fn select_signer(&self) -> MaybeSendBoxFuture<'_, Arc<dyn JwsSigner>> {
        let signer: Arc<dyn JwsSigner> = self.inner.clone();
        Box::pin(async move { signer })
    }
}

impl AsymmetricJwsSignerSelector for Es256PrivateKey {
    fn select_asymmetric_signer(&self) -> MaybeSendBoxFuture<'_, Arc<dyn AsymmetricJwsSigner>> {
        let signer: Arc<dyn AsymmetricJwsSigner> = self.inner.clone();
        Box::pin(async move { signer })
    }

    fn select_signer_by_thumbprint<'a>(
        &'a self,
        thumbprint: &'a str,
    ) -> MaybeSendBoxFuture<'a, Option<Arc<dyn AsymmetricJwsSigner>>> {
        let signer: Arc<dyn AsymmetricJwsSigner> = self.inner.clone();
        let matches = self.inner.thumbprint == thumbprint;
        Box::pin(async move { matches.then_some(signer) })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use huskarl_core::crypto::verifier::{JwsVerifier, KeyMatch, VerifyError};
    use security_framework::key::{GenerateKeyOptions, KeyType};

    use super::*;

    fn software_key() -> Es256PrivateKey {
        let mut options = GenerateKeyOptions::default();
        options.set_key_type(KeyType::ec()).set_size_in_bits(256);
        Es256PrivateKey::from_key(SecKey::new(&options).unwrap(), None).unwrap()
    }

    #[tokio::test]
    async fn apple_signatures_verify_as_jws() {
        let key = software_key().with_key_id("version-1");
        let signature = key.sign(b"header.payload").await.unwrap();
        assert_eq!(signature.len(), 64);
        let verifier = key.verifier().unwrap();
        let criteria = KeyMatch::builder().alg("ES256").kid("version-1").build();
        verifier
            .verify(b"header.payload", &signature, &criteria)
            .await
            .unwrap();
        assert!(matches!(
            verifier.verify(b"changed", &signature, &criteria).await,
            Err(VerifyError::SignatureMismatch)
        ));
        assert!(matches!(
            verifier
                .verify(b"header.payload", &signature[..63], &criteria)
                .await,
            Err(VerifyError::MalformedSignature { .. })
        ));
        let wrong_kid = KeyMatch::builder().alg("ES256").kid("version-2").build();
        assert!(matches!(
            verifier
                .verify(b"header.payload", &signature, &wrong_kid)
                .await,
            Err(VerifyError::NoMatchingKey)
        ));
        let wrong_alg = KeyMatch::builder().alg("HS256").build();
        assert!(matches!(
            verifier
                .verify(b"header.payload", &signature, &wrong_alg)
                .await,
            Err(VerifyError::NoMatchingKey)
        ));
        assert!(matches!(
            software_key()
                .verifier()
                .unwrap()
                .verify(b"header.payload", &signature, &criteria)
                .await,
            Err(VerifyError::SignatureMismatch)
        ));
    }

    #[tokio::test]
    async fn key_id_and_selectors_preserve_identity() {
        let original = software_key();
        let thumbprint = original.public_key_jwk().thumbprint();
        let key = original.clone().with_key_id("version-1");
        assert!(original.key_id().is_none());
        assert_eq!(key.public_key_jwk().kid.as_deref(), Some("version-1"));
        assert_eq!(key.public_key_jwk().thumbprint(), thumbprint);
        let selected = key.select_signer_by_thumbprint(&thumbprint).await.unwrap();
        assert_eq!(selected.key_id().as_deref(), Some("version-1"));
        assert!(key.select_signer_by_thumbprint("wrong").await.is_none());
        let a = key.select_signer().await;
        let b = key.select_signer().await;
        assert!(Arc::ptr_eq(&a, &b));
    }
}
