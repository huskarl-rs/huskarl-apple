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
///
/// Keychain setup and deletion run on a blocking pool. Dropping their futures
/// does not cancel work already running; it may still create or delete items.
#[derive(Debug, Clone)]
pub struct Es256PrivateKey {
    inner: Arc<Es256PrivateKeyInner>,
}

#[derive(Debug)]
struct Es256PrivateKeyInner {
    key: SecKey,
    application_label: Vec<u8>,
    access_group: Option<String>,
    #[cfg(feature = "local-authentication")]
    authentication_context: Option<crate::authentication::AuthenticationContext>,
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
    #[builder(finish_fn = generate)]
    pub async fn generate_with(
        label: &str,
        #[builder(default)] creation_policy: KeyAccessPolicy,
        #[builder(into)] access_group: Option<String>,
        /// Shared context used for setup and subsequent private-key operations.
        #[cfg(feature = "local-authentication")]
        authentication_context: Option<crate::authentication::AuthenticationContext>,
    ) -> Result<Self, SetupError> {
        let label = label.to_owned();
        blocking::unblock(move || {
            let key = generate_key(
                &label,
                KeyPurpose::Signing,
                creation_policy,
                access_group.as_deref(),
                #[cfg(feature = "local-authentication")]
                authentication_context.as_ref(),
            )?;
            Self::from_key(
                key,
                access_group,
                #[cfg(feature = "local-authentication")]
                authentication_context,
            )
        })
        .await
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
    pub async fn generate(label: &str) -> Result<Self, SetupError> {
        Self::generate_with().label(label).generate().await
    }

    /// Load an existing ES256 key from the Secure Enclave by label.
    /// The persisted access policy is retained; this does not configure or
    /// remove user-presence requirements. Signing may prompt accordingly.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is not found or could not be loaded.
    pub async fn load(label: &str) -> Result<Self, SetupError> {
        Self::load_with().label(label).load().await
    }

    /// Load from an optional entitled access group.
    ///
    /// If omitted, all accessible groups are searched and ambiguous matches
    /// are rejected. This never falls back to a different group when specified.
    ///
    /// # Errors
    /// Returns an error for missing, ambiguous, incorrectly tagged, or inaccessible keys.
    #[builder(finish_fn = load)]
    pub async fn load_with(
        label: &str,
        #[builder(into)] access_group: Option<String>,
        /// Shared context used for setup and subsequent private-key operations.
        #[cfg(feature = "local-authentication")]
        authentication_context: Option<crate::authentication::AuthenticationContext>,
    ) -> Result<Self, SetupError> {
        let label = label.to_owned();
        blocking::unblock(move || {
            let key = load_key(
                &label,
                KeyPurpose::Signing,
                access_group.as_deref(),
                #[cfg(feature = "local-authentication")]
                authentication_context.as_ref(),
            )?;
            Self::from_key(
                key,
                access_group,
                #[cfg(feature = "local-authentication")]
                authentication_context,
            )
        })
        .await
    }

    /// Load an existing key, or generate only after a definite not-found result.
    ///
    /// All cooperating creators must use the same persistent lock file in a
    /// trusted local directory (an app-group container for multiple apps).
    /// The parent directory must exist. Never remove or replace the lock file
    /// while callers may use it. The file contains no key material.
    ///
    /// The blocking worker waits for an exclusive OS lock. The lock is
    /// released when the worker finishes or the process exits. Direct `generate`
    /// calls and external writers do not participate; do not race them against this operation.
    /// Existing keys retain their policy; `creation_policy` applies only to creation.
    ///
    /// # Errors
    /// Returns lock, lookup, validation, generation, or extraction errors.
    /// Authorization failures and malformed results never trigger creation.
    #[builder(finish_fn = load_or_generate)]
    pub async fn load_or_generate(
        label: &str,
        #[builder(into)] access_group: String,
        lock_path: &std::path::Path,
        #[builder(default)] creation_policy: KeyAccessPolicy,
        /// Shared context used for setup and subsequent private-key operations.
        #[cfg(feature = "local-authentication")]
        authentication_context: Option<crate::authentication::AuthenticationContext>,
    ) -> Result<Self, SetupError> {
        let label = label.to_owned();
        let lock_path = lock_path.to_owned();
        blocking::unblock(move || {
            let key = super::provision::load_or_generate(
                &label,
                KeyPurpose::Signing,
                &access_group,
                creation_policy,
                &lock_path,
                #[cfg(feature = "local-authentication")]
                authentication_context.as_ref(),
            )?;
            Self::from_key(
                key,
                Some(access_group),
                #[cfg(feature = "local-authentication")]
                authentication_context,
            )
        })
        .await
    }

    fn from_key(
        key: SecKey,
        access_group: Option<String>,
        #[cfg(feature = "local-authentication")] authentication_context: Option<
            crate::authentication::AuthenticationContext,
        >,
    ) -> Result<Self, SetupError> {
        let application_label = key.application_label().context(PublicKeyExtractionSnafu)?;
        let public = key.public_key().context(PublicKeyExtractionSnafu)?;
        let mut jwk = super::public_key::extract(&public)?;
        jwk.algorithm = Some("ES256".into());
        jwk.key_use = Some(KeyUse::Sign);
        let thumbprint = jwk.thumbprint();

        Ok(Self {
            inner: Arc::new(Es256PrivateKeyInner {
                key,
                application_label,
                access_group,
                #[cfg(feature = "local-authentication")]
                authentication_context,
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

    /// Delete this persisted key, its public half, and associated client certificates.
    /// All clones refer to the same key; this is not local handle cleanup.
    ///
    /// Repeated calls resume cleanup after partial deletion and succeed when
    /// all of these items are already absent.
    ///
    /// # Errors
    /// Returns an error if Keychain deletion fails.
    pub async fn delete_key_and_associated_items(&self) -> Result<(), SetupError> {
        let key = self.clone();
        blocking::unblock(move || {
            super::delete_key(
                &key.inner.application_label,
                key.inner.access_group.as_deref(),
                #[cfg(feature = "local-authentication")]
                key.inner.authentication_context.as_ref(),
            )
        })
        .await
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
                application_label: self.inner.application_label.clone(),
                access_group: self.inner.access_group.clone(),
                #[cfg(feature = "local-authentication")]
                authentication_context: self.inner.authentication_context.clone(),
                jwk,
                thumbprint: self.inner.thumbprint.clone(),
            }),
        }
    }
}

#[cfg(feature = "urlsession")]
#[bon::bon]
impl Es256PrivateKey {
    /// Install an X.509 certificate for this key and return a TLS client identity.
    ///
    /// Stores the certificate in the data protection Keychain, in this key's
    /// access group, and returns the identity the Keychain forms from the
    /// pair. The certificate must certify this key's public key and should
    /// permit client authentication. Pass the result to
    /// [`UrlSessionClient`](crate::urlsession::UrlSessionClient) for mTLS.
    /// Reinstalling the same certificate is harmless. Failed installation
    /// attempts leave previously installed certificates intact.
    /// An existing duplicate must have this library's label for this key;
    /// certificates stored under another label are rejected without modification.
    ///
    /// Installation runs on a blocking pool. Dropping the future does not
    /// cancel an installation already running.
    ///
    /// Certificates remain in the Keychain after this key or the returned
    /// identity is dropped; [`Self::delete_key_and_associated_items`] removes them
    /// with the key. Use
    /// [`ClientIdentity::remove_certificates`](crate::urlsession::ClientIdentity::remove_certificates)
    /// to remove them while keeping the key.
    /// Use [`Self::install_client_identity_with`] when the server needs intermediate
    /// certificates to build the client certificate chain.
    ///
    /// # Errors
    /// Returns an error if the certificate is malformed, does not match this
    /// key, or cannot be stored.
    pub async fn install_client_identity(
        &self,
        certificate_der: &[u8],
    ) -> Result<crate::urlsession::ClientIdentity, crate::urlsession::ClientIdentityError> {
        self.install_client_identity_with()
            .certificate_der(certificate_der)
            .install()
            .await
    }

    /// Install a TLS client identity with optional intermediate certificates.
    ///
    /// Runs on a blocking pool with the same cancellation behavior as
    /// [`Self::install_client_identity`].
    /// The leaf certificate is stored as described by [`Self::install_client_identity`].
    /// Intermediates are held in memory and sent with the identity during TLS
    /// authentication. They are neither installed in the Keychain nor added to
    /// the client's server trust anchors.
    ///
    /// Certificates are parsed before any Keychain write. Supply a chain in
    /// issuer order; this method does not build or validate the chain. The
    /// server decides whether to trust it.
    ///
    /// # Errors
    /// Returns an error if any certificate is malformed, the leaf does not
    /// match this key, or Keychain installation fails. Malformed intermediate
    /// errors include the zero-based index in the supplied list.
    #[builder(finish_fn = install)]
    pub async fn install_client_identity_with(
        &self,
        /// DER-encoded leaf certificate for this key.
        certificate_der: &[u8],
        /// DER-encoded intermediates, starting with the leaf's issuer and
        /// proceeding toward the root. Exclude the leaf and root. Defaults
        /// to an empty chain.
        #[builder(default, into)]
        intermediates: Vec<Vec<u8>>,
    ) -> Result<crate::urlsession::ClientIdentity, crate::urlsession::ClientIdentityError> {
        let key = self.clone();
        let certificate_der = certificate_der.to_owned();
        blocking::unblock(move || {
            crate::urlsession::install_identity(
                &key.inner.key,
                key.inner.access_group.as_deref(),
                &certificate_der,
                intermediates,
            )
        })
        .await
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
        #[cfg(feature = "local-authentication")]
        let authentication_context = self.authentication_context.clone();
        let input = input.to_vec();
        Box::pin(async move {
            blocking::unblock(move || {
                #[cfg(feature = "local-authentication")]
                let _operation = authentication_context
                    .as_ref()
                    .map(crate::authentication::AuthenticationContext::operation);
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
        Es256PrivateKey::from_key(
            SecKey::new(&options).unwrap(),
            None,
            #[cfg(feature = "local-authentication")]
            None,
        )
        .unwrap()
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
