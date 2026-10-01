use std::sync::Arc;

use core_foundation::error::CFError;
use huskarl_core::{
    crypto::{
        cipher::DecryptError,
        seal::{AeadSealer, AeadUnsealer, SealOutput},
    },
    platform::MaybeSendBoxFuture,
};
use security_framework::key::{Algorithm, SecKey};
use snafu::prelude::*;
use zeroize::Zeroizing;

use super::{
    KeyAccessPolicy, KeyPurpose, PublicKeyExtractionSnafu, SetupError, delete_key, generate_key,
    load_key,
};
use crate::PlatformError;

const ALGORITHM: Algorithm = Algorithm::ECIESEncryptionCofactorX963SHA256AESGCM;
// This prefix is INSIDE the ECIES-authenticated plaintext. Apple's output is
// kept opaque; no assumptions are made about its internal binary layout.
const DOMAIN: &[u8] = b"huskarl-apple/seal/v1\0";

/// Failures sealing or opening an authenticated blob.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum SealingError {
    /// Apple's encryption operation failed.
    #[snafu(display("ECIES encryption failed: {source}"))]
    Encryption {
        /// The underlying Apple error.
        #[snafu(source(from(CFError, PlatformError::from)))]
        source: PlatformError,
    },
    /// Apple's decryption or authentication operation failed.
    #[snafu(display("ECIES decryption failed: {source}"))]
    Decryption {
        /// The underlying Apple error.
        #[snafu(source(from(CFError, PlatformError::from)))]
        source: PlatformError,
    },
    /// The authenticated payload belongs to another format or AAD context.
    #[snafu(display("invalid sealed payload or associated data"))]
    InvalidPayload,
}

impl From<SealingError> for huskarl_core::Error {
    fn from(error: SealingError) -> Self {
        let advice = match &error {
            SealingError::Encryption { source } | SealingError::Decryption { source } => {
                source.retry_advice()
            }
            SealingError::InvalidPayload => huskarl_core::RetryAdvice::No,
        };
        Self::new(advice, error)
    }
}

/// A persisted Secure Enclave P-256 key for ECIES sealing and unsealing.
///
/// Encryption uses the public key; unsealing uses the hardware-protected
/// private key. This is not a JWE content cipher or a hardware AES key.
///
/// Apple returns an opaque ECIES blob and accepts no caller-supplied AAD.
/// We encrypt a domain-separated, versioned payload containing the exact AAD
/// and plaintext. On opening, the payload is authenticated by ECIES and its
/// AAD is checked before any plaintext is returned. The bundle is therefore
/// specific to this adapter, not a raw application-plaintext ECIES message.
///
/// The default key ID is the public JWK thumbprint; persist it beside the blob for key dispatch.
///
/// Keychain setup and deletion run on a blocking pool. Dropping their futures
/// does not cancel work already running; it may still create or delete items.
#[derive(Debug, Clone)]
pub struct SealingKey {
    inner: Arc<SealingKeyInner>,
}

#[derive(Debug)]
struct SealingKeyInner {
    key: SecKey,
    application_label: Vec<u8>,
    access_group: Option<String>,
    #[cfg(feature = "local-authentication")]
    authentication_context: Option<crate::authentication::AuthenticationContext>,
    public: SecKey,
    key_id: String,
}

#[bon::bon]
impl SealingKey {
    /// Generate and persist an enclave encryption key with an access policy.
    ///
    /// Authentication constrains unsealing, not public-key sealing.
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
                KeyPurpose::Sealing,
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

    /// Generate and persist a new enclave key with this label.
    ///
    /// # Errors
    /// Returns an error if hardware generation or public-key extraction fails.
    pub async fn generate(label: &str) -> Result<Self, SetupError> {
        Self::generate_with().label(label).generate().await
    }

    /// Load exactly one hardware-backed key matching this label.
    /// The persisted access policy is retained; unsealing may prompt for
    /// authentication if the key was created with such a requirement.
    ///
    /// # Errors
    /// Returns an error for missing, ambiguous, software, or invalid keys.
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
                KeyPurpose::Sealing,
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
    /// Uses the same [coordination contract](super::Es256PrivateKey::load_or_generate)
    /// as signing keys: supply a persistent lock file shared by all creators in
    /// a trusted local directory. Existing keys retain their policy.
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
                KeyPurpose::Sealing,
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
        let key_id = super::public_key::extract(&public)?.thumbprint();
        Ok(Self {
            inner: Arc::new(SealingKeyInner {
                key,
                application_label,
                access_group,
                #[cfg(feature = "local-authentication")]
                authentication_context,
                public,
                key_id,
            }),
        })
    }

    /// The stable public-key thumbprint used for blob key selection.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.inner.key_id
    }

    /// Delete this persisted key, its public half, and associated client certificates.
    /// All clones refer to the same key; this is not local handle cleanup.
    /// Repeated calls resume cleanup after partial deletion and succeed when
    /// the key and its associated items are already absent.
    ///
    /// # Errors
    /// Returns an error if Keychain deletion fails.
    pub async fn delete_key_and_associated_items(&self) -> Result<(), SetupError> {
        let key = self.clone();
        blocking::unblock(move || {
            delete_key(
                &key.inner.application_label,
                key.inner.access_group.as_deref(),
                #[cfg(feature = "local-authentication")]
                key.inner.authentication_context.as_ref(),
            )
        })
        .await
    }
}

impl AeadSealer for SealingKey {
    fn seal<'a>(
        &'a self,
        plaintext: &'a [u8],
        aad: &'a [u8],
    ) -> MaybeSendBoxFuture<'a, Result<SealOutput, huskarl_core::Error>> {
        let public = self.inner.public.clone();
        let key_id = self.inner.key_id.clone();
        // Allocate once, before copying sensitive plaintext into the buffer.
        let payload = encode_payload(plaintext, aad);
        Box::pin(async move {
            let bundle = blocking::unblock(move || {
                public
                    .encrypt_data(ALGORITHM, &payload)
                    .context(EncryptionSnafu)
            })
            .await?;
            Ok(SealOutput {
                bundle,
                kid: Some(key_id),
            })
        })
    }
}

impl AeadUnsealer for SealingKey {
    fn unseal<'a>(
        &'a self,
        bundle: &'a [u8],
        aad: &'a [u8],
        kid: Option<&'a str>,
    ) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, DecryptError>> {
        Box::pin(async move {
            if kid.is_some_and(|kid| kid != self.inner.key_id) {
                return Err(DecryptError::NoMatchingKey);
            }
            let key = self.inner.key.clone();
            #[cfg(feature = "local-authentication")]
            let authentication_context = self.inner.authentication_context.clone();
            let bundle = bundle.to_vec();
            let aad = aad.to_vec();
            blocking::unblock(move || {
                #[cfg(feature = "local-authentication")]
                let _operation = authentication_context
                    .as_ref()
                    .map(crate::authentication::AuthenticationContext::operation);
                let payload = Zeroizing::new(
                    key.decrypt_data(ALGORITHM, &bundle)
                        .context(DecryptionSnafu)?,
                );
                decode_payload(&payload, &aad)
            })
            .await
            .map_err(|error| DecryptError::Other {
                source: error.into(),
            })
        })
    }
}

fn encode_payload(plaintext: &[u8], aad: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut payload = Zeroizing::new(Vec::with_capacity(
        DOMAIN.len() + 8 + aad.len() + plaintext.len(),
    ));
    payload.extend_from_slice(DOMAIN);
    payload.extend_from_slice(&(aad.len() as u64).to_be_bytes());
    payload.extend_from_slice(aad);
    payload.extend_from_slice(plaintext);
    payload
}

fn decode_payload(payload: &[u8], aad: &[u8]) -> Result<Vec<u8>, SealingError> {
    let rest = payload.strip_prefix(DOMAIN).context(InvalidPayloadSnafu)?;
    let length = rest.get(..8).context(InvalidPayloadSnafu)?;
    ensure!(
        length == (aad.len() as u64).to_be_bytes(),
        InvalidPayloadSnafu
    );
    let rest = rest.get(8..).context(InvalidPayloadSnafu)?;
    let plaintext = rest.strip_prefix(aad).context(InvalidPayloadSnafu)?;
    Ok(plaintext.to_vec())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use security_framework::key::{GenerateKeyOptions, KeyType};

    use super::*;

    // Ephemeral software keys exercise the real Apple ECIES API without
    // entitlements or persistent Keychain changes. Hardware tests are separate.
    fn software_key() -> SealingKey {
        let mut options = GenerateKeyOptions::default();
        options.set_key_type(KeyType::ec()).set_size_in_bits(256);
        SealingKey::from_key(
            SecKey::new(&options).unwrap(),
            None,
            #[cfg(feature = "local-authentication")]
            None,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn roundtrip_and_authentication() {
        let key = software_key();
        let sealed = key.seal(b"secret", b"context").await.unwrap();
        assert_eq!(
            key.unseal(&sealed.bundle, b"context", sealed.kid.as_deref())
                .await
                .unwrap(),
            b"secret"
        );
        assert_eq!(
            key.unseal(&sealed.bundle, b"context", None).await.unwrap(),
            b"secret"
        );
        assert!(key.unseal(&sealed.bundle, b"changed", None).await.is_err());
        assert!(key.unseal(&sealed.bundle, b"contex", None).await.is_err());
        assert!(matches!(
            key.unseal(&sealed.bundle, b"context", Some("other")).await,
            Err(DecryptError::NoMatchingKey)
        ));
        assert!(
            software_key()
                .unseal(&sealed.bundle, b"context", None)
                .await
                .is_err()
        );
        let mut corrupt = sealed.bundle;
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert!(key.unseal(&corrupt, b"context", None).await.is_err());
        assert!(key.unseal(&[], b"context", None).await.is_err());
    }

    #[tokio::test]
    async fn empty_input_and_raw_ecies_are_distinct() {
        let key = software_key();
        let sealed = key.seal(b"", b"").await.unwrap();
        assert!(
            key.unseal(&sealed.bundle, b"", None)
                .await
                .unwrap()
                .is_empty()
        );
        let raw = key
            .inner
            .public
            .encrypt_data(ALGORITHM, b"unframed plaintext")
            .unwrap();
        assert!(key.unseal(&raw, b"", None).await.is_err());
    }

    #[test]
    fn framing_rejects_truncation_and_wrong_version() {
        let payload = encode_payload(b"message", b"aad");
        for end in 0..DOMAIN.len() + 8 + 3 {
            assert!(decode_payload(&payload[..end], b"aad").is_err());
        }
        let mut changed = payload;
        changed[0] ^= 1;
        assert!(decode_payload(&changed, b"aad").is_err());
    }
}
