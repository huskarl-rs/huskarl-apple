#![forbid(unsafe_code)]
#![deny(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![warn(clippy::pedantic)]

//! macOS Secure Enclave backed ES256 signing keys.

use std::borrow::Cow;
use std::sync::Arc;

use huskarl_core::crypto::signer::{
    AsymmetricJwsSigner, AsymmetricJwsSignerSelector, JwsSigner, JwsSignerSelector,
};
use huskarl_core::jwk::{EcPublicKey, PublicJwk};
use p256::ecdsa::signature;
use p256::elliptic_curve::sec1::ToSec1Point as _;
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::item::{ItemSearchOptions, KeyClass, Reference, SearchResult};
use security_framework::{
    item::Location,
    key::{GenerateKeyOptions, KeyType, SecKey, Token},
};
use security_framework_sys::access_control::kSecAccessControlPrivateKeyUsage;
use snafu::prelude::*;

/// Errors that can occur when creating a key.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum SetupError {
    /// Failed to create access control.
    #[snafu(display("Failed to create access control: {message}"))]
    AccessControl {
        /// Description of the access control error.
        message: String,
    },
    /// Failed to generate key in Secure Enclave.
    #[snafu(display("Failed to generate key in Secure Enclave: {message}"))]
    KeyGeneration {
        /// Description of the key generation error.
        message: String,
    },
    /// Failed to extract public key from Secure Enclave key.
    PublicKeyExtraction,
    /// Failed to search keychain for key.
    KeychainSearch {
        /// The underlying keychain error.
        source: security_framework::base::Error,
    },
    /// Key not found in keychain.
    KeyNotFound,
}

/// Errors that can occur when signing data.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum SigningError {
    /// Signing operation failed.
    #[snafu(display("Signing operation failed: {message}"))]
    Signing {
        /// Description of the signing error.
        message: String,
    },
    /// Failed to convert ECDSA signature from DER to fixed format.
    SignatureConversion {
        /// The underlying signature conversion error.
        source: signature::Error,
    },
}

impl huskarl_core::Error for SigningError {
    fn is_retryable(&self) -> bool {
        false
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
    jwk: PublicJwk,
    thumbprint: String,
    key_id: Option<String>,
}

/// Extracts the public key JWK from a Secure Enclave key.
fn extract_public_jwk(key: &SecKey) -> Result<PublicJwk, SetupError> {
    let public_key = key.public_key().context(PublicKeyExtractionSnafu)?;

    let external_representation = public_key
        .external_representation()
        .context(PublicKeyExtractionSnafu)?;

    let p256_key = p256::PublicKey::from_sec1_bytes(&external_representation)
        .ok()
        .context(PublicKeyExtractionSnafu)?;

    let point = p256_key.to_sec1_point(false);

    Ok(PublicJwk::builder()
        .key(
            EcPublicKey::builder()
                .crv("P-256")
                .x(point.x().context(PublicKeyExtractionSnafu)?.to_vec())
                .y(point.y().context(PublicKeyExtractionSnafu)?.to_vec()),
        )
        .build())
}

impl Es256PrivateKey {
    /// Generate a new ES256 key in the Secure Enclave.
    ///
    /// The private key never leaves the hardware and cannot be extracted.
    /// Requires code signing with keychain-access-groups entitlement.
    /// See SIGNING.md for setup instructions.
    ///
    /// # Errors
    ///
    /// Returns an error if the key could not be generated or the public
    /// key could not be extracted.
    pub fn generate(label: &str) -> Result<Self, SetupError> {
        let access_control = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
            kSecAccessControlPrivateKeyUsage,
        )
        .map_err(|e| {
            AccessControlSnafu {
                message: e.to_string(),
            }
            .build()
        })?;

        let mut generate_options = GenerateKeyOptions::default();
        generate_options.set_key_type(KeyType::ec());
        generate_options.set_size_in_bits(256);
        generate_options.set_label(label);
        generate_options.set_location(Location::DataProtectionKeychain);
        generate_options.set_token(Token::SecureEnclave);
        generate_options.set_access_control(access_control);

        let key = SecKey::new(&generate_options).map_err(|e| {
            KeyGenerationSnafu {
                message: e.to_string(),
            }
            .build()
        })?;

        let jwk = extract_public_jwk(&key)?;
        let thumbprint = jwk.thumbprint().context(PublicKeyExtractionSnafu)?;

        Ok(Self {
            inner: Arc::new(Es256PrivateKeyInner {
                key,
                jwk,
                thumbprint,
                key_id: None,
            }),
        })
    }

    /// Load an existing ES256 key from the Secure Enclave by label.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is not found or could not be loaded.
    pub fn load(label: &str) -> Result<Self, SetupError> {
        let results = ItemSearchOptions::new()
            .key_class(KeyClass::private())
            .label(label)
            .load_refs(true)
            .search()
            .context(KeychainSearchSnafu)?;

        let key = results
            .into_iter()
            .find_map(|r| match r {
                SearchResult::Ref(Reference::Key(k)) => Some(k),
                _ => None,
            })
            .context(KeyNotFoundSnafu)?;

        let jwk = extract_public_jwk(&key)?;
        let thumbprint = jwk.thumbprint().context(PublicKeyExtractionSnafu)?;

        Ok(Self {
            inner: Arc::new(Es256PrivateKeyInner {
                key,
                jwk,
                thumbprint,
                key_id: None,
            }),
        })
    }

    /// Set the key ID for this key.
    ///
    /// The key ID is used in the JWT `kid` header parameter.
    #[must_use]
    pub fn with_key_id(self, key_id: impl Into<String>) -> Self {
        Self {
            inner: Arc::new(Es256PrivateKeyInner {
                key: self.inner.key.clone(),
                jwk: self.inner.jwk.clone(),
                thumbprint: self.inner.thumbprint.clone(),
                key_id: Some(key_id.into()),
            }),
        }
    }
}

impl JwsSignerSelector for Es256PrivateKey {
    type Signer = Self;

    fn select_signer(&self) -> Self::Signer {
        self.clone()
    }
}

impl JwsSigner for Es256PrivateKey {
    type Error = SigningError;

    fn jws_algorithm(&self) -> Cow<'_, str> {
        Cow::Borrowed("ES256")
    }

    fn key_id(&self) -> Option<Cow<'_, str>> {
        self.inner.key_id.as_deref().map(Cow::Borrowed)
    }

    async fn sign(&self, input: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let der_signature = self
            .inner
            .key
            .create_signature(
                security_framework::key::Algorithm::ECDSASignatureMessageX962SHA256,
                input,
            )
            .map_err(|e| {
                SigningSnafu {
                    message: e.to_string(),
                }
                .build()
            })?;

        let signature = p256::ecdsa::Signature::from_der(&der_signature)
            .context(SignatureConversionSnafu)?;

        Ok(signature.to_bytes().to_vec())
    }
}

impl AsymmetricJwsSigner for Es256PrivateKey {
    fn public_key_jwk(&self) -> Cow<'_, PublicJwk> {
        Cow::Borrowed(&self.inner.jwk)
    }
}

impl AsymmetricJwsSignerSelector for Es256PrivateKey {
    type AsymmetricSigner = Self;

    fn select_asymmetric_signer(&self) -> Self::AsymmetricSigner {
        self.clone()
    }

    fn select_asymmetric_signer_by_thumbprint(
        &self,
        thumbprint: &str,
    ) -> Option<Self::AsymmetricSigner> {
        if self.inner.thumbprint == thumbprint {
            Some(self.clone())
        } else {
            None
        }
    }
}
