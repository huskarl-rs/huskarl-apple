#![doc = include_str!("README.md")]

mod policy;
mod provision;
mod public_key;
mod seal;
mod signer;
mod verifier;

use core_foundation::{
    base::ToVoid as _,
    data::CFData,
    dictionary::{CFDictionary, CFMutableDictionary},
    error::CFError,
    string::CFString,
};
pub use policy::KeyAccessPolicy;
pub use seal::{SealingError, SealingKey};
use security_framework::{
    item::{ItemSearchOptions, KeyClass, Location, Reference, SearchResult},
    key::{GenerateKeyOptions, KeyType, SecKey, Token},
};
use security_framework_sys::base::errSecItemNotFound;
pub use signer::{Es256PrivateKey, SigningError};
use snafu::prelude::*;
pub use verifier::VerifyingKey;

use crate::PlatformError;
// Retain the original public paths for existing callers.
pub use crate::policy::{Authentication as KeyAuthentication, Availability as KeyAvailability};

/// Errors creating, loading, or deleting an enclave key.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum SetupError {
    /// Could not configure private-key access.
    #[snafu(display("failed to create access control: {source}"))]
    AccessControl {
        /// The underlying Keychain status.
        source: security_framework::base::Error,
    },
    /// Hardware key generation failed.
    #[snafu(display("failed to generate Secure Enclave key: {source}"))]
    KeyGeneration {
        /// The underlying Apple error.
        #[snafu(source(from(CFError, PlatformError::from)))]
        source: PlatformError,
    },
    /// The public key could not be exported or was not P-256.
    PublicKeyExtraction,
    /// Caller-supplied bytes are not a valid SEC1-encoded P-256 public key.
    #[snafu(display("invalid SEC1 P-256 public key: {source}"))]
    InvalidPublicKey {
        /// The public-key decoding error.
        source: p256::ecdsa::signature::Error,
    },
    /// Keychain lookup failed.
    KeychainSearch {
        /// The underlying Keychain status.
        source: security_framework::base::Error,
    },
    /// No private key matches the label in the requested purpose namespace.
    KeyNotFound,
    /// A successful lookup did not return the requested private-key reference.
    InvalidKeyResult,
    /// Could not open or acquire the cooperating creators' file lock.
    Coordination {
        /// The underlying filesystem or lock error.
        source: std::io::Error,
    },
    /// The key's persisted purpose tag is missing or does not match.
    #[snafu(display("key purpose tag is missing or mismatched"))]
    KeyPurposeMismatch,
    /// The label matches more than one private key in the requested namespace.
    #[snafu(display("multiple private keys match the label"))]
    AmbiguousKey,
    /// The loaded key does not identify the Secure Enclave as its token.
    #[snafu(display("the key is not backed by the Secure Enclave"))]
    NotSecureEnclave,
    /// Deletion failed.
    KeyDeletion {
        /// The underlying Keychain status.
        source: security_framework::base::Error,
    },
}

impl From<SetupError> for huskarl_core::Error {
    fn from(error: SetupError) -> Self {
        let advice = match &error {
            SetupError::AccessControl { source }
            | SetupError::KeychainSearch { source }
            | SetupError::KeyDeletion { source } => {
                crate::platform::status_retry_advice(source.code())
            }
            SetupError::KeyGeneration { source } => source.retry_advice(),
            _ => huskarl_core::RetryAdvice::No,
        };
        Self::new(advice, error)
    }
}

#[derive(Debug, Clone, Copy)]
enum KeyPurpose {
    Signing,
    Sealing,
}

impl KeyPurpose {
    fn tag(self) -> &'static str {
        match self {
            Self::Signing => "huskarl-apple/sign",
            Self::Sealing => "huskarl-apple/seal",
        }
    }

    fn stored_label(self, label: &str) -> String {
        format!("{}/{label}", self.tag())
    }
}

fn generate_key(
    label: &str,
    purpose: KeyPurpose,
    policy: KeyAccessPolicy,
    access_group: Option<&str>,
) -> Result<SecKey, SetupError> {
    let access = policy.access_control()?;
    let mut options = GenerateKeyOptions::default();
    options
        .set_key_type(KeyType::ec())
        .set_size_in_bits(256)
        .set_label(purpose.stored_label(label))
        .set_location(Location::DataProtectionKeychain)
        .set_token(Token::SecureEnclave)
        .set_access_control(access);
    generate_tagged_key(&options, purpose, access_group).context(KeyGenerationSnafu)
}

// security-framework does not expose generation setters for application tag
// or access group. Its dictionary-based generation API still provides a safe
// route to those Apple attributes. Keep deprecated API use isolated here.
#[allow(deprecated)]
fn generation_attributes(
    options: &GenerateKeyOptions,
    purpose: KeyPurpose,
    access_group: Option<&str>,
) -> CFDictionary {
    let original = options.to_dictionary();
    let (keys, values) = original.get_keys_and_values();
    // The source dictionary remains alive while the new dictionary retains
    // each CF object. No raw pointers are dereferenced by this crate.
    let pairs: Vec<_> = keys.into_iter().zip(values).collect();
    let mut attributes = CFMutableDictionary::from_CFType_pairs(&pairs);
    // Apple's kSecAttrApplicationTag / kSecAttrAccessGroup string values.
    let tag_name = CFString::new("atag");
    let tag = CFData::from_buffer(purpose.tag().as_bytes());
    attributes.set(tag_name.to_void(), tag.to_void());
    if let Some(group) = access_group {
        let name = CFString::new("agrp");
        let group = CFString::new(group);
        attributes.set(name.to_void(), group.to_void());
    }
    attributes.to_immutable()
}

#[allow(deprecated)]
fn generate_tagged_key(
    options: &GenerateKeyOptions,
    purpose: KeyPurpose,
    access_group: Option<&str>,
) -> Result<SecKey, CFError> {
    SecKey::generate(generation_attributes(options, purpose, access_group))
}

fn key_query(label: &str, purpose: KeyPurpose, access_group: Option<&str>) -> ItemSearchOptions {
    let mut query = ItemSearchOptions::new();
    #[cfg(target_os = "macos")]
    query.ignore_legacy_keychains();
    query
        .key_class(KeyClass::private())
        .label(&purpose.stored_label(label));
    if let Some(group) = access_group {
        query.access_group(group);
    }
    query
}

fn load_key(
    label: &str,
    purpose: KeyPurpose,
    access_group: Option<&str>,
) -> Result<SecKey, SetupError> {
    let result = key_query(label, purpose, access_group)
        .load_refs(true)
        .limit(2)
        .search();
    let key = key_from_search(result)?;
    validate_token(&key)?;
    // SecKeyCopyAttributes does not promise application tags. Read persisted
    // Keychain metadata instead, pinning the query to this exact public-key
    // identity to avoid validating metadata for a replacement key.
    let identity = key.application_label().context(PublicKeyExtractionSnafu)?;
    let metadata = key_query(label, purpose, access_group)
        .application_label(&identity)
        .load_attributes(true)
        .limit(2)
        .search()
        .context(KeychainSearchSnafu)?;
    validate_purpose_metadata(&metadata, purpose)?;
    Ok(key)
}

fn key_from_search(
    result: Result<Vec<SearchResult>, security_framework::base::Error>,
) -> Result<SecKey, SetupError> {
    let results = match result {
        Err(error) if error.code() == errSecItemNotFound => return KeyNotFoundSnafu.fail(),
        result => result.context(KeychainSearchSnafu)?,
    };
    ensure!(results.len() <= 1, AmbiguousKeySnafu);
    results
        .into_iter()
        .find_map(|result| match result {
            SearchResult::Ref(Reference::Key(key)) => Some(key),
            _ => None,
        })
        .context(InvalidKeyResultSnafu)
}

fn validate_purpose_metadata(
    metadata: &[SearchResult],
    purpose: KeyPurpose,
) -> Result<(), SetupError> {
    ensure!(metadata.len() <= 1, AmbiguousKeySnafu);
    let attributes = metadata.first().and_then(SearchResult::simplify_dict);
    ensure!(
        attributes
            .as_ref()
            .and_then(|attrs| attrs.get("atag"))
            .is_some_and(|tag| tag == purpose.tag()),
        KeyPurposeMismatchSnafu
    );
    Ok(())
}

fn validate_token(key: &SecKey) -> Result<(), SetupError> {
    // These are Apple's kSecAttrTokenID and kSecAttrTokenIDSecureEnclave
    // string values (Security/OSX/sec/Security/SecItemConstants.c).
    // simplify_dict provides safe access without raw CF pointer casts.
    let attributes = SearchResult::Dict(key.attributes()).simplify_dict();
    ensure!(
        attributes
            .as_ref()
            .and_then(|attrs| attrs.get("tkid"))
            .is_some_and(|token| token == "com.apple.setoken"),
        NotSecureEnclaveSnafu
    );
    Ok(())
}

fn delete_key(key: &SecKey, access_group: Option<&str>) -> Result<(), SetupError> {
    let identity = key.application_label().context(PublicKeyExtractionSnafu)?;
    let mut query = ItemSearchOptions::new();
    #[cfg(target_os = "macos")]
    query.ignore_legacy_keychains();
    query
        .key_class(KeyClass::private())
        .application_label(&identity);
    if let Some(group) = access_group {
        query.access_group(group);
    }
    query.delete().context(KeyDeletionSnafu)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn only_item_not_found_means_absence() {
        assert!(matches!(
            key_from_search(Err(security_framework::base::Error::from_code(
                errSecItemNotFound
            ))),
            Err(SetupError::KeyNotFound)
        ));
        for results in [vec![], vec![SearchResult::Other]] {
            assert!(matches!(
                key_from_search(Ok(results)),
                Err(SetupError::InvalidKeyResult)
            ));
        }
        for status in [
            crate::platform::ERR_SEC_INTERACTION_NOT_ALLOWED,
            -25293,
            -34018,
            -128,
        ] {
            assert!(
                matches!(key_from_search(Err(security_framework::base::Error::from_code(status))), Err(SetupError::KeychainSearch { source }) if source.code() == status)
            );
        }
    }

    #[test]
    fn purpose_tag_is_required_and_checked() {
        let options = GenerateKeyOptions::default();
        let signing =
            || SearchResult::Dict(generation_attributes(&options, KeyPurpose::Signing, None));
        let sealing =
            || SearchResult::Dict(generation_attributes(&options, KeyPurpose::Sealing, None));
        assert!(validate_purpose_metadata(&[signing()], KeyPurpose::Signing).is_ok());
        assert!(validate_purpose_metadata(&[sealing()], KeyPurpose::Sealing).is_ok());
        assert!(matches!(
            validate_purpose_metadata(&[signing()], KeyPurpose::Sealing),
            Err(SetupError::KeyPurposeMismatch)
        ));
        assert!(matches!(
            validate_purpose_metadata(&[sealing()], KeyPurpose::Signing),
            Err(SetupError::KeyPurposeMismatch)
        ));
        let untagged =
            CFDictionary::from_CFType_pairs(&[(CFString::new("labl"), CFString::new("external"))]);
        assert!(matches!(
            validate_purpose_metadata(
                &[SearchResult::Dict(untagged.into_untyped())],
                KeyPurpose::Signing
            ),
            Err(SetupError::KeyPurposeMismatch)
        ));
        assert!(matches!(
            validate_purpose_metadata(&[signing(), signing()], KeyPurpose::Signing),
            Err(SetupError::AmbiguousKey)
        ));
    }

    #[test]
    fn generation_preserves_policy_and_adds_group_and_purpose() {
        let mut options = GenerateKeyOptions::default();
        options
            .set_key_type(KeyType::ec())
            .set_size_in_bits(256)
            .set_label(KeyPurpose::Signing.stored_label("account"))
            .set_location(Location::DataProtectionKeychain)
            .set_token(Token::SecureEnclave)
            .set_access_control(KeyAccessPolicy::default().access_control().unwrap());
        let dict = generation_attributes(&options, KeyPurpose::Signing, Some("TEAM.group"));
        let attrs = SearchResult::Dict(dict.clone()).simplify_dict().unwrap();
        assert_eq!(attrs.get("agrp").map(String::as_str), Some("TEAM.group"));
        assert_eq!(
            attrs.get("atag").map(String::as_str),
            Some("huskarl-apple/sign")
        );
        assert_eq!(
            attrs.get("labl").map(String::as_str),
            Some("huskarl-apple/sign/account")
        );
        assert_eq!(
            attrs.get("tkid").map(String::as_str),
            Some("com.apple.setoken")
        );
        // Ensure the private-key access-control subdictionary survived copying.
        assert!(dict.contains_key(&CFString::new("private").to_void()));
        let default_group =
            SearchResult::Dict(generation_attributes(&options, KeyPurpose::Signing, None))
                .simplify_dict()
                .unwrap();
        assert!(!default_group.contains_key("agrp"));
    }

    #[test]
    fn software_key_is_not_an_enclave_key() {
        let mut options = GenerateKeyOptions::default();
        options.set_key_type(KeyType::ec()).set_size_in_bits(256);
        let key = SecKey::new(&options).unwrap();
        assert!(matches!(
            validate_token(&key),
            Err(SetupError::NotSecureEnclave)
        ));
    }

    #[test]
    #[allow(deprecated)]
    fn token_constants_agree_with_framework() {
        let mut options = GenerateKeyOptions::default();
        options.set_token(Token::SecureEnclave);
        let attributes = SearchResult::Dict(options.to_dictionary())
            .simplify_dict()
            .unwrap();
        assert_eq!(
            attributes.get("tkid").map(String::as_str),
            Some("com.apple.setoken")
        );
    }
}
