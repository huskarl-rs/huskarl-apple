use security_framework::{
    certificate::SecCertificate,
    identity::SecIdentity,
    item::{
        AddRef, ItemAddOptions, ItemAddValue, ItemClass, ItemSearchOptions, Limit, Location,
        Reference, SearchResult,
    },
    key::SecKey,
};
use security_framework_sys::base::{errSecDuplicateItem, errSecItemNotFound};
use snafu::prelude::*;

/// A TLS client identity: a leaf certificate, Keychain key, and optional intermediates.
///
/// The Keychain forms an identity when a stored certificate's public key
/// matches a stored private key. The private key never leaves its token, so
/// an identity for a Secure Enclave key authenticates this device only.
/// Intermediate certificates are held in memory for the TLS handshake;
/// they are not installed in the Keychain or used as server trust anchors.
#[derive(Clone)]
pub struct ClientIdentity {
    pub(super) identity: SecIdentity,
    pub(super) intermediates: Vec<SecCertificate>,
    certificate_der: Vec<u8>,
    label: String,
    access_group: Option<String>,
}

impl std::fmt::Debug for ClientIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientIdentity")
            .field("label", &self.label)
            .field("access_group", &self.access_group)
            .field("intermediate_count", &self.intermediates.len())
            .finish_non_exhaustive()
    }
}

/// Errors pairing a certificate with a private key.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum ClientIdentityError {
    /// The bytes are not a DER-encoded X.509 certificate.
    #[snafu(display("invalid certificate: {source}"))]
    InvalidCertificate {
        /// The underlying Security framework status.
        source: security_framework::base::Error,
    },
    /// An intermediate is not a DER-encoded X.509 certificate.
    #[snafu(display("invalid intermediate certificate at index {index}: {source}"))]
    InvalidIntermediate {
        /// Zero-based position in the supplied intermediates.
        index: usize,
        /// The underlying Security framework status.
        source: security_framework::base::Error,
    },
    /// The private key's public-key hash could not be read.
    PublicKeyExtraction,
    /// A Keychain add, search, or delete failed.
    #[snafu(display("Keychain operation failed: {source}"))]
    Keychain {
        /// The underlying Keychain status.
        source: security_framework::base::Error,
    },
    /// No identity formed, so the certificate does not certify this key.
    #[snafu(display("the certificate does not match the private key"))]
    CertificateKeyMismatch,
    /// A duplicate certificate exists outside this key's library-managed label.
    /// It is left untouched; remove it explicitly before installing it here.
    #[snafu(display("an existing certificate is not managed by this key's certificate label"))]
    CertificateOwnershipConflict,
}

impl From<ClientIdentityError> for huskarl_core::Error {
    fn from(error: ClientIdentityError) -> Self {
        let advice = match &error {
            ClientIdentityError::Keychain { source } => {
                crate::platform::status_retry_advice(source.code())
            }
            _ => huskarl_core::RetryAdvice::No,
        };
        Self::new(advice, error)
    }
}

impl ClientIdentity {
    /// The DER-encoded leaf certificate presented to servers.
    #[must_use]
    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }

    /// Removes every certificate installed for this identity's private key.
    ///
    /// This also removes older certificates installed for the same key.
    /// The private key is unaffected. Dropping an identity does not remove
    /// its stored certificates; deleting the private key does.
    ///
    /// Runs on a blocking pool. Dropping the future does not cancel deletion
    /// already in progress.
    ///
    /// # Errors
    /// Returns an error if Keychain deletion fails.
    pub async fn remove_certificates(&self) -> Result<(), ClientIdentityError> {
        let identity = self.clone();
        blocking::unblock(move || {
            delete_certificates(&identity.label, identity.access_group.as_deref())
        })
        .await
    }
}

/// Stores `certificate_der` beside `key` and returns the resulting identity.
///
/// Reinstalling the same certificate is harmless. If identity lookup fails,
/// rollback attempts to remove only the certificate added by this call.
pub(crate) fn install(
    key: &SecKey,
    access_group: Option<&str>,
    certificate_der: &[u8],
    intermediates: impl IntoIterator<Item = Vec<u8>>,
) -> Result<ClientIdentity, ClientIdentityError> {
    let certificate = SecCertificate::from_der(certificate_der).context(InvalidCertificateSnafu)?;
    // Parse the complete input before making any persistent changes.
    let intermediates = intermediates
        .into_iter()
        .enumerate()
        .map(|(index, der)| {
            SecCertificate::from_der(&der).context(InvalidIntermediateSnafu { index })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let key_hash = key.application_label().context(PublicKeyExtractionSnafu)?;
    // Labels group this key's certificates for removal; the Keychain's own
    // uniqueness (issuer and serial) still prevents exact duplicates.
    let label = crate::secure_enclave::tls_certificate_label(&key_hash);

    let mut options =
        ItemAddOptions::new(ItemAddValue::Ref(AddRef::Certificate(certificate.clone())));
    options
        .set_location(Location::DataProtectionKeychain)
        .set_label(&label);
    if let Some(group) = access_group {
        options.set_access_group(group);
    }
    let added = match options.add() {
        Ok(()) => true,
        Err(error) if error.code() == errSecDuplicateItem => {
            // Only reuse certificates that cleanup will find. Do not relabel
            // or adopt certificates installed by another owner.
            let managed = certificates_with_label(&label, access_group)?
                .iter()
                .any(|stored| stored.to_der() == certificate_der);
            ensure!(managed, CertificateOwnershipConflictSnafu);
            false
        }
        Err(source) => return Err(ClientIdentityError::Keychain { source }),
    };

    match find_identity(&certificate, &key_hash, access_group) {
        Ok(Some(identity)) => Ok(ClientIdentity {
            identity,
            intermediates,
            certificate_der: certificate_der.to_vec(),
            label,
            access_group: access_group.map(str::to_owned),
        }),
        result => {
            if added {
                // Best effort: report the lookup outcome, not a cleanup failure.
                let _ = delete_certificate(&certificate, &label, access_group);
            }
            result.and_then(|_| CertificateKeyMismatchSnafu.fail())
        }
    }
}

fn find_identity(
    certificate: &SecCertificate,
    key_hash: &[u8],
    access_group: Option<&str>,
) -> Result<Option<SecIdentity>, ClientIdentityError> {
    let mut query = ItemSearchOptions::new();
    #[cfg(target_os = "macos")]
    query.ignore_legacy_keychains();
    query
        .class(ItemClass::identity())
        .load_refs(true)
        .limit(Limit::All);
    if let Some(group) = access_group {
        query.access_group(group);
    }
    let results = match query.search() {
        Err(error) if error.code() == errSecItemNotFound => return Ok(None),
        result => result.context(KeychainSnafu)?,
    };
    // Identity queries do not filter by certificate, so match the exact
    // certificate and private key among every accessible identity. A stored
    // public key shares the private key's hash and also forms an "identity"
    // (Apple lists it first); presenting that one fails at the TLS signature.
    let der = certificate.to_der();
    Ok(results.into_iter().find_map(|result| match result {
        SearchResult::Ref(Reference::Identity(identity))
            if identity.certificate().is_ok_and(|c| c.to_der() == der)
                && identity
                    .private_key()
                    .is_ok_and(|key| is_private_key_for(&key, key_hash)) =>
        {
            Some(identity)
        }
        _ => None,
    }))
}

fn is_private_key_for(key: &SecKey, key_hash: &[u8]) -> bool {
    // Apple's kSecAttrKeyClass attribute and its kSecAttrKeyClassPrivate value.
    let private = SearchResult::Dict(key.attributes())
        .simplify_dict()
        .is_some_and(|attributes| attributes.get("kcls").is_some_and(|class| class == "1"));
    private && key.application_label().is_some_and(|hash| hash == key_hash)
}

fn delete_certificates(label: &str, access_group: Option<&str>) -> Result<(), ClientIdentityError> {
    let mut query = ItemSearchOptions::new();
    #[cfg(target_os = "macos")]
    query.ignore_legacy_keychains();
    query.class(ItemClass::certificate()).label(label);
    if let Some(group) = access_group {
        query.access_group(group);
    }
    match query.delete() {
        Err(error) if error.code() == errSecItemNotFound => Ok(()),
        result => result.context(KeychainSnafu),
    }
}

fn certificates_with_label(
    label: &str,
    access_group: Option<&str>,
) -> Result<Vec<SecCertificate>, ClientIdentityError> {
    let mut query = ItemSearchOptions::new();
    #[cfg(target_os = "macos")]
    query.ignore_legacy_keychains();
    query
        .class(ItemClass::certificate())
        .label(label)
        .load_refs(true)
        .limit(Limit::All);
    if let Some(group) = access_group {
        query.access_group(group);
    }
    let results = match query.search() {
        Err(error) if error.code() == errSecItemNotFound => return Ok(Vec::new()),
        result => result.context(KeychainSnafu)?,
    };
    Ok(results
        .into_iter()
        .filter_map(|result| match result {
            SearchResult::Ref(Reference::Certificate(stored)) => Some(stored),
            _ => None,
        })
        .collect())
}

fn delete_certificate(
    certificate: &SecCertificate,
    label: &str,
    access_group: Option<&str>,
) -> Result<(), ClientIdentityError> {
    let der = certificate.to_der();
    for stored in certificates_with_label(label, access_group)? {
        if stored.to_der() == der {
            // Delete the stored reference, preserving other certificates
            // under the same key-wide label (including previous renewals).
            match stored.delete() {
                Err(error) if error.code() == errSecItemNotFound => {}
                result => result.context(KeychainSnafu)?,
            }
        }
    }
    Ok(())
}
