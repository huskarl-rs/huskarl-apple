#![doc = include_str!("keychain/README.md")]

mod backend;
mod refresh;
mod storage;

pub use backend::KeychainBackend;
use bon::Builder;
use huskarl_core::{
    platform::MaybeSendBoxFuture,
    secrets::{Secret, SecretBytes, SecretOutput},
};
pub use refresh::{KeychainRefreshTokenStore, RefreshTokenStoreError};
use security_framework::item::{ItemClass, SearchResult};
use security_framework_sys::base::errSecItemNotFound;
use snafu::prelude::*;
pub use storage::{KeychainSecretStore, SecretAccessPolicy};

/// Whether secret lookups may request user authentication.
///
/// This controls a read query, not the persisted item's access policy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum SecretInteraction {
    /// Allow macOS to prompt if the stored item's policy requires it (default).
    ///
    /// The operation can wait for the user. This does not request an unlock
    /// timeout or guarantee a fresh prompt on each read.
    #[default]
    Allow,
    /// Exclude items requiring authentication instead of presenting UI.
    ///
    /// Uses `kSecUseAuthenticationUISkip`. If no eligible item remains, the
    /// provider returns [`SecretError::NotFoundWithoutInteraction`]. This does
    /// not bypass protection or distinguish an absent item from a skipped one.
    SkipProtectedItems,
}

/// Failures while accessing or modifying a Keychain secret.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum SecretError {
    /// Empty item identifiers or options incompatible with the selected backend.
    #[snafu(display("invalid Keychain configuration: {reason}"))]
    Configuration {
        /// The incompatible option, without secret values.
        reason: &'static str,
    },
    /// Could not resolve or open the selected file-based keychain.
    OpenKeychain {
        /// The underlying Keychain status.
        source: security_framework::base::Error,
    },
    /// The requested service/account pair does not exist.
    #[snafu(display("Keychain secret not found"))]
    NotFound,
    /// The noninteractive query found no eligible item.
    ///
    /// The item may be absent or excluded because it requires authentication.
    /// Do not interpret this as proof that it is safe to replace a secret.
    #[snafu(display("Keychain secret absent or unavailable without user authentication"))]
    NotFoundWithoutInteraction,
    /// Multiple access groups contained matching secrets.
    #[snafu(display("multiple Keychain secrets matched; specify an access group"))]
    Ambiguous,
    /// The framework could not perform the lookup.
    #[snafu(display("failed to read Keychain secret: {source}"))]
    Access {
        /// The underlying Keychain status.
        source: security_framework::base::Error,
    },
    /// A successful query did not return secret bytes.
    #[snafu(display("Keychain did not return secret data"))]
    MissingData,
    /// A successful file-keychain lookup did not return an item to update.
    MissingItemReference,
    /// Could not construct the policy for a new secret.
    AccessControl {
        /// The underlying Keychain status.
        source: security_framework::base::Error,
    },
    /// Could not create or update the secret.
    Write {
        /// The underlying Keychain status.
        source: security_framework::base::Error,
    },
    /// Could not delete the secret.
    Delete {
        /// The underlying Keychain status.
        source: security_framework::base::Error,
    },
}

impl From<SecretError> for huskarl_core::Error {
    fn from(error: SecretError) -> Self {
        let advice = match &error {
            SecretError::Access { source }
            | SecretError::OpenKeychain { source }
            | SecretError::AccessControl { source }
            | SecretError::Write { source }
            | SecretError::Delete { source } => crate::platform::status_retry_advice(source.code()),
            _ => huskarl_core::RetryAdvice::No,
        };
        Self::new(advice, error)
    }
}

/// A generic-password item addressed by service, account, and optional group.
///
/// The default data protection backend requires signing and entitlements.
/// On macOS, select `KeychainBackend::Login` for file-backed storage without provisioning.
/// Retrieved bytes enter application memory in zeroizing [`SecretBytes`].
/// Service and account must be nonempty; invalid identifiers are rejected on read.
///
/// Availability and user-presence requirements belong to the stored item and
/// must be set when provisioning it. A reader cannot change those requirements.
/// Reading defaults to allowing macOS authentication UI; choose
/// [`SecretInteraction::SkipProtectedItems`] for unattended data protection reads. Values already
/// returned to the application are not revoked when the Keychain later locks.
///
/// ```no_run
/// use huskarl_apple::keychain::KeychainSecret;
/// use huskarl_core::secrets::{Secret, encodings::StringEncoding};
///
/// # async fn example() -> Result<(), huskarl_core::Error> {
/// let source = KeychainSecret::builder()
///     .service("io.example.oauth")
///     .account("client-secret")
///     .build();
/// let secret = source.mapped(StringEncoding).get_secret_value().await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Builder)]
pub struct KeychainSecret {
    /// The item's service identifier.
    #[builder(into)]
    service: String,
    /// The item's account identifier.
    #[builder(into)]
    account: String,
    /// Restrict lookup to this entitled access group.
    #[builder(into)]
    access_group: Option<String>,
    /// Backend to search, defaulting to data protection.
    #[builder(default)]
    backend: KeychainBackend,
    /// Whether this lookup may involve the user, defaulting to allowing UI.
    #[builder(default)]
    interaction: SecretInteraction,
}

impl KeychainSecret {
    fn read(&self) -> Result<SecretBytes, SecretError> {
        validate_identifiers(&self.service, &self.account)?;
        self.backend
            .validate(self.access_group.as_deref(), self.interaction)?;
        self.read_validated()
    }

    // The caller has checked identifiers and backend options; store readers also validate
    // write-specific configuration before reaching this path.
    fn read_validated(&self) -> Result<SecretBytes, SecretError> {
        let location = self.backend.resolve()?;
        let mut query = backend::query(&location);
        query
            .class(ItemClass::generic_password())
            .service(&self.service)
            .account(&self.account)
            .skip_authenticated_items(self.interaction == SecretInteraction::SkipProtectedItems)
            .load_data(true)
            // An explicit group plus service/account identifies one local
            // generic password; only a cross-group search needs ambiguity detection.
            .limit(
                if self.access_group.is_some() || self.backend != KeychainBackend::DataProtection {
                    1
                } else {
                    2
                },
            );
        if let Some(group) = &self.access_group {
            query.access_group(group);
        }
        secret_from_search(query.search(), self.interaction)
    }
}

fn validate_identifiers(service: &str, account: &str) -> Result<(), SecretError> {
    // Empty attributes can broaden a Keychain query beyond the intended item.
    ensure!(
        !service.is_empty() && !account.is_empty(),
        ConfigurationSnafu {
            reason: "service and account must be nonempty"
        }
    );
    Ok(())
}

fn secret_from_search(
    result: Result<Vec<SearchResult>, security_framework::base::Error>,
    interaction: SecretInteraction,
) -> Result<SecretBytes, SecretError> {
    let results = match result {
        Err(error) if error.code() == errSecItemNotFound => {
            return match interaction {
                SecretInteraction::Allow => NotFoundSnafu.fail(),
                SecretInteraction::SkipProtectedItems => NotFoundWithoutInteractionSnafu.fail(),
            };
        }
        result => result.context(AccessSnafu)?,
    };
    secret_from_results(results)
}

fn secret_from_results(results: Vec<SearchResult>) -> Result<SecretBytes, SecretError> {
    // Wrap *all* returned data before rejecting ambiguous results, so
    // extra secret copies are also zeroized on the error path.
    let values: Vec<_> = results
        .into_iter()
        .map(|result| match result {
            SearchResult::Data(bytes) => Some(SecretBytes::new(bytes)),
            _ => None,
        })
        .collect();
    ensure!(values.len() <= 1, AmbiguousSnafu);
    values
        .into_iter()
        .next()
        .flatten()
        .context(MissingDataSnafu)
}

impl Secret for KeychainSecret {
    type Output = SecretBytes;

    fn get_secret_value(
        &self,
    ) -> MaybeSendBoxFuture<'_, Result<SecretOutput<Self::Output>, huskarl_core::Error>> {
        let source = self.clone();
        Box::pin(async move {
            let value = blocking::unblock(move || source.read()).await?;
            Ok(SecretOutput {
                value,
                identity: None,
            })
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use huskarl_core::secrets::{SecretMap, encodings::StringEncoding};

    use super::*;

    #[tokio::test]
    async fn empty_identifiers_are_rejected_on_read() {
        for (service, account) in [("", "account"), ("service", ""), ("", "")] {
            for interaction in [
                SecretInteraction::Allow,
                SecretInteraction::SkipProtectedItems,
            ] {
                let source = KeychainSecret::builder()
                    .service(service)
                    .account(account)
                    .interaction(interaction)
                    .build();
                assert!(matches!(
                    source.read(),
                    Err(SecretError::Configuration {
                        reason: "service and account must be nonempty"
                    })
                ));
                let error = source.get_secret_value().await.unwrap_err();
                assert!(
                    error
                        .to_string()
                        .contains("service and account must be nonempty")
                );
            }
        }
    }

    #[test]
    fn skipped_items_are_not_reported_as_definitely_absent() {
        let absent = || {
            Err(security_framework::base::Error::from_code(
                errSecItemNotFound,
            ))
        };
        assert!(matches!(
            secret_from_search(absent(), SecretInteraction::Allow),
            Err(SecretError::NotFound)
        ));
        assert!(matches!(
            secret_from_search(absent(), SecretInteraction::SkipProtectedItems),
            Err(SecretError::NotFoundWithoutInteraction)
        ));
    }

    #[test]
    fn interaction_errors_are_preserved_in_both_query_modes() {
        for interaction in [
            SecretInteraction::Allow,
            SecretInteraction::SkipProtectedItems,
        ] {
            let error = security_framework::base::Error::from_code(
                crate::platform::ERR_SEC_INTERACTION_NOT_ALLOWED,
            );
            assert!(matches!(
                secret_from_search(Err(error), interaction),
                Err(SecretError::Access { source }) if source.code() == crate::platform::ERR_SEC_INTERACTION_NOT_ALLOWED
            ));
        }
    }

    #[test]
    fn preserves_binary_and_empty_secrets() {
        let bytes = secret_from_results(vec![SearchResult::Data(vec![0, 255, 1])]).unwrap();
        assert_eq!(bytes.expose_secret(), &[0, 255, 1]);
        assert!(StringEncoding.apply(bytes).is_err());
        assert!(
            secret_from_results(vec![SearchResult::Data(vec![])])
                .unwrap()
                .expose_secret()
                .is_empty()
        );
    }

    #[test]
    fn rejects_ambiguous_or_missing_data() {
        assert!(matches!(
            secret_from_results(vec![
                SearchResult::Data(vec![1]),
                SearchResult::Data(vec![2])
            ]),
            Err(SecretError::Ambiguous)
        ));
        assert!(matches!(
            secret_from_results(vec![SearchResult::Other]),
            Err(SecretError::MissingData)
        ));
        assert!(matches!(
            secret_from_results(vec![]),
            Err(SecretError::MissingData)
        ));
    }
}
