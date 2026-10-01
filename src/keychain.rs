#![doc = include_str!("keychain/README.md")]

mod backend;
mod configuration;
mod refresh;
mod storage;

#[cfg(target_os = "macos")]
pub use backend::FileKeychain;
#[cfg(target_os = "macos")]
pub use configuration::FileSecret;
pub use configuration::{DataProtectionKeychain, DataProtectionSecret, SecretReadMode};
use configuration::{ItemIdentifiers, ReadScope, ReadTarget};
use huskarl_core::{
    platform::MaybeSendBoxFuture,
    secrets::{Secret, SecretBytes, SecretOutput},
};
pub use refresh::{KeychainRefreshTokenStore, RefreshTokenStoreError};
use security_framework::item::{ItemClass, SearchResult};
use security_framework_sys::base::errSecItemNotFound;
use snafu::prelude::*;
pub use storage::{KeychainSecretStore, SecretAccessPolicy};

/// Failures while accessing or modifying a Keychain secret.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum SecretError {
    /// Invalid identifiers, file paths, or operation inputs.
    #[snafu(display("invalid Keychain configuration: {reason}"))]
    Configuration {
        /// The invalid input, without secret values.
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

/// A read provider for a validated generic-password identity or explicit search.
///
/// Create through [`DataProtectionSecret::reader`],
/// [`DataProtectionKeychain::search_all_groups`], or a file-backed item reader.
/// Retrieved bytes enter application memory in zeroizing [`SecretBytes`].
/// The stored item's policy determines its protection; a reader cannot change it.
/// Dropping a future does not cancel an in-progress Keychain operation.
///
/// ```no_run
/// use huskarl_apple::keychain::DataProtectionKeychain;
/// use huskarl_core::secrets::{Secret, encodings::StringEncoding};
///
/// # async fn example() -> Result<(), huskarl_core::Error> {
/// let source = DataProtectionKeychain::new("TEAM.io.example.app")?
///     .secret("io.example.oauth", "client-secret")?
///     .reader();
/// let secret = source.mapped(StringEncoding).get_secret_value().await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct KeychainSecret {
    identifiers: ItemIdentifiers,
    target: ReadTarget,
}

impl KeychainSecret {
    fn read(&self) -> Result<SecretBytes, SecretError> {
        #[cfg(feature = "local-authentication")]
        let _operation = self
            .target
            .context()
            .map(crate::authentication::AuthenticationContext::operation);
        let location = self.target.resolve()?;
        let mut query = backend::query(&location);
        query
            .class(ItemClass::generic_password())
            .service(&self.identifiers.service)
            .account(&self.identifiers.account)
            .load_data(true)
            .limit(1);
        let skip_protected_items = match &self.target {
            ReadTarget::DataProtection { scope, mode } => {
                let skip_protected_items = mode.skips_protected_items();
                query.skip_authenticated_items(skip_protected_items);
                match scope {
                    ReadScope::Group(group) => {
                        query.access_group(group);
                    }
                    ReadScope::AllGroups => {
                        query.limit(2);
                    }
                }
                #[cfg(feature = "local-authentication")]
                if let Some(context) = mode.context() {
                    context.apply_query(&mut query);
                }
                skip_protected_items
            }
            #[cfg(target_os = "macos")]
            ReadTarget::File(_) => false,
        };
        secret_from_search(query.search(), skip_protected_items)
    }
}

fn secret_from_search(
    result: Result<Vec<SearchResult>, security_framework::base::Error>,
    skip_protected_items: bool,
) -> Result<SecretBytes, SecretError> {
    let results = match result {
        Err(error) if error.code() == errSecItemNotFound => {
            return if skip_protected_items {
                NotFoundWithoutInteractionSnafu.fail()
            } else {
                NotFoundSnafu.fail()
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

    #[test]
    fn skipped_items_are_not_reported_as_definitely_absent() {
        let absent = || {
            Err(security_framework::base::Error::from_code(
                errSecItemNotFound,
            ))
        };
        assert!(matches!(
            secret_from_search(absent(), false),
            Err(SecretError::NotFound)
        ));
        assert!(matches!(
            secret_from_search(absent(), true),
            Err(SecretError::NotFoundWithoutInteraction)
        ));
    }

    #[test]
    fn interaction_errors_are_preserved_in_both_query_modes() {
        for interaction in [false, true] {
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
