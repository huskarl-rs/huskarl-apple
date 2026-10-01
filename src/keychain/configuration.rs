use security_framework::item::Location;
use snafu::prelude::*;

use super::{
    ConfigurationSnafu, KeychainSecret, KeychainSecretStore, SecretAccessPolicy, SecretError,
};

/// How a data protection read may authenticate.
///
/// This is an operation option, not the persisted item's protection policy.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub enum SecretReadMode {
    /// Permit authentication UI when required by the item (default).
    #[default]
    Allow,
    /// Skip protected items without presenting UI.
    /// An absent or skipped item returns [`SecretError::NotFoundWithoutInteraction`].
    SkipProtectedItems,
    /// Use shared authentication state and its interaction settings.
    /// Disable interaction on the context to fail instead of skipping items
    /// when authentication UI would be needed.
    ///
    /// A read mode cannot also skip protected items:
    ///
    /// ```compile_fail,E0599
    /// use huskarl_apple::{authentication::AuthenticationContext, keychain::SecretReadMode};
    /// let mode = SecretReadMode::SkipProtectedItems
    ///     .authentication_context(AuthenticationContext::default());
    /// ```
    #[cfg(feature = "local-authentication")]
    Context(crate::authentication::AuthenticationContext),
}

impl SecretReadMode {
    pub(super) fn skips_protected_items(&self) -> bool {
        matches!(self, Self::SkipProtectedItems)
    }

    #[cfg(feature = "local-authentication")]
    pub(super) fn context(&self) -> Option<&crate::authentication::AuthenticationContext> {
        match self {
            Self::Context(context) => Some(context),
            _ => None,
        }
    }
}

/// A data protection Keychain namespace restricted to one entitled access group.
///
/// Construction validates configuration only. Signing, entitlements, and access
/// are checked by the platform when an operation runs; failures never fall back
/// to a different backend or group.
#[derive(Debug, Clone)]
pub struct DataProtectionKeychain {
    access_group: String,
}

impl DataProtectionKeychain {
    /// Select one exact access group without accessing the Keychain.
    ///
    /// # Errors
    /// Rejects an empty access group.
    pub fn new(access_group: impl Into<String>) -> Result<Self, SecretError> {
        let access_group = access_group.into();
        ensure!(
            !access_group.is_empty(),
            ConfigurationSnafu {
                reason: "access group must be nonempty"
            }
        );
        Ok(Self { access_group })
    }

    /// Address an exact generic-password item in this access group.
    ///
    /// # Errors
    /// Rejects empty service or account identifiers.
    pub fn secret(
        &self,
        service: impl Into<String>,
        account: impl Into<String>,
    ) -> Result<DataProtectionSecret, SecretError> {
        Ok(DataProtectionSecret {
            identifiers: ItemIdentifiers::new(service, account)?,
            keychain: self.clone(),
        })
    }

    /// Create a read-only search across all accessible data protection groups.
    ///
    /// Multiple eligible matches return [`SecretError::Ambiguous`]. This search
    /// cannot be converted into a writable store: writes require an exact group.
    ///
    /// ```compile_fail,E0599
    /// use huskarl_apple::keychain::{DataProtectionKeychain, SecretReadMode};
    /// # fn example() -> Result<(), huskarl_apple::keychain::SecretError> {
    /// let search = DataProtectionKeychain::search_all_groups(
    ///     "service", "account", SecretReadMode::Allow,
    /// )?;
    /// let store = search.store();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    /// Rejects empty service or account identifiers.
    pub fn search_all_groups(
        service: impl Into<String>,
        account: impl Into<String>,
        mode: SecretReadMode,
    ) -> Result<KeychainSecret, SecretError> {
        Ok(KeychainSecret {
            identifiers: ItemIdentifiers::new(service, account)?,
            target: ReadTarget::DataProtection {
                scope: ReadScope::AllGroups,
                mode,
            },
        })
    }
}

/// A validated generic-password identity in one data protection access group.
#[derive(Debug, Clone)]
pub struct DataProtectionSecret {
    identifiers: ItemIdentifiers,
    keychain: DataProtectionKeychain,
}

#[bon::bon]
impl DataProtectionSecret {
    /// Read this exact item, allowing authentication UI.
    #[must_use]
    pub fn reader(&self) -> KeychainSecret {
        self.reader_with(SecretReadMode::Allow)
    }

    /// Read this exact item with one explicit authentication mode.
    #[must_use]
    pub fn reader_with(&self, mode: SecretReadMode) -> KeychainSecret {
        KeychainSecret {
            identifiers: self.identifiers.clone(),
            target: ReadTarget::DataProtection {
                scope: ReadScope::Group(self.keychain.access_group.clone()),
                mode,
            },
        }
    }

    /// Configure writable storage for this item.
    ///
    /// `creation_policy` applies only when creating an item. Existing items
    /// retain their policy. Reserve this identity for the application rather
    /// than adopting an item whose protection is unknown.
    /// Authentication UI is allowed unless a supplied context disables it.
    ///
    /// ```
    /// use huskarl_apple::keychain::{DataProtectionKeychain, SecretAccessPolicy};
    /// # fn example() -> Result<(), huskarl_apple::keychain::SecretError> {
    /// let item = DataProtectionKeychain::new("TEAM.io.example.app")?
    ///     .secret("io.example.oauth", "refresh-token")?;
    /// let store = item
    ///     .store()
    ///     .creation_policy(SecretAccessPolicy::default())
    ///     .build();
    /// let reader = store.reader();
    /// # Ok(())
    /// # }
    /// # example()?;
    /// # Ok::<(), huskarl_apple::keychain::SecretError>(())
    /// ```
    #[builder(finish_fn = build)]
    pub fn store(
        &self,
        #[builder(default)] creation_policy: SecretAccessPolicy,
        #[cfg(feature = "local-authentication")] authentication_context: Option<
            crate::authentication::AuthenticationContext,
        >,
    ) -> KeychainSecretStore {
        KeychainSecretStore {
            identifiers: self.identifiers.clone(),
            target: StoreTarget::DataProtection {
                access_group: self.keychain.access_group.clone(),
                creation_policy,
                #[cfg(feature = "local-authentication")]
                authentication_context,
            },
        }
    }
}

/// A validated generic-password identity in one file-backed macOS Keychain.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone)]
pub struct FileSecret {
    pub(super) identifiers: ItemIdentifiers,
    pub(super) keychain: super::FileKeychain,
}

#[cfg(target_os = "macos")]
impl FileSecret {
    /// Read this item using the file keychain's ACLs and authentication behavior.
    #[must_use]
    pub fn reader(&self) -> KeychainSecret {
        KeychainSecret {
            identifiers: self.identifiers.clone(),
            target: ReadTarget::File(self.keychain.clone()),
        }
    }

    /// Write this item using the file keychain's ACLs and authentication behavior.
    ///
    /// Data protection options are unavailable for file-backed items:
    ///
    /// ```compile_fail,E0599
    /// use huskarl_apple::keychain::{FileKeychain, SecretAccessPolicy};
    /// # fn example() -> Result<(), huskarl_apple::keychain::SecretError> {
    /// let item = FileKeychain::login().secret("service", "account")?;
    /// let store = item.store().creation_policy(SecretAccessPolicy::default());
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn store(&self) -> KeychainSecretStore {
        KeychainSecretStore {
            identifiers: self.identifiers.clone(),
            target: StoreTarget::File(self.keychain.clone()),
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct ItemIdentifiers {
    pub(super) service: String,
    pub(super) account: String,
}

impl ItemIdentifiers {
    pub(super) fn new(
        service: impl Into<String>,
        account: impl Into<String>,
    ) -> Result<Self, SecretError> {
        let service = service.into();
        let account = account.into();
        ensure!(
            !service.is_empty() && !account.is_empty(),
            ConfigurationSnafu {
                reason: "service and account must be nonempty"
            }
        );
        Ok(Self { service, account })
    }
}

#[derive(Debug, Clone)]
pub(super) enum ReadScope {
    Group(String),
    AllGroups,
}

#[derive(Debug, Clone)]
pub(super) enum ReadTarget {
    DataProtection {
        scope: ReadScope,
        mode: SecretReadMode,
    },
    #[cfg(target_os = "macos")]
    File(super::FileKeychain),
}

impl ReadTarget {
    #[cfg_attr(not(target_os = "macos"), allow(clippy::unnecessary_wraps))]
    pub(super) fn resolve(&self) -> Result<Location, SecretError> {
        match self {
            Self::DataProtection { .. } => Ok(Location::DataProtectionKeychain),
            #[cfg(target_os = "macos")]
            Self::File(keychain) => keychain.resolve(),
        }
    }

    #[cfg(feature = "local-authentication")]
    pub(super) fn context(&self) -> Option<&crate::authentication::AuthenticationContext> {
        match self {
            Self::DataProtection { mode, .. } => mode.context(),
            #[cfg(target_os = "macos")]
            Self::File(_) => None,
        }
    }
}

#[derive(Debug, Clone)]
pub(super) enum StoreTarget {
    DataProtection {
        access_group: String,
        creation_policy: SecretAccessPolicy,
        #[cfg(feature = "local-authentication")]
        authentication_context: Option<crate::authentication::AuthenticationContext>,
    },
    #[cfg(target_os = "macos")]
    File(super::FileKeychain),
}

impl StoreTarget {
    pub(super) fn reader(&self) -> ReadTarget {
        match self {
            Self::DataProtection { access_group, .. } => {
                #[cfg(feature = "local-authentication")]
                let mode = self
                    .context()
                    .cloned()
                    .map_or(SecretReadMode::Allow, SecretReadMode::Context);
                #[cfg(not(feature = "local-authentication"))]
                let mode = SecretReadMode::Allow;
                ReadTarget::DataProtection {
                    scope: ReadScope::Group(access_group.clone()),
                    mode,
                }
            }
            #[cfg(target_os = "macos")]
            Self::File(keychain) => ReadTarget::File(keychain.clone()),
        }
    }

    #[cfg_attr(not(target_os = "macos"), allow(clippy::unnecessary_wraps))]
    pub(super) fn resolve(&self) -> Result<Location, SecretError> {
        match self {
            Self::DataProtection { .. } => Ok(Location::DataProtectionKeychain),
            #[cfg(target_os = "macos")]
            Self::File(keychain) => keychain.resolve(),
        }
    }

    #[cfg(feature = "local-authentication")]
    pub(super) fn context(&self) -> Option<&crate::authentication::AuthenticationContext> {
        match self {
            Self::DataProtection {
                authentication_context,
                ..
            } => authentication_context.as_ref(),
            #[cfg(target_os = "macos")]
            Self::File(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_is_validated_without_keychain_access() -> Result<(), SecretError> {
        assert!(matches!(
            DataProtectionKeychain::new(""),
            Err(SecretError::Configuration { .. })
        ));
        let keychain = DataProtectionKeychain::new("unentitled.test.group")?;
        for (service, account) in [("", "account"), ("service", ""), ("", "")] {
            assert!(matches!(
                keychain.secret(service, account),
                Err(SecretError::Configuration { .. })
            ));
            assert!(matches!(
                DataProtectionKeychain::search_all_groups(service, account, SecretReadMode::Allow),
                Err(SecretError::Configuration { .. })
            ));
            #[cfg(target_os = "macos")]
            assert!(matches!(
                super::super::FileKeychain::login().secret(service, account),
                Err(SecretError::Configuration { .. })
            ));
        }
        // These constructors succeed without entitlement checks or OS access.
        let store = keychain.secret("service", "account")?.store().build();
        let reader = store.reader();
        assert!(
            matches!(reader.target, ReadTarget::DataProtection { scope: ReadScope::Group(ref group), .. } if group == "unentitled.test.group")
        );
        assert_eq!(reader.identifiers.service, "service");
        assert_eq!(reader.identifiers.account, "account");
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn file_paths_are_validated_without_opening() -> Result<(), SecretError> {
        use super::super::FileKeychain;
        for path in ["relative.keychain-db", "/tmp/keychain\0wrong"] {
            assert!(matches!(
                FileKeychain::at(path),
                Err(SecretError::Configuration { .. })
            ));
        }
        let store = FileKeychain::at("/nonexistent/huskarl-test.keychain-db")?
            .secret("service", "account")?
            .store();
        assert!(matches!(store.reader().target, ReadTarget::File(_)));
        Ok(())
    }

    #[test]
    fn exact_reads_and_cross_group_searches_preserve_their_scope() -> Result<(), SecretError> {
        let item = DataProtectionKeychain::new("group")?.secret("service", "account")?;
        let reader = item.reader_with(SecretReadMode::SkipProtectedItems);
        assert!(matches!(reader.target, ReadTarget::DataProtection {
            scope: ReadScope::Group(ref group), mode: SecretReadMode::SkipProtectedItems,
        } if group == "group"));
        let search = DataProtectionKeychain::search_all_groups(
            "service",
            "account",
            SecretReadMode::SkipProtectedItems,
        )?;
        assert!(matches!(
            search.target,
            ReadTarget::DataProtection {
                scope: ReadScope::AllGroups,
                mode: SecretReadMode::SkipProtectedItems,
            }
        ));
        Ok(())
    }

    #[cfg(feature = "local-authentication")]
    #[test]
    fn store_reader_preserves_shared_authentication_context() -> Result<(), SecretError> {
        let context = crate::authentication::AuthenticationContext::default();
        let store = DataProtectionKeychain::new("group")?
            .secret("service", "account")?
            .store()
            .authentication_context(context.clone())
            .build();
        let reader = store.reader();
        let Some(shared) = reader.target.context() else {
            return Err(SecretError::Configuration {
                reason: "reader lost its context",
            });
        };
        // SAFETY: These aliases are used sequentially, solely to compare identity.
        #[allow(unsafe_code)]
        unsafe {
            assert_eq!(
                objc2::rc::Retained::as_ptr(&context.to_native()),
                objc2::rc::Retained::as_ptr(&shared.to_native()),
            );
        }
        Ok(())
    }
}
