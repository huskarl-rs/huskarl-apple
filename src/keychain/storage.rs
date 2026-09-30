use bon::Builder;
use core_foundation::{
    base::ToVoid as _, data::CFData, dictionary::CFMutableDictionary, string::CFString,
};
use huskarl_core::{
    platform::MaybeSendBoxFuture,
    secrets::{Secret, SecretBytes, SecretOutput},
};
#[cfg(target_os = "macos")]
use security_framework::item::{Reference, SearchResult};
use security_framework::{
    access_control::SecAccessControl,
    item::{
        ItemAddOptions, ItemAddValue, ItemClass, ItemSearchOptions, ItemUpdateOptions,
        ItemUpdateValue, Location, update_item,
    },
};
use security_framework_sys::base::{errSecDuplicateItem, errSecItemNotFound};
use snafu::prelude::*;

#[cfg(target_os = "macos")]
use super::MissingItemReferenceSnafu;
use super::{
    AccessControlSnafu, ConfigurationSnafu, DeleteSnafu, KeychainBackend, KeychainSecret,
    SecretError, SecretInteraction, WriteSnafu, backend,
};
use crate::policy::{Authentication, Availability};

/// Device-only protection requested when creating a generic-password item.
///
/// Defaults to availability while unlocked, without additional authentication.
/// Updates preserve the existing item's policy. This policy does not configure
/// idle timers or authentication reuse; macOS controls unlocking and prompts.
#[derive(Debug, Clone, Copy, Default, Builder, PartialEq, Eq)]
pub struct SecretAccessPolicy {
    /// Availability for newly created items.
    #[builder(default)]
    pub availability: Availability,
    /// Authentication required by newly created items.
    #[builder(default)]
    pub authentication: Authentication,
}

impl SecretAccessPolicy {
    fn access_control(self) -> Result<SecAccessControl, SecretError> {
        // Generic passwords must not use the enclave's PrivateKeyUsage flag.
        SecAccessControl::create_with_protection(
            Some(self.availability.protection()),
            self.authentication.flags(),
        )
        .context(AccessControlSnafu)
    }
}

/// Writable generic-password storage in the selected Keychain backend.
///
/// The default data protection backend requires an explicit entitled access
/// group and creates device-only items. File backends instead use one selected
/// keychain and its ACLs; access groups and `SecretAccessPolicy` are rejected.
/// Existing items retain their access policy; no backend synchronizes with iCloud.
/// Reserve a service/account pair for this store rather than adopting an item
/// whose protection policy is unknown.
/// Service and account must be nonempty; operations and [`Self::reader`] validate them.
///
/// All operations run on a blocking pool and allow system authentication UI.
/// Dropping a future does not cancel an in-progress Keychain operation.
#[derive(Debug, Clone, Builder)]
pub struct KeychainSecretStore {
    /// Service identifying the application's storage namespace.
    #[builder(into)]
    service: String,
    /// Account identifying one stored secret.
    #[builder(into)]
    account: String,
    /// Required for data protection; rejected for file-backed storage.
    #[builder(into)]
    access_group: Option<String>,
    /// Data-protection creation policy; omitted means its default. Rejected for files.
    access_policy: Option<SecretAccessPolicy>,
    /// Backend to use for all operations.
    #[builder(default)]
    backend: KeychainBackend,
}

impl KeychainSecretStore {
    /// Obtain a read provider for this exact item, allowing authentication UI.
    ///
    /// # Errors
    /// Rejects empty identifiers and options incompatible with the selected backend.
    pub fn reader(&self) -> Result<KeychainSecret, SecretError> {
        self.validate()?;
        Ok(KeychainSecret::builder()
            .service(&self.service)
            .account(&self.account)
            .maybe_access_group(self.access_group.clone())
            .backend(self.backend.clone())
            .build())
    }

    fn validate(&self) -> Result<(), SecretError> {
        super::validate_identifiers(&self.service, &self.account)?;
        self.backend
            .validate(self.access_group.as_deref(), SecretInteraction::Allow)?;
        if self.backend == KeychainBackend::DataProtection {
            ensure!(
                self.access_group
                    .as_ref()
                    .is_some_and(|group| !group.is_empty()),
                ConfigurationSnafu {
                    reason: "writable data protection storage requires an explicit access group"
                }
            );
        } else {
            ensure!(
                self.access_policy.is_none(),
                ConfigurationSnafu {
                    reason: "SecretAccessPolicy requires the data protection backend"
                }
            );
        }
        Ok(())
    }

    fn query(&self, location: &Location) -> ItemSearchOptions {
        let mut query = backend::query(location);
        query
            .class(ItemClass::generic_password())
            .service(&self.service)
            .account(&self.account);
        if let Some(group) = &self.access_group {
            query.access_group(group);
        }
        query
    }

    /// Read the item; only a definitive item-not-found status becomes `None`.
    ///
    /// # Errors
    /// Returns access, authentication, or malformed-result errors unchanged.
    pub async fn get(&self) -> Result<Option<SecretBytes>, SecretError> {
        let reader = self.reader()?;
        blocking::unblock(move || match reader.read_validated() {
            Ok(value) => Ok(Some(value)),
            Err(SecretError::NotFound) => Ok(None),
            Err(error) => Err(error),
        })
        .await
    }

    /// Create or replace the secret, preserving the policy of an existing item.
    ///
    /// Updates modify the existing item in place, never delete/recreate. A concurrent creator
    /// is handled by one additional update; operations are last-writer-wins,
    /// without compare-and-swap or cross-process rotation coordination.
    ///
    /// # Errors
    /// Returns policy or Keychain errors without discarding the previous item.
    pub async fn set(&self, value: &SecretBytes) -> Result<(), SecretError> {
        let store = self.clone();
        let value = value.clone();
        blocking::unblock(move || store.write(&value)).await
    }

    /// Delete this item. Clearing an absent item succeeds.
    ///
    /// # Errors
    /// Returns access or authentication failures; these are not treated as absence.
    pub async fn clear(&self) -> Result<(), SecretError> {
        let store = self.clone();
        blocking::unblock(move || {
            store.validate()?;
            let location = store.backend.resolve()?;
            match store.query(&location).delete() {
                Err(error) if error.code() == errSecItemNotFound => Ok(()),
                result => result.context(DeleteSnafu),
            }
        })
        .await
    }

    fn write(&self, value: &SecretBytes) -> Result<(), SecretError> {
        self.validate()?;
        let location = self.backend.resolve()?;
        #[cfg(target_os = "macos")]
        if matches!(location, Location::FileKeychain(_)) {
            ensure!(
                u32::try_from(value.expose_secret().len()).is_ok(),
                ConfigurationSnafu {
                    reason: "secret exceeds the file-keychain API size limit"
                }
            );
            return upsert(
                || {
                    // The SecItemUpdate compatibility layer can ignore empty data.
                    // Update the exact legacy item instead, preserving its ACL.
                    let results = self
                        .query(&location)
                        .load_refs(true)
                        .limit(1)
                        .search()
                        .context(WriteSnafu)?;
                    let mut item = results
                        .into_iter()
                        .find_map(|result| match result {
                            SearchResult::Ref(Reference::KeychainItem(item)) => Some(item),
                            _ => None,
                        })
                        .context(MissingItemReferenceSnafu)?;
                    item.set_password(value.expose_secret()).context(WriteSnafu)
                },
                || self.add(CFData::from_buffer(value.expose_secret()), &location),
            );
        }
        let data = CFData::from_buffer(value.expose_secret());
        let mut update = ItemUpdateOptions::new();
        update.set_value(ItemUpdateValue::Data(data.clone()));
        upsert(
            || update_item(&self.query(&location), &update).context(WriteSnafu),
            || self.add(data.clone(), &location),
        )
    }

    // The wrapper has no access-control setter. Extend its dictionary through
    // safe Core Foundation APIs, as with enclave generation attributes.
    #[allow(deprecated)]
    fn add(&self, data: CFData, location: &Location) -> Result<(), SecretError> {
        let mut options = ItemAddOptions::new(ItemAddValue::Data {
            class: ItemClass::generic_password(),
            data,
        });
        options
            .set_location(match location {
                #[cfg(target_os = "macos")]
                Location::FileKeychain(keychain) => Location::FileKeychain(keychain.clone()),
                _ => Location::DataProtectionKeychain,
            })
            .set_service(&self.service)
            .set_account_name(&self.account);
        if let Some(group) = &self.access_group {
            options.set_access_group(group);
        }
        #[cfg(target_os = "macos")]
        if matches!(location, Location::FileKeychain(_)) {
            return options.add().context(WriteSnafu);
        }
        let access = self.access_policy.unwrap_or_default().access_control()?;
        let original = options.to_dictionary();
        let (keys, values) = original.get_keys_and_values();
        let pairs: Vec<_> = keys.into_iter().zip(values).collect();
        let mut attributes = CFMutableDictionary::from_CFType_pairs(&pairs);
        // kSecAttrAccessControl; CF objects remain alive while retained here.
        attributes.set(CFString::new("accc").to_void(), access.to_void());
        security_framework::item::add_item(attributes.to_immutable()).context(WriteSnafu)
    }
}

fn upsert(
    mut update: impl FnMut() -> Result<(), SecretError>,
    add: impl FnOnce() -> Result<(), SecretError>,
) -> Result<(), SecretError> {
    match update() {
        Err(SecretError::Write { source }) if source.code() == errSecItemNotFound => {}
        result => return result,
    }
    match add() {
        Err(SecretError::Write { source }) if source.code() == errSecDuplicateItem => update(),
        result => result,
    }
}

impl Secret for KeychainSecretStore {
    type Output = SecretBytes;

    fn get_secret_value(
        &self,
    ) -> MaybeSendBoxFuture<'_, Result<SecretOutput<SecretBytes>, huskarl_core::Error>> {
        Box::pin(async move {
            let value = self.get().await?.context(super::NotFoundSnafu)?;
            Ok(SecretOutput {
                value,
                identity: None,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    #[tokio::test]
    async fn empty_identifiers_block_every_operation() {
        for (service, account) in [("", "account"), ("service", ""), ("", "")] {
            let backends = [
                KeychainBackend::DataProtection,
                // An invalid file path checks validation precedes opening a keychain.
                #[cfg(target_os = "macos")]
                KeychainBackend::File("relative.keychain-db".into()),
            ];
            for backend in backends {
                let store = KeychainSecretStore::builder()
                    .service(service)
                    .account(account)
                    .backend(backend)
                    .build();
                assert_empty_identifiers(store.reader());
                assert_empty_identifiers(store.get().await);
                assert_empty_identifiers(store.set(&SecretBytes::new(vec![1])).await);
                assert_empty_identifiers(store.clear().await);
                assert!(matches!(store.get_secret_value().await, Err(error)
                        if error.to_string().contains("service and account must be nonempty")));
            }
        }
    }

    fn assert_empty_identifiers<T>(result: Result<T, SecretError>) {
        assert!(matches!(
            result.err(),
            Some(SecretError::Configuration {
                reason: "service and account must be nonempty"
            })
        ));
    }

    #[tokio::test]
    async fn incompatible_configuration_blocks_every_operation() {
        let stores = [
            KeychainSecretStore::builder()
                .service("test")
                .account("test")
                .build(),
            KeychainSecretStore::builder()
                .service("test")
                .account("test")
                .backend(KeychainBackend::Login)
                .access_group("group")
                .build(),
            KeychainSecretStore::builder()
                .service("test")
                .account("test")
                .backend(KeychainBackend::Login)
                .access_policy(SecretAccessPolicy::default())
                .build(),
        ];
        for store in stores {
            assert!(matches!(
                store.reader(),
                Err(SecretError::Configuration { .. })
            ));
            assert!(matches!(
                store.get().await,
                Err(SecretError::Configuration { .. })
            ));
            assert!(matches!(
                store.set(&SecretBytes::new(vec![1])).await,
                Err(SecretError::Configuration { .. })
            ));
            assert!(matches!(
                store.clear().await,
                Err(SecretError::Configuration { .. })
            ));
            assert!(store.get_secret_value().await.is_err());
        }
    }

    fn status(code: i32) -> SecretError {
        SecretError::Write {
            source: security_framework::base::Error::from_code(code),
        }
    }

    #[test]
    fn upsert_does_not_create_after_access_failures() {
        for code in [
            crate::platform::ERR_SEC_INTERACTION_NOT_ALLOWED,
            -25293,
            -34018,
            -128,
        ] {
            let mut added = false;
            let result = upsert(
                || Err(status(code)),
                || {
                    added = true;
                    Ok(())
                },
            );
            assert!(!added);
            assert!(matches!(result, Err(SecretError::Write { source }) if source.code() == code));
        }
    }

    #[test]
    fn upsert_handles_concurrent_creation_once() {
        let calls = RefCell::new(Vec::new());
        let mut updates = 0;
        let result = upsert(
            || {
                calls.borrow_mut().push("update");
                updates += 1;
                if updates == 1 {
                    Err(status(errSecItemNotFound))
                } else {
                    Ok(())
                }
            },
            || {
                calls.borrow_mut().push("add");
                Err(status(errSecDuplicateItem))
            },
        );
        assert!(result.is_ok());
        assert_eq!(*calls.borrow(), ["update", "add", "update"]);
    }

    #[test]
    fn upsert_stops_when_the_racing_item_disappears() {
        let mut updates = 0;
        let result = upsert(
            || {
                updates += 1;
                Err(status(errSecItemNotFound))
            },
            || Err(status(errSecDuplicateItem)),
        );
        assert_eq!(updates, 2);
        assert!(
            matches!(result, Err(SecretError::Write { source }) if source.code() == errSecItemNotFound)
        );
    }

    #[test]
    fn successful_update_does_not_recreate_item() {
        let mut added = false;
        assert!(
            upsert(
                || Ok(()),
                || {
                    added = true;
                    Ok(())
                }
            )
            .is_ok()
        );
        assert!(!added);
    }

    #[test]
    fn generic_password_policies_are_accepted() -> Result<(), SecretError> {
        for availability in [Availability::WhenUnlocked, Availability::AfterFirstUnlock] {
            for authentication in [
                Authentication::None,
                Authentication::UserPresence,
                Authentication::BiometryAny,
                Authentication::BiometryCurrentSet,
            ] {
                SecretAccessPolicy::builder()
                    .availability(availability)
                    .authentication(authentication)
                    .build()
                    .access_control()?;
            }
        }
        Ok(())
    }
}
