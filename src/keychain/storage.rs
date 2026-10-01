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

use super::{
    AccessControlSnafu, DeleteSnafu, KeychainSecret, SecretError, WriteSnafu, backend,
    configuration::{ItemIdentifiers, StoreTarget},
};
#[cfg(target_os = "macos")]
use super::{ConfigurationSnafu, MissingItemReferenceSnafu};
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

/// Writable storage for one validated generic-password identity.
///
/// Create through [`super::DataProtectionSecret::store`] or a file-backed item.
/// Existing items retain their access policy; no backend synchronizes with iCloud.
/// All operations run on a blocking pool. Dropping a future does not cancel an
/// in-progress Keychain operation.
#[derive(Debug, Clone)]
pub struct KeychainSecretStore {
    pub(super) identifiers: ItemIdentifiers,
    pub(super) target: StoreTarget,
}

impl KeychainSecretStore {
    /// Obtain a read provider for this exact item, sharing its authentication context.
    /// Authentication UI is allowed unless the context disables it.
    #[must_use]
    pub fn reader(&self) -> KeychainSecret {
        KeychainSecret {
            identifiers: self.identifiers.clone(),
            target: self.target.reader(),
        }
    }

    fn query(&self, location: &Location) -> ItemSearchOptions {
        let mut query = backend::query(location);
        query
            .class(ItemClass::generic_password())
            .service(&self.identifiers.service)
            .account(&self.identifiers.account);
        match &self.target {
            StoreTarget::DataProtection { access_group, .. } => {
                query.access_group(access_group);
            }
            #[cfg(target_os = "macos")]
            StoreTarget::File(_) => {}
        }
        #[cfg(feature = "local-authentication")]
        if let Some(context) = self.target.context() {
            context.apply_query(&mut query);
        }
        query
    }

    /// Read the item; only a definitive item-not-found status becomes `None`.
    ///
    /// # Errors
    /// Returns access, authentication, or malformed-result errors unchanged.
    pub async fn get(&self) -> Result<Option<SecretBytes>, SecretError> {
        let reader = self.reader();
        blocking::unblock(move || match reader.read() {
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
            #[cfg(feature = "local-authentication")]
            let _operation = store
                .target
                .context()
                .map(crate::authentication::AuthenticationContext::operation);
            let location = store.target.resolve()?;
            match store.query(&location).delete() {
                Err(error) if error.code() == errSecItemNotFound => Ok(()),
                result => result.context(DeleteSnafu),
            }
        })
        .await
    }

    fn write(&self, value: &SecretBytes) -> Result<(), SecretError> {
        #[cfg(feature = "local-authentication")]
        let _operation = self
            .target
            .context()
            .map(crate::authentication::AuthenticationContext::operation);
        let location = self.target.resolve()?;
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
            .set_service(&self.identifiers.service)
            .set_account_name(&self.identifiers.account);
        let access = match &self.target {
            StoreTarget::DataProtection {
                access_group,
                creation_policy,
                ..
            } => {
                options.set_access_group(access_group);
                creation_policy.access_control()?
            }
            #[cfg(target_os = "macos")]
            StoreTarget::File(_) => return options.add().context(WriteSnafu),
        };
        let original = options.to_dictionary();
        let (keys, values) = original.get_keys_and_values();
        let pairs: Vec<_> = keys.into_iter().zip(values).collect();
        let mut attributes = CFMutableDictionary::from_CFType_pairs(&pairs);
        // kSecAttrAccessControl; CF objects remain alive while retained here.
        attributes.set(CFString::new("accc").to_void(), access.to_void());
        #[cfg(feature = "local-authentication")]
        if let Some(context) = self.target.context() {
            context.apply_attributes(&mut attributes);
        }
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
