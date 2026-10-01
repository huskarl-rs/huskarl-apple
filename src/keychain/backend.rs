#[cfg(target_os = "macos")]
use std::{
    os::unix::ffi::OsStrExt as _,
    path::{Path, PathBuf},
};

use security_framework::item::{ItemSearchOptions, Location};
#[cfg(target_os = "macos")]
use security_framework::os::macos::keychain::SecKeychain;
#[cfg(target_os = "macos")]
use snafu::prelude::*;

#[cfg(target_os = "macos")]
use super::OpenKeychainSnafu;
#[cfg(target_os = "macos")]
use super::{ConfigurationSnafu, SecretError};

/// A file-backed macOS Keychain location.
///
/// Construction validates the location without opening or unlocking a keychain.
/// File keychains use their existing ACLs and lock settings, and may prompt.
/// Data protection policies, access groups, and authentication contexts are not
/// available on this backend.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileKeychain {
    location: FileLocation,
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, PartialEq, Eq)]
enum FileLocation {
    Login,
    Default,
    Path(PathBuf),
}

#[cfg(target_os = "macos")]
impl FileKeychain {
    /// Select the current user's login keychain, independently of the default.
    /// Home-directory resolution honors `$HOME`; use [`Self::at`] to pin a path.
    #[must_use]
    pub fn login() -> Self {
        Self {
            location: FileLocation::Login,
        }
    }

    /// Select the current default file keychain, resolved on every operation.
    #[must_use]
    pub fn default_file() -> Self {
        Self {
            location: FileLocation::Default,
        }
    }

    /// Select an existing file keychain without opening it.
    ///
    /// # Errors
    /// Rejects relative paths and paths containing NUL bytes.
    pub fn at(path: impl Into<PathBuf>) -> Result<Self, SecretError> {
        let path = path.into();
        ensure!(
            path.is_absolute() && !path.as_os_str().as_bytes().contains(&0),
            ConfigurationSnafu {
                reason: "keychain path must be absolute and contain no NUL bytes"
            }
        );
        Ok(Self {
            location: FileLocation::Path(path),
        })
    }

    /// Address one generic-password item without accessing the Keychain.
    ///
    /// # Errors
    /// Rejects empty service or account identifiers.
    pub fn secret(
        &self,
        service: impl Into<String>,
        account: impl Into<String>,
    ) -> Result<super::FileSecret, SecretError> {
        Ok(super::FileSecret {
            identifiers: super::ItemIdentifiers::new(service, account)?,
            keychain: self.clone(),
        })
    }

    pub(super) fn resolve(&self) -> Result<Location, SecretError> {
        match &self.location {
            FileLocation::Default => SecKeychain::default()
                .map(Location::FileKeychain)
                .context(OpenKeychainSnafu),
            FileLocation::Login => {
                let home = std::env::home_dir().context(ConfigurationSnafu {
                    reason: "cannot determine the user's home directory",
                })?;
                open(&home.join("Library/Keychains/login.keychain-db"))
            }
            FileLocation::Path(path) => open(path),
        }
    }
}

#[cfg(target_os = "macos")]
fn open(path: &Path) -> Result<Location, SecretError> {
    SecKeychain::open(path)
        .map(Location::FileKeychain)
        .context(OpenKeychainSnafu)
}

pub(super) fn query(location: &Location) -> ItemSearchOptions {
    #[cfg(not(target_os = "macos"))]
    let _ = location;
    #[cfg_attr(not(target_os = "macos"), allow(unused_mut))]
    let mut query = ItemSearchOptions::new();
    #[cfg(target_os = "macos")]
    match location {
        Location::FileKeychain(keychain) => {
            query.keychains(std::slice::from_ref(keychain));
        }
        _ => {
            query.ignore_legacy_keychains();
        }
    }
    query
}
