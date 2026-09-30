#[cfg(target_os = "macos")]
use std::{
    os::unix::ffi::OsStrExt as _,
    path::{Path, PathBuf},
};

use security_framework::item::{ItemSearchOptions, Location};
#[cfg(target_os = "macos")]
use security_framework::os::macos::keychain::SecKeychain;
use snafu::prelude::*;

#[cfg(target_os = "macos")]
use super::OpenKeychainSnafu;
use super::{ConfigurationSnafu, SecretError, SecretInteraction};

/// Backend used for generic-password secrets and refresh tokens.
///
/// Selection is explicit; an access failure never causes fallback. File-backed
/// keychains use macOS ACLs and existing lock settings, not data-protection
/// access groups or device-only protection. They may prompt for authorization.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeychainBackend {
    /// Data protection Keychain, requiring signing and entitlements (default).
    #[default]
    DataProtection,
    /// The current user's `~/Library/Keychains/login.keychain-db` file.
    ///
    /// Independent of which keychain is configured as the default.
    /// Home-directory resolution honors `$HOME`; `sudo` or an overridden
    /// environment may select another user's path. Use `File` to pin it.
    #[cfg(target_os = "macos")]
    Login,
    /// The current default file-based keychain, resolved on every operation.
    ///
    /// This is not necessarily the login keychain. The search list is not used.
    #[cfg(target_os = "macos")]
    DefaultFile,
    /// One existing file-based keychain at an absolute path.
    ///
    /// The crate does not create or unlock the keychain explicitly.
    #[cfg(target_os = "macos")]
    File(PathBuf),
}

impl KeychainBackend {
    pub(super) fn validate(
        &self,
        group: Option<&str>,
        interaction: SecretInteraction,
    ) -> Result<(), SecretError> {
        if *self != Self::DataProtection {
            ensure!(
                group.is_none(),
                ConfigurationSnafu {
                    reason: "access groups require the data protection backend"
                }
            );
            ensure!(
                interaction == SecretInteraction::Allow,
                ConfigurationSnafu {
                    reason: "SkipProtectedItems requires the data protection backend"
                }
            );
        }
        Ok(())
    }

    // Resolving a file backend can fail on macOS; keep the same internal API on iOS.
    #[cfg_attr(not(target_os = "macos"), allow(clippy::unnecessary_wraps))]
    pub(super) fn resolve(&self) -> Result<Location, SecretError> {
        match self {
            Self::DataProtection => Ok(Location::DataProtectionKeychain),
            #[cfg(target_os = "macos")]
            Self::DefaultFile => SecKeychain::default()
                .map(Location::FileKeychain)
                .context(OpenKeychainSnafu),
            #[cfg(target_os = "macos")]
            Self::Login => {
                let home = std::env::home_dir().context(ConfigurationSnafu {
                    reason: "cannot determine the user's home directory",
                })?;
                open(&home.join("Library/Keychains/login.keychain-db"))
            }
            #[cfg(target_os = "macos")]
            Self::File(path) => open(path),
        }
    }
}

#[cfg(target_os = "macos")]
fn open(path: &Path) -> Result<Location, SecretError> {
    ensure!(
        path.is_absolute() && !path.as_os_str().as_bytes().contains(&0),
        ConfigurationSnafu {
            reason: "keychain path must be absolute and contain no NUL bytes"
        }
    );
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

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn file_backends_reject_data_protection_options() {
        for backend in [
            KeychainBackend::Login,
            KeychainBackend::DefaultFile,
            KeychainBackend::File("/unused.keychain-db".into()),
        ] {
            assert!(matches!(
                backend.validate(Some("group"), SecretInteraction::Allow),
                Err(SecretError::Configuration { .. })
            ));
            assert!(matches!(
                backend.validate(None, SecretInteraction::SkipProtectedItems),
                Err(SecretError::Configuration { .. })
            ));
            assert!(backend.validate(None, SecretInteraction::Allow).is_ok());
        }
    }

    #[test]
    fn invalid_paths_are_rejected_before_opening() {
        for path in ["relative.keychain-db", "/tmp/keychain\0wrong"] {
            assert!(matches!(
                open(Path::new(path)),
                Err(SecretError::Configuration { .. })
            ));
        }
    }
}
