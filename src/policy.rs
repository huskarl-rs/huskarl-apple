//! Shared availability and authentication controls for Keychain items and enclave keys.

use security_framework::access_control::ProtectionMode;
use security_framework_sys::access_control::{
    kSecAccessControlBiometryAny, kSecAccessControlBiometryCurrentSet,
    kSecAccessControlUserPresence,
};

/// Availability class requested when creating a device-only item.
///
/// These are Keychain protection classes, not application idle timers. macOS
/// controls when protected key material is available. An inaccessible key
/// fails an operation; it does not automatically unlock after a timeout.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Availability {
    /// Request `AccessibleWhenUnlockedThisDeviceOnly` (the default).
    #[default]
    WhenUnlocked,
    /// Request `AccessibleAfterFirstUnlockThisDeviceOnly` for background work.
    ///
    /// The class permits access after the first unlock following a restart,
    /// including later locked periods. It does not bypass user authentication
    /// configured separately through [`Authentication`].
    AfterFirstUnlock,
}

impl Availability {
    pub(crate) fn protection(self) -> ProtectionMode {
        match self {
            Self::WhenUnlocked => ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly,
            Self::AfterFirstUnlock => ProtectionMode::AccessibleAfterFirstUnlockThisDeviceOnly,
        }
    }
}

/// Authentication constraint attached to a new item.
///
/// The system enforces this constraint when reading secrets, signing, or
/// unsealing. Public operations (verification and encryption) require no user
/// authentication.
/// This setting is persisted with the item; loading cannot weaken it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Authentication {
    /// No additional presence or biometric constraint (the default).
    ///
    /// Keychain availability and application entitlements still apply.
    #[default]
    None,
    /// Require user presence, allowing biometrics or the system credential.
    ///
    /// On macOS, the system may offer Touch ID or the user's login password.
    /// Suitable when password fallback is needed on Macs without biometrics.
    UserPresence,
    /// Require enrolled biometrics without password fallback.
    ///
    /// Adding or removing enrolled fingerprints does not invalidate the item.
    BiometryAny,
    /// Require the biometric enrollment that existed at item creation.
    ///
    /// Changing that enrollment invalidates access. There is no password
    /// fallback; applications need a recovery or re-enrollment strategy.
    BiometryCurrentSet,
}

impl Authentication {
    pub(crate) fn flags(self) -> usize {
        match self {
            Self::None => 0,
            Self::UserPresence => kSecAccessControlUserPresence,
            Self::BiometryAny => kSecAccessControlBiometryAny,
            Self::BiometryCurrentSet => kSecAccessControlBiometryCurrentSet,
        }
    }
}
