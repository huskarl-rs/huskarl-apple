use bon::Builder;
use security_framework::access_control::SecAccessControl;
use security_framework_sys::access_control::kSecAccessControlPrivateKeyUsage;
use snafu::ResultExt as _;

use super::{AccessControlSnafu, SetupError};
use crate::policy::{Authentication, Availability};

/// Persistent access policy for newly generated Secure Enclave keys.
///
/// The default requests device-only access while unlocked with no additional
/// human acknowledgement. Changing this value does not update existing keys:
/// generate a new key with the desired policy and rotate to it.
///
/// This policy does not configure `LAContext` reuse or promise a fresh prompt
/// for every call. It also does not impose a timeout on an authentication UI.
#[derive(Debug, Clone, Copy, Default, Builder, PartialEq, Eq)]
pub struct KeyAccessPolicy {
    /// Requested availability class, defaulting to [`Availability::WhenUnlocked`].
    #[builder(default)]
    pub availability: Availability,
    /// Private-operation authentication, defaulting to [`Authentication::None`].
    #[builder(default)]
    pub authentication: Authentication,
}

impl KeyAccessPolicy {
    pub(super) fn access_control(self) -> Result<SecAccessControl, SetupError> {
        SecAccessControl::create_with_protection(
            Some(self.availability.protection()),
            kSecAccessControlPrivateKeyUsage | self.authentication.flags(),
        )
        .context(AccessControlSnafu)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framework_accepts_supported_policy_combinations() -> Result<(), SetupError> {
        // Constructs real SecAccessControl objects, without creating keys,
        // requiring enrolled biometrics, or presenting authentication UI.
        for availability in [Availability::WhenUnlocked, Availability::AfterFirstUnlock] {
            for authentication in [
                Authentication::None,
                Authentication::UserPresence,
                Authentication::BiometryAny,
                Authentication::BiometryCurrentSet,
            ] {
                KeyAccessPolicy::builder()
                    .availability(availability)
                    .authentication(authentication)
                    .build()
                    .access_control()?;
            }
        }
        Ok(())
    }
}
