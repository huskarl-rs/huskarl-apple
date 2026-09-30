# Signing and entitlements

## Which backend needs provisioning?

Secure Enclave keys and the default secret backend use the macOS **data
protection Keychain**. The `keychain-access-groups` entitlement must be authorized
by a provisioning profile. Signing a bare Cargo executable with an entitlements
file does not supply that authorization: package it in an app-like bundle and
embed the matching profile before signing.

Secrets and refresh tokens can instead use `KeychainBackend::Login`,
`DefaultFile`, or `File(path)` without provisioning. Those backends retain the
file keychain's ACLs and lock settings; they do not enable Secure Enclave keys.
See [selecting a backend](crate::_docs::guide::selecting_a_backend).

Apple describes the requirements in [TN3137: Mac keychains][keychains],
[TN3125: Provisioning profiles][profiles], and
[wrapping a command-line executable in an app-like bundle][bundle-guide].
Although the last article discusses daemons, run this crate's data protection
examples and tests in a **logged-in user session**, not a system daemon or via
`sudo`. Packaging does not remove the backend's user-login requirement.

## Identity, entitlements, and provisioning

A code signature identifies an executable and protects its integrity. A
provisioning profile authorizes restricted entitlement claims. The executable's
application identifier and access groups must fit that authorization; a valid
signature alone does not establish access to the data protection Keychain.

The App ID prefix and Team ID are distinct identifiers; they need not be
identical. A profile describes allowed claims, while an executable requests the
subset it needs. See [Apple's App ID prefix guidance][prefixes].

A bundle carries the original signed profile alongside the executable and its
metadata. Keep those artifacts together when running the program. Rebuilding or
changing bundle contents requires signing again. Hardened Runtime and
notarization are distribution requirements, not substitutes for provisioning.

## Secure Enclave support

Signing and sealing keys require an Apple Silicon Mac or a supported Intel Mac
with Secure Enclave hardware; there is no software fallback. Defaults request
device-only protection while unlocked, without additional human acknowledgement.
Loading retains the stored policy; see
[key authentication](crate::_docs::guide::key_authentication).
The signing and sealing examples use disposable labels and explicitly delete their keys.

[keychains]: https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains
[profiles]: https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles
[bundle-guide]: https://developer.apple.com/documentation/xcode/signing-a-daemon-with-a-restricted-entitlement
[prefixes]: https://developer.apple.com/library/archive/technotes/tn2311/_index.html
