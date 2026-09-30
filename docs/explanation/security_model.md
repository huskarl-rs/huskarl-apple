# Security model

Keychain storage protects persisted secrets; Secure Enclave keys keep private
operations in hardware. Choose the boundary that matches the application:
secret reads place bytes in process memory, whereas signing and unsealing use
an enclave-protected private key. Verification and sealing use public keys.

## Availability and authentication

Keychain **availability**, **user authentication**, and **application idle time**
are different controls. Enclave keys use the data protection Keychain. The
`SecKeychainSettings` idle interval / lock-on-sleep knobs apply to the legacy
file-based Keychain, not to this backend. There is no per-key “lock after N
minutes” or “unlock again after N seconds” setting here. macOS controls the
availability of protected key material; authentication and unlock events restore
access, not an elapsed lock duration. See Apple's [Keychain implementations
note](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains)
and [legacy locking settings](https://developer.apple.com/documentation/security/seckeychainsettings).

Availability follows the selected protection class and macOS's keybag state;
it is not an application-controlled screen-lock deadline. A class permitting
background access does not bypass an authentication constraint. The data
protection Keychain requires a user login context; it is not a system-daemon
secret store. Apple's [accessibility guide](https://developer.apple.com/documentation/security/restricting-keychain-item-accessibility)
and [background-execution guidance](https://developer.apple.com/forums/thread/724013)
explain these distinctions.

Both `SecretAccessPolicy` and `KeyAccessPolicy` use the shared
`policy::Availability` and `policy::Authentication` enums. The enclave module
also exports the original `KeyAvailability` and `KeyAuthentication` names for
compatibility. Policies apply when creating an item; updates and loads preserve
its stored protection. Changing protection requires deliberate rotation.

## Authentication UI and retries

Apple's `errSecInteractionNotAllowed` status is classified as potentially
retryable throughout setup, secret access, signing, and sealing errors. No
retry delay is supplied: recovery may require unlocking or changing the
authentication context. Callers should wait for a relevant lifecycle event or
use bounded backoff. Cancellation, authentication denial, missing entitlements,
and other statuses remain nonretryable.

This crate does not configure a reusable `LAContext`, a Touch ID grace period,
or a per-call prompt deadline. Apple's [Touch ID reuse duration](https://developer.apple.com/documentation/localauthentication/lacontext/touchidauthenticationallowablereuseduration)
is a separate authentication-context setting, not a Keychain idle timer.
Do not assume a presence policy means exactly one fresh dialog for every call.
An allowed prompt can wait for human input. Operations run on a blocking pool;
dropping a future does not cancel an Apple operation already in progress.
Generating, loading, and deleting keys are synchronous setup operations.

Finally, locking the Keychain does **not** revoke secret bytes, cached secrets,
or native AES/HMAC keys already loaded into application memory. If the host app
needs an inactivity lock, it must control its own session, clear those caches
and key handles, and gate future operations on authentication. This crate does
not change the user's screen-lock settings or lock other applications' Keychains.

## Sealed payloads

Apple's `SecKeyCreateEncryptedData` API returns an opaque ECIES blob, not a
structured JWE content-encryption result, and has no caller-AAD argument.
The sealing implementation encrypts a versioned, domain-separated payload
containing the AAD and plaintext. Opening authenticates it and checks the exact
AAD before returning plaintext. Apple's blob itself is never parsed. These
bundles are specific to this adapter and are not JWE/JWT serializations.
Asymmetric encryption does not authenticate the sender: anyone with the public
key can encrypt a new message. Use signatures when sender authentication is needed.

## Backend boundaries

The default data protection backend requires signing and authorized access
groups. File keychains support local macOS tools and follow the selected
keychain's ACLs and lock settings. Every operation stays in its selected backend;
there is no fallback or search for iCloud-synchronized items. Secure Enclave keys
always use the data protection Keychain.

Rebuilding an unsigned or ad-hoc-signed CLI can trigger authorization again even
after “Always Allow”. Approval is generally stable when reusing an unchanged
binary; reinstalling or updating it can prompt again.

## Further reading

- [Signing and entitlements](crate::_docs::explanation::signing_and_entitlements)
- [Storing secrets](crate::_docs::guide::storing_secrets)
- [Signing and sealing](crate::_docs::guide::signing_and_sealing)
- [Running tests](crate::_docs::guide::testing)
