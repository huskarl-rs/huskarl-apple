# Choose a `DPoP` key policy

For the complete grant-to-request flow, see
[the persisted `DPoP` session guide](crate::_docs::guide::dpop_session).

For routine `DPoP` requests, create the signing key with
`Authentication::None` (the default). A `DPoP` proof requires a signature for each
protected API request. `UserPresence`, `BiometryAny`, or `BiometryCurrentSet`
therefore puts authentication on every proof operation and can prompt on every
API call. Keychain availability and application entitlements still protect a
key created with `Authentication::None`.

To require authentication when starting a session, put the requirement on the
refresh-token Keychain item through `SecretAccessPolicy` instead. Load the token
when opening the session and retain it in the application's session state; proof
signing can then proceed without a presence requirement on the `DPoP` key. See
the [refresh-token guide](crate::_docs::guide::refresh_tokens).

## Notes

Apple controls authentication reuse, so neither configuration guarantees an
exact dialog count. Reading the protected token again, or persisting a rotated
token, may require authentication again. A once-per-session experience requires
the application to manage token loading and session lifetime accordingly.

