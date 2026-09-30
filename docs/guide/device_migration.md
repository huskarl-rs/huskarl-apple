# Handle a missing `DPoP` key after device migration

Secure Enclave keys are device-only: restoring an app or backup to a new device
does not transfer its `DPoP` private key. Treat a definitively missing key for an
existing session as **sign in again**, an expected recovery path. Generate a new
`DPoP` key for the new sign-in and obtain tokens bound to that key.

If a refresh token survives through some other storage or restore mechanism,
its old `DPoP` binding still requires the original key. A replacement key with the
same label cannot use that token. Stop using the old session and discard its
unusable token state as part of reauthentication. This also applies when a key
has been deleted or otherwise permanently lost.

## Notes

Use `load` to check the key belonging to an existing session. If startup uses
`load_or_generate`, compare the loaded token's `DPoP` thumbprint with the returned
key before using the token; successful key creation does not restore the old
session. Locked access, canceled authentication, and other lookup failures are
not proof of key loss. Preserve the session state and handle those failures
separately instead of replacing the key or clearing tokens.

