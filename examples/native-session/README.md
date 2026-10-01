# Complete macOS native session

For the integration recipe, start with
[adding a persisted browser-login session](../../docs/guide/native_session.md).
For adapting the bridge to your application, see
[connecting an Apple UI](../../docs/guide/apple_app.md).
The [first-login tutorial](../../docs/tutorial/first_login.md) provides a smaller
starting point without provisioning assets.

A signed AppKit application with a Rust session owner:

```text
ASWebAuthenticationSession → authorization code + PKCE/state validation
                                         ↓
Secure Enclave DPoP key ←→ Keychain refresh token + key binding
                                         ↓
GrantTokenSource → InMemoryTokenCache → HttpAuthorizer → URLSession GET
```

The app restores credentials at launch, offers **Sign in**, **Make request**,
**Cancel sign-in**, and **Log out**, and preserves the session when quitting.
On the next launch, its first API request refreshes the saved token. Tokens,
authorization codes, and response bodies stay inside Rust; the UI receives only
status text and response sizes.

## Requirements and provider setup

- macOS 14+, Xcode command-line tools, Rust 1.92+, and Secure Enclave hardware.
- A signing identity and provisioning profile authorizing the app identifier
  and Keychain access group. Follow [signing an app](../../docs/guide/signing_an_app.md)
  and the existing `mise.local.toml.example` configuration.
- An HTTPS OAuth authorization server with OIDC discovery, authorization-code
  flow, S256 PKCE, ES256 DPoP, and refresh tokens for public clients.
- An HTTPS API that accepts the server's DPoP-bound access tokens and verifies
  their proofs. Register `io.huskarl.native-session:/oauth/callback` as an allowed
  redirect URI for the OAuth client, matching the configuration below exactly.

This is an OAuth API-access example. It uses OIDC discovery to obtain endpoints,
but does not request or validate an ID token or display an asserted user identity.
Do not include `openid` in `SCOPE`. For an OIDC identity UI, configure Huskarl's
ID-token verification before using identity claims.

## Configure and run

Keep the signing configuration in the gitignored `mise.local.toml`. Configure
the provider in the shell used to launch the task:

```sh
export ISSUER='https://issuer.example.com/realms/example'
export CLIENT_ID='your-public-client'
export REDIRECT_URI='io.huskarl.native-session:/oauth/callback'
export RESOURCE_URL='https://api.example.com/v1/profile'
export SCOPE='read offline_access'
export HUSKARL_SESSION_ID='example-api-primary'
export HUSKARL_STATE_DIR="$HOME/Library/Application Support/HuskarlNativeSession/$HUSKARL_SESSION_ID"
mkdir -p "$HUSKARL_STATE_DIR"
chmod 700 "$HUSKARL_STATE_DIR"
mise run example:native-session
```

`REDIRECT_URI` is the callback destination registered with your OAuth provider.
For this native example, use the custom-scheme URI above. Apple's authentication
session receives the callback directly; there is no localhost HTTP listener to
configure. The native browser adapter does not support `http://localhost` or
`http://127.0.0.1` redirect URIs. If you choose another custom scheme, set
`REDIRECT_URI` to that URI and register the identical value with the provider.

Replace the scopes with your provider's API scopes. `offline_access` alone does
not guarantee a refresh token. The app requires both access and refresh tokens
to be DPoP-bound to its enclave key and refuses requests without a DPoP proof.
If your provider requires resource indicators, add those to `StartInput` and the
grant's refresh configuration as described in Huskarl's authorization-code guide.

`HUSKARL_ACCESS_GROUP` can select a profile-authorized group; otherwise the build
script uses `HUSKARL_TEST_ACCESS_GROUP`, then the application's identifier.
`HUSKARL_BUNDLE_ID` selects a concrete bundle identifier for wildcard profiles.
The script validates the profile, builds and signs the app, verifies its signature,
then runs its bundle executable with your shell's configuration. Keep that terminal
open. Relaunch with the same command and configuration to restore the session.

### Choose a local session name

`HUSKARL_SESSION_ID` names a **local saved-session slot**. Choose a stable label
for the session you want to save and restore. Internally, the example maps it to
the Keychain item's `account` field and the enclave key label. It stays local to
the app and is independent of the person who signs in.

For one saved session, use a stable label such as `example-api-primary`. Choose
it before signing in; you do not need to know the eventual user's identity.
The example uses this label to identify the refresh-token Keychain item and the
Secure Enclave key. Keep the same label and state directory across launches to
restore that session. Changing the label selects a different slot and leaves
the old slot's credentials stored.

Use different labels and state directories for different providers, OAuth clients,
or simultaneous user sessions, such as `example-api-primary` and
`example-api-secondary`. This example manages one slot per app process. To replace
the user in an existing slot, complete **Log out** before signing in again.
All processes using the same slot must use the same state directory so they
share the refresh-token ownership lock. The path above incorporates the label;
use a simple label without path separators.

For a signed build without launching:

```sh
mise run example:native-session --build-only
```

For compilation on a machine without provisioning assets:

```sh
mise run example:native-session --build-only --unsigned
```

The unsigned option creates an ad-hoc compile-only bundle. It cannot validate
Secure Enclave or entitled Keychain operations. The app is generated under
`target/native-session/HuskarlNativeSession.app`.

## Walk through the complete lifecycle

1. Launch. With no saved credentials, choose **Sign in** and authorize the system
   browser. The flow validates the callback destination, OAuth state, and PKCE.
2. Complete login and authorize Keychain access when requested. Choose
   **Make request** twice; the cache reuses the access token while each request
   receives a fresh DPoP proof. The UI shows the HTTP status and response size.
3. Quit with no operation pending and relaunch with the same configuration.
   Authorize the saved token read. **Make request** refreshes the session without
   presenting a new browser login while the refresh token remains valid.
4. Choose **Log out**, wait for successful removal, then quit and relaunch.
   The app should report no saved session, and requests require a new sign-in.
5. Start sign-in and choose **Cancel sign-in**, or cancel in the browser. The app
   returns to an idle state and can start a fresh authorization flow.

**Retry restore** retries initialization after a network, configuration, or
Keychain access failure. Once initialized, use the other controls. An expired
refresh token leads to an explicit sign-in action rather than an automatic
browser loop. A definitively lost/replaced device key invalidates its old token
binding; the app removes that unusable token and asks for a new sign-in. Locked
or denied key access does not count as key loss and does not erase credentials.
**Log out** also removes saved credentials after initialization fails, without
requiring provider discovery or access to the enclave key. It still takes the
session ownership lock and requires permission to delete the Keychain item.

## Session ownership and UI execution

The example permits one operation at a time. A process-lifetime `session.lock`
also prevents multiple app instances from rotating the same saved token. Every
process using this token item must use the same state directory and ownership
protocol. Keep both lock files on disk; replacing one can split lock ownership.

AppKit's timer polls the Rust future once every 50 ms on the main thread, entering
a current-thread Tokio runtime only for that single poll. It immediately returns
to the UI event loop rather than blocking on completion. Browser creation,
polling, cancellation, and destruction all remain on the main thread. Keychain
operations and key provisioning use the adapter's blocking pool through async APIs.
The app rejects closing/quitting while an operation is pending. Browser login
can be cancelled; dropping a pending Keychain operation would not cancel a
native operation already in progress.

## Protection and recovery

New refresh-token items require user presence; the session reads the item once
into zeroizing memory. Writes can still prompt during rotation, and Apple controls
authentication reuse. The signing key uses device-only, while-unlocked access
without an additional presence requirement, so proofs do not demand Touch ID
on every API call. Existing items keep their stored policy; builder changes do
not upgrade old protection.

A failed write after server-side token rotation retains the new token in memory
and displays a warning that restart recovery may fail. Initial sign-in persistence
failure is reported and requires another sign-in. This is not a transaction with
the authorization server; a crash during rotation can still require login again.

Logout clears the access-token cache and session-memory refresh token, then
removes the saved token. A failed Keychain deletion leaves requests gated and
asks you to retry **Log out**. Quitting at that point may leave a saved credential.
The enclave key is retained for future sign-ins; delete it only when deliberately
retiring the key and all sessions bound to it. Local logout does not revoke tokens
at the server or clear browser/provider cookies. An ephemeral browser preference
does not implement provider logout.

Network and access failures preserve credentials. Each response is passed to the
authorizer; a nonce or explicit `invalid_token` challenge permits one GET retry
with new headers. Redirects are disabled and response buffering is bounded by
URLSession's default 1 MiB limit. Use the final API URL. Do not generalize the GET
retry to writes without an API idempotency contract.

For an application inactivity lock, also drop its source/cache/session state and
gate operations. Locking Keychain does not revoke secrets already in memory.

## Automated checks

```sh
cargo test --locked --manifest-path examples/native-session/rust/Cargo.toml
cargo clippy --locked --manifest-path examples/native-session/rust/Cargo.toml --all-targets -- -D warnings
python3 scripts/native-session.py --build-only --unsigned
```

Unit tests exercise rotation persistence failure and failed logout cleanup.
Compilation checks the Rust/Swift bridge and native app. Full browser login,
restart persistence, authenticated API access, and logout require the configured
provider and signed hardware app; perform the lifecycle walkthrough above.
