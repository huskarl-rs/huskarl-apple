# Add a persisted browser-login session

Use this path for a foreground macOS application that needs browser sign-in,
authenticated API requests, and session restoration after restart. The runnable
[native-session example](https://github.com/huskarl-rs/huskarl-apple/tree/main/examples/native-session)
contains the complete Rust owner, Swift AppKit UI, signing task, provider
configuration, and expected results. For an initial exercise without signing
assets, start with [your first login](crate::_docs::tutorial::first_login).

## Prepare the provider and application

The complete example requires macOS 14+, supported Secure Enclave hardware, and
a signed application authorized for its Keychain access group. Follow
[signing an app](crate::_docs::guide::signing_an_app) before configuring the
example's `mise.local.toml` signing settings.

Register a public client with authorization-code flow, S256 PKCE, ES256 DPoP,
and refresh-token support. The example uses OIDC discovery for endpoints and
requires an API accepting DPoP-bound tokens. Register exactly
`io.huskarl.native-session:/oauth/callback` as its redirect URI. Select the
provider's API scopes and refresh-token requirements; do not include `openid`
in this example, which does not implement ID-token verification.

Set `ISSUER`, `CLIENT_ID`, `REDIRECT_URI`, `RESOURCE_URL`, `SCOPE`,
`HUSKARL_SESSION_ID`, and `HUSKARL_STATE_DIR` using the example README's
[configuration instructions](https://github.com/huskarl-rs/huskarl-apple/tree/main/examples/native-session#configure-and-run).
The session ID is a stable local storage slot, chosen before login. Give distinct
providers, clients, or simultaneous sessions distinct slots and state directories.

Then run from the repository root:

```sh
mise run example:native-session
```

The task builds, signs, verifies, and launches the app. Keep its terminal open.
Use **Sign in**, then **Make request**. A successful request displays the HTTP
status and response size. Quit and relaunch with the same configuration: the
first request should refresh the saved session without another browser login
while the refresh token remains valid.

## Compose the session in your application

1. **Own the saved session.** Choose stable Keychain identifiers and an enclave
   key label. Coordinate every process that can rotate that refresh token. The
   example holds a process-lifetime lock in the session's state directory.
2. **Restore credentials.** Read the token using `KeychainRefreshTokenStore` and
   load the enclave key. Compare the saved token's DPoP thumbprint with the key.
   Handle [permanent key loss](crate::_docs::guide::device_migration) separately
   from locked or denied access.
3. **Configure the grant.** Supply the provider, public-client authentication,
   HTTP client, registered redirect, and `DPoP` signer to
   `AuthorizationCodeGrant`. Preserve the pending state from each `start` call.
4. **Present login.** Pass that attempt's authorization URL to
   `WebAuthenticationSession` and its callback to `grant.complete`. Follow
   [browser login](crate::_docs::guide::browser_login) for main-thread and
   redirect requirements. Cancellation starts a fresh attempt on the next click.
5. **Persist and authorize.** Connect `GrantTokenSource` with `NoSource` for
   explicitly initiated interactive login, `InMemoryTokenCache`, and
   `HttpAuthorizer`. Prime the source with the completed token response. Persist
   its refresh token and DPoP binding, including replacements during rotation.
6. **Send requests.** Obtain authorization headers for the actual method and
   final URL, then execute the request. Pass responses back to the authorizer
   for challenge handling. The example permits one GET retry for a supported
   challenge; writes need a separate idempotency policy.

The example's
[Rust implementation](https://github.com/huskarl-rs/huskarl-apple/blob/main/examples/native-session/rust/src/lib.rs)
is the complete composition. To transfer its ownership model into SwiftUI or
UIKit, follow [connecting an Apple UI](crate::_docs::guide::apple_app).

## Handle persistence failure and logout

If the server rotates a token but Keychain persistence fails, retain the new
token in memory and report that restart recovery may fail. Do not silently
revert to the old token. Initial login persistence failure also needs an explicit
failure path. The example distinguishes these cases; storage and server rotation
cannot form a single transaction.

Gate new operations during logout, clear cached and in-memory credentials, and
remove the saved token. If deletion fails, keep requests gated and offer a logout
retry. The example retains the enclave key for future login. Local logout does
not revoke server tokens or clear provider cookies; provider logout and revocation
require separate integration.

Verify sign-in, repeated requests, restart restoration, cancellation/retry, and
logout followed by restart with the example's lifecycle walkthrough. Also check
denied Keychain access and expired refresh tokens without entering automatic
browser retry loops.

## Adapt the choices

For a provider without DPoP, keep browser PKCE and Keychain storage but adapt the
grant and authorizer for that provider's token type; the supplied complete example
intentionally rejects non-DPoP sessions. For an identity UI, configure Huskarl's
OIDC issuer and ID-token verification before displaying identity claims. See
[Huskarl's authorization-code API](https://docs.rs/huskarl/latest/huskarl/grant/authorization_code/).

For a command-line device-authorization flow, use the separate
[persisted device session](crate::_docs::guide::dpop_session). For iOS, follow the
dedicated path in [connecting an Apple UI](crate::_docs::guide::apple_app);
the complete executable above is macOS-only.
