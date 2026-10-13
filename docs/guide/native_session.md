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

Set `ISSUER`, `CLIENT_ID`, `REDIRECT_URI`, `RESOURCE_URL`, and `SCOPE` using the example README's
[configuration instructions](https://github.com/huskarl-rs/huskarl-apple/tree/main/examples/native-session#configure-and-run).
The launcher supplies a default `HUSKARL_SESSION_ID` of `example-api-primary`
and creates `HUSKARL_STATE_DIR` under
`~/Library/Application Support/HuskarlNativeSession/<session-id>`.
Both can be overridden. The session ID is a stable local storage slot, chosen before login. Give distinct
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

## Own the session with `AppleSession`

Enable `session` (and `urlsession` if using Apple's HTTP transport).
The application supplies a main-thread executor; see
[the application integration guide](crate::_docs::guide::apple_app). Supply an
existing `AuthorizationCodeGrant` and a dedicated `KeychainRefreshTokenStore`:

```rust,no_run
# #[cfg(all(feature = "session", any(target_os = "macos", target_os = "ios")))]
# fn configure(grant: huskarl::grant::authorization_code::AuthorizationCodeGrant,
#     store: huskarl_apple::keychain::KeychainRefreshTokenStore,
#     main_thread: objc2::MainThreadMarker) {
use huskarl_apple::session::AppleSession;

let (session, driver) = AppleSession::builder()
    .grant(grant)
    .refresh_store(store)
    .main_thread(main_thread)
    .build();

// Schedule driver.run() on your main-thread executor before awaiting operations.
// Keep it running until session.shutdown().await completes.
# let _ = (session, driver);
# }
```

The grant retains provider configuration, client authentication, redirect URI,
transport, OIDC verification and DPoP signing. The controller uses the same grant
for interactive completion and refresh. Each attempt accepts the existing
`StartInput`, with native presentation and token-endpoint resource options separate:

```rust,no_run
# #[cfg(all(feature = "session", any(target_os = "macos", target_os = "ios")))]
# async fn interact(session: &huskarl_apple::session::AppleSession,
#     window: &huskarl_apple::web_authentication::PresentationAnchor)
#     -> Result<(), huskarl_apple::session::SessionError> {
use huskarl::grant::authorization_code::StartInput;
use huskarl_apple::session::{SessionPhase, SignInOptions};

let state = session.restore().await?;
if state.phase == SessionPhase::SignedOut {
    let outcome = session.sign_in(
        window,
        StartInput::builder().scope(vec!["read".into()]).build(),
        SignInOptions::default(),
    ).await?;
    // outcome.id_token is verified by the configured grant, if present.
    // Access and refresh tokens remain inside the controller.
    let _ = outcome;
}

let access = session.access()?;
let method = http::Method::GET;
let uri = "https://api.example.com/profile".parse().unwrap();
let headers = access.get_headers(&method, &uri).await?;
// Send the request with these headers, then call:
// access.process_response(&uri, &response.headers).await?;
let _ = headers;
# Ok(())
# }
```

`subscribe()` is a coalescing stream of secret-free snapshots; `snapshot()` reads
one synchronously. `Ready` means local credentials are available, not that the
server has verified a restored refresh token. The first request refreshes it.
A failed rotation write reports `Ready` with `UnsavedChanges`, retaining the new
token in memory. A definitively rejected refresh reports `ReauthenticationRequired`.
Temporary network failures do not sign the user out.

The controller owns the browser attempt, source, cache, and authorizer. It
serializes credential operations while your HTTP requests can run concurrently.
`SessionAccess` handles are revoked on lock/logout/new login, including responses
arriving from an older generation. Already-issued headers and sent requests
cannot be retracted. Retry GET challenges explicitly; do not retry writes without
an API idempotency contract.

## Authorize requests from background Rust tasks

`AppleSession` and its driver stay on the main thread. The `SessionAccess`
returned by `session.access()` is `Send + Sync`; clone or move it into background
workers. Both authorization methods return owned `Send` futures. For example,
with an existing Tokio runtime:

```rust,no_run
# #[cfg(all(feature = "session", any(target_os = "macos", target_os = "ios")))]
# fn background(session: &huskarl_apple::session::AppleSession)
#     -> Result<(), huskarl_apple::session::SessionError> {
let access = session.access()?;
tokio::spawn(async move {
    let uri = http::Uri::from_static("https://api.example.com/profile");
    let headers = access.get_headers(&http::Method::GET, &uri).await?;
    // Send the request in this worker, then await
    // access.process_response(&uri, &response.headers).
    Ok::<_, huskarl_apple::session::SessionError>(headers)
});
# Ok(())
# }
```

The main-thread driver must continue running while workers await results. Do not
block the AppKit thread waiting for a worker. Authorization and response processing
remain serialized by the driver; HTTP execution belongs to the worker. Lock,
logout, or another login revokes existing handles. Obtain a new handle from the
controller after it becomes ready again. Requests made after the driver stops
return `SessionError::Closed`.

## Cancellation, locking, and logout

`cancel_sign_in()` or dropping its result future cancels browser/network work.
If credential persistence has begun, the driver finishes it and removes the
cancelled attempt's credentials before allowing another login. Other operation
futures may be dropped without cancelling their queued work.

`lock()` immediately gates access, waits for credential mutations, and drops token
memory while retaining saved credentials. Call `restore()` to resume. It does not
invalidate authentication contexts embedded in the supplied key/store or promise
a fresh biometric prompt. Configure those adapters' policies explicitly; if you
invalidate a context yourself, rebuild adapters with a fresh context before reuse.

`logout()` immediately gates access, settles outstanding writes, and deletes the
saved token. Failed deletion leaves `CleanupRequired`; retry logout. Binding
mismatches on restore also require explicit logout and preserve the stored token
until that action. Local logout does not revoke server tokens, delete the signing
key, or clear provider cookies.

`shutdown()` drains outstanding work and stops the driver while retaining saved
credentials. Await it before stopping the executor. Dropping the driver cannot
cancel a native Keychain operation already running on a worker. The example
refuses termination while busy, then defers AppKit termination until shutdown
and driver exit complete.

Use one controller per saved-session slot. The application must coordinate other
processes using the same slot; the example retains a file lock for the driver's
lifetime. Do not mutate the supplied store or grant through external clones.

The [native example](https://github.com/huskarl-rs/huskarl-apple/tree/main/examples/native-session)
uses this controller directly. Its Rust bridge contains application configuration,
HTTP execution, and completion callbacks, rather than a second session implementation.

## Adapt the choices

For a provider without DPoP, keep browser PKCE and Keychain storage but adapt the
grant and authorizer for that provider's token type; the supplied complete example
uses a DPoP-configured grant. The controller itself supports bearer sessions too. For an identity UI, configure Huskarl's
OIDC issuer and ID-token verification before displaying identity claims. See
[Huskarl's authorization-code API](https://docs.rs/huskarl/latest/huskarl/grant/authorization_code/).

For a command-line device-authorization flow, use the separate
[persisted device session](crate::_docs::guide::dpop_session). For iOS, follow the
dedicated path in [connecting an Apple UI](crate::_docs::guide::apple_app);
the complete executable above is macOS-only.
