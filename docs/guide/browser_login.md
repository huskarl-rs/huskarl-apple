# Sign in with Apple's authentication browser

For a guided first run with a disposable server, follow
[your first native OAuth login](crate::_docs::tutorial::first_login).
To integrate this into a SwiftUI, AppKit, or UIKit app, see
[connecting an Apple UI](crate::_docs::guide::apple_app).

Enable `web-authentication` to present an OAuth login in an iOS or macOS
application. The adapter uses `ASWebAuthenticationSession`, returns the callback
URL, and dismisses the browser if the pending session is dropped. You do not need
`open` or a loopback HTTP listener for this flow.

For a complete macOS app combining browser login, Keychain persistence, Secure
Enclave DPoP, API requests, restart restoration, and logout, follow
[the native session guide](crate::_docs::guide::native_session).

```toml
[dependencies]
huskarl-apple = { version = "0.1", features = ["web-authentication"] }
```

Call the adapter from your app's main thread with the window that initiated
sign-in. On iOS, the window must belong to a foreground scene. Await the session
on an executor integrated with the main UI event loop. Do not block the main
thread with `block_on`, or move the session into `tokio::spawn`: the session is
intentionally not `Send`. The app supplies the executor and owns its UI lifecycle.

## Connect an authorization-code flow

Configure your `AuthorizationCodeGrant` with the provider's endpoints, client ID,
HTTP transport, and registered redirect URI. For OIDC, also configure the issuer
and ID-token verifier. Then pass the URL from `start` to the native session and
pass its result to `complete`:

```rust,no_run
# #[cfg(all(feature = "web-authentication", any(target_os = "macos", target_os = "ios")))]
# async fn sign_in(
#     grant: &huskarl::grant::authorization_code::AuthorizationCodeGrant,
#     window: &huskarl_apple::web_authentication::PresentationAnchor,
# ) -> Result<huskarl::grant::authorization_code::CompleteOutput, Box<dyn std::error::Error>> {
use huskarl::grant::authorization_code::StartInput;
use huskarl_apple::web_authentication::WebAuthenticationSession;

let started = grant.start(StartInput::builder().build()).await?;
let callback = WebAuthenticationSession::start()
    .authorization_url(&started.authorization_url.to_string())
    .redirect_uri(&started.pending_state.redirect_uri)
    .window(window)
    .call()?
    .await?;

let completed = grant.complete(&started.pending_state, callback.parse()?).await?;
# Ok(completed)
# }
```

The native adapter checks the callback destination. Huskarl's `complete` still
validates OAuth state, handles provider errors, and exchanges the code using the
pending flow's PKCE material. A callback URL alone is not proof of a successful
login. Persist the resulting session using your existing token storage; the
browser adapter does not store tokens. Do not log callback URLs: they contain
short-lived authorization codes and state.

## Choose a redirect

Custom schemes such as `com.example.myapp:/oauth/callback` work on macOS 10.15+
and iOS 13+. Register the exact redirect URI with your authorization server.
The session supplies the scheme to Apple; no separate app URL callback handler
is needed for the active authentication session. Reverse-domain schemes reduce
collisions with other applications.

HTTPS redirects such as `https://login.example.com/mobile/callback` require
macOS 14.4+ or iOS 17.4+. Configure the app's Associated Domains entitlement with
`webcredentials:login.example.com` and the corresponding server-side
`apple-app-site-association` file. Merely adding an `applinks` entry is not enough.
Older systems return `HttpsCallbackUnavailable`; choose a registered custom
scheme before starting the OAuth flow if those systems must be supported.

The adapter accepts HTTPS authorization URLs and query-based callbacks. For local
development, HTTP authorization URLs are allowed only for loopback IP literals
(`127.0.0.1` or `::1`), not hostnames or LAN addresses. Redirect
URIs with fixed query parameters or fragments, HTTP loopback redirects, and
HTTPS callbacks on nondefault ports are not supported. Browser `form_post`
responses need a server endpoint and are outside this adapter's scope.

## Cancellation and browser privacy

Awaiting a session returns `WebAuthenticationError::Cancelled` when the user
cancels. You can also call `cancel()` on the handle, or drop the pending future
to dismiss it. Restart login with a fresh authorization flow after cancellation.
Keep at most one login presentation active per UI flow.

By default, Apple may reuse an existing browser login with the user's consent.
Set `.prefers_ephemeral(true)` before `.call()` to request an isolated browser
session. This is a browser preference, not a logout operation or a guarantee
that the identity provider will request credentials again.

This adapter does not configure the browser's TLS client identity. The
`UrlSessionClient` mTLS identity applies to requests made by that client, such as
the token exchange, not to the system authentication browser.

See Apple's [authentication session documentation](https://developer.apple.com/documentation/authenticationservices/aswebauthenticationsession)
and [HTTPS callback documentation](https://developer.apple.com/documentation/authenticationservices/aswebauthenticationsession/callback/https(host:path:)).
