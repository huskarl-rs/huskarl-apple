# Platforms, features, and example coverage

The crate requires Rust 1.92 or newer. Its documented macOS baseline is 10.15;
iOS support is experimental. Example applications have their own requirements,
listed below. This crate does not document support for tvOS, watchOS, or visionOS.

## Cargo features

The three optional integrations are opt-in; Keychain and Secure Enclave APIs do
not require a feature flag.

| API | Cargo feature | Runtime prerequisites |
|---|---|---|
| `keychain` data protection storage | None | Authorized access group and appropriate app signing; iOS uses its normal Keychain backend |
| `FileKeychain` | None | macOS only; login or explicitly selected file Keychain |
| `secure_enclave` | None | Supported physical hardware and access to the data protection Keychain |
| `authentication::AuthenticationContext` | `local-authentication` | Protection policy on the item; Face ID usage description on iOS when using Face ID |
| `web_authentication::WebAuthenticationSession` | `web-authentication` | macOS 10.15+ or iOS 13+; main thread, running UI loop, and presentation window |
| HTTPS browser callback | `web-authentication` | macOS 14.4+ or iOS 17.4+; associated-domain configuration |
| `urlsession::UrlSessionClient` | `urlsession` | Apple networking; TLS client identity optional |

For all optional integrations:

```toml
[dependencies]
huskarl-apple = { version = "0.1", features = ["web-authentication", "urlsession", "local-authentication"] }
```

The crate is a Rust library. Swift applications supply a bridge; the examples
contain application-specific C interfaces, not a packaged Swift SDK.

## Browser adapter constraints

| Setting | Supported values or behavior |
|---|---|
| Authorization URL | HTTPS; development HTTP only on loopback IP literals |
| Custom-scheme callback | Exact registered redirect; no fixed query or fragment |
| HTTPS callback | Default HTTPS port; associated domain using `webcredentials` and server AASA configuration |
| OAuth response | Query-based callback; no browser `form_post` receiver |
| HTTP loopback callback | Unsupported by this adapter |
| Presentation | `NSWindow` on macOS; foreground-scene `UIWindow` on iOS |
| Executor | Session is not `Send`; creation, polling, cancellation, and destruction stay on the main thread |

Callback requirements and fallback selection are described in
[browser login](crate::_docs::guide::browser_login). Apple's
[HTTPS callback reference](https://developer.apple.com/documentation/authenticationservices/aswebauthenticationsession/callback/https(host:path:))
describes domain association.

## Executable examples and validation scope

| Example or task | Requirements | What it exercises |
|---|---|---|
| `test:browser` / `examples/browser-login` | macOS 14+, Xcode, Docker; ad-hoc signing | Browser authorization-code/PKCE, custom-scheme callback, cancellation; no persisted session or ID-token validation |
| `example:native-session` | macOS 14+, signing profile, Secure Enclave, configured DPoP provider and API | Browser login, persisted refresh token, DPoP API requests, restart and local logout |
| `examples/dpop_session.rs` | Signed macOS harness, Secure Enclave, device-authorization provider and API | Device authorization, persistence, DPoP requests |
| `example:macos` | Signed macOS SwiftUI app | Disposable token storage across launches |
| `example:ios` | Xcode and iOS 18+ simulator runtime | Disposable token storage; no browser login or hardware-key validation |
| `test:ios` | iOS simulator | Native adapter tests; not a complete browser-login UI walkthrough |
| `test:ios-device`, `test:oauth-ios` | Provisioned physical iPhone; additional server setup for OAuth | Hardware mTLS and OAuth checks; not a complete native browser-session example |

Tasks describe available checks, not a guarantee that every deployment or provider
has been tested. Simulator results do not establish physical-device biometric,
Keychain protection, or Secure Enclave behavior. Follow
[testing](crate::_docs::guide::testing) for the exact task prerequisites.

## Build the API reference

On macOS, build all optional modules from this checkout with:

```sh
cargo doc --all-features --no-deps --open
```

The published docs.rs configuration also enables all three integrations. Default
feature builds omit their API modules. The [API reference](https://docs.rs/huskarl-apple/latest/huskarl_apple/)
documents individual types, builders, errors, and methods.
