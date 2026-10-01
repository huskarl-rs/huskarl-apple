# Huskarl Apple documentation

Build an OAuth session using Apple's browser, Keychain, Secure Enclave, local
authentication, and networking. Start with [how the integrations fit together](explanation/apple_oauth.md)
for component choices and the distinction between OAuth access, OIDC identity,
and local authentication.

For a foreground app, follow the native-login path below. For a command-line
flow, use [device authorization](guide/dpop_session.md). Check
[platforms and features](reference/platforms.md) for requirements and iOS scope.

## Tutorials — learn by doing

- [Your first native OAuth login](tutorial/first_login.md): macOS and disposable
  Keycloak, without a provisioning profile or hardware key.
- [Store and retrieve your first secret](tutorial/first_secret.md): a small
  macOS login-Keychain exercise.

## How-to guides — build and operate a session

### Prepare the application

- [Add a persisted browser-login session](guide/native_session.md)
- [Connect a SwiftUI, AppKit, or UIKit UI](guide/apple_app.md), including the iOS adaptation path
- [Sign a macOS app or command-line harness](guide/signing_an_app.md)
- [Select a Keychain backend](guide/selecting_a_backend.md)
- [Select an access group](guide/access_groups.md)

### Sign in and make requests

- [Sign in with Apple's authentication browser](guide/browser_login.md)
- [Use Apple networking and TLS client identities](guide/native_networking.md)
- [Make authenticated requests with a persisted device-authorization DPoP session](guide/dpop_session.md)
- [Choose a DPoP key policy](guide/dpop_policy.md)
- [Provision a key at startup](guide/provisioning_keys.md)

### Persist, protect, and recover

- [Persist refresh tokens](guide/refresh_tokens.md)
- [Reuse local authentication and require user approval](guide/key_authentication.md)
- [Control authentication during reads](guide/secret_authentication.md)
- [Handle a missing DPoP key after device migration](guide/device_migration.md)
- [Handle rotation failure and local logout](guide/native_session.md#handle-persistence-failure-and-logout)

### Other storage and cryptography tasks

- [Read a secret](guide/reading_secrets.md)
- [Store a secret](guide/storing_secrets.md)
- [Sign, verify, seal, and unseal](guide/signing_and_sealing.md)
- [Use a stored symmetric key](guide/symmetric_crypto.md)

## Explanation — understand the design

- [How Apple integrations fit an OAuth session](explanation/apple_oauth.md)
- [Security model](explanation/security_model.md)
- [Signing and entitlements](explanation/signing_and_entitlements.md)

## Reference — look up facts

- [Platforms, Cargo features, prerequisites, and example coverage](reference/platforms.md)
- [API reference](https://docs.rs/huskarl-apple/latest/huskarl_apple/)

Build the complete local API reference with `cargo doc --all-features --no-deps --open`.

## Runnable examples and contributor checks

- [macOS browser login with disposable Keycloak](../examples/browser-login/README.md)
- [Complete macOS browser-login and persisted DPoP session](../examples/native-session/README.md)
- [macOS SwiftUI refresh-token storage](../examples/apple/README.md)
- [Experimental iOS simulator token storage](../examples/ios/README.md)
- [Run the tests](guide/testing.md)

The iOS storage example does not implement browser login. Simulator checks do not
validate hardware keys or biometric protection; see the platform reference for
separate physical-device checks.
