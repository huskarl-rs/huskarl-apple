# Huskarl Apple documentation

Choose a page by what you need now. The layout follows the other huskarl crates.

## Tutorial

- [Store and retrieve your first secret](tutorial/first_secret.md)

## How-to guides

- [Make authenticated requests with a persisted `DPoP` session](guide/dpop_session.md)
- [Select an access group](guide/access_groups.md)
- [Handle a missing `DPoP` key after device migration](guide/device_migration.md)
- [Choose a `DPoP` key policy](guide/dpop_policy.md)
- [Require user authentication](guide/key_authentication.md)
- [Provision a key at startup](guide/provisioning_keys.md)
- [Read a secret](guide/reading_secrets.md)
- [Persist refresh tokens](guide/refresh_tokens.md)
- [Control authentication during reads](guide/secret_authentication.md)
- [Select a backend](guide/selecting_a_backend.md)
- [Sign a macOS app or command-line harness](guide/signing_an_app.md)
- [Sign, verify, seal, and unseal](guide/signing_and_sealing.md)
- [Store a secret](guide/storing_secrets.md)
- [Use a stored symmetric key](guide/symmetric_crypto.md)
- [Run the tests](guide/testing.md)

## Explanation

- [Security model](explanation/security_model.md)
- [Signing and entitlements](explanation/signing_and_entitlements.md)

## Reference

Use the [API reference](https://docs.rs/huskarl-apple/latest/huskarl_apple/),
or build this checkout with `cargo doc --no-deps --open`.

## Application examples

- [macOS SwiftUI refresh-token app](../examples/apple/README.md)
- [Experimental iOS simulator app](../examples/ios/README.md)

The iOS example exercises token persistence; Secure Enclave behavior still needs
physical-device validation.
