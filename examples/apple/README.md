# SwiftUI Keychain examples

The macOS app and [iOS simulator app](../ios/README.md) share `App.swift`, a C
header, and the Rust static library in `rust/`. The Rust bridge uses this crate's
`KeychainRefreshTokenStore`; no token contents cross the C interface.

## macOS

Requires Xcode, Rust, mise, and macOS 14 or newer. Configure the signing identity
and provisioning profile in gitignored `mise.local.toml`, following
[the signing guide](../../docs/guide/signing_an_app.md). The example uses the same profile-authorized
bundle identifier and access group as the signed test harness, with its own
service/account pair reserved for a disposable example token.

```sh
mise run example:macos
```

Tap **Store**, quit the app, launch it again, and tap **Load**. Load verifies the
token matches the expected example value. **Clear** removes the example item.
Rebuilding the app preserves that item so persistence can be checked.

```sh
mise run example:macos --build-only
mise run example:macos --verify
```

Verification launches a fresh process for each step: clear, store, load, clear,
confirm absence. It clears only the example's disposable token. Quit the
interactive example before running verification. An interruption can leave the
example token stored; use Clear or rerun verification to remove it.

The app is built under `target/macos-example/HuskarlExample.app`, embeds the
matching provisioning profile, and is signed with the configured identity. It
uses the data protection Keychain, not the login/file backend. Run in a logged-in
user session. No OAuth server or Secure Enclave operations are involved.

The existing `dpop_proof`, `seal`, and `keychain_cipher` Cargo examples remain
available for the cryptographic flows described in the signing guide.
