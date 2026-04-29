# macOS Code Signing for Keychain-Backed DPoP Keys

## Background

The `Es256PrivateKey` type stores EC private keys in the macOS keychain. Two
keychain backends are available, with different signing requirements:

| | `DefaultFileKeychain` | `DataProtectionKeychain` |
|---|---|---|
| Signing needed | None | Developer ID + entitlements |
| `SecKeyCopyExternalRepresentation` works | No (CSSM format) | Yes |
| Secure Enclave support | No | Yes |
| Production-appropriate | No | Yes |

`DefaultFileKeychain` is the legacy CSSM-based keychain. Keys stored there
cannot be read back via `SecKeyCopyExternalRepresentation`, which makes
reconstructing the public JWK after a process restart impossible without
workarounds.

`DataProtectionKeychain` is the modern keychain (used by iOS since iOS 8, macOS
since 10.15). It works correctly with `SecKeyCopyExternalRepresentation` and is
the only option that supports the Secure Enclave. It requires a
`keychain-access-groups` entitlement provisioned by Apple, meaning the binary
must be signed with a valid Apple Developer certificate.

## Prerequisites

1. Enroll in the [Apple Developer Program](https://developer.apple.com/programs/)
   ($99/year).
2. In Xcode → Settings → Accounts, add your Apple ID and download your
   certificates. You need either:
   - **Apple Development** (for local development/testing), or
   - **Developer ID Application** (for distribution outside the App Store).
3. Verify the certificate is available:
   ```
   security find-identity -v -p codesigning
   ```
   You should see a line like:
   ```
   1) ABC123DEF4 "Apple Development: you@example.com (TEAMID123)"
   ```
   The 10-character `TEAMID123` is your team ID.

## Entitlements file

Create `entitlements.plist` in the repo root:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>keychain-access-groups</key>
    <array>
        <string>TEAMID123.io.huskarl.crypto</string>
    </array>
</dict>
</plist>
```

Replace `TEAMID123` with your actual team ID. The string after the dot is an
arbitrary reverse-DNS identifier for this app — it determines which keychain
access group the keys are stored under.

## Build and sign

Because `cargo run` rebuilds the binary and strips signatures, sign and run in
two steps:

```sh
cargo build --example dpop_proof

codesign \
  --sign "Apple Development: you@example.com (TEAMID123)" \
  --entitlements entitlements.plist \
  --force \
  target/debug/examples/dpop_proof

./target/debug/examples/dpop_proof
```

For release builds:

```sh
cargo build --release --example dpop_proof

codesign \
  --sign "Developer ID Application: Your Name (TEAMID123)" \
  --entitlements entitlements.plist \
  --options runtime \
  --force \
  target/release/examples/dpop_proof
```

The `--options runtime` flag enables the Hardened Runtime, which is required
for notarization.

## Enabling the Secure Enclave

Once `DataProtectionKeychain` is working, switching to the Secure Enclave
requires:

1. The same entitlements setup as above (already needed for
   `DataProtectionKeychain`).
2. A Mac with a T1/T2 chip (Intel, ~2017+) or Apple Silicon.
3. Code changes in `Es256PrivateKey::generate()`:
   ```rust
   use security_framework::key::Token;
   use security_framework::access_control::{ProtectionMode, SecAccessControl};
   use security_framework_sys::access_control::kSecAccessControlPrivateKeyUsage;

   generate_options.set_token(Token::SecureEnclave);
   generate_options.set_location(Location::DataProtectionKeychain);
   let ac = SecAccessControl::create_with_protection(
       Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
       kSecAccessControlPrivateKeyUsage,
   ).unwrap();
   generate_options.set_access_control(ac);
   ```
   SE private keys are non-extractable by design, but
   `SecKeyCopyPublicKey` + `SecKeyCopyExternalRepresentation` on the
   public key still works.

## Development without signing

Until signing is set up, use `huskarl`'s native in-memory `Es256PrivateKey`
to trial the DPoP flow:

```rust
use huskarl::crypto::signer::native::Es256PrivateKey;

let key = Es256PrivateKey::generate();
let dpop = DPoP::builder().signer(key).build();
```

Keys are ephemeral (lost on process restart) and live in process memory, so
DPoP-bound refresh tokens won't survive restarts. Suitable for integration
testing but not production use.
