# iOS simulator example

A minimal SwiftUI app linked to a Rust static library, sharing its source with
the [macOS example](../apple/README.md). Store, load, and clear a
disposable refresh token through `KeychainRefreshTokenStore`. No OAuth server,
real credentials, or Secure Enclave keys are involved. Tokens never cross the
Rust/Swift interface; the UI reports only whether the expected example token was
stored or loaded.

## Requirements

- Xcode selected with `xcode-select`, including its iOS SDK and an installed iOS
  simulator runtime (iOS 18 or newer). Install runtimes in Xcode Settings >
  Components, and create a device in Device Hub (Xcode 27) or Window > Devices
  and Simulators (earlier Xcode) if needed.
- Rust and mise. On Apple Silicon, install the target with
  `rustup target add aarch64-apple-ios-sim`. On Intel, use `x86_64-apple-ios`.

No developer certificate or provisioning profile is required for this simulator
example. The build embeds simulated entitlements in the executable's
`__TEXT,__entitlements` section and uses an ad-hoc host signature without those
entitlements. Its fixed simulator-only access group is separate from the signed
macOS tests. This signing configuration is not
suitable for a physical iPhone.

## Run

From the repository root:

```sh
mise run example:ios
```

The task builds the Rust library and SwiftUI executable, creates and signs an
app bundle under `target/ios-example`, installs it, and opens Simulator or
[Device Hub](https://developer.apple.com/documentation/xcode/device-hub). It uses
a booted iOS simulator when available, otherwise boots an available device.
Select a specific simulator UDID in the gitignored `mise.local.toml`:

```toml
[env]
HUSKARL_IOS_SIMULATOR = "YOUR-SIMULATOR-UDID"
```

List devices with `xcrun simctl list devices available`. Preserve any existing
`[env]` settings when adding this entry.

Tap **Store**, terminate and reopen the app, then tap **Load**. A successful load
compares the full token with the expected example value. **Clear** removes only
the example's service/account item. Rebuilding/reinstalling intentionally keeps
the item so persistence can be checked.

```sh
# Build without a simulator runtime/device:
mise run example:ios --build-only

# Launch separate app processes to clear, store, load, clear, and confirm absence:
mise run example:ios --verify
```

Verification clears the example token before and after the sequence. An
interruption may leave it stored; use Clear or rerun verification to remove it.
The task fails if an operation returns an unexpected result. UI operations run
off the main thread, and buttons are disabled while an operation is running.

The verification sequence has passed on the iOS 27 iPhone 18 Pro simulator,
including reloading the stored token from a fresh app process.

## Scope

The library's macOS file-Keychain backends are excluded on iOS. The example uses
the iOS Keychain with the normal device-only, while-unlocked creation policy.
Simulator behaviour does not validate physical-device access protection,
biometric authentication, or Secure Enclave support. Those require a separately
provisioned device app and hardware tests. iOS support remains experimental.

The integer-only C bridge is confined to `../apple/rust/src/lib.rs`; the main crate keeps
its `forbid(unsafe_code)` policy. The task uses the Xcode command-line compilers
directly, so no generated Xcode project or extra project generator is required.
