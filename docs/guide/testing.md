# Run the tests

Run commands from the repository root. Unit tests and doctests require Rust and
macOS; persisted data protection tests also need signing assets, and enclave
tests need supported hardware.

## Run unit tests and documentation checks

```sh
cargo test --all-targets
cargo test --doc
cargo clippy --all-targets -- -D warnings
cargo doc --no-deps
```

To include the optional URLSession client and its local HTTP/TLS tests, add
`--features urlsession` to these commands. The URLSession tests need permission
to open loopback sockets. The Secure Enclave mTLS test uses the signed workflow
below.

To test the session controller and its lifecycle races, run
`cargo test --features session --lib session::`. These tests use in-memory stores
and a scripted HTTP client; they do not present native authentication UI.

The native-session example's private executor has a custom test harness so its
checks run on the actual process main thread:

```sh
cargo test --manifest-path examples/native-session/rust/Cargo.toml --test main_thread_executor
```

It exercises worker wakes, coalescing, idle tasks, local task ownership, nested
spawning, and Tokio timers using the native run loop. It requires no signing,
provider configuration, or interactive UI, and runs with the example's test suite.

To include the native browser adapter, use `--features web-authentication`, or
`--all-features` to test all optional adapters. Its automated tests cover URL validation,
callback matching, native errors, and completion/cancellation ordering.

With `--features local-authentication`, unit tests also check native context
identity, configuration sharing and invalidation. Compile-fail doctests check that
unsupported backend options and read-mode combinations are unavailable.
Run `mise run test:signed authentication_context` for noninteractive, signed
Keychain and enclave checks (including protected operations with UI disabled).
Run `mise run test:signed user_presence` to also check authenticated context reuse
and invalidation with system prompts. The signed runner enables this feature.

CI runs tests, doctests, and documentation builds with default features, each
optional adapter independently, and all features together, on both Rust 1.92.0
and stable. Stable also runs Clippy and checks iOS device and simulator library
builds for every feature configuration. Persisted-item, hardware, and interactive
browser checks remain opt-in through the workflows below.

CI also tests and lints the standalone native-session Rust bridge and compiles
its Swift app as an ad-hoc bundle. See the
[native session example](https://github.com/huskarl-rs/huskarl-apple/tree/main/examples/native-session)
for the signed browser-login, restart, API request, and logout walkthrough.

For a ready-to-run macOS browser check with disposable Keycloak, run
`mise run test:browser`; see `examples/browser-login/README.md`.

For other app configurations, integrate the [browser login example](crate::_docs::guide::browser_login)
into a foreground app and use a registered OAuth client. Check successful login,
user cancellation, dropping a pending session, and the ephemeral preference.
Test HTTPS callbacks with a configured associated domain and verify a custom
scheme on older supported OS versions. These require app/provider setup and
are not exercised by the unit suite.

Unit tests use ephemeral software keys for Apple's signature and ECIES APIs.
They may require execution outside an OS sandbox. Integration tests that create
persisted items or prompt for authentication are opt-in.

## Run native adapter tests on iOS

With an iOS simulator runtime installed in Xcode, run:

```sh
mise run test:ios
```

This runs the HTTP/error-handling, TLS trust, and browser-adapter unit tests
inside the simulator. Browser-adapter unit tests do not present a login UI. Set `HUSKARL_IOS_SIMULATOR` to a simulator UDID to select one; otherwise
the task prefers a booted simulator. Secure Enclave tests remain ignored here.

For the hardware tests, connect and unlock an iPhone. On the **iPhone**, enable
Settings → Privacy & Security → Developer Mode, restart, and confirm the setting.
On the **Mac**, add your Apple developer account in Xcode → Settings → Accounts.
Then run:

```sh
mise run test:ios-device
```

The task builds the Rust mTLS tests and generates an Xcode project under
`target/ios-device-tests/HuskarlTests.xcodeproj`. Xcode uses automatic signing
to register the test app/device and create an iOS development profile; no manual
profile download is needed. It installs the app and checks the device's console
for both Secure Enclave tests passing. The tests use an HTTPS server on the
phone itself, and clean up their disposable keys and certificates on success.

The team defaults to the team in `HUSKARL_PROVISIONING_PROFILE`, if configured.
Otherwise set `HUSKARL_IOS_TEAM`. Use `HUSKARL_IOS_DEVICE` to choose a device when
multiple phones are connected, and `HUSKARL_IOS_BUNDLE_ID` to override the generated
test bundle identifier. If automatic signing needs account setup, open the
generated project in Xcode and select your team under Signing & Capabilities.
If Xcode reports `PLA Update available`, the team's Account Holder must review
and accept the pending agreement at [Apple Developer](https://developer.apple.com/account/)
before provisioning can proceed.

## Test against a real OAuth server

With Docker running and the macOS signing configuration below in place:

```sh
mise run test:oauth
```

This starts a disposable Keycloak 26.5.3 container on a random loopback HTTPS
port. The test realm uses X.509 client authentication and certificate-bound
access tokens. A temporary root and intermediate CA certify a Secure Enclave
key's public key; its private key stays in the enclave.

The test checks that Keycloak rejects an anonymous token request, then obtains
a token through Huskarl's client-credentials grant and checks its `cnf.x5t#S256`
claim against the client certificate. A small HTTPS resource server validates
the token using Keycloak introspection, checks its issuer and audience, and
compares the token's certificate binding with the TLS peer certificate.

The matching certificate gets access. The same token with another valid
certificate or no certificate gets rejected, as does an invalid token. Tokens
are not printed. The resource server is a test fixture, not a production server;
this test covers service authentication, not an interactive user-login flow.

The task stops the container and removes its temporary CA material afterward.
It requires no existing realm, admin account, or production credentials. The
container image remains in Docker's cache.

To run the complete OAuth/resource test from the iPhone, use the device signing
setup above and put the phone on the same Wi-Fi as the Mac:

```sh
# Replace this with your Mac's LAN IPv4 address (for example, from ipconfig getifaddr en0).
mise run test:oauth-ios 192.168.1.170
```

This binds the temporary servers to the specified LAN address instead of
loopback. Allow Local Network access when the test app asks. The generated app
under `target/ios-oauth-tests` uses a UIKit scene to handle that permission before
running Rust tests. It creates the client keys in the **iPhone's** Secure Enclave.
For this disposable test only, the app carries the intermediate CA's signing key
so it can certify its newly generated public keys. Real enrollment would obtain
those certificates from a CA without putting a CA private key on the device.
The task uninstalls the OAuth test app and removes the copied fixtures afterward.

## Run signed tests with mise

With macOS, Rust, Python 3, and [mise](https://mise.jdx.dev/) installed, copy the
local configuration template:

```sh
cp mise.local.toml.example mise.local.toml
security find-identity -v -p codesigning
```

Edit `mise.local.toml` with your signing identity (its name or SHA-1 fingerprint)
and the path to its matching provisioning profile. This file is gitignored;
keep certificates and profiles outside the repository. mise loads its `[env]`
settings automatically using its [local configuration support][mise-local].
Then run from a logged-in user session:

```sh
mise trust
mise run test:signed
```

The task runs `keychain_lifecycle`, `keychain_storage`, and `load_or_generate`
sequentially. It decodes the profile, checks expiration and requested identifiers,
generates bundle metadata and entitlements, builds each test, embeds the original
profile, signs/verifies the bundle, and executes it. Signing or test failure stops
the task. Temporary bundles under `target/signing` are removed on exit. macOS may
ask to authorize use of the signing private key.

For an explicit application identifier, the identity and profile path are the
only required settings. A wildcard application profile also needs
`HUSKARL_BUNDLE_ID`. The access group defaults to the resulting application
identifier; `HUSKARL_TEST_ACCESS_GROUP` overrides it. Every group must be authorized
by the profile. See the commented settings in `mise.local.toml.example`.

Select individual test executables by name:

```sh
mise run test:signed keychain_storage
mise run test:signed keychain_lifecycle load_or_generate
```

The following tests are deliberately opt-in:

```sh
# Set two distinct, authorized groups in mise.local.toml first:
# HUSKARL_TEST_ACCESS_GROUP_A and HUSKARL_TEST_ACCESS_GROUP_B
mise run test:signed access_groups

# Requires a person to respond to authentication prompts:
mise run test:signed user_presence

# Verifies Secure Enclave mTLS, intermediate chains, and installation rollback:
mise run test:signed urlsession_mtls
```

Run `mise run test:signed --help` for task usage. Without mise, export the
same environment variables and run `python3 scripts/signed-tests.py`.
See [signing an app](crate::_docs::guide::signing_an_app) to obtain signing
assets and perform the packaging steps manually. These tasks use disposable
test items, but interruption can leave items behind; they do not rotate or delete your application's keys.

## Clean up leftover test keys

Successful integration tests delete their keys, but a panic or interruption can
leave persisted keys behind. With the same local signing configuration, preview
leftovers before deleting them:

```sh
mise run test:cleanup
mise run test:cleanup --delete
```

The task builds and signs a development helper. It searches the data protection
Keychain in `HUSKARL_TEST_ACCESS_GROUP` (defaulting to the application identifier)
and either of `HUSKARL_TEST_ACCESS_GROUP_A` / `_B` that is configured. It selects
only private Secure Enclave keys with matching `huskarl-apple/sign` or
`huskarl-apple/seal` purpose tags and the integration tests' generated label
formats. Preview prints the group, purpose, and label; it does not read private
key material. Deletion reloads each candidate through the crate to revalidate
its purpose and enclave provenance before deleting both halves of the key pair.
The helper also selects leftover public halves by their test-label format;
these public items have no purpose tag or enclave token attribute.

Stop signed tests before cleanup: an active test's keys also match these naming
rules. Reserve those label formats for this repository's tests, and prefer a
dedicated test access group. This helper does not delete secrets, refresh tokens,
example keys, untagged private keys, certificates, or arbitrary application keys.
It cannot discover items in groups absent from the current signing configuration.
No key-listing API is added to the library.

## Development without signing

For secret and refresh-token persistence without Keychain entitlements, select
`FileKeychain::login()`. To exercise file-backend storage and isolation in two
disposable keychains, run `cargo test --test file_keychain -- --ignored`.
This test creates and deletes its temporary keychains, and macOS may prompt for
authorization. It does not use your login keychain or change the default keychain.

Use `huskarl-crypto-native` with these secrets when trying the OAuth/`DPoP` flow
without Secure Enclave signing entitlements. Those private keys live in process
memory and do not have the enclave's nonextractability guarantee. The regular
unit tests also use ephemeral software keys; production enclave constructors
never do this.

## Integration test executables

| Test executable | Additional configuration | Coverage |
|---|---|---|
| `keychain_lifecycle` | None; uses the default entitled group | Signing/sealing reload, purpose separation, and secret loading with native AES |
| `keychain_storage` | `HUSKARL_TEST_ACCESS_GROUP` | Secret updates, policy preservation, refresh-token reload/rotation, corruption, and clearing |
| `load_or_generate` | `HUSKARL_TEST_ACCESS_GROUP` | Concurrent enclave provisioning returns the same key |
| `access_groups` | `HUSKARL_TEST_ACCESS_GROUP_A` and `_B` | Key and secret isolation across two distinct entitled groups |
| `user_presence` | Interactive user session; add `--nocapture` | Signing/unsealing with human authentication |
| `urlsession_mtls` | `urlsession` feature; enabled by the signed test task | Secure Enclave mTLS, intermediate chains, validation before storage, and installation rollback |

## Bundled integration tests

First complete [signing an app](crate::_docs::guide::signing_an_app) through
defining `huskarl_package`. Keep that shell session open: the commands below
reuse its variables, metadata, profile, and packaging function for each test
executable.
Build the test with its embedded `Info.plist`; Cargo's JSON output identifies
its exact executable path without selecting a stale hashed file:

```sh
huskarl_test=keychain_lifecycle
cargo rustc --test "$huskarl_test" --message-format=json -- \
  -C "link-arg=-Wl,-sectcreate,__TEXT,__info_plist,$huskarl_work/Info.plist" \
  > "$huskarl_work/test-build.jsonl"
huskarl_binary="$(python3 - "$huskarl_work/test-build.jsonl" "$huskarl_test" <<'PYCODE'
import json
import sys
from pathlib import Path

artifacts = [json.loads(line) for line in Path(sys.argv[1]).read_text().splitlines()]
paths = [entry['executable'] for entry in artifacts
         if entry.get('reason') == 'compiler-artifact'
         and entry.get('target', {}).get('name') == sys.argv[2]
         and 'test' in entry.get('target', {}).get('kind', [])
         and entry.get('executable')]
if len(paths) != 1:
    raise SystemExit('expected exactly one test executable')
print(paths[0])
PYCODE
)"
huskarl_package
codesign --verify --strict --verbose=2 "$huskarl_app"
"$huskarl_app/Contents/MacOS/huskarl-harness" --ignored --test-threads=1
```

Choose the executable and configuration from the [test matrix](#integration-test-executables).
For `urlsession_mtls`, also pass `--features urlsession` to `cargo rustc`.

For a single-group test, set the actual group claimed by the signed executable
before running the bundled harness:

```sh
export HUSKARL_TEST_ACCESS_GROUP='APPIDPREFIX.io.example.HuskarlHarness'
```

For `access_groups`, put **two distinct, profile-authorized groups** into the
entitlements array, repackage/re-sign, and set both environment variables to
those exact values. The tests do not authorize or provision groups themselves.
Rebuild and repackage each test separately: the harness path contains only the
most recently copied executable. Run the bundled harness, not `cargo test`, for
these provisioned tests.

All tests use disposable labels/service names and attempt cleanup after fallible
operations. A panic or interruption can leave test items behind. The normal unit
suite needs no provisioning; `keychain_storage` needs no enclave hardware.
The bundled workflow has been validated locally with a matching development
identity and provisioning profile: all four `keychain_lifecycle` tests, both
`keychain_storage` tests, and both `load_or_generate` tests passed through
`mise run test:signed`. This covers actual Secure Enclave operations,
concurrent key creation, and data protection Keychain storage. The other
three `access_groups` tests also passed when selected explicitly. Interactive
authentication and Developer ID distribution remain separate checks.

## Checking human acknowledgement and lock behavior

`tests/user_presence.rs` is a separate opt-in, interactive test executable. Build
it using the bundled integration-test workflow above with
`huskarl_test=user_presence`. Run the bundled executable with
`--ignored --nocapture`. It creates distinct
signing and sealing keys with `UserPresence`, reloads them, and exercises private
operations. macOS may request Touch ID or the login credential. No production
keys are used. Authentication UI is intentionally not part of unattended tests.

On each supported macOS/hardware deployment, also exercise the host application
with an unlocked session, a locked session, and after a restart before first
unlock, for both availability classes. Check cancellation and denied access, and
verify that noninteractive secret reads do not show authentication UI. These
checks require controlling a real login session; the unit suite does not lock
the developer's desktop or change system policy. Authentication reuse and lock
transitions are controlled by macOS, so the tests do not assert a fixed number of
prompts or a duration in seconds.

## Regenerate the README

The crate overview in `src/lib.rs` is the source for `README.md`, matching the
other huskarl crates. With `cargo-reedme` installed, run:

```sh
mise run docs:readme
```

Tutorials and guides are included through the documentation-only `_docs` module.
Their Rust examples are checked by `cargo test --doc`; use
`cargo test --all-features --doc` to include the optional browser, networking,
and local-authentication examples. Build the complete reference with
`cargo doc --all-features --no-deps --open`.

[mise-local]: https://mise.jdx.dev/configuration.html#mise-toml
