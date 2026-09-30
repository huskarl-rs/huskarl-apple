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

Unit tests use ephemeral software keys for Apple's signature and ECIES APIs.
They may require execution outside an OS sandbox. Integration tests that create
persisted items or prompt for authentication are opt-in.

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
its purpose and enclave provenance before deleting it.

Stop signed tests before cleanup: an active test's keys also match these naming
rules. Reserve those label formats for this repository's tests, and prefer a
dedicated test access group. This helper does not delete secrets, refresh tokens,
example keys, untagged keys, or arbitrary application keys. It cannot discover
items in groups absent from the current signing configuration. No key-listing
API is added to the library.

## Development without signing

For secret and refresh-token persistence without Keychain entitlements, select
`KeychainBackend::Login`. To exercise file-backend storage and isolation in two
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
Their Rust examples are checked by ordinary `cargo test --doc`.

[mise-local]: https://mise.jdx.dev/configuration.html#mise-toml
