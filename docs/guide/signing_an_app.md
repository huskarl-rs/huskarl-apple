# Sign a macOS app or command-line harness

Use this guide to package and sign a Cargo example for data protection Keychain
or Secure Enclave access. Start with a logged-in macOS user session, Rust, and
Xcode's command-line tools. For the authorization model and hardware requirements,
see [signing and entitlements](crate::_docs::explanation::signing_and_entitlements).
For the automated repository test workflow, see [running tests](crate::_docs::guide::testing).

## Obtain matching signing assets

Use an Apple Development identity and a macOS development provisioning profile
for local testing. Register an explicit bundle identifier, configure Keychain
Sharing in a macOS Xcode target with that identifier, and let Xcode manage its
profile, or generate the corresponding profile in your developer account.
The profile must authorize the signing certificate, application identifier,
access groups, and development Mac, and must not be expired.

For distribution outside the App Store, use a Developer ID Application identity
and a matching Developer ID provisioning profile authorizing the entitlements.
A development profile is not a substitute for a distribution profile. See
[Apple's distribution signing guide][distribution].

List available identities:

```sh
security find-identity -v -p codesigning
```

The remaining commands assume one shell session in the repository root. Set
these values to your actual signing identity and downloaded profile:

```sh
huskarl_identity='Apple Development: Your Name (YOURTEAMID)'
huskarl_profile='/absolute/path/to/HuskarlHarness.provisionprofile'
huskarl_work="$PWD/target/signing"
huskarl_app="$huskarl_work/HuskarlHarness.app"
mkdir -p "$huskarl_work"
security cms -D -i "$huskarl_profile" -o "$huskarl_work/profile.plist"
/usr/libexec/PlistBuddy -c 'Print :Entitlements' "$huskarl_work/profile.plist"
/usr/libexec/PlistBuddy -c 'Print :ExpirationDate' "$huskarl_work/profile.plist"
```

Use the decoded profile to fill in the templates below:

- `io.example.HuskarlHarness` is the registered bundle identifier.
- `APPIDPREFIX.io.example.HuskarlHarness` must match the profile's
  `com.apple.application-identifier` authorization.
- `YOURTEAMID` is the profile's `com.apple.developer.team-identifier`.
- Each concrete `keychain-access-groups` value must be authorized by the profile,
  either explicitly or by a permitted wildcard. Do not put wildcards into the
  executable's entitlement claims.

Request only the entitlements shown here, using the identifiers from your
profile. See [signing and entitlements](crate::_docs::explanation::signing_and_entitlements)
for how the identifiers and authorization fit together.

## Prepare bundle metadata and entitlements

Save this as `target/signing/Info.plist`, replacing the bundle identifier:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>io.example.HuskarlHarness</string>
    <key>CFBundleExecutable</key>
    <string>huskarl-harness</string>
    <key>CFBundleName</key>
    <string>HuskarlHarness</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleVersion</key>
    <string>1</string>
</dict>
</plist>
```

Save this as `target/signing/entitlements.plist`, replacing every identifier
with values authorized by your profile:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.application-identifier</key>
    <string>APPIDPREFIX.io.example.HuskarlHarness</string>
    <key>com.apple.developer.team-identifier</key>
    <string>YOURTEAMID</string>
    <key>keychain-access-groups</key>
    <array>
        <string>APPIDPREFIX.io.example.HuskarlHarness</string>
    </array>
</dict>
</plist>
```

The first access group is used by examples that do not select a group explicitly.
These local harness instructions do not enable App Sandbox. Sandboxed products
need their own additional entitlements and container configuration.

```sh
plutil -lint "$huskarl_work/Info.plist" "$huskarl_work/entitlements.plist"
```

## Build, package, and sign an example

Embed the same `Info.plist` into the command-line executable's
`__TEXT,__info_plist` section when linking. This gives the executable its bundle
identity when launched directly from Terminal. The linker argument below
assumes the repository path contains no commas.

```sh
cargo rustc --example dpop_proof -- \
  -C "link-arg=-Wl,-sectcreate,__TEXT,__info_plist,$huskarl_work/Info.plist"
huskarl_binary="$PWD/target/debug/examples/dpop_proof"
```

Define this packaging function once; it also works for test executables. It
copies the binary into the bundle under the name from `CFBundleExecutable`,
embeds the **original signed profile**, and signs the completed bundle:

```sh
huskarl_package() {
    mkdir -p "$huskarl_app/Contents/MacOS" &&
    cp "$huskarl_binary" "$huskarl_app/Contents/MacOS/huskarl-harness" &&
    cp "$huskarl_work/Info.plist" "$huskarl_app/Contents/Info.plist" &&
    cp "$huskarl_profile" "$huskarl_app/Contents/embedded.provisionprofile" &&
    codesign --force --sign "$huskarl_identity" \
      --entitlements "$huskarl_work/entitlements.plist" "$@" "$huskarl_app"
}
huskarl_package
```

The resulting layout is:

```text
HuskarlHarness.app/
  Contents/
    Info.plist
    embedded.provisionprofile
    MacOS/huskarl-harness
    _CodeSignature/CodeResources
```

Inspect and verify the bundle, then execute its main binary in place:

```sh
codesign --verify --strict --verbose=2 "$huskarl_app"
codesign --display --verbose=4 "$huskarl_app"
codesign --display --entitlements - "$huskarl_app"
"$huskarl_app/Contents/MacOS/huskarl-harness"
```

Check the displayed application
identifier, team identifier, and groups against the profile, then run the actual
Keychain operation. Keep the profile embedded; do not copy the binary back out
and expect its restricted entitlements to work standalone.

For `seal`, substitute `--example seal` and its Cargo output path. For release
builds, add `--release` to `cargo rustc` and use `target/release/examples/...`.
For Developer ID distribution, select the matching identity/profile, package
with `huskarl_package --options runtime --timestamp`, and follow Apple's separate
notarization workflow. Hardened Runtime is required for notarization but does
not replace provisioning.

Every rebuild or change to the metadata/profile requires repackaging and
re-signing. Do not change signed bundle contents before running it.

[distribution]: https://developer.apple.com/documentation/xcode/creating-distribution-signed-code-for-the-mac
