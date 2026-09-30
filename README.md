<!-- cargo-reedme: start -->

<!-- cargo-reedme: info-start

    Do not edit this region by hand
    ===============================

    This region was generated from Rust documentation comments by `cargo-reedme` using this command:

        cargo +nightly reedme

    for more info: https://github.com/nik-rev/cargo-reedme

cargo-reedme: info-end -->

Keychain secrets and Secure Enclave cryptography for the huskarl ecosystem.

- [`keychain`](https://docs.rs/huskarl-apple/latest/huskarl_apple/keychain/) provides secret reads, writable storage, and refresh-token
  persistence with `DPoP` bindings.
- [`secure_enclave`](https://docs.rs/huskarl-apple/latest/huskarl_apple/secure_enclave/) provides ES256 signing and verification, and device-bound
  sealing with a hardware-protected private key.
- [`policy`](https://docs.rs/huskarl-apple/latest/huskarl_apple/policy/) provides shared availability and authentication controls.

Requires macOS 10.15+ and Rust 1.92+. Secure Enclave operations also require
supported hardware. iOS support is experimental.

The default data protection backend uses signing and entitled access groups.
For a local macOS tool, select `KeychainBackend::Login`; see the [`keychain`](https://docs.rs/huskarl-apple/latest/huskarl_apple/keychain/) backend options.
New data protection items default to device-only access while unlocked;
existing items retain their policy.

# Documentation

- **Learn:** [store and retrieve your first secret](https://docs.rs/huskarl-apple/latest/huskarl_apple/_docs/tutorial/first_secret/).
- **Solve a task:** [build a complete `DPoP` session](https://docs.rs/huskarl-apple/latest/huskarl_apple/_docs/guide/dpop_session/),
  [store secrets](https://docs.rs/huskarl-apple/latest/huskarl_apple/_docs/guide/storing_secrets/),
  [persist refresh tokens](https://docs.rs/huskarl-apple/latest/huskarl_apple/_docs/guide/refresh_tokens/),
  [sign and seal](https://docs.rs/huskarl-apple/latest/huskarl_apple/_docs/guide/signing_and_sealing/),
  [provision keys](https://docs.rs/huskarl-apple/latest/huskarl_apple/_docs/guide/provisioning_keys/), or
  [choose a `DPoP` key policy](https://docs.rs/huskarl-apple/latest/huskarl_apple/_docs/guide/dpop_policy/).
- **Set up an application:** [sign a macOS app](https://docs.rs/huskarl-apple/latest/huskarl_apple/_docs/guide/signing_an_app/)
  or [select a Keychain backend](https://docs.rs/huskarl-apple/latest/huskarl_apple/_docs/guide/selecting_a_backend/).
- **Understand the design:** read the [security model](https://docs.rs/huskarl-apple/latest/huskarl_apple/_docs/explanation/security_model/)
  and [signing and entitlements](https://docs.rs/huskarl-apple/latest/huskarl_apple/_docs/explanation/signing_and_entitlements/).
- **Look up the API:** use the crate modules and item pages in this reference.

For the complete reading map, see [all documentation](https://docs.rs/huskarl-apple/latest/huskarl_apple/_docs/).
Contributors can follow [running tests](https://docs.rs/huskarl-apple/latest/huskarl_apple/_docs/guide/testing/) for unit,
signed integration, and interactive hardware checks.

Related huskarl guides:

- [Providing secrets](https://docs.rs/huskarl-core/latest/huskarl_core/_docs/guide/providing_secrets/index.html)
- [Building and signing a JWT](https://docs.rs/huskarl-core/latest/huskarl_core/_docs/guide/signing_a_jwt/index.html)
- [Composing crypto strategies](https://docs.rs/huskarl-core/latest/huskarl_core/_docs/explanation/crypto_strategies/index.html)

<!-- cargo-reedme: end -->

## Repository documentation

Browse the [documentation map](docs/README.md) for this checkout, including
[testing instructions](docs/guide/testing.md) and the application examples.
