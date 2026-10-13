<!-- cargo-reedme: start -->

<!-- cargo-reedme: info-start

    Do not edit this region by hand
    ===============================

    This region was generated from Rust documentation comments by `cargo-reedme` using this command:

        cargo +nightly reedme

    for more info: https://github.com/nik-rev/cargo-reedme

cargo-reedme: info-end -->

Native OAuth integration for Apple applications in the huskarl ecosystem.

Compose Huskarl’s OAuth grants and session management with Apple’s browser,
Keychain, Secure Enclave, local authentication, and HTTP networking.
Start with [how the integrations fit together](https://docs.rs/huskarl-apple/latest/huskarl_apple/_docs/explanation/apple_oauth/).

| Application need | Adapter | Cargo feature |
|---|---|---|
| Present browser login | `web_authentication::WebAuthenticationSession` | `web-authentication` |
| Own a native login/session lifecycle | `session::AppleSession` | `session` |
| Persist refresh tokens | [`keychain::KeychainRefreshTokenStore`](https://docs.rs/huskarl-apple/latest/huskarl_apple/keychain/refresh/struct.KeychainRefreshTokenStore.html) | None |
| Sign `DPoP` proofs with a hardware key | [`secure_enclave::Es256PrivateKey`](https://docs.rs/huskarl-apple/latest/huskarl_apple/secure_enclave/signer/struct.Es256PrivateKey.html) | None |
| Control local authentication | `authentication::AuthenticationContext` | `local-authentication` |
| Use Apple networking and TLS client identities | `urlsession::UrlSessionClient` | `urlsession` |
| Store other secrets or sign and seal data | [`keychain`](https://docs.rs/huskarl-apple/latest/huskarl_apple/keychain/) and [`secure_enclave`](https://docs.rs/huskarl-apple/latest/huskarl_apple/secure_enclave/) | None |

Requires Rust 1.92+ and macOS 10.15+; iOS support is experimental. Browser
callbacks and examples have additional version requirements. See the
[platform and feature reference](https://docs.rs/huskarl-apple/latest/huskarl_apple/_docs/reference/platforms/).
Secure Enclave operations require supported hardware; data protection
Keychain access requires appropriate signing and authorized access groups.
For a local macOS tool, `keychain::FileKeychain::login()` selects the login Keychain.

OAuth API access, verified OIDC identity, and local biometric authorization
are separate integrations. The native session example obtains API access;
it does not validate an ID token. Native Sign in with Apple, passkey, and
enterprise SSO adapters are outside this crate’s supplied integrations; see
[authentication boundaries](https://docs.rs/huskarl-apple/latest/huskarl_apple/_docs/explanation/apple_oauth/).

# Documentation

- **Learn:** [your first native OAuth login](https://docs.rs/huskarl-apple/latest/huskarl_apple/_docs/tutorial/first_login/)
  or [store and retrieve your first secret](https://docs.rs/huskarl-apple/latest/huskarl_apple/_docs/tutorial/first_secret/).
- **Build an application:** [add a persisted browser-login session](https://docs.rs/huskarl-apple/latest/huskarl_apple/_docs/guide/native_session/),
  [connect a SwiftUI/AppKit/UIKit UI](https://docs.rs/huskarl-apple/latest/huskarl_apple/_docs/guide/apple_app/), or
  [use device authorization for a command-line session](https://docs.rs/huskarl-apple/latest/huskarl_apple/_docs/guide/dpop_session/).
- **Solve a task:** [present browser login](https://docs.rs/huskarl-apple/latest/huskarl_apple/_docs/guide/browser_login/),
  [persist refresh tokens](https://docs.rs/huskarl-apple/latest/huskarl_apple/_docs/guide/refresh_tokens/),
  [use Apple networking and mTLS](https://docs.rs/huskarl-apple/latest/huskarl_apple/_docs/guide/native_networking/),
  [choose a `DPoP` key policy](https://docs.rs/huskarl-apple/latest/huskarl_apple/_docs/guide/dpop_policy/), or
  [sign an app](https://docs.rs/huskarl-apple/latest/huskarl_apple/_docs/guide/signing_an_app/).
- **Understand:** [Apple and OAuth responsibilities](https://docs.rs/huskarl-apple/latest/huskarl_apple/_docs/explanation/apple_oauth/),
  [the security model](https://docs.rs/huskarl-apple/latest/huskarl_apple/_docs/explanation/security_model/), and
  [signing and entitlements](https://docs.rs/huskarl-apple/latest/huskarl_apple/_docs/explanation/signing_and_entitlements/).
- **Look up:** [platforms, features, and example coverage](https://docs.rs/huskarl-apple/latest/huskarl_apple/_docs/reference/platforms/)
  and the crate’s API modules.

See [all documentation](https://docs.rs/huskarl-apple/latest/huskarl_apple/_docs/) for the complete reading map and
[testing](https://docs.rs/huskarl-apple/latest/huskarl_apple/_docs/guide/testing/) for contributor checks.

Related Huskarl APIs:

- [Authorization-code grants](https://docs.rs/huskarl/latest/huskarl/grant/authorization_code/)
- [Providing secrets](https://docs.rs/huskarl-core/latest/huskarl_core/_docs/guide/providing_secrets/index.html)
- [Building and signing a JWT](https://docs.rs/huskarl-core/latest/huskarl_core/_docs/guide/signing_a_jwt/index.html)

<!-- cargo-reedme: end -->

## Repository documentation

Browse the [documentation map](docs/README.md) for this checkout, including
[testing instructions](docs/guide/testing.md) and the application examples.
