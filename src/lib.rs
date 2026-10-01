//! Native OAuth integration for Apple applications in the huskarl ecosystem.
//!
//! Compose Huskarl's OAuth grants and session management with Apple's browser,
//! Keychain, Secure Enclave, local authentication, and HTTP networking.
//! Start with [how the integrations fit together](crate::_docs::explanation::apple_oauth).
//!
//! | Application need | Adapter | Cargo feature |
//! |---|---|---|
//! | Present browser login | `web_authentication::WebAuthenticationSession` | `web-authentication` |
//! | Persist refresh tokens | [`keychain::KeychainRefreshTokenStore`] | None |
//! | Sign DPoP proofs with a hardware key | [`secure_enclave::Es256PrivateKey`] | None |
//! | Control local authentication | `authentication::AuthenticationContext` | `local-authentication` |
//! | Use Apple networking and TLS client identities | `urlsession::UrlSessionClient` | `urlsession` |
//! | Store other secrets or sign and seal data | [`keychain`] and [`secure_enclave`] | None |
//!
//! Requires Rust 1.92+ and macOS 10.15+; iOS support is experimental. Browser
//! callbacks and examples have additional version requirements. See the
//! [platform and feature reference](crate::_docs::reference::platforms).
//! Secure Enclave operations require supported hardware; data protection
//! Keychain access requires appropriate signing and authorized access groups.
//! For a local macOS tool, `keychain::FileKeychain::login()` selects the login Keychain.
//!
//! OAuth API access, verified OIDC identity, and local biometric authorization
//! are separate integrations. The native session example obtains API access;
//! it does not validate an ID token. Native Sign in with Apple, passkey, and
//! enterprise SSO adapters are outside this crate's supplied integrations; see
//! [authentication boundaries](crate::_docs::explanation::apple_oauth).
//!
//! # Documentation
//!
//! - **Learn:** [your first native OAuth login](crate::_docs::tutorial::first_login)
//!   or [store and retrieve your first secret](crate::_docs::tutorial::first_secret).
//! - **Build an application:** [add a persisted browser-login session](crate::_docs::guide::native_session),
//!   [connect a SwiftUI/AppKit/UIKit UI](crate::_docs::guide::apple_app), or
//!   [use device authorization for a command-line session](crate::_docs::guide::dpop_session).
//! - **Solve a task:** [present browser login](crate::_docs::guide::browser_login),
//!   [persist refresh tokens](crate::_docs::guide::refresh_tokens),
//!   [use Apple networking and mTLS](crate::_docs::guide::native_networking),
//!   [choose a DPoP key policy](crate::_docs::guide::dpop_policy), or
//!   [sign an app](crate::_docs::guide::signing_an_app).
//! - **Understand:** [Apple and OAuth responsibilities](crate::_docs::explanation::apple_oauth),
//!   [the security model](crate::_docs::explanation::security_model), and
//!   [signing and entitlements](crate::_docs::explanation::signing_and_entitlements).
//! - **Look up:** [platforms, features, and example coverage](crate::_docs::reference::platforms)
//!   and the crate's API modules.
//!
//! See [all documentation](crate::_docs) for the complete reading map and
//! [testing](crate::_docs::guide::testing) for contributor checks.
//!
//! Related Huskarl APIs:
//!
//! - [Authorization-code grants](https://docs.rs/huskarl/latest/huskarl/grant/authorization_code/)
//! - [Providing secrets](https://docs.rs/huskarl-core/latest/huskarl_core/_docs/guide/providing_secrets/index.html)
//! - [Building and signing a JWT](https://docs.rs/huskarl-core/latest/huskarl_core/_docs/guide/signing_a_jwt/index.html)

// Native Objective-C adapters opt into unsafe code locally.
#![deny(unsafe_code)]
#![deny(missing_docs, rustdoc::broken_intra_doc_links)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![warn(clippy::pedantic)]

#[cfg(any(doc, doctest))]
pub mod _docs;

#[cfg(feature = "local-authentication")]
pub mod authentication;
pub mod keychain;
mod platform;
pub mod policy;
pub mod secure_enclave;
#[cfg(feature = "urlsession")]
pub mod urlsession;
#[cfg(all(
    feature = "web-authentication",
    any(target_os = "macos", target_os = "ios")
))]
pub mod web_authentication;

#[cfg(test)]
#[path = "../support/unique_label.rs"]
mod test_support;

pub use platform::PlatformError;
pub use secure_enclave::{Es256PrivateKey, SetupError, SigningError};
