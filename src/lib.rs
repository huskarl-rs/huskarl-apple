//! Keychain secrets and Secure Enclave cryptography for the huskarl ecosystem.
//!
//! - [`keychain`] provides secret reads, writable storage, and refresh-token
//!   persistence with `DPoP` bindings.
//! - [`secure_enclave`] provides ES256 signing and verification, and device-bound
//!   sealing with a hardware-protected private key.
//! - [`policy`] provides shared availability and authentication controls.
//!
//! Requires macOS 10.15+ and Rust 1.92+. Secure Enclave operations also require
//! supported hardware. iOS support is experimental.
//!
//! The default data protection backend uses signing and entitled access groups.
//! For a local macOS tool, select `KeychainBackend::Login`; see the [`keychain`] backend options.
//! New data protection items default to device-only access while unlocked;
//! existing items retain their policy.
//!
//! # Documentation
//!
//! - **Learn:** [store and retrieve your first secret](crate::_docs::tutorial::first_secret).
//! - **Solve a task:** [build a complete `DPoP` session](crate::_docs::guide::dpop_session),
//!   [store secrets](crate::_docs::guide::storing_secrets),
//!   [persist refresh tokens](crate::_docs::guide::refresh_tokens),
//!   [sign and seal](crate::_docs::guide::signing_and_sealing),
//!   [provision keys](crate::_docs::guide::provisioning_keys), or
//!   [choose a `DPoP` key policy](crate::_docs::guide::dpop_policy).
//! - **Set up an application:** [sign a macOS app](crate::_docs::guide::signing_an_app)
//!   or [select a Keychain backend](crate::_docs::guide::selecting_a_backend).
//! - **Understand the design:** read the [security model](crate::_docs::explanation::security_model)
//!   and [signing and entitlements](crate::_docs::explanation::signing_and_entitlements).
//! - **Look up the API:** use the crate modules and item pages in this reference.
//!
//! For the complete reading map, see [all documentation](crate::_docs).
//! Contributors can follow [running tests](crate::_docs::guide::testing) for unit,
//! signed integration, and interactive hardware checks.
//!
//! Related huskarl guides:
//!
//! - [Providing secrets](https://docs.rs/huskarl-core/latest/huskarl_core/_docs/guide/providing_secrets/index.html)
//! - [Building and signing a JWT](https://docs.rs/huskarl-core/latest/huskarl_core/_docs/guide/signing_a_jwt/index.html)
//! - [Composing crypto strategies](https://docs.rs/huskarl-core/latest/huskarl_core/_docs/explanation/crypto_strategies/index.html)

#![forbid(unsafe_code)]
#![deny(missing_docs, rustdoc::broken_intra_doc_links)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![warn(clippy::pedantic)]

#[cfg(any(doc, doctest))]
pub mod _docs;

pub mod keychain;
mod platform;
pub mod policy;
pub mod secure_enclave;

#[cfg(test)]
#[path = "../support/unique_label.rs"]
mod test_support;

pub use platform::PlatformError;
pub use secure_enclave::{Es256PrivateKey, SetupError, SigningError};
