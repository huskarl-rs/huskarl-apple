//! Documentation for integrating Huskarl OAuth with Apple applications.
//!
//! Start with [the integration overview](explanation::apple_oauth) to choose your
//! components. New users can follow [the native login tutorial](tutorial::first_login).
//!
//! - **[Tutorials](tutorial)** — learn native OAuth login or Keychain storage.
//! - **[How-to guides](guide)** — build and operate an application session.
//! - **[Explanation](explanation)** — understand component and security boundaries.
//! - **[Reference](mod@reference)** — look up platform support, features, and prerequisites;
//!   the crate's API modules document individual operations.
//!
//! For a foreground app, continue with [a persisted browser session](guide::native_session)
//! and [Apple UI integration](guide::apple_app). For a command-line flow, use
//! [device authorization](guide::dpop_session). iOS adaptation and its current
//! limitations have a dedicated section in the Apple UI guide.
//!
//! This module is documentation only. Rust examples are checked by `cargo test --doc`;
//! enable all features to check optional adapter examples too.

/// Guided learning experiences with native login and the login Keychain.
pub mod tutorial {
    #[doc = include_str!("../docs/tutorial/first_login.md")]
    pub mod first_login {}

    #[doc = include_str!("../docs/tutorial/first_secret.md")]
    pub mod first_secret {}
}

/// Task-oriented recipes for using and developing the crate.
///
/// Follow the session lifecycle:
/// [set up signing](guide::signing_an_app), [connect an Apple UI](guide::apple_app),
/// [present login](guide::browser_login), [persist a native session](guide::native_session),
/// [store refresh tokens](guide::refresh_tokens), [make native HTTP requests](guide::native_networking),
/// and [recover after migration](guide::device_migration).
/// Use [device authorization](guide::dpop_session) for the command-line example.
pub mod guide {
    #[doc = include_str!("../docs/guide/native_session.md")]
    pub mod native_session {}

    #[doc = include_str!("../docs/guide/apple_app.md")]
    pub mod apple_app {}

    #[doc = include_str!("../docs/guide/native_networking.md")]
    pub mod native_networking {}

    #[doc = include_str!("../docs/guide/browser_login.md")]
    pub mod browser_login {}

    #[doc = include_str!("../docs/guide/access_groups.md")]
    pub mod access_groups {}

    #[doc = include_str!("../docs/guide/device_migration.md")]
    pub mod device_migration {}

    #[doc = concat!(
        include_str!("../docs/guide/dpop_session.md"),
        "\n## Complete program\n\n```rust,no_run\n",
        include_str!("../examples/dpop_session.rs"),
        "\n```\n",
    )]
    pub mod dpop_session {}

    #[doc = include_str!("../docs/guide/dpop_policy.md")]
    pub mod dpop_policy {}

    #[doc = include_str!("../docs/guide/key_authentication.md")]
    pub mod key_authentication {}

    #[doc = include_str!("../docs/guide/provisioning_keys.md")]
    pub mod provisioning_keys {}

    #[doc = include_str!("../docs/guide/reading_secrets.md")]
    pub mod reading_secrets {}

    #[doc = include_str!("../docs/guide/refresh_tokens.md")]
    pub mod refresh_tokens {}

    #[doc = include_str!("../docs/guide/secret_authentication.md")]
    pub mod secret_authentication {}

    #[doc = include_str!("../docs/guide/selecting_a_backend.md")]
    pub mod selecting_a_backend {}

    #[doc = include_str!("../docs/guide/signing_an_app.md")]
    pub mod signing_an_app {}

    #[doc = include_str!("../docs/guide/signing_and_sealing.md")]
    pub mod signing_and_sealing {}

    #[doc = include_str!("../docs/guide/storing_secrets.md")]
    pub mod storing_secrets {}

    #[doc = include_str!("../docs/guide/symmetric_crypto.md")]
    pub mod symmetric_crypto {}

    #[doc = include_str!("../docs/guide/testing.md")]
    pub mod testing {}
}

/// Understanding-oriented background on the design.
pub mod explanation {
    #[doc = include_str!("../docs/explanation/apple_oauth.md")]
    pub mod apple_oauth {}

    #[doc = include_str!("../docs/explanation/security_model.md")]
    pub mod security_model {}

    #[doc = include_str!("../docs/explanation/signing_and_entitlements.md")]
    pub mod signing_and_entitlements {}
}

/// Platform, feature, and example facts; individual APIs live in the crate modules.
pub mod reference {
    #[doc = include_str!("../docs/reference/platforms.md")]
    pub mod platforms {}
}
