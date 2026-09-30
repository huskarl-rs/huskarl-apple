//! Learning, task-oriented, and conceptual documentation for the Apple backend.
//!
//! - **[Tutorial](tutorial)** — store and retrieve your first secret.
//! - **[How-to guides](guide)** — recipes for secrets, keys, application setup, and testing.
//! - **[Explanation](explanation)** — the security model and signing requirements.
//! - **Reference** — the crate's API modules describe types and operations.
//!
//! This module is documentation only. Its examples run under `cargo test --doc`.

/// A complete learning experience using the login keychain.
pub mod tutorial {
    #[doc = include_str!("../docs/tutorial/first_secret.md")]
    pub mod first_secret {}
}

/// Task-oriented recipes for using and developing the crate.
pub mod guide {
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
    #[doc = include_str!("../docs/explanation/security_model.md")]
    pub mod security_model {}

    #[doc = include_str!("../docs/explanation/signing_and_entitlements.md")]
    pub mod signing_and_entitlements {}
}
