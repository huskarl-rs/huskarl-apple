//! Interactive tests: sign this executable with Keychain entitlements first.
//! Run directly with --ignored --nocapture and approve the system prompts.
#[path = "../support/unique_label.rs"]
mod support;

use huskarl_apple::secure_enclave::{
    Es256PrivateKey, KeyAccessPolicy, KeyAuthentication, SealingKey,
};
use huskarl_core::crypto::{
    seal::{AeadSealer as _, AeadUnsealer as _},
    signer::JwsSigner as _,
    verifier::{JwsVerifier as _, KeyMatch},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[cfg(feature = "local-authentication")]
#[tokio::test]
#[ignore = "interactive: requires signed executable, Secure Enclave, and user authentication"]
async fn shared_context_reuses_authentication_and_invalidation_revokes_it() -> TestResult {
    use huskarl_apple::authentication::AuthenticationContext;

    let label = support::unique_label("huskarl-apple-test")?;
    let context = AuthenticationContext::builder()
        .localized_reason("Authorize the authentication-context integration test")
        .build();
    let key = Es256PrivateKey::generate_with()
        .label(&label)
        .creation_policy(
            KeyAccessPolicy::builder()
                .authentication(KeyAuthentication::UserPresence)
                .build(),
        )
        .authentication_context(context.clone())
        .generate()
        .await?;
    let result: TestResult = async {
        eprintln!("Approve authentication; subsequent signatures must work with UI disabled.");
        key.sign(b"first request").await?;
        context.set_interaction_allowed(false).await;
        key.sign(b"second request").await?;
        let loaded = Es256PrivateKey::load_with()
            .label(&label)
            .authentication_context(context.clone())
            .load()
            .await?;
        loaded.sign(b"reloaded request").await?;
        context.clone().invalidate();
        assert!(key.sign(b"invalidated request").await.is_err());
        assert!(loaded.sign(b"invalidated reloaded request").await.is_err());
        Ok(())
    }
    .await;
    // An invalidated context cannot be reused for cleanup or a new session.
    let cleanup = async {
        Es256PrivateKey::load(&label)
            .await?
            .delete_key_and_associated_items()
            .await
    }
    .await;
    result?;
    cleanup?;
    Ok(())
}

#[tokio::test]
#[ignore = "interactive: requires signed executable, Secure Enclave, and user authentication"]
async fn presence_protected_keys_survive_reload() -> TestResult {
    let suffix = support::unique_label("huskarl-apple-presence")?;
    let signing_label = format!("huskarl-apple-presence-sign-{suffix}");
    let sealing_label = format!("huskarl-apple-presence-seal-{suffix}");
    let policy = KeyAccessPolicy::builder()
        .authentication(KeyAuthentication::UserPresence)
        .build();
    let signing = Es256PrivateKey::generate_with()
        .label(&signing_label)
        .creation_policy(policy)
        .generate()
        .await?;
    let result: TestResult = async {
        eprintln!("Signing with a reloaded presence-protected key; approve if macOS prompts.");
        let loaded = Es256PrivateKey::load(&signing_label).await?;
        let signature = loaded.sign(b"header.payload").await?;
        loaded
            .verifier()?
            .verify(
                b"header.payload",
                &signature,
                &KeyMatch::builder().alg("ES256").build(),
            )
            .await?;

        let sealing = SealingKey::generate_with()
            .label(&sealing_label)
            .creation_policy(policy)
            .generate()
            .await?;
        let sealed_result: TestResult = async {
            let blob = sealing.seal(b"message", b"context").await?;
            eprintln!(
                "Unsealing with a reloaded presence-protected key; approve if macOS prompts."
            );
            let loaded = SealingKey::load(&sealing_label).await?;
            assert_eq!(
                loaded
                    .unseal(&blob.bundle, b"context", blob.kid.as_deref())
                    .await?,
                b"message"
            );
            Ok(())
        }
        .await;
        let cleanup = sealing.delete_key_and_associated_items().await;
        sealed_result?;
        cleanup?;
        Ok(())
    }
    .await;
    let cleanup = signing.delete_key_and_associated_items().await;
    result?;
    cleanup?;
    Ok(())
}
