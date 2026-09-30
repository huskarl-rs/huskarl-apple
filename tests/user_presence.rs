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
        .access_policy(policy)
        .generate()?;
    let result: TestResult = async {
        eprintln!("Signing with a reloaded presence-protected key; approve if macOS prompts.");
        let loaded = Es256PrivateKey::load(&signing_label)?;
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
            .access_policy(policy)
            .generate()?;
        let sealed_result: TestResult = async {
            let blob = sealing.seal(b"message", b"context").await?;
            eprintln!(
                "Unsealing with a reloaded presence-protected key; approve if macOS prompts."
            );
            let loaded = SealingKey::load(&sealing_label)?;
            assert_eq!(
                loaded
                    .unseal(&blob.bundle, b"context", blob.kid.as_deref())
                    .await?,
                b"message"
            );
            Ok(())
        }
        .await;
        let cleanup = sealing.delete();
        sealed_result?;
        cleanup?;
        Ok(())
    }
    .await;
    let cleanup = signing.delete();
    result?;
    cleanup?;
    Ok(())
}
