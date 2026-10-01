//! Signed, noninteractive checks for LocalAuthentication integration.
#![cfg(feature = "local-authentication")]

#[path = "../support/unique_label.rs"]
mod support;

use huskarl_apple::{
    authentication::AuthenticationContext,
    keychain::{DataProtectionKeychain, SecretAccessPolicy, SecretError},
    policy::Authentication,
    secure_enclave::{Es256PrivateKey, KeyAccessPolicy, SealingKey},
};
use huskarl_core::{
    crypto::{
        seal::{AeadSealer as _, AeadUnsealer as _},
        signer::JwsSigner as _,
    },
    secrets::{Secret as _, SecretBytes},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[tokio::test]
#[ignore = "requires signed executable and HUSKARL_TEST_ACCESS_GROUP"]
async fn secret_context_is_used_by_store_and_reader() -> TestResult {
    let service = support::unique_label("huskarl-apple-storage")?;
    let group = std::env::var("HUSKARL_TEST_ACCESS_GROUP")?;
    let context = AuthenticationContext::builder()
        .interaction_allowed(false)
        .build();
    let store = DataProtectionKeychain::new(&group)?
        .secret(&service, "secret")?
        .store()
        .authentication_context(context.clone())
        .build();
    let result: TestResult = async {
        assert!(store.get().await?.is_none());
        store.set(&SecretBytes::new(vec![1])).await?;
        store.set(&SecretBytes::new(vec![2])).await?;
        assert_eq!(
            store
                .reader()
                .get_secret_value()
                .await?
                .value
                .expose_secret(),
            &[2]
        );
        assert_eq!(
            store.get().await?.ok_or("item missing")?.expose_secret(),
            &[2]
        );
        store.clear().await?;
        assert!(store.get().await?.is_none());
        Ok(())
    }
    .await;
    let cleanup = store.clear().await;
    result?;
    cleanup?;

    // A new context has no cached authentication. Reading a protected item must
    // fail without a dialog, and must never become Ok(None).
    let protected = DataProtectionKeychain::new(&group)?
        .secret(&service, "protected")?
        .store()
        .creation_policy(
            SecretAccessPolicy::builder()
                .authentication(Authentication::UserPresence)
                .build(),
        )
        .authentication_context(context.clone())
        .build();
    protected.set(&SecretBytes::new(vec![3])).await?;
    let result: TestResult = async {
        assert!(matches!(protected.get().await, Err(SecretError::Access { source }) if source.code() == -25308));
        assert!(protected.reader().get_secret_value().await.is_err());
        context.invalidate();
        assert!(protected.get().await.is_err());
        Ok(())
    }.await;
    // Cleanup uses a fresh context; invalidation is permanent.
    let cleanup = DataProtectionKeychain::new(&group)?
        .secret(&service, "protected")?
        .store()
        .build()
        .clear()
        .await;
    result?;
    cleanup?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires signed executable and Secure Enclave"]
async fn enclave_keys_keep_the_context_through_generation_and_reload() -> TestResult {
    let label = support::unique_label("huskarl-apple-test")?;
    let context = AuthenticationContext::builder()
        .interaction_allowed(false)
        .build();
    let signing = Es256PrivateKey::generate_with()
        .label(&label)
        .authentication_context(context.clone())
        .generate()
        .await?;
    let result: TestResult = async {
        signing.sign(b"message").await?;
        let loaded = Es256PrivateKey::load_with()
            .label(&label)
            .authentication_context(context.clone())
            .load()
            .await?;
        loaded.with_key_id("custom").sign(b"message").await?;
        let sealing = SealingKey::generate_with()
            .label(&label)
            .authentication_context(context.clone())
            .generate()
            .await?;
        let result: TestResult = async {
            let sealed = sealing.seal(b"message", b"aad").await?;
            assert_eq!(
                sealing
                    .unseal(&sealed.bundle, b"aad", sealed.kid.as_deref())
                    .await?,
                b"message"
            );
            let loaded = SealingKey::load_with()
                .label(&label)
                .authentication_context(context.clone())
                .load()
                .await?;
            assert_eq!(
                loaded
                    .unseal(&sealed.bundle, b"aad", sealed.kid.as_deref())
                    .await?,
                b"message"
            );
            Ok(())
        }
        .await;
        let cleanup = sealing.delete_key_and_associated_items().await;
        result?;
        cleanup?;
        Ok(())
    }
    .await;
    let cleanup = signing.delete_key_and_associated_items().await;
    result?;
    cleanup?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires signed executable and Secure Enclave"]
async fn protected_keys_fail_without_ui_for_generated_and_loaded_handles() -> TestResult {
    let label = support::unique_label("huskarl-apple-test")?;
    let context = AuthenticationContext::builder()
        .interaction_allowed(false)
        .build();
    let policy = KeyAccessPolicy::builder()
        .authentication(Authentication::UserPresence)
        .build();
    let signing = Es256PrivateKey::generate_with()
        .label(&label)
        .creation_policy(policy)
        .authentication_context(context.clone())
        .generate()
        .await?;
    let result: TestResult = async {
        assert!(signing.sign(b"message").await.is_err());
        let loaded = Es256PrivateKey::load_with()
            .label(&label)
            .authentication_context(context.clone())
            .load()
            .await?;
        assert!(loaded.sign(b"message").await.is_err());
        let sealing = SealingKey::generate_with()
            .label(&label)
            .creation_policy(policy)
            .authentication_context(context.clone())
            .generate()
            .await?;
        let result: TestResult = async {
            let sealed = sealing.seal(b"message", b"aad").await?;
            assert!(
                sealing
                    .unseal(&sealed.bundle, b"aad", sealed.kid.as_deref())
                    .await
                    .is_err()
            );
            let loaded = SealingKey::load_with()
                .label(&label)
                .authentication_context(context.clone())
                .load()
                .await?;
            assert!(
                loaded
                    .unseal(&sealed.bundle, b"aad", sealed.kid.as_deref())
                    .await
                    .is_err()
            );
            Ok(())
        }
        .await;
        let cleanup = sealing.delete_key_and_associated_items().await;
        result?;
        cleanup?;
        Ok(())
    }
    .await;
    let cleanup = signing.delete_key_and_associated_items().await;
    result?;
    cleanup?;
    Ok(())
}
