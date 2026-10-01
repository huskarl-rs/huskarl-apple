//! Opt-in tests requiring a signed test executable with Keychain entitlements.
#[path = "../support/unique_label.rs"]
mod support;

use core_foundation::data::CFData;
use huskarl_apple::{
    Es256PrivateKey, SetupError,
    keychain::{DataProtectionKeychain, SecretReadMode},
    secure_enclave::SealingKey,
};
use huskarl_core::{
    crypto::{
        cipher::{AeadDecryptor as _, AeadEncryptorSelector as _},
        seal::{AeadSealer as _, AeadUnsealer as _},
        signer::{AsymmetricJwsSigner as _, JwsSigner as _},
        verifier::{JwsVerifier as _, KeyMatch},
    },
    jwk::OctBytes,
    secrets::Secret as _,
};
use huskarl_crypto_native::aead::AesGcmKey;
use security_framework::item::{
    ItemAddOptions, ItemAddValue, ItemClass, ItemSearchOptions, KeyClass, Limit, Location,
};
use security_framework_sys::base::errSecItemNotFound;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Asserts that deletion removed both halves of the key pair.
fn assert_no_key_items(stored_label: &str) {
    let result = ItemSearchOptions::new()
        .ignore_legacy_keychains()
        .class(ItemClass::key())
        .label(stored_label)
        .load_attributes(true)
        .limit(Limit::All)
        .search();
    assert!(
        matches!(&result, Err(error) if error.code() == errSecItemNotFound),
        "key items remain after delete: {result:?}"
    );
}

#[tokio::test]
#[ignore = "requires a signed test executable, Keychain entitlements, and Secure Enclave"]
async fn sealing_key_deletion_resumes_after_private_key_removal() -> TestResult {
    let label = support::unique_label("huskarl-apple-test")?;
    let key = SealingKey::generate(&label).await?;
    let stored_label = format!("huskarl-apple/seal/{label}");
    let result: TestResult = async {
        let mut private = ItemSearchOptions::new();
        private
            .ignore_legacy_keychains()
            .key_class(KeyClass::private())
            .label(&stored_label);
        private.delete()?;
        key.clone().delete_key_and_associated_items().await?;
        key.delete_key_and_associated_items().await?;
        assert_no_key_items(&stored_label);
        Ok(())
    }
    .await;
    let cleanup = key.delete_key_and_associated_items().await;
    result?;
    cleanup?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires a signed test executable, Keychain entitlements, and Secure Enclave"]
async fn signing_key_survives_reload() -> TestResult {
    let label = support::unique_label("huskarl-apple-test")?;
    assert!(matches!(
        Es256PrivateKey::load(&label).await,
        Err(SetupError::KeyNotFound)
    ));
    let key = Es256PrivateKey::generate(&label).await?;
    let result: TestResult = async {
        let signature = key.sign(b"header.payload").await?;
        let loaded = Es256PrivateKey::load(&label).await?;
        assert_eq!(
            loaded.public_key_jwk().thumbprint(),
            key.public_key_jwk().thumbprint()
        );
        loaded
            .verifier()?
            .verify(
                b"header.payload",
                &signature,
                &KeyMatch::builder().alg("ES256").build(),
            )
            .await?;
        Ok(())
    }
    .await;
    let cleanup = key.delete_key_and_associated_items().await;
    result?;
    cleanup?;
    assert!(matches!(
        Es256PrivateKey::load(&label).await,
        Err(SetupError::KeyNotFound)
    ));
    assert_no_key_items(&format!("huskarl-apple/sign/{label}"));
    Ok(())
}

#[tokio::test]
#[ignore = "requires a signed test executable, Keychain entitlements, and Secure Enclave"]
async fn sealing_key_survives_reload() -> TestResult {
    let label = support::unique_label("huskarl-apple-test")?;
    let key = SealingKey::generate(&label).await?;
    let result: TestResult = async {
        let sealed = key.seal(b"secret", b"context").await?;
        let loaded = SealingKey::load(&label).await?;
        assert_eq!(loaded.key_id(), key.key_id());
        assert_eq!(
            loaded
                .unseal(&sealed.bundle, b"context", sealed.kid.as_deref())
                .await?,
            b"secret"
        );
        assert!(loaded.unseal(&sealed.bundle, b"wrong", None).await.is_err());
        Ok(())
    }
    .await;
    let cleanup = key.delete_key_and_associated_items().await;
    result?;
    cleanup?;
    assert!(matches!(
        SealingKey::load(&label).await,
        Err(SetupError::KeyNotFound)
    ));
    assert_no_key_items(&format!("huskarl-apple/seal/{label}"));
    Ok(())
}

#[tokio::test]
#[ignore = "requires a signed test executable with Keychain entitlements"]
async fn keychain_secret_composes_with_native_cipher() -> TestResult {
    let service = support::unique_label("huskarl-apple-test")?;
    ItemAddOptions::new(ItemAddValue::Data {
        class: ItemClass::generic_password(),
        data: CFData::from_buffer(&[42; 32]),
    })
    .set_location(Location::DataProtectionKeychain)
    .set_service(&service)
    .set_account_name("aes-key")
    .add()?;
    let source =
        DataProtectionKeychain::search_all_groups(&service, "aes-key", SecretReadMode::Allow)?;
    let result: TestResult = async {
        let secret = source.get_secret_value().await?;
        assert_eq!(secret.value.expose_secret(), &[42; 32]);
        assert!(secret.identity.is_none());
        let cipher =
            AesGcmKey::from_secret(source.clone().mapped(OctBytes::new("A256GCM"))).await?;
        let encrypted = cipher
            .select_encryptor()
            .await
            .encrypt(b"message", b"context")
            .await?;
        assert_eq!(
            cipher
                .decrypt(
                    None,
                    &encrypted.nonce,
                    &encrypted.ciphertext,
                    &encrypted.tag,
                    b"context"
                )
                .await?,
            b"message"
        );
        Ok(())
    }
    .await;
    let cleanup = ItemSearchOptions::new()
        .ignore_legacy_keychains()
        .class(ItemClass::generic_password())
        .service(&service)
        .account("aes-key")
        .delete();
    result?;
    cleanup?;
    assert!(source.get_secret_value().await.is_err());
    Ok(())
}

#[tokio::test]
#[ignore = "requires a signed test executable, Keychain entitlements, and Secure Enclave"]
async fn purposes_have_independent_namespaces() -> TestResult {
    let label = support::unique_label("huskarl-apple-test")?;
    let signing = Es256PrivateKey::generate(&label).await?;
    let result: TestResult = async {
        assert!(matches!(
            SealingKey::load(&label).await,
            Err(SetupError::KeyNotFound)
        ));
        let sealing = SealingKey::generate(&label).await?;
        let result: TestResult = async {
            let loaded_signing = Es256PrivateKey::load(&label).await?;
            let loaded_sealing = SealingKey::load(&label).await?;
            assert_eq!(
                loaded_signing.public_key_jwk().thumbprint(),
                signing.public_key_jwk().thumbprint()
            );
            assert_eq!(loaded_sealing.key_id(), sealing.key_id());
            Ok(())
        }
        .await;
        let cleanup = sealing.delete_key_and_associated_items().await;
        result?;
        cleanup?;
        assert!(matches!(
            SealingKey::load(&label).await,
            Err(SetupError::KeyNotFound)
        ));
        Es256PrivateKey::load(&label).await?;
        Ok(())
    }
    .await;
    let cleanup = signing.delete_key_and_associated_items().await;
    result?;
    cleanup?;

    // Also check the other direction when only a sealing key exists.
    let sealing = SealingKey::generate(&label).await?;
    let result = Es256PrivateKey::load(&label).await;
    sealing.delete_key_and_associated_items().await?;
    assert!(matches!(result, Err(SetupError::KeyNotFound)));
    Ok(())
}
