//! Opt-in tests requiring a signed test executable with Keychain entitlements.
#[path = "../support/unique_label.rs"]
mod support;

use core_foundation::data::CFData;
use huskarl_apple::{
    Es256PrivateKey, SetupError, keychain::KeychainSecret, secure_enclave::SealingKey,
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
    ItemAddOptions, ItemAddValue, ItemClass, ItemSearchOptions, Location,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[tokio::test]
#[ignore = "requires a signed test executable, Keychain entitlements, and Secure Enclave"]
async fn signing_key_survives_reload() -> TestResult {
    let label = support::unique_label("huskarl-apple-test")?;
    assert!(matches!(
        Es256PrivateKey::load(&label),
        Err(SetupError::KeyNotFound)
    ));
    let key = Es256PrivateKey::generate(&label)?;
    let result: TestResult = async {
        let signature = key.sign(b"header.payload").await?;
        let loaded = Es256PrivateKey::load(&label)?;
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
    let cleanup = key.delete();
    result?;
    cleanup?;
    assert!(matches!(
        Es256PrivateKey::load(&label),
        Err(SetupError::KeyNotFound)
    ));
    Ok(())
}

#[tokio::test]
#[ignore = "requires a signed test executable, Keychain entitlements, and Secure Enclave"]
async fn sealing_key_survives_reload() -> TestResult {
    let label = support::unique_label("huskarl-apple-test")?;
    let key = SealingKey::generate(&label)?;
    let result: TestResult = async {
        let sealed = key.seal(b"secret", b"context").await?;
        let loaded = SealingKey::load(&label)?;
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
    let cleanup = key.delete();
    result?;
    cleanup?;
    assert!(matches!(
        SealingKey::load(&label),
        Err(SetupError::KeyNotFound)
    ));
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
    let source = KeychainSecret::builder()
        .service(&service)
        .account("aes-key")
        .build();
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

#[test]
#[ignore = "requires a signed test executable, Keychain entitlements, and Secure Enclave"]
fn purposes_have_independent_namespaces() -> TestResult {
    let label = support::unique_label("huskarl-apple-test")?;
    let signing = Es256PrivateKey::generate(&label)?;
    let result: TestResult = (|| {
        assert!(matches!(
            SealingKey::load(&label),
            Err(SetupError::KeyNotFound)
        ));
        let sealing = SealingKey::generate(&label)?;
        let result: TestResult = (|| {
            let loaded_signing = Es256PrivateKey::load(&label)?;
            let loaded_sealing = SealingKey::load(&label)?;
            assert_eq!(
                loaded_signing.public_key_jwk().thumbprint(),
                signing.public_key_jwk().thumbprint()
            );
            assert_eq!(loaded_sealing.key_id(), sealing.key_id());
            Ok(())
        })();
        let cleanup = sealing.delete();
        result?;
        cleanup?;
        assert!(matches!(
            SealingKey::load(&label),
            Err(SetupError::KeyNotFound)
        ));
        Es256PrivateKey::load(&label)?;
        Ok(())
    })();
    let cleanup = signing.delete();
    result?;
    cleanup?;

    // Also check the other direction when only a sealing key exists.
    let sealing = SealingKey::generate(&label)?;
    let result = Es256PrivateKey::load(&label);
    sealing.delete()?;
    assert!(matches!(result, Err(SetupError::KeyNotFound)));
    Ok(())
}
