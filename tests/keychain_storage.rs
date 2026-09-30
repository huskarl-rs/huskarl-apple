//! Opt-in writable storage tests requiring a signed, entitled executable.
#[path = "../support/unique_label.rs"]
mod support;

use huskarl::{cache::RefreshTokenStore as _, token::RefreshToken};
use huskarl_apple::{
    keychain::{KeychainRefreshTokenStore, KeychainSecretStore, SecretAccessPolicy},
    secure_enclave::KeyAvailability,
};
use huskarl_core::secrets::{Secret as _, SecretBytes, SecretString};
use security_framework::item::{ItemClass, ItemSearchOptions, SearchResult};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn store(service: &str, group: &str, availability: KeyAvailability) -> KeychainSecretStore {
    KeychainSecretStore::builder()
        .service(service)
        .account("token")
        .access_group(group)
        .access_policy(
            SecretAccessPolicy::builder()
                .availability(availability)
                .build(),
        )
        .build()
}

#[tokio::test]
#[ignore = "requires signed executable and HUSKARL_TEST_ACCESS_GROUP"]
async fn secret_updates_preserve_policy() -> TestResult {
    let service = support::unique_label("huskarl-apple-storage")?;
    let group = std::env::var("HUSKARL_TEST_ACCESS_GROUP")?;
    let original = store(&service, &group, KeyAvailability::WhenUnlocked);
    let result: TestResult = async {
        original.clear().await?;
        assert!(original.get().await?.is_none());
        original.set(&SecretBytes::new(vec![0, 255, 1])).await?;
        let reloaded = store(&service, &group, KeyAvailability::AfterFirstUnlock);
        assert_eq!(
            reloaded
                .reader()?
                .get_secret_value()
                .await?
                .value
                .expose_secret(),
            &[0, 255, 1]
        );
        reloaded.set(&SecretBytes::new(vec![])).await?;
        assert!(
            original
                .get_secret_value()
                .await?
                .value
                .expose_secret()
                .is_empty()
        );
        let attributes = ItemSearchOptions::new()
            .ignore_legacy_keychains()
            .class(ItemClass::generic_password())
            .service(&service)
            .account("token")
            .access_group(&group)
            .load_attributes(true)
            .search()?;
        let attributes = attributes
            .first()
            .and_then(SearchResult::simplify_dict)
            .ok_or("missing attributes")?;
        assert_eq!(attributes.get("pdmn").map(String::as_str), Some("aku"));
        reloaded.clear().await?;
        reloaded.clear().await?;
        assert!(original.get().await?.is_none());
        Ok(())
    }
    .await;
    let cleanup = original.clear().await;
    result?;
    cleanup?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires signed executable and HUSKARL_TEST_ACCESS_GROUP"]
async fn refresh_tokens_survive_reload_and_rotation() -> TestResult {
    let service = support::unique_label("huskarl-apple-storage")?;
    let group = std::env::var("HUSKARL_TEST_ACCESS_GROUP")?;
    let storage = store(&service, &group, KeyAvailability::WhenUnlocked);
    let tokens = KeychainRefreshTokenStore::builder()
        .storage(storage.clone())
        .build();
    let result: TestResult = async {
        tokens.clear().await?;
        assert!(tokens.get().await?.is_none());
        let bound = RefreshToken::new(SecretString::new("original"), Some("thumbprint".into()));
        tokens.set(&bound).await?;
        let reloaded = KeychainRefreshTokenStore::builder()
            .storage(store(&service, &group, KeyAvailability::WhenUnlocked))
            .build();
        assert_eq!(reloaded.get().await?, Some(bound));
        let rotated = RefreshToken::new(SecretString::new("rotated"), None);
        reloaded.set(&rotated).await?;
        assert_eq!(tokens.get().await?, Some(rotated));
        // Corruption is an error, not absence, and a failed read retains the item.
        let corrupt = SecretBytes::new(b"invalid stored token".to_vec());
        storage.set(&corrupt).await?;
        assert!(tokens.get().await.is_err());
        assert_eq!(
            storage.get_secret_value().await?.value.expose_secret(),
            corrupt.expose_secret()
        );
        tokens.clear().await?;
        tokens.clear().await?;
        assert!(tokens.get().await?.is_none());
        Ok(())
    }
    .await;
    let cleanup = storage.clear().await;
    result?;
    cleanup?;
    Ok(())
}
