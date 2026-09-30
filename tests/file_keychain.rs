//! File-based storage without signing entitlements, using disposable keychains.
#[path = "../support/unique_label.rs"]
mod support;

use huskarl::{cache::RefreshTokenStore as _, token::RefreshToken};
use huskarl_apple::keychain::{KeychainBackend, KeychainRefreshTokenStore, KeychainSecretStore};
use huskarl_core::secrets::{Secret as _, SecretBytes, SecretString};
use security_framework::os::macos::keychain::CreateOptions;

#[tokio::test]
#[ignore = "creates disposable file keychains; macOS may request authorization"]
async fn file_storage_roundtrip_and_isolation() -> Result<(), Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(support::unique_label("huskarl-file-keychains")?);
    std::fs::create_dir(&dir)?;
    let paths = [
        dir.join("first.keychain-db"),
        dir.join("second.keychain-db"),
    ];
    let result: Result<(), Box<dyn std::error::Error>> = async {
        let mut keychains = Vec::new();
        for path in &paths {
            keychains.push(
                CreateOptions::new()
                    .password("disposable-test-password")
                    .create(path)?,
            );
        }
        let store = |path: &std::path::Path| {
            KeychainSecretStore::builder()
                .service("huskarl-isolation")
                .account("same-account")
                .backend(KeychainBackend::File(path.to_owned()))
                .build()
        };
        let first = store(&paths[0]);
        let second = store(&paths[1]);
        assert!(first.get().await?.is_none());
        first.set(&SecretBytes::new(vec![0, 255])).await?;
        assert!(second.get().await?.is_none());
        second.set(&SecretBytes::new(vec![2])).await?;
        first.set(&SecretBytes::new(vec![])).await?;
        assert!(
            first
                .reader()?
                .get_secret_value()
                .await?
                .value
                .expose_secret()
                .is_empty()
        );
        assert_eq!(second.get_secret_value().await?.value.expose_secret(), &[2]);
        first.clear().await?;
        first.clear().await?;
        assert_eq!(second.get_secret_value().await?.value.expose_secret(), &[2]);
        let tokens = KeychainRefreshTokenStore::builder().storage(first).build();
        let token = RefreshToken::new(SecretString::new("test-token"), Some("binding".into()));
        tokens.set(&token).await?;
        let reloaded = KeychainRefreshTokenStore::builder()
            .storage(store(&paths[0]))
            .build();
        assert_eq!(reloaded.get().await?, Some(token));
        reloaded.clear().await?;
        assert!(tokens.get().await?.is_none());
        Ok(())
    }
    .await;
    // SecKeychainCreate may register these files in the search list. Delete
    // through Security's CLI so the registration is removed too.
    let mut cleanup_ok = true;
    for path in &paths {
        if path.exists() {
            cleanup_ok &= std::process::Command::new("/usr/bin/security")
                .arg("delete-keychain")
                .arg(path)
                .status()?
                .success();
        }
    }
    result?;
    assert!(cleanup_ok);
    std::fs::remove_dir(dir)?;
    Ok(())
}
