# Store and retrieve your first secret

This walkthrough uses the macOS login keychain. You will create a temporary
secret, read it back, and delete it. The system may ask you to authorize access.

1. Create a Rust binary project and add these dependencies:

```toml
[target.'cfg(target_os = "macos")'.dependencies]
huskarl-apple = "0.1"
huskarl-core = { version = "0.10", default-features = false }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

2. Replace `src/main.rs` with this program:

```rust,no_run
use huskarl_apple::keychain::{KeychainBackend, KeychainSecretStore};
use huskarl_core::secrets::SecretBytes;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let account = format!("tutorial-{}", std::process::id());
    let store = KeychainSecretStore::builder()
        .service("io.example.huskarl-tutorial")
        .account(account)
        .backend(KeychainBackend::Login)
        .build();
    store.set(&SecretBytes::new(b"hello keychain".to_vec())).await?;
    let value = store.get().await?;
    store.clear().await?;
    assert_eq!(value.as_ref().map(SecretBytes::expose_secret), Some(b"hello keychain".as_slice()));
    println!("Secret retrieved and removed.");
    Ok(())
}
```

3. Run `cargo run` and authorize access if prompted. You should see
   `Secret retrieved and removed.` The assertion confirms the bytes survived a
   write/read roundtrip; `clear()` removes the persisted item.

4. For persistent application storage, choose a stable service/account pair and
   retain the item. Continue with the [storing secrets](crate::_docs::guide::storing_secrets) for
   refresh tokens, access groups, and read providers.
