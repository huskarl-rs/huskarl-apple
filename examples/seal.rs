//! Generate, seal, reload, unseal, and delete an enclave encryption key.
#[path = "../support/unique_label.rs"]
mod support;

use huskarl_apple::secure_enclave::SealingKey;
use huskarl_core::crypto::seal::{AeadSealer as _, AeadUnsealer as _};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let label = support::unique_label("huskarl-apple-sealing-example")?;
    let key = SealingKey::generate(&label)?;
    let result: Result<(), Box<dyn std::error::Error>> = async {
        let sealed = key.seal(b"secret payload", b"example-context").await?;
        let loaded = SealingKey::load(&label)?;
        let plaintext = loaded
            .unseal(&sealed.bundle, b"example-context", sealed.kid.as_deref())
            .await?;
        assert_eq!(plaintext, b"secret payload");
        assert!(
            loaded
                .unseal(&sealed.bundle, b"different-context", None)
                .await
                .is_err()
        );
        println!("Sealed and unsealed with the same key after reloading; wrong AAD rejected.");
        Ok(())
    }
    .await;
    let cleanup = key.delete();
    result?;
    cleanup?;
    println!("Deleted the example key.");
    Ok(())
}
