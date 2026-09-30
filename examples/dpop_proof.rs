//! Generate, sign, verify, reload, and delete an enclave signing key.
#[path = "../support/unique_label.rs"]
mod support;

use huskarl_apple::Es256PrivateKey;
use huskarl_core::crypto::{
    signer::{AsymmetricJwsSigner as _, JwsSigner as _},
    verifier::{JwsVerifier as _, KeyMatch},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let label = support::unique_label("huskarl-apple-signing-example")?;
    let key = Es256PrivateKey::generate(&label)?;
    let result: Result<(), Box<dyn std::error::Error>> = async {
        let signature = key.sign(b"header.payload").await?;
        let criteria = KeyMatch::builder().alg("ES256").build();
        key.verifier()?
            .verify(b"header.payload", &signature, &criteria)
            .await?;
        let loaded = Es256PrivateKey::load(&label)?;
        assert_eq!(
            loaded.public_key_jwk().thumbprint(),
            key.public_key_jwk().thumbprint()
        );
        loaded
            .verifier()?
            .verify(b"header.payload", &signature, &criteria)
            .await?;
        println!("Verified ES256 signature before and after reloading the key.");
        println!(
            "Public JWK: {}",
            serde_json::to_string_pretty(&*key.public_key_jwk())?
        );
        Ok(())
    }
    .await;
    let cleanup = key.delete();
    result?;
    cleanup?;
    println!("Deleted the example key.");
    Ok(())
}
