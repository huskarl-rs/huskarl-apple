/// Quick smoke test: generate a keychain-backed EC key, print its public JWK,
/// then sign some data and verify the signature structure.
use huskarl_core::crypto::signer::{AsymmetricJwsSigner as _, JwsSigner as _};
use huskarl_crypto_macos::Es256PrivateKey;
use security_framework::item::{ItemSearchOptions, KeyClass};

const LABEL: &str = "huskarl-dpop-test-key";

fn delete_test_key() {
    let _ = ItemSearchOptions::new()
        .key_class(KeyClass::private())
        .label(LABEL)
        .delete();
}

#[tokio::main]
async fn main() {
    // Clean up any leftover key from a previous run.
    delete_test_key();

    let key = Es256PrivateKey::generate(LABEL).expect("could not generate key");

    let jwk = key.public_key_jwk();
    println!(
        "Public JWK:\n{}\n",
        serde_json::to_string_pretty(&*jwk).unwrap()
    );
    println!(
        "JWK thumbprint: {}\n",
        jwk.thumbprint().unwrap_or_default()
    );

    println!("JWS algorithm: {}", key.jws_algorithm());
    println!("Key ID: {:?}\n", key.key_id());

    let data = b"test data to sign";
    let signature = key.sign(data).await.expect("signing failed");

    println!("Signature ({} bytes): {}", signature.len(), {
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&signature)
    });

    delete_test_key();
    println!("\nKeychain key deleted.");
}
