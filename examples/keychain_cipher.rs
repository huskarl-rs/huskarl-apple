//! Read a pre-provisioned 32-byte AES key from Keychain and use structured AEAD.
//! Usage: keychain_cipher <service> <account>
use huskarl_apple::keychain::KeychainSecret;
use huskarl_core::{
    crypto::cipher::{AeadDecryptor as _, AeadEncryptorSelector as _},
    jwk::OctBytes,
    secrets::Secret as _,
};
use huskarl_crypto_native::aead::AesGcmKey;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let service = args.next().ok_or("missing service argument")?;
    let account = args.next().ok_or("missing account argument")?;
    let source = KeychainSecret::builder()
        .service(service)
        .account(account)
        .build();
    let cipher = AesGcmKey::from_secret(source.mapped(OctBytes::new("A256GCM"))).await?;
    let encrypted = cipher
        .select_encryptor()
        .await
        .encrypt(b"example plaintext", b"context")
        .await?;
    let plaintext = cipher
        .decrypt(
            None,
            &encrypted.nonce,
            &encrypted.ciphertext,
            &encrypted.tag,
            b"context",
        )
        .await?;
    assert_eq!(plaintext, b"example plaintext");
    println!("Keychain-loaded AES key encrypted and decrypted successfully.");
    Ok(())
}
