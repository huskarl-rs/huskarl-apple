# Use a stored symmetric key

Add `huskarl-crypto-native = "0.11.1"` alongside this crate. For a Keychain item
containing 32 raw key bytes:

```rust,no_run
use huskarl_core::{jwk::OctBytes, secrets::Secret};
use huskarl_crypto_native::aead::AesGcmKey;
use huskarl_apple::keychain::KeychainSecret;

# async fn example() -> Result<(), huskarl_core::Error> {
let source = KeychainSecret::builder()
    .service("io.example.crypto")
    .account("aes-v1")
    .build();
let cipher = AesGcmKey::from_secret(source.mapped(OctBytes::new("A256GCM"))).await?;
# Ok(())
# }
```

This gives the existing structured `AeadEncryptor` / `AeadDecryptor` interfaces.
For HMAC, use a separate secret with `OctBytes::new("HS256")` and
`huskarl_crypto_native::symmetric::SymmetricKey::from_secret`. For PKCS#8 or JWK
private keys, use the native crate's existing decoders and asymmetric loader.
These paths protect stored secrets with Keychain; they do not make the loaded
keys nonextractable. See the [keychain_cipher example](https://github.com/huskarl-rs/huskarl-apple/blob/main/examples/keychain_cipher.rs) for a complete roundtrip.

