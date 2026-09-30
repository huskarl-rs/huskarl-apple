# Sign, verify, seal, and unseal

Use separate signing and sealing keys in a signed application with Secure Enclave
hardware. See the [signing setup](crate::_docs::guide::signing_an_app) first.

```rust,no_run
use huskarl_core::crypto::{
    signer::JwsSigner,
    verifier::{JwsVerifier, KeyMatch},
    seal::{AeadSealer, AeadUnsealer},
};
use huskarl_apple::secure_enclave::{Es256PrivateKey, SealingKey};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let signer = Es256PrivateKey::generate("io.example.signing-v1")?;
let signature = signer.sign(b"header.payload").await?;
signer.verifier()?.verify(
    b"header.payload", &signature, &KeyMatch::builder().alg("ES256").build(),
).await?;

let cipher = SealingKey::generate("io.example.sealing-v1")?;
let sealed = cipher.seal(b"payload", b"context").await?;
let reopened = cipher.unseal(&sealed.bundle, b"context", sealed.kid.as_deref()).await?;
# Ok(())
# }
```

## Notes

Keys persist across restarts; use `load(label)` to reopen them. Signing and
sealing use separate stored-label namespaces and application tags
(`huskarl-apple/sign` and `huskarl-apple/seal`). They can share a caller-facing
label; loading checks the persisted purpose tag and enclave token. Missing,
ambiguous, and incorrectly tagged keys are rejected. `generate` always creates
a new key; it is not an upsert. `with_key_id` changes signing metadata
for that handle only and must be reapplied after loading. Sealing uses a stable
public-key thumbprint as its ID. Explicit `delete()` removes the persisted
private key; dropping a handle does not delete it.

