# Require user authentication

For newly generated enclave keys, use `KeyAccessPolicy`:

| Option | Requested behavior |
|---|---|
| `Availability::WhenUnlocked` (default) | Device-only protection while unlocked |
| `Availability::AfterFirstUnlock` | Device-only protection allowing background use after the first unlock following restart |
| `Authentication::None` (default) | No additional human-presence requirement |
| `Authentication::UserPresence` | System authentication, with biometrics or system-credential fallback |
| `Authentication::BiometryAny` | Biometrics only, without password fallback |
| `Authentication::BiometryCurrentSet` | Biometrics only; enrollment changes invalidate access |

```rust,no_run
use huskarl_apple::{
    policy::{Authentication, Availability},
    secure_enclave::{Es256PrivateKey, KeyAccessPolicy},
};

# fn example() -> Result<(), huskarl_apple::SetupError> {
let policy = KeyAccessPolicy::builder()
    .availability(Availability::WhenUnlocked)
    .authentication(Authentication::UserPresence)
    .build();
let key = Es256PrivateKey::generate_with()
    .label("io.example.signing-with-presence-v1")
    .access_policy(policy)
    .generate()?;
# Ok(())
# }
```

## Notes

`SealingKey::generate_with()` accepts the same policy. Authentication gates signing
and unsealing. Public-key verification and sealing do not need it. The original
`generate(label)` methods retain the defaults above. `load(label)` preserves
the item's existing policy: it cannot add, remove, or relax the stored
constraints. To change the policy, generate a new key and rotate to it.

For secret read UI, retry advice, authentication reuse, and handling cached
plaintext, see the [Keychain access guide](crate::_docs::guide::secret_authentication).
