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

# async fn example() -> Result<(), huskarl_apple::SetupError> {
let policy = KeyAccessPolicy::builder()
    .availability(Availability::WhenUnlocked)
    .authentication(Authentication::UserPresence)
    .build();
let key = Es256PrivateKey::generate_with()
    .label("io.example.signing-with-presence-v1")
    .creation_policy(policy)
    .generate().await?;
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


## Reuse and control an authentication context

Enable the `local-authentication` Cargo feature. Pass clones of one
`AuthenticationContext` to adapters belonging to the same application session:

```rust,no_run
# #[cfg(feature = "local-authentication")]
# async fn example() -> Result<(), Box<dyn std::error::Error>> {
use huskarl_apple::{
    authentication::AuthenticationContext,
    keychain::DataProtectionKeychain,
    secure_enclave::Es256PrivateKey,
};
use huskarl_core::crypto::signer::JwsSigner as _;

let context = AuthenticationContext::builder()
    .localized_reason("Unlock your saved session")
    .build();
let secrets = DataProtectionKeychain::new("APPIDPREFIX.io.example.app")?
    .secret("io.example.oauth", "refresh-token")?
    .store()
    .authentication_context(context.clone())
    .build();
let key = Es256PrivateKey::load_with()
    .label("io.example.signing-with-presence-v1")
    .access_group("APPIDPREFIX.io.example.app")
    .authentication_context(context.clone())
    .load().await?;

// Authentication follows each item's existing policy. A successful protected
// operation can authenticate this context for subsequent compatible operations.
let saved = secrets.get().await?;
let signature = key.sign(b"header.payload").await?;

// Subsequent operations may reuse authentication, but cannot display new UI.
// This waits asynchronously for the current operation to finish.
context.set_interaction_allowed(false).await;

// End the session for all clones. Rebuild the adapters with a new context later.
context.invalidate();
drop(saved); // Invalidation does not erase bytes already returned to the app.
# Ok(())
# }
```

For data protection storage, pass the context to the item's `.store()` builder.
For read-only access, use `.reader_with(SecretReadMode::Context(context.clone()))`.
The setter is also available on both enclave key types' `generate_with`,
`load_with`, and `load_or_generate` builders. A store forwards its context to its reader and refresh-token adapter.
Key handles keep their context for signing, unsealing, and private-key deletion.
Public-key verification and sealing do not require authentication. TLS identities
obtained through `install_client_identity` perform a separate Keychain lookup; they do
not inherit this context for URLSession's TLS authentication.

`set_localized_reason(...).await` changes the next prompt's explanation for every clone.
`biometric_unlock_reuse_duration` on the context builder allows reuse of a recent
biometric **device unlock**, capped at five minutes. Its default is zero; it does
not set the lifetime of this application's authenticated session. Explicit
invalidation is the application's responsibility.

File-backed items do not expose authentication-context options. `SecretReadMode`
makes using a context and skipping protected items mutually exclusive. Use
`SecretReadMode::Context` with `interaction_allowed(false)` to get an access
error when authentication is required, preserving the distinction from absence.

### Interoperate with objc2

An application can reuse a context it created or authenticated through
`objc2-local-authentication` 0.3. Import and export preserve the same native object
and its authentication state:

```rust,no_run
# #[cfg(feature = "local-authentication")]
# async fn example() {
use huskarl_apple::authentication::AuthenticationContext;
use objc2_local_authentication::LAContext;

// SAFETY: This example uses the native handle sequentially. In an application,
// finish native evaluations before handing the context to the worker adapters.
let native = unsafe { LAContext::new() };
let context = unsafe { AuthenticationContext::from_native(native) };

// SAFETY: No adapter operation is running while native code accesses this alias.
let native_again = unsafe { context.to_native() };
unsafe { native_again.invalidate() };
# }
```

These two interop methods are unsafe because objc2's `LAContext` is neither
`Send` nor `Sync`, whereas this crate's adapters use blocking worker threads.
All native aliases must obey the synchronization contract in `from_native`:
native access and evaluations must not overlap wrapper operations or property
changes. Native `invalidate` may interrupt a pending evaluation. Do not import
one native object into two wrappers with independent locks; clone the wrapper.
Contexts created and used entirely through the wrapper have a safe API.

On iOS, apps using Face ID must supply `NSFaceIDUsageDescription` in their
Info.plist. The operating system controls which authentication methods are
available and whether previous authentication satisfies an item's policy.
