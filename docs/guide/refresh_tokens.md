# Persist refresh tokens

For the complete grant-to-request flow, see
[the persisted `DPoP` session guide](crate::_docs::guide::dpop_session).

For OAuth, use `KeychainRefreshTokenStore` with huskarl's `RefreshTokenStore` trait:

```rust,no_run
use huskarl::{cache::RefreshTokenStore, token::RefreshToken};
use huskarl_core::secrets::SecretString;
use huskarl_apple::keychain::{KeychainRefreshTokenStore, KeychainSecretStore};

# async fn example() -> Result<(), huskarl_core::Error> {
let tokens = KeychainRefreshTokenStore::builder()
    .storage(KeychainSecretStore::builder()
        .service("io.example.oauth.refresh-tokens")
        .account("issuer-client-user")
        .access_group("TEAMID.io.example.shared")
        .build())
    .build();
let token = RefreshToken::new(SecretString::new("refresh-token"), None);
tokens.set(&token).await?;
let restored = tokens.get().await?;
tokens.clear().await?;
# Ok(())
# }
```

For a session that requires user authentication, set the policy on the
refresh-token item when creating its `KeychainSecretStore`:

```rust
use huskarl_apple::{
    keychain::SecretAccessPolicy,
    policy::Authentication,
};

let policy = SecretAccessPolicy::builder()
    .authentication(Authentication::UserPresence)
    .build();
// Pass .access_policy(policy) to the storage builder above.
```

Keep the `DPoP` signing key at `Authentication::None`: protecting that key with
user presence or biometrics can prompt for every API request's proof. Read the
protected refresh token when opening a session and retain it in session state
to place the authentication step at token loading. Apple controls prompt reuse;
later reads or writes, including token rotation, may prompt again. This policy
applies to data protection storage and requires a newly provisioned item;
updating an existing item preserves its original policy.

## Notes

Reconstruct the store with the same identifiers after restarting. Its versioned
format preserves both the token and its optional `DPoP` thumbprint. Reserve the
item for this format and use distinct accounts for each issuer/client/user
combination. Retain the corresponding enclave key when tokens are `DPoP`-bound.
Only a missing item returns `None`; locked, denied, malformed, and unsupported
items return errors without being cleared. Clearing an absent item succeeds.

Plan for **sign in again** after moving to a new device: the device-only `DPoP`
key cannot migrate, and any surviving token bound to it is unusable. Follow the
[`DPoP` recovery guide](crate::_docs::guide::device_migration)
to distinguish permanent key loss from temporarily unavailable access.

Updates never delete and recreate the item. Concurrent creation is handled with
one additional update if another writer wins, but concurrent writes are
last-writer-wins. This is not a cross-process refresh lock: follow huskarl's
single-owner requirement for rotation-only public clients to avoid races during
refresh-token rotation.

