# Read a secret

Read an existing generic-password item by service and account, then decode it
with a core secret mapping.

Service, account, and the exact access group must be nonempty. Constructors
reject empty identifiers with `SecretError::Configuration` without accessing
the Keychain. Once an item is configured, creating its reader is infallible.

```rust,no_run
use huskarl_core::secrets::{Secret, encodings::StringEncoding};
use huskarl_apple::keychain::DataProtectionKeychain;

# async fn example() -> Result<(), huskarl_core::Error> {
let source = DataProtectionKeychain::new("TEAMID.io.example.shared")?
    .secret("io.example.oauth", "client-secret")?
    .reader();
let secret = source.mapped(StringEncoding).get_secret_value().await?;
# Ok(())
# }
```

This provider reads generic-password items from one **data protection Keychain**
access group. File-backed storage is available through `FileKeychain` on macOS.
Provision items with [`KeychainSecretStore`](crate::keychain::KeychainSecretStore), or another suitably entitled
app using `kSecUseDataProtectionKeychain`. A matching
item in the wrong backend or an iCloud-synchronized item will not be found.
Values are fetched on each call and use core's zeroizing secret
containers. Core's mapping and caching wrappers compose normally.

## Notes

An item can change without its service/account changing, so the provider returns
`identity: None`. For key rotation, store distinct versions and use `WithIdentity`
or an explicit JWK `kid`; retain old versions while old data still needs them.
To search across accessible groups, explicitly use
`DataProtectionKeychain::search_all_groups(service, account, mode)?`.
Multiple eligible matches return `SecretError::Ambiguous`. This search cannot
become a writable store; select an exact group for writes.

