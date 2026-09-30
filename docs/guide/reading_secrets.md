# Read a secret

Read an existing generic-password item by service and account, then decode it
with a core secret mapping.

Service and account must both be nonempty. Reads, writes, deletion, and
`KeychainSecretStore::reader()` reject empty identifiers with
`SecretError::Configuration` before accessing the Keychain.

```rust,no_run
use huskarl_core::secrets::{Secret, encodings::StringEncoding};
use huskarl_apple::keychain::KeychainSecret;

# async fn example() -> Result<(), huskarl_core::Error> {
let source = KeychainSecret::builder()
    .service("io.example.oauth")
    .account("client-secret")
    // .access_group("TEAMID.io.example.shared")
    .build();
let secret = source.mapped(StringEncoding).get_secret_value().await?;
# Ok(())
# }
```

By default, the provider reads generic-password items from the **data protection
Keychain**. File-backed storage is available through explicit backend selection.
Provision items with [`KeychainSecretStore`](crate::keychain::KeychainSecretStore), or another suitably entitled
app using `kSecUseDataProtectionKeychain`. A matching
item in the wrong backend or an iCloud-synchronized item will not be found.
Values are fetched on each call and use core's zeroizing secret
containers. Core's mapping and caching wrappers compose normally.

## Notes

An item can change without its service/account changing, so the provider returns
`identity: None`. For key rotation, store distinct versions and use `WithIdentity`
or an explicit JWK `kid`; retain old versions while old data still needs them.
Multiple matching items across accessible groups are rejected; specify an access
group to disambiguate.

