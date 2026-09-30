# Store a secret

`KeychainSecretStore` creates, updates, and clears one generic-password item.
Data protection requires an explicit entitled access group so mutations cannot
affect the same service/account in another group. File-backed storage requires
no access group and scopes every operation to the selected keychain. It also
implements `Secret`, and its `reader()?` returns a `KeychainSecret` for composition
with existing loaders.

```rust,no_run
use huskarl_core::secrets::SecretBytes;
use huskarl_apple::keychain::KeychainSecretStore;

# async fn example() -> Result<(), huskarl_apple::keychain::SecretError> {
let storage = KeychainSecretStore::builder()
    .service("io.example.credentials")
    .account("client-secret")
    .access_group("TEAMID.io.example.shared")
    .build();
storage.set(&SecretBytes::new(b"secret-value".to_vec())).await?;
let value = storage.get().await?;
storage.clear().await?;
# Ok(())
# }
```

New data protection items default to device-only access while unlocked, without additional
human authentication. `SecretAccessPolicy::builder()` accepts the same
`policy::Availability` and `policy::Authentication` enums as enclave policies. Pass it
through `.access_policy(...)` when constructing the store. Generic-password
policies omit the enclave-specific private-key-usage constraint. They use
Apple's [device-only accessibility](https://developer.apple.com/documentation/security/ksecattraccessiblewhenunlockedthisdeviceonly)
and do not synchronize with iCloud.

## Notes

Updates replace only the data and **preserve existing protection settings**.
Changing a builder's policy does not change an existing item. Reserve new
service/account pairs for these stores; do not assume an externally provisioned
item has the requested creation policy. Reads and writes allow system
authentication UI and run on a blocking pool. Rust-owned secret buffers use
zeroizing wrappers; copies made inside Apple APIs are managed by the framework.

