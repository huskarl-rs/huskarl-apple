# Select an access group

Generation uses the default entitled access group unless one is specified.
Loading without a group searches all accessible groups and rejects ambiguity.
Both key types support explicit groups for creation and loading; deletion
retains the selected group:

```rust,no_run
use huskarl_apple::secure_enclave::Es256PrivateKey;

# async fn example() -> Result<(), huskarl_apple::SetupError> {
let key = Es256PrivateKey::generate_with()
    .label("io.example.signing-v1")
    .access_group("TEAMID.io.example.shared")
    .generate().await?;
let loaded = Es256PrivateKey::load_with()
    .label("io.example.signing-v1")
    .access_group("TEAMID.io.example.shared")
    .load().await?;
# Ok(())
# }
```

