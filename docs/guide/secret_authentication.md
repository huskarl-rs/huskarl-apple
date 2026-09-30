# Control authentication during reads

`SecretAccessPolicy` controls the availability and authentication of new data
protection items.
Use the shared `policy::Availability` and `policy::Authentication` types.
Device-only access while unlocked is the data protection backend's default.
These settings are protection classes, not idle timers; macOS controls the
keybag and authentication state.
The data protection Keychain requires a user login context.

For secrets, availability and acknowledgement requirements are set by
`SecretAccessPolicy` when `KeychainSecretStore` creates an item, or by another
app that **provisions the Keychain item**. `KeychainSecret` only reads that item.
Reads allow authentication UI by default, but unattended callers can explicitly
exclude protected items:

```rust,no_run
use huskarl_apple::keychain::{KeychainSecret, SecretInteraction};

let source = KeychainSecret::builder()
    .service("io.example.oauth")
    .account("client-secret")
    .interaction(SecretInteraction::SkipProtectedItems)
    .build();
```

## Notes

This uses Apple's [skip-authenticated-items query mode](https://developer.apple.com/documentation/security/ksecuseauthenticationuiskip).
If nothing eligible remains, `NotFoundWithoutInteraction` means the item is
absent **or requires authentication**. It is not proof that a secret should be
recreated. Other errors, including a locked Keychain or denied access, retain
the underlying status. There is no automatic prompt retry loop.

For retry advice, authentication reuse, and cached plaintext, see the
[security model](crate::_docs::explanation::security_model).
