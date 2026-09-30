# Select a backend

Both `KeychainSecret` and `KeychainSecretStore` accept `.backend(...)`.
For data protection storage, follow [signing an app](crate::_docs::guide::signing_an_app)
to prepare entitlements and provisioning. For a local tool without provisioning,
select `Login` as in the example below.

The available backends are:

| Backend | Selected storage |
|---|---|
| `KeychainBackend::DataProtection` (default) | Entitled data protection Keychain |
| `KeychainBackend::Login` | `~/Library/Keychains/login.keychain-db`, regardless of the configured default |
| `KeychainBackend::DefaultFile` | Current default file keychain, resolved once per operation |
| `KeychainBackend::File(path)` | One existing file keychain at an absolute path |

```rust,no_run
use huskarl::{cache::RefreshTokenStore, token::RefreshToken};
use huskarl_core::secrets::SecretString;
use huskarl_apple::keychain::{KeychainBackend, KeychainSecretStore, KeychainRefreshTokenStore};

# async fn example() -> Result<(), huskarl_core::Error> {
let storage = KeychainSecretStore::builder()
    .service("io.example.cli.refresh-tokens")
    .account("issuer-client-user")
    .backend(KeychainBackend::Login)
    .build();
let tokens = KeychainRefreshTokenStore::builder().storage(storage).build();
tokens.set(&RefreshToken::new(SecretString::new("refresh-token"), None)).await?;
let restored = tokens.get().await?;
# Ok(())
# }
```

## Notes

`Login` resolves the home directory using `$HOME` when set. Under `sudo` or an
overridden environment, this may select a different user's path or fail;
choose `File(path)` to specify the intended keychain explicitly.

Reads, updates, and deletion are scoped to that exact keychain, including when
using `DefaultFile`; they do not search the user's full keychain search list.
Creation uses the same resolved keychain as the preceding update attempt.
There is no fallback on missing items, inaccessible keychains, or authorization
errors. A missing keychain is an error, not an absent token. The crate does not
create keychain files, change the default/search list, or modify keychain locking.

File-based keychains support local tools without provisioning profiles, but may
require unlocking or authorization prompts. New items use the system's default
ACL for the creating application; updates preserve that ACL. They do not offer
this adapter's device-only or biometric policy settings. Lock-on-idle/sleep
settings belong to the whole file keychain and are inherited, never changed by
the adapter. See Apple's [backend and access-control distinctions](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains).

During CLI development, rebuilding an unsigned or ad-hoc-signed executable can
trigger authorization again even after “Always Allow”, because trust can be
tied to that particular binary's code hash. Reusing the unchanged executable
from `cargo install` generally keeps approval stable; installation itself grants
no special trust, and reinstalling or updating can prompt again. See Apple's
[code-signing requirement rules](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/RequirementLang/RequirementLang.html).

Supplying an access group, any explicit `SecretAccessPolicy` (even its default),
or `SkipProtectedItems` with a file backend returns `SecretError::Configuration`
before Keychain access. With data protection, writable storage still requires
an explicit nonempty access group. These checks run on operations and
`reader()`, which returns `Result<KeychainSecret, SecretError>`.

For existing items provisioned by `security add-generic-password`, select the
same file keychain that command used; `Login` and `DefaultFile` need not coincide.
File-backed secrets enter process memory; this choice does not change Secure
Enclave key storage or make those operations available to unsigned tools.

