# Provision a key at startup

For startup provisioning, both key types provide `load_or_generate()`:

```rust,no_run
use huskarl_apple::secure_enclave::{Es256PrivateKey, KeyAccessPolicy};
use std::path::Path;

# fn example(lock_path: &Path) -> Result<(), huskarl_apple::SetupError> {
let key = Es256PrivateKey::load_or_generate()
    .label("io.example.signing-v1")
    .access_group("TEAMID.io.example.shared")
    .lock_path(lock_path)
    .access_policy(KeyAccessPolicy::default())
    .call()?;
# Ok(())
# }
```

## Notes

Generation occurs only when the initial lookup returns Apple's definitive
item-not-found status. Locked or denied access, cancellation, ambiguity, bad
purpose tags, and malformed lookup results remain errors. Existing keys keep
their policy; the supplied policy applies only to new keys. An exact
duplicate-item generation error triggers one reload, whose result is returned
without another creation attempt.

Key labels are **not unique constraints** in Apple's Keychain: independently
generated keys can share a label and purpose tag. See Apple's
[duplicate-item rules](https://developer.apple.com/documentation/security/errsecduplicateitem).
To serialize lookup and creation across threads and processes, this API requires
an explicit access group and an OS file lock. All creators of the same
purpose/label/group must use the **same persistent lock file** in a trusted,
local application directory; cooperating sandboxed apps need a shared app-group
container. One lock file may coordinate multiple keys. The parent directory
must already exist. Do not remove or replace the file while callers may use it.
It contains no key material and remains on disk after the OS lock is released.
The OS releases the lock on process exit, including crashes.

This is synchronous setup and may wait for another creator or system
authentication. Use a blocking worker when calling from an async application.
Direct `generate()` calls, external writers, and concurrent deletion do not
participate in this protocol; coordinate those separately. A key created before
a process exits is loaded on the next attempt.

