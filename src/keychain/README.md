# Keychain secrets and refresh tokens

[`KeychainSecret`] reads generic-password items as zeroizing secret bytes.
[`KeychainSecretStore`] adds writes and deletion; [`KeychainRefreshTokenStore`]
stores OAuth refresh tokens with their optional `DPoP` binding. Wrap configured
storage with `KeychainRefreshTokenStore::new(storage)`.

Select an entitled access group with [`DataProtectionKeychain::new`], then
address an item with `.secret(service, account)?`. Its `.reader()` creates a
read provider; `.store().creation_policy(policy).build()` creates writable storage.
On macOS, `FileKeychain::login()`, `FileKeychain::default_file()`, and
`FileKeychain::at(path)?` select file-backed storage; their items expose
`.reader()` and `.store()` without data protection options.

Constructors validate identifiers and paths without accessing the Keychain.
Store and reader construction is then infallible. Access, unlocking, and item
existence remain runtime concerns. [`SecretReadMode`] selects one read mode:
allow interaction, skip protected items, or use an authentication context.
[`DataProtectionKeychain::search_all_groups`] explicitly creates a read-only
cross-group search; writable items always have an exact group.

The former `KeychainSecret::builder()` and `KeychainSecretStore::builder()`
constructors are replaced by these backend-specific item APIs. Use
`.creation_policy(...)` for [`SecretAccessPolicy`]; existing items keep their
protection. `KeychainSecretStore::reader()` now returns a reader directly.

For task recipes, see [reading secrets](crate::_docs::guide::reading_secrets),
[storing secrets](crate::_docs::guide::storing_secrets), and
[refresh tokens](crate::_docs::guide::refresh_tokens). For backend selection,
see [selecting a backend](crate::_docs::guide::selecting_a_backend).
