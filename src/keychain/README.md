# Keychain secrets and refresh tokens

[`KeychainSecret`] reads generic-password items as zeroizing secret bytes.
[`KeychainSecretStore`] adds writes and deletion; [`KeychainRefreshTokenStore`]
stores OAuth refresh tokens with their optional `DPoP` binding.

Select storage with [`KeychainBackend`], creation protection with
[`SecretAccessPolicy`], and read UI behavior with [`SecretInteraction`].

For task recipes, see [reading secrets](crate::_docs::guide::reading_secrets),
[storing secrets](crate::_docs::guide::storing_secrets), and
[refresh tokens](crate::_docs::guide::refresh_tokens). For backend selection,
see [selecting a backend](crate::_docs::guide::selecting_a_backend).
