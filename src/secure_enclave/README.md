# Secure Enclave cryptography

[`Es256PrivateKey`] signs ES256 messages, [`VerifyingKey`] verifies signatures,
and [`SealingKey`] seals and unseals device-bound payloads. Private keys remain
hardware-protected. [`KeyAccessPolicy`] controls protection at creation.

Generate and load keys with async `generate`/`load` convenience methods or the
`generate_with`/`load_with` builders, ending in `.generate().await` and
`.load().await`. Coordinated provisioning ends in `.load_or_generate().await`.
The `creation_policy` setter applies only to new keys; existing keys keep their
persisted protection.

`delete_key_and_associated_items().await` removes a persisted key, its public
half, and associated client certificates. With `urlsession`, use
`install_client_identity(...).await` or the `install_client_identity_with`
builder ending in `.install().await` to persist a certificate for a signing key.
These operations use a blocking pool. Dropping a future does not cancel work
already running, which may still create or delete persisted items.

For task recipes, see [signing and sealing](crate::_docs::guide::signing_and_sealing),
[provisioning keys](crate::_docs::guide::provisioning_keys), and
[choosing a `DPoP` key policy](crate::_docs::guide::dpop_policy).
Start with [signing an app](crate::_docs::guide::signing_an_app) to prepare a
signed executable, and read the [security model](crate::_docs::explanation::security_model)
for storage and authentication boundaries.
