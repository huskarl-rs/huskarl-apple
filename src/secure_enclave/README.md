# Secure Enclave cryptography

[`Es256PrivateKey`] signs ES256 messages, [`VerifyingKey`] verifies signatures,
and [`SealingKey`] seals and unseals device-bound payloads. Private keys remain
hardware-protected. [`KeyAccessPolicy`] controls protection at creation.

For task recipes, see [signing and sealing](crate::_docs::guide::signing_and_sealing),
[provisioning keys](crate::_docs::guide::provisioning_keys), and
[choosing a `DPoP` key policy](crate::_docs::guide::dpop_policy).
Start with [signing an app](crate::_docs::guide::signing_an_app) to prepare a
signed executable, and read the [security model](crate::_docs::explanation::security_model)
for storage and authentication boundaries.
