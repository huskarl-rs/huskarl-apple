# huskarl-crypto-macos

Crypto implementation using MacOS keychain (only secure enclave for now). This can be
used to create device-bound private keys that can't be extracted from the machine,
and then when used with DPoP, can bind the resulting access/refresh tokens to the
machine.
