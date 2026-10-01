# Use Apple networking for OAuth requests

Enable `urlsession` to use `UrlSessionClient` as Huskarl's `HttpClient`. This is
useful for requests that should use Apple's networking stack or a Keychain TLS
client identity. Browser presentation remains a separate integration.

```toml
[dependencies]
huskarl-apple = { version = "0.1", features = ["urlsession"] }
```

## Create the transport

```rust,no_run
# #[cfg(feature = "urlsession")]
# fn example() -> Result<(), Box<dyn std::error::Error>> {
use huskarl_apple::urlsession::UrlSessionClient;

let client = UrlSessionClient::builder()
    .max_response_bytes(1024 * 1024)
    .build()?;
# Ok(())
# }
```

Supply the client to Huskarl's discovery and grant configuration, and use an
appropriately configured client for protected resource requests. The
[native session implementation](https://github.com/huskarl-rs/huskarl-apple/blob/main/examples/native-session/rust/src/lib.rs)
shows the grant, authorizer, and transport together. The client sends requests;
`HttpAuthorizer` supplies OAuth/DPoP headers for the final URL and method.

The session disables cookies, credential storage, caching, and redirects. Use
final endpoint URLs. Its default response-body limit is 1 MiB and its default
whole-request timeout is 60 seconds. Adjust these deliberately for your API.
Clones share the native session; dropping the last clone invalidates it and
cancels outstanding tasks.

## Add a TLS client identity when required

Obtain an X.509 certificate from your certificate authority for the enclave key's
public key. Install that certificate and build the client with its identity:

```rust,no_run
# #[cfg(feature = "urlsession")]
# async fn example(key: &huskarl_apple::Es256PrivateKey, certificate_der: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
use huskarl_apple::urlsession::UrlSessionClient;

let identity = key.install_client_identity(certificate_der).await?;
let client = UrlSessionClient::builder()
    .client_identity(identity)
    .build()?;
# Ok(())
# }
```

For an intermediate-issued certificate, use `install_client_identity_with` to
supply the intermediates from leaf issuer toward root, excluding the root and
leaf. See the
[URLSession API reference](https://docs.rs/huskarl-apple/latest/huskarl_apple/urlsession/)
for chain handling, ownership conflicts, renewal cleanup, and custom trust roots.
Installing an identity persists the certificate; dropping the client does not
delete it.

Configure Huskarl's OAuth client-authentication strategy and provider registration
for the server's mTLS requirements as well. For certificate-bound access tokens,
the resource request must present the matching identity. Limit use of an
identity-bearing client to intended servers. The repository's
[OAuth mTLS tests](https://github.com/huskarl-rs/huskarl-apple/blob/main/tests/urlsession_oauth.rs)
demonstrate certificate-bound resource checks; run them through
[the OAuth testing tasks](crate::_docs::guide::testing).

The browser session does not inherit this identity. Enclave key `LAContext`
settings also do not carry into the separate TLS identity lookup. Plan and test
TLS key access independently of browser login and protected token reads.
