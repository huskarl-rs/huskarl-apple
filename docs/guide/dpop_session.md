# Make authenticated requests with a persisted `DPoP` session

This guide connects the Apple adapters to a complete OAuth client:

```text
persisted Es256PrivateKey → DPoP → DeviceAuthorizationGrant
                                        ↓
KeychainRefreshTokenStore → GrantTokenSource → InMemoryTokenCache → HttpAuthorizer
                                                                  ↓
                                                    authenticated HTTPS GET
```

The executable example is
[`examples/dpop_session.rs`](https://github.com/huskarl-rs/huskarl-apple/blob/main/examples/dpop_session.rs).
It runs a real device authorization grant, persists the returned refresh token,
and makes two API requests. On the next launch it restores the session and
refreshes the access token. `HttpAuthorizer` is the client-side component that
produces request authentication headers; it is not a resource-server validator.

## Prepare the application and authorization server

Use a macOS device with Secure Enclave support and a signed application authorized
for a data protection Keychain access group. Follow
[signing an app](crate::_docs::guide::signing_an_app) for the signing assets,
bundle metadata, and `huskarl_package` function. The example uses a public client
with `NoAuth`; register a client that supports device authorization, ES256
`DPoP`, and refresh tokens. Configure the API scopes and any provider-specific
requirements for issuing refresh tokens. This example uses OAuth authorization
server metadata discovery; for a provider with only OIDC discovery, use
`AuthorizationServerMetadata::oidc_fetch()` instead of `fetch()`.

For your own Cargo application, the complete program below uses these dependencies:

```toml
[dependencies]
huskarl-apple = "0.1"
huskarl = { version = "0.11", default-features = false }
huskarl-core = { version = "0.10", default-features = false }
huskarl-reqwest = { version = "0.9", features = ["rustls-tls"] }
reqwest = { version = "0.13", default-features = false, features = ["rustls"] }
http = "1"
blocking = "1"
tokio = { version = "1", features = ["macros", "rt-multi-thread", "time"] }
```

## Configure and run the signed example

In the repository root, in the shell used for the signing guide, configure your
issuer, registered client, and a final HTTPS resource URL. Use a service account
identifier that distinguishes the issuer, client, and user. Reserve a separate
private state directory for this session, and keep using it across launches.
All processes using this same token item must use that same directory.

```sh
export ISSUER='https://issuer.example.com'
export CLIENT_ID='your-registered-public-client'
export RESOURCE_URL='https://api.example.com/v1/profile'
export SCOPE='read offline_access' # Replace with your provider's actual scopes.
export HUSKARL_ACCESS_GROUP='APPIDPREFIX.io.example.HuskarlHarness'
export HUSKARL_ACCOUNT='issuer-client-user'
export HUSKARL_STATE_DIR="$HOME/Library/Application Support/HuskarlDpopExample/issuer-client-user"
mkdir -p "$HUSKARL_STATE_DIR"
chmod 700 "$HUSKARL_STATE_DIR"

cargo rustc --example dpop_session -- \
  -C "link-arg=-Wl,-sectcreate,__TEXT,__info_plist,$huskarl_work/Info.plist"
huskarl_binary="$PWD/target/debug/examples/dpop_session"
huskarl_package
codesign --verify --strict --verbose=2 "$huskarl_app"
"$huskarl_app/Contents/MacOS/huskarl-harness"
```

`offline_access` is a common convention, not a promise that a particular server
will issue a refresh token. The program rejects an initial response without a
refresh token or `DPoP`-bound access token; it also checks for a proof before every
resource request, including after refresh. An API that needs a resource indicator
requires adding that provider's resource to the device flow's start/poll inputs
and refresh configuration; the minimal example selects its API through scopes.

On first use, visit the displayed verification URL, enter the displayed code,
and complete sign-in. The program should print `Authenticated GET: 200 OK`
(or your API's successful status) twice. Keychain may request authentication
when storing the refresh token. Run the same signed executable again: it should
restore the session, authenticate the protected Keychain read, and refresh
without another device authorization flow while the refresh token remains valid.

## Follow the session lifecycle

1. **Take ownership.** A process-lifetime file lock prevents two instances of
   this example from rotating the same refresh token concurrently. The separate
   key-provisioning lock coordinates enclave key creation. Keep both lock files;
   do not delete or replace them while any caller may use them.
2. **Restore credentials.** Load the refresh token from Keychain and load or
   generate the enclave key on a blocking worker. Key lookup authorization
   failures propagate; only definite absence allows key creation.
3. **Check the binding.** Compare the stored token's `dpop_jkt()` with the key's
   public JWK thumbprint. A mismatch means the old session is unusable: clear
   that token and sign in again. A restored backup cannot recreate the original
   device-only enclave key. Missing tokens also lead to a fresh sign-in.
4. **Wire the source and cache.** Attach `DPoP::builder().signer(key).build()` to
   the actual `DeviceAuthorizationGrant`. Build `GrantTokenSource` with `NoSource`
   because interactive login is handled explicitly, then wrap it in
   `InMemoryTokenCache` and `HttpAuthorizer`. Keep the source in an `Arc` so the
   interactive path can hand its token response to `source.prime(response)`.
5. **Authorize a request.** `get_headers(GET, uri)` uses the cached access token
   or refreshes it. If no automatic token path remains, `Recovery::Reauthenticate`
   starts the device grant. Its completed response is primed into the source,
   persisting the refresh token and binding before the first API request.
6. **Process every response.** Call `process_response` for success and failure.
   It records resource-server nonces and invalidates rejected access tokens.
   Rebuild headers and resend the GET once for a `DPoP` nonce challenge or an
   explicit `invalid_token` challenge. The grant handles token-endpoint nonce
   challenges itself. Other failures are returned; there is no endless login
   or retry loop.

The full source is included below in the rustdoc version of this guide and is
also available through the executable-example link above. It is compiled both
as an example and as a `no_run` doctest; compilation does not contact your issuer
or create Keychain items.

## Authentication, rotation, and shutdown

The enclave key uses the default `Authentication::None` so every proof can be
signed without a user-presence requirement. The refresh-token item is created
with `Authentication::UserPresence`. The small `SessionRefreshTokens` adapter
loads it once into zeroizing session storage: subsequent reads use memory,
while updates and clearing change session memory and write through to Keychain.
Updates preserve the persisted item's protection. Token rotation may still require authentication;
Apple controls prompt reuse, so this does not promise exactly one prompt.

Treat the example's service/account pair as dedicated storage. Setting a creation
policy on a builder does not upgrade an existing item's protection. For a long-lived
application, gate access to the entire session and drop its source/cache/token
state when locking the application; locking Keychain alone does not revoke bytes
already loaded into memory.

Only one source/cache owns this session. Do not hand its store to independent
sources or processes outside the lock protocol. The memory-plus-Keychain adapter
is not a distributed transaction: a crash or persistence failure after a server
rotates a token can require signing in again. The adapter retains a rotated token
in memory even when persistence fails, because the previous token may already
be invalid. It reports a warning and returns the storage error. Initial `prime`
propagates that error; `GrantTokenSource` deliberately treats persistence after
refresh as best-effort and can still serve the new access token. The warning
therefore means that restart recovery is not assured. Clearing failures are
also reported; a successful in-memory logout alone does not erase a persisted item.

The example deliberately keeps its enclave key and refresh token after exit.
For logout, stop in-flight requests, clear the source's credentials through
`TokenSource::clear()`, and discard the authorizer/cache and session handles.
Delete the enclave key only when retiring it and every token bound to it.

Transient network or Keychain failures are returned without deleting credentials.
An application can offer retry based on `TokenError::recovery()` and its delay;
`AdjustRequest` and configuration failures need a corrected request or setup.
The bounded resource retry here is for GET. Repeating non-idempotent operations
requires the API's own idempotency guarantees.

For a browser-based app, replace the device grant and interactive function with
an authorization-code flow using PKCE and redirect/state validation. The
persisted signer, refresh store, `prime` handoff, cache, and authorizer wiring
remain the same. See the
[authorization-code guide](https://docs.rs/huskarl/latest/huskarl/_docs/guide/authorization_code/).
