# How Apple integrations fit an OAuth session

Huskarl handles OAuth grants, token refresh, caching, and request authorization.
`huskarl-apple` connects those operations to Apple browser presentation, secret
storage, hardware keys, local authentication, and networking. An application
composes the adapters it needs and owns the UI and session lifecycle.

## From sign-in to an authenticated request

```text
Application window → ASWebAuthenticationSession → callback URL
                             ↑                        ↓
                   Huskarl authorization-code grant (PKCE + state)
                                                      ↓
                       Keychain ← refresh token → session/cache
                                                      ↓
                       Secure Enclave → DPoP → HttpAuthorizer
                                                      ↓
                                            URLSession → API
```

The browser presents the authorization server's login page. Huskarl creates the
authorization request and completes the code exchange. Keychain can preserve the
refresh token across launches. An enclave key can sign DPoP proofs, allowing a
supporting server to bind tokens to that key. `HttpAuthorizer` produces request
authentication headers; the HTTP client sends the request.

These are independent choices. Browser login does not require Secure Enclave or
DPoP. Keychain persistence does not require Apple's HTTP client. URLSession can
replace another Huskarl `HttpClient` when native networking or a Keychain TLS
identity is useful. The complete native example deliberately combines them.

| Application need | Apple integration | Huskarl connection |
|---|---|---|
| Present interactive login | `ASWebAuthenticationSession` | Authorization-code `start` URL and `complete` callback |
| Restore after restart | Keychain | `KeychainRefreshTokenStore` implements `RefreshTokenStore` |
| Bind tokens to a hardware key | Secure Enclave ES256 | Signer supplied to `DPoP`; provider and API must support it |
| Require local approval to read credentials | Keychain access policies and `LAContext` | Protected token loading and reusable authentication contexts |
| Send requests using Apple networking | `URLSession` | `UrlSessionClient` implements `HttpClient` |
| Present a TLS client certificate | Keychain identity backed by an enclave key | URLSession transport plus provider-specific OAuth mTLS configuration |
| Share stored credentials between authorized apps | Keychain access groups | Shared storage identifiers and coordinated refresh ownership |

## Choose a login route

A foreground macOS or iOS app can present browser authorization-code login with
PKCE. Start with [your first native login](crate::_docs::tutorial::first_login),
then [add a persisted native session](crate::_docs::guide::native_session).

A command-line application can instead use device authorization when the server
supports it: the user visits a verification URL and enters a code. The
[device-authorization session guide](crate::_docs::guide::dpop_session) follows
that route. The browser adapter needs a live application window and main UI loop;
it is not a headless browser launcher.

## Four different meanings of authentication

**OAuth API access** grants permission to call an API. The examples obtain access
tokens; receiving a browser callback by itself is not a completed grant.

**OIDC user identity** requires an OIDC flow and ID-token verification configured
in Huskarl before the application relies on identity claims. Using OIDC discovery
only to find OAuth endpoints does not establish a user's identity. The supplied
native-session example intentionally does not request `openid` or validate an
ID token.

**Local user authentication** authorizes access to a protected Keychain item or
key. Touch ID, Face ID, or a system credential does not perform OAuth login or
validate the remote account. Invalidating an `LAContext` also does not remove
tokens already loaded into process memory.

**TLS client authentication and DPoP** prove possession of keys at different
layers. Configuring a URLSession identity does not by itself configure the
provider's OAuth client-authentication method or certificate-bound tokens. DPoP
signs HTTP-level proofs. Neither substitutes for ID-token verification.

## Browser sessions and adjacent Apple capabilities

Apple's [authentication browser](https://developer.apple.com/documentation/authenticationservices/aswebauthenticationsession)
presents a web service's sign-in flow. Browser session reuse can reduce repeated
login prompts. Requesting an ephemeral session changes a browser preference;
local logout removes application credentials but does not end the provider's
browser session.

The following capabilities require additional integration beyond this crate:

| Capability | Scope here |
|---|---|
| Native Sign in with Apple | No `ASAuthorizationAppleIDProvider` adapter or native Apple credential exchange recipe is supplied. Integrate Apple's native flow and the application's backend separately. |
| Native passkeys | No credential registration/assertion adapter is supplied. A provider's browser page may offer passkeys; that remains part of its web login. |
| Enterprise SSO or an identity broker | No SSO extension, broker adapter, or device-management configuration is supplied. Browser compatibility must be established with the provider and deployment. |

Apple documents these separately under
[Sign in with Apple](https://developer.apple.com/sign-in-with-apple/),
[passkeys](https://developer.apple.com/passkeys/), and
[Extensible SSO](https://developer.apple.com/videos/play/tech-talks/301/).
Using this crate does not establish support for those native flows.

## Session ownership and protection

Persisting a refresh token makes restart recovery possible, but refresh rotation
still needs a single owner. Sharing an access group alone does not coordinate
multiple applications rotating the same token. The examples use a shared lock
protocol and stable local session identifiers.

Hardware binding also changes recovery: a surviving token cannot be used with a
replacement DPoP key. Device migration may require a fresh login. Conversely,
temporary locked or denied key access is not evidence that the key was lost.

See the [security model](crate::_docs::explanation::security_model) for protection
boundaries and the [platform reference](crate::_docs::reference::platforms) for
features, prerequisites, and example coverage.
