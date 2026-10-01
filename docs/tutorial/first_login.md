# Your first native OAuth login

In this tutorial you will launch a macOS app, sign into a disposable local
authorization server through Apple's browser, cancel a second login, and sign in
again. Success means Huskarl has validated OAuth state and exchanged an
authorization code using PKCE. This exercise does not save tokens or assert an
OIDC user identity.

## Prepare

Use macOS 14 or newer with Xcode command-line tools selected, Rust 1.92 or newer,
Python 3, and Docker installed and running. Work from a checkout of this repository.
The harness builds and ad-hoc signs its own app. You do not need a developer
certificate, provisioning profile, Secure Enclave, or an existing OAuth account.

Check the tools from the repository root:

```sh
xcrun --find swiftc
rustc --version
python3 --version
docker info
```

Each command should finish successfully. Docker must report a running server
before continuing.

## Launch the app and server

Run:

```sh
python3 scripts/browser-smoke.py
```

The first run may download Rust dependencies and the Keycloak container image.
The script creates a temporary realm, a public client requiring S256 PKCE, and a
test account. It registers `io.huskarl.browser-smoke:/callback` as the redirect.
Keep the terminal open while the app runs.

When the terminal reports `Ready:` and an issuer URL, the app should show
**Ready. Click Sign in, allow the browser prompt, then log in.** The server's
random loopback port is configured automatically.

## Complete a login

1. Choose **Sign in** and allow the system browser prompt if shown.
2. On the Keycloak page, enter username `huskarl` and password
   `huskarl-test-only`. These credentials belong only to this disposable server.
3. Complete sign-in. The browser should dismiss and the app should display
   **Success: callback received, state validated, PKCE code exchanged.**

You have now exercised the complete browser-to-code-exchange roundtrip. The app
passes Huskarl's authorization URL to Apple, then returns the callback to Huskarl
with the pending flow's state and PKCE material.

## Cancel and try again

1. Select **Request ephemeral browser session** and choose **Sign in**. This
   requests an isolated browser session; the browser decides whether to honor it.
2. While the login is pending, choose **Cancel session** in the app. The browser
   should dismiss and the app should report **Session cancelled or failed. See
   the smoke-test log for details.**
3. Open `target/browser-smoke/app.log` and confirm that the completion message
   reports cancellation. The UI deliberately groups cancellation and failure.
4. Choose **Sign in** again and complete login. The success message should return.

Each attempt creates a fresh authorization flow. You do not need to restart the
app after cancellation.

## Finish

Choose **Quit** in the app. The script stops and removes the disposable server;
the built app and milestone log remain under `target/browser-smoke`. The harness
does not persist OAuth tokens. The development HTTP endpoint is restricted to a
loopback IP; production remote authorization endpoints must use HTTPS.

If the app never reaches `Ready:`, inspect the terminal error and recheck Docker
and Xcode. If it launches but login fails, inspect `target/browser-smoke/app.log`
for the failing milestone. Do not add logging of tokens or callback URLs.

Continue with [a persisted native session](crate::_docs::guide::native_session)
to use your provider, restore credentials after restart, and call an API. To
understand the components before extending the app, read
[how Apple integrations fit OAuth](crate::_docs::explanation::apple_oauth).
