# Native browser login smoke test

New to this integration? Follow the
[first native OAuth login tutorial](../../docs/tutorial/first_login.md) for a
guided run and expected results. This page describes the test harness.

On macOS with Xcode and Docker running:

```sh
mise run test:browser
```

The script builds an ad-hoc-signed AppKit app and a disposable Keycloak realm.
The server binds only to a random loopback port. No trust-store changes or
provisioning profile are needed. The test account is `huskarl` with password
`huskarl-test-only`; these credentials exist only in the disposable server.

1. Click **Sign in**, allow Apple's prompt, and log in. The app should report
   that the callback arrived, state was validated, and the PKCE code was exchanged.
2. Request an ephemeral session to show the login form again. Cancel in the
   browser and verify that the app reports cancellation.
3. Start again and use **Cancel session**, then repeat with **Drop session**.
   Both should dismiss the browser. A later sign-in should still work.
4. Quit the app to stop and remove Keycloak.

The test exercises an OAuth authorization-code flow, not OIDC ID-token validation.
The local HTTP exception is limited to loopback IP addresses. Production remote
login endpoints must use HTTPS. HTTPS associated-domain callbacks and iOS UI
presentation need separate app configuration and are not tested by this harness.

For an automated cancellation/drop/restart sequence with no login input:

```sh
python3 scripts/browser-smoke.py --check-cancellation
```

The log is `target/browser-smoke/app.log`. It records lifecycle milestones, not
callback URLs or tokens. To compile without starting Docker or the app:

```sh
python3 scripts/browser-smoke.py --build-only
```

The Rust bridge is test-only. It polls the login future once per AppKit timer tick
while servicing a current-thread Tokio runtime. Production applications should
use their existing main-thread executor.
