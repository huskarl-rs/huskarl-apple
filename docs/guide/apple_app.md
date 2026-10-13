# Connect an Apple UI to a Rust OAuth session

Use this guide when adapting the Rust adapters to an existing SwiftUI, AppKit,
or UIKit application. Start with a working provider configuration from
[the native session guide](crate::_docs::guide::native_session). The crate exposes
Rust APIs; the examples' C bridges are application code, not a reusable Swift SDK.

## Build and link the Rust owner

Build your Rust application library as a `staticlib` and enable the integrations
you use:

```toml
[lib]
crate-type = ["staticlib"]

[dependencies]
huskarl-apple = { version = "0.1", features = ["session", "urlsession"] }
```

Add Huskarl and your executor dependencies as in the
[native example manifest](https://github.com/huskarl-rs/huskarl-apple/blob/main/examples/native-session/rust/Cargo.toml).
Link the library for the application's target architecture and import a C header
into Swift. The example's
[build script](https://github.com/huskarl-rs/huskarl-apple/blob/main/scripts/native-session.py)
shows the static library, bridging header, and Apple framework linkage for macOS.
In an Xcode project, put the equivalent settings in the application target.

Use `AppleSession` to own the pending login, token source/cache, and credential
lifecycle. Configure the grant, Keychain store and DPoP key before construction. Expose operations and UI results rather than raw
tokens. Define ownership and lifetimes for every pointer crossing the bridge.

## Provide a main-thread execution boundary

Keep the UI-facing controller on Swift's `MainActor`. Pass the initiating
`NSWindow` or foreground-scene `UIWindow` to the Rust browser adapter while it is
valid. The example retains the native window on the Rust side. SwiftUI views need
to obtain their hosting window and give it to that controller; a view value is
not a presentation anchor.

Keep browser creation, polling, cancellation, and destruction on the main thread.
The session future is not `Send`, so do not submit it to `tokio::spawn`. A Swift
`Task` alone does not drive a Rust future: supply a Rust executor integrated with
the UI event loop, or a bridge that schedules polls on the main thread.

The application owns execution. `huskarl-apple` exposes the session driver as a
future and does not supply an executor. Schedule the driver and UI operations on
your application's main-thread executor and retain it until shutdown completes.

The native-session example contains a private
[executor helper](https://github.com/huskarl-rs/huskarl-apple/blob/main/examples/native-session/rust/src/executor.rs)
that schedules ready futures through `dispatch2`. It demonstrates one integration
with AppKit; it is example support, not a library API or required runtime.

That helper drives local futures; it does not provide Tokio I/O or timers.
If your grant/transport uses Tokio (including Huskarl retry delays), keep a Tokio
runtime with background workers alive and enter its handle on **each poll**.
The native example's `spawn` helper does this with `poll_fn`. Entering a runtime
only when submitting a task is insufficient, and an idle current-thread runtime
will not drive timers. Applications with an existing main-thread executor can
continue using it instead.

The native-session example uses completion callbacks to update Swift, with no
polling timer. The driver remains scheduled even when no UI operation is active,
so background `SessionAccess` requests can wake it independently.

The adapters' async Keychain APIs already move blocking native work to workers. For background Rust services, obtain a
`SessionAccess` on the main thread and move or clone it into the worker; it is
`Send + Sync` and queues authorization work to the driver. Keep driving the
main-thread session while workers await their results. See
[background authorization](crate::_docs::guide::native_session#authorize-requests-from-background-rust-tasks).

## Expose operations and explicit UI states

The example's
[C header](https://github.com/huskarl-rs/huskarl-apple/blob/main/examples/native-session/Bridge.h)
and [Swift controller](https://github.com/huskarl-rs/huskarl-apple/blob/main/examples/native-session/App.swift)
form a concrete bridge contract:

| Bridge call | Contract in this example |
|---|---|
| `huskarl_native_start(window, action, ephemeral, completion)` | Main thread; live window; actions 0 restore, 1 login, 2 GET, 3 logout; busy task is not replaced |
| `huskarl_native_status()` | Copy the returned C string immediately; valid only until the next bridge call; no credentials |
| `huskarl_native_cancel()` | Cancel the current login attempt through `AppleSession` |
| `huskarl_native_shutdown(completion)` | Await shutdown and driver exit before reporting completion; normal example shutdown begins with no pending operation |

The completion callback runs on the main thread with 2 for success or 3 for failure,
and must remain callable until invoked. Invalid submissions may complete immediately.
The example disables competing UI actions while busy. Other applications can
use `snapshot()` or `subscribe()` to render the library session state, including
`CleanupRequired` and `UnsavedChanges`, with explicit retry actions. Do not interpret every Keychain error as signed-out:
locked or denied access needs a retry path that preserves credentials.

## Handle cancellation, closure, and local locking

Cancel or drop a pending browser session on the main thread when its UI flow
ends. Preserve the session owner across transient SwiftUI view reconstruction;
view disappearance must not accidentally create another token owner.

Dropping a Keychain future does not cancel native work already running on a
worker. `AppleSession` serializes logout and credential mutation in its driver;
keep that driver running until `shutdown()` completes.
The example prevents window closure and app termination while an operation is
pending. Once idle, it returns AppKit's `terminateLater`, awaits shutdown and
driver exit, then replies to the termination request. Retain the executor until
that drain finishes; dropping it cancels pending futures. In a production app, define equivalent behavior for scene changes and
shutdown without assuming the operating system will wait for cleanup.

For an application inactivity lock, await `AppleSession::lock()` to gate requests
and discard token memory. This does not invalidate an externally supplied authentication context. If using `local-authentication`, invalidate the context and
create a new one when rebuilding adapters. Context invalidation does not erase
previously read tokens. Follow [authentication contexts](crate::_docs::guide::key_authentication)
for item policies and native `LAContext` interop.

## Integrate on iOS

iOS support is experimental; this repository has no complete iOS browser-login
and persisted-session application. Use the following path to adapt your app:

1. Run the
   [iOS storage example](https://github.com/huskarl-rs/huskarl-apple/tree/main/examples/ios)
   to establish Swift/Rust linkage and Keychain persistence on the simulator.
   Its shared storage bridge does not implement OAuth login.
2. Build your Rust library for the device or simulator target matching the app.
   Use UIKit and a `UIWindow` belonging to the initiating foreground scene in
   place of the macOS example's AppKit window. Rebuild the bridge for this type;
   do not reuse its macOS binary.
3. Drive the browser future on the main thread while UIKit's event loop runs.
   Own it per login flow and handle scene disconnection and cancellation. Keep
   token rotation under one session owner across scenes.
4. Configure the registered redirect using
   [browser login](crate::_docs::guide::browser_login). Provision a physical-device
   app with the correct Keychain group. Supply `NSFaceIDUsageDescription` if
   using Face ID; the simulator example's signing setup is not a device profile.
5. Validate browser presentation, cancellation, callback completion, restart,
   rotation, logout, and protected reads on a real device. Use a physical device
   for Secure Enclave behavior and test foreground/background transitions.

See [platform coverage](crate::_docs::reference::platforms) for the existing
simulator and device checks. Choosing a background-accessible Keychain class
does not schedule background execution or permit authentication UI in the
background; app scheduling and a noninteractive failure path remain yours.
