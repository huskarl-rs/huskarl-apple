//! Reusable local authentication for data protection Keychain items and enclave keys.
//!
//! Enable `local-authentication`, create an [`AuthenticationContext`], and pass
//! clones to data protection store or enclave `authentication_context` setters,
//! or use `SecretReadMode::Context` for a reader. Clones share Apple's
//! authentication state. The stored item's policy still determines what must be
//! authenticated; creating a context does not authenticate the user.
//!
//! Call [`AuthenticationContext::invalidate`] when ending the session, then create
//! a new context and rebuild the stores or reload the keys for the next session.
//! Invalidation does not erase secrets already read into application memory.

#![allow(unsafe_code)]

use std::{
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use core_foundation::{
    base::{CFType, TCFType, ToVoid as _},
    dictionary::CFMutableDictionary,
};
use objc2::rc::Retained;
use objc2_foundation::NSString;
use objc2_local_authentication::LAContext;
use security_framework::item::ItemSearchOptions;

/// A shared `LAContext` with explicit lifetime and interaction control.
///
/// Operations using the same context are serialized on blocking workers.
/// Configuration changes wait asynchronously for those operations.
/// `invalidate` can interrupt a pending authentication evaluation.
/// Dropping one clone does not invalidate the remaining clones.
#[derive(Clone)]
pub struct AuthenticationContext {
    inner: Arc<ContextInner>,
}

struct ContextInner {
    native: Mutex<NativeContext>,
    operations: Mutex<()>,
}

struct NativeContext(Retained<LAContext>);

// SAFETY: LAContext has no main-thread affinity. All direct access is protected
// by `native`; Security operations and property changes are serialized by
// `operations`. Only invalidate may overlap an evaluation, as explicitly
// supported by LAContext's cancellation contract. The native object never
// escapes except through unsafe interop with the same synchronization contract.
unsafe impl Send for NativeContext {}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // No Rust invariants are modified under these locks. A panicking caller must
    // not prevent later invalidation of the native authentication state.
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl std::fmt::Debug for AuthenticationContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthenticationContext")
            .finish_non_exhaustive()
    }
}

#[bon::bon]
impl AuthenticationContext {
    /// Create a context without prompting or evaluating a policy.
    ///
    /// `localized_reason` is a short explanation in the user's language.
    /// `interaction_allowed` defaults to true. When false, an operation that
    /// needs authentication UI fails instead of skipping a protected item.
    ///
    /// `biometric_unlock_reuse_duration` permits reuse of a recent biometric
    /// **device unlock**, up to Apple's five-minute maximum (larger durations
    /// are clamped). It defaults to zero. This is not an application session
    /// timeout or a lifetime for authentication already cached in this context.
    #[builder]
    #[must_use]
    pub fn new(
        #[builder(into)] localized_reason: Option<String>,
        #[builder(default = true)] interaction_allowed: bool,
        #[builder(default)] biometric_unlock_reuse_duration: Duration,
    ) -> Self {
        // SAFETY: All selectors are available on the crate's supported systems;
        // the newly allocated context is exclusively owned during configuration.
        let native = unsafe {
            let native = LAContext::new();
            if let Some(reason) = localized_reason {
                native.setLocalizedReason(&NSString::from_str(&reason));
            }
            native.setInteractionNotAllowed(!interaction_allowed);
            native.setTouchIDAuthenticationAllowableReuseDuration(
                biometric_unlock_reuse_duration
                    .min(Duration::from_secs(300))
                    .as_secs_f64(),
            );
            native
        };
        // SAFETY: This context was just created and has no external aliases.
        unsafe { Self::from_native(native) }
    }

    /// Adopt an existing objc2 context, preserving its settings and authentication.
    ///
    /// The same native object is retained; it is neither copied nor reconfigured.
    /// This is useful when an application has already evaluated a policy using
    /// `LocalAuthentication`. Clone this wrapper to share it with multiple adapters.
    ///
    /// # Safety
    /// The context may subsequently be used on blocking worker threads. The
    /// caller must coordinate **all** external aliases: native property access,
    /// policy evaluation, and Security operations using those aliases must not
    /// overlap operations or configuration changes through this wrapper.
    /// Native `invalidate` is the exception: it may cancel a pending evaluation.
    /// Do not wrap the same object twice; the wrappers would have separate locks.
    #[must_use]
    pub unsafe fn from_native(native: Retained<LAContext>) -> Self {
        Self {
            inner: Arc::new(ContextInner {
                native: Mutex::new(NativeContext(native)),
                operations: Mutex::new(()),
            }),
        }
    }

    /// Retain the underlying objc2 context for use by native application code.
    ///
    /// The returned handle is the same object, including its authentication state.
    /// Dropping the handle releases that retain; it does not invalidate the context.
    ///
    /// # Safety
    /// The returned handle is an external alias. Its use, and the use of any
    /// clones made from it, must obey [`Self::from_native`]'s synchronization
    /// contract. In particular, stop and await wrapper operations before passing
    /// it to another Security or `LocalAuthentication` operation. Keep using this
    /// wrapper rather than importing the exported handle into another wrapper.
    #[must_use]
    pub unsafe fn to_native(&self) -> Retained<LAContext> {
        lock(&self.inner.native).0.clone()
    }

    /// Change whether subsequent operations may present authentication UI.
    ///
    /// Applies to every clone, waiting on a blocking worker for current operations.
    /// Dropping the future does not cancel a change already running.
    /// Disabling interaction preserves authentication already in the context.
    pub async fn set_interaction_allowed(&self, allowed: bool) {
        let context = self.clone();
        blocking::unblock(move || {
            let _operation = context.operation();
            // SAFETY: Exclusive property access, serialized with Security operations.
            unsafe {
                lock(&context.inner.native)
                    .0
                    .setInteractionNotAllowed(!allowed);
            }
        })
        .await;
    }

    /// Change the explanation shown by subsequent authentication prompts.
    /// Applies to every clone, waiting on a blocking worker for current operations.
    /// Dropping the future does not cancel a change already running.
    pub async fn set_localized_reason(&self, reason: &str) {
        let context = self.clone();
        let reason = reason.to_owned();
        blocking::unblock(move || {
            let _operation = context.operation();
            // SAFETY: Exclusive property access; LAContext copies the string.
            unsafe {
                lock(&context.inner.native)
                    .0
                    .setLocalizedReason(&NSString::from_str(&reason));
            }
        })
        .await;
    }

    /// Permanently invalidate this context and all its clones.
    ///
    /// Cancels pending local-authentication evaluations. Repeated invalidation
    /// is harmless. It does not revoke returned plaintext or guarantee cancellation
    /// of an operation that has already passed authentication.
    pub fn invalidate(&self) {
        // SAFETY: LAContext explicitly supports invalidating pending evaluations.
        // Do not acquire `operations`: the evaluation may be waiting for the user.
        unsafe {
            lock(&self.inner.native).0.invalidate();
        }
    }

    pub(crate) fn operation(&self) -> MutexGuard<'_, ()> {
        lock(&self.inner.operations)
    }

    fn cf_type(&self) -> CFType {
        let native = lock(&self.inner.native);
        // SAFETY: Security accepts LAContext as a CFType value for
        // kSecUseAuthenticationContext. The get rule retains the live Objective-C
        // object; the CF wrapper and the query each release their own retain.
        unsafe { CFType::wrap_under_get_rule(Retained::as_ptr(&native.0).cast()) }
    }

    pub(crate) fn apply_query(&self, query: &mut ItemSearchOptions) {
        query.local_authentication_context(Some(self.cf_type()));
    }

    pub(crate) fn apply_attributes(&self, attributes: &mut CFMutableDictionary) {
        // SAFETY: Framework-exported constant is valid for the process lifetime.
        let name = unsafe { security_framework_sys::item::kSecUseAuthenticationContext };
        attributes.set(name.to_void(), self.cf_type().to_void());
    }
}

impl Default for AuthenticationContext {
    fn default() -> Self {
        Self::builder().build()
    }
}

#[cfg(test)]
mod tests {
    use objc2_local_authentication::LAPolicy;

    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn configuration_waits_without_blocking_the_executor()
    -> Result<(), Box<dyn std::error::Error>> {
        for update_reason in [false, true] {
            let context = AuthenticationContext::default();
            let occupied = context.clone();
            let (ready, started) = std::sync::mpsc::channel();
            let (release, released) = std::sync::mpsc::channel();
            let worker = std::thread::spawn(move || {
                let _operation = occupied.operation();
                let _ = ready.send(());
                // Bound the wait so a regression cannot deadlock the test runner.
                let _ = released.recv_timeout(Duration::from_secs(5));
            });
            started.recv_timeout(Duration::from_secs(5))?;
            let mut change = std::pin::pin!(async {
                if update_reason {
                    context.set_localized_reason("Updated prompt").await;
                } else {
                    context.set_interaction_allowed(false).await;
                }
            });
            let pending = tokio::time::timeout(Duration::from_millis(50), &mut change).await;
            let _ = release.send(());
            assert!(worker.join().is_ok());
            assert!(
                pending.is_err(),
                "setter blocked the timer or bypassed serialization"
            );
            change.await;
            // SAFETY: The update has completed and this test owns all native access.
            unsafe {
                let native = context.to_native();
                if update_reason {
                    assert_eq!(native.localizedReason().to_string(), "Updated prompt");
                } else {
                    assert!(native.interactionNotAllowed());
                }
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn clones_share_configuration_and_native_invalidation() {
        fn send_sync<T: Send + Sync>() {}
        send_sync::<AuthenticationContext>();
        let context = AuthenticationContext::builder()
            .localized_reason("Unlock the saved session")
            .biometric_unlock_reuse_duration(Duration::MAX)
            .build();
        let other = context.clone();
        other.set_interaction_allowed(false).await;
        other.set_localized_reason("Sign this request").await;
        {
            let native = lock(&context.inner.native);
            // SAFETY: Exclusive test access to the native context; getters and
            // canEvaluatePolicy never display authentication UI.
            unsafe {
                assert!(native.0.interactionNotAllowed());
                assert_eq!(native.0.localizedReason().to_string(), "Sign this request");
                assert!(
                    (native.0.touchIDAuthenticationAllowableReuseDuration() - 300.0).abs()
                        < f64::EPSILON
                );
            }
        }
        other.invalidate();
        context.invalidate();
        let native = lock(&context.inner.native);
        // SAFETY: This checks a policy's availability without evaluating it.
        let result = unsafe {
            native
                .0
                .canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthentication)
        };
        assert_eq!(result.err().map(|error| error.code()), Some(-10)); // LAErrorInvalidContext.
    }

    #[test]
    fn invalidation_does_not_wait_for_a_blocked_operation() {
        let context = AuthenticationContext::default();
        let guard = context.operation();
        let other = context.clone();
        let (sent, received) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            other.invalidate();
            let _ = sent.send(());
        });
        let result = received.recv_timeout(Duration::from_secs(5));
        drop(guard);
        assert!(worker.join().is_ok());
        assert!(result.is_ok(), "invalidation blocked behind an operation");
    }

    #[tokio::test]
    async fn native_roundtrip_preserves_identity_and_configuration() {
        // SAFETY: The native object is exclusively used by this test, sequentially.
        unsafe {
            let native = LAContext::new();
            native.setLocalizedReason(&NSString::from_str("Existing application prompt"));
            native.setInteractionNotAllowed(true);
            let pointer = Retained::as_ptr(&native);
            let context = AuthenticationContext::from_native(native);
            let exported = context.to_native();
            assert_eq!(Retained::as_ptr(&exported), pointer);
            assert!(exported.interactionNotAllowed());
            assert_eq!(
                exported.localizedReason().to_string(),
                "Existing application prompt"
            );
            context.set_localized_reason("Updated prompt").await;
            assert_eq!(exported.localizedReason().to_string(), "Updated prompt");
            exported.invalidate();
            let result = lock(&context.inner.native)
                .0
                .canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthentication);
            assert_eq!(result.err().map(|error| error.code()), Some(-10));
        }
    }
}
