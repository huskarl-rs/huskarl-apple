//! Wake-driven execution of local futures on Apple's main dispatch queue.
//!
//! Example-local AppKit support, not part of huskarl-apple's public API.
//! The application owns this executor alongside its event loop and schedules
//! the session driver and UI operations. Wakes from any thread schedule a
//! main-thread turn; idle tasks are not polled.
//!
//! This is a local executor, not an I/O or timer runtime. Futures that require
//! Tokio must enter an independently driven Tokio runtime on each poll (see the
//! native-session example). Do not block the UI thread waiting for a task.
//!
//! Dropping the executor cancels its tasks on the main thread. Await session
//! shutdown and let the driver finish before dropping it: cancelling a future
//! cannot stop a Keychain mutation already executing on a blocking worker.

use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
    future::Future,
    pin::Pin,
    rc::{Rc, Weak},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};

use dispatch2::DispatchQueue;
use futures_util::{Stream, stream::FuturesUnordered};
use objc2::{MainThreadMarker, rc::autoreleasepool};

type Task = Pin<Box<dyn Future<Output = ()>>>;

thread_local! {
    // Native callbacks carry only a thread-safe wake token. Local futures never
    // cross the thread boundary, including when a stale callback is discarded.
    static EXECUTORS: RefCell<HashMap<usize, Weak<Inner>>> = RefCell::new(HashMap::new());
}

#[derive(Default)]
struct QueueWake {
    queued: AtomicBool,
    closed: AtomicBool,
}

impl QueueWake {
    fn key(this: &Arc<Self>) -> usize {
        // The queued callback retains the Arc, preventing address reuse while
        // an old callback or waker can still refer to this executor.
        Arc::as_ptr(this) as usize
    }
}

impl Wake for QueueWake {
    fn wake(self: Arc<Self>) {
        Self::wake_by_ref(&self);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        if self.closed.load(Ordering::Acquire) || self.queued.swap(true, Ordering::AcqRel) {
            return;
        }
        let wake = self.clone();
        DispatchQueue::main().exec_async(move || {
            wake.queued.store(false, Ordering::Release);
            let inner = EXECUTORS.with(|registry| {
                registry
                    .borrow()
                    .get(&Self::key(&wake))
                    .and_then(Weak::upgrade)
            });
            if let Some(inner) = inner {
                autoreleasepool(|_| inner.poll_ready());
            }
        });
    }
}

struct Inner {
    wake: Arc<QueueWake>,
    tasks: RefCell<FuturesUnordered<Task>>,
    incoming: RefCell<Vec<Task>>,
    count: Cell<usize>,
    repoll: Cell<bool>,
}

impl Inner {
    fn poll_ready(&self) {
        let Ok(mut tasks) = self.tasks.try_borrow_mut() else {
            // A task can enter a nested native run loop. Never poll it
            // recursively; arrange a turn after the outer poll returns.
            self.repoll.set(true);
            return;
        };
        for task in self.incoming.take() {
            tasks.push(task);
        }
        let waker = Waker::from(self.wake.clone());
        let mut cx = Context::from_waker(&waker);
        // Bound completions per turn so ready work yields back to AppKit.
        // FuturesUnordered also yields when tasks repeatedly wake themselves.
        for _ in 0..64 {
            match Pin::new(&mut *tasks).poll_next(&mut cx) {
                Poll::Ready(Some(())) => self.count.set(self.count.get() - 1),
                Poll::Ready(None) | Poll::Pending => {
                    if self.repoll.replace(false) || !self.incoming.borrow().is_empty() {
                        waker.wake_by_ref();
                    }
                    return;
                }
            }
        }
        waker.wake_by_ref();
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.wake.closed.store(true, Ordering::Release);
        // TLS may already be tearing down during process exit.
        let _ = EXECUTORS.try_with(|registry| {
            registry.borrow_mut().remove(&QueueWake::key(&self.wake));
        });
    }
}

/// Owns local futures driven by Apple's main dispatch queue.
///
/// Create and keep this owner on the main thread. No timer, manual polling, or
/// `block_on` is needed. Tasks must cooperate by returning promptly from `poll`.
/// A panic in a task crosses a native callback boundary and aborts the process.
/// Dropping this owner cancels pending tasks; drain session drivers first.
pub(crate) struct MainThreadExecutor {
    inner: Rc<Inner>,
}

impl MainThreadExecutor {
    /// Creates an idle executor. The application must run its native event loop.
    #[must_use]
    pub(crate) fn new(_main_thread: MainThreadMarker) -> Self {
        let inner = Rc::new(Inner {
            wake: Arc::new(QueueWake::default()),
            tasks: RefCell::new(FuturesUnordered::new()),
            incoming: RefCell::new(Vec::new()),
            count: Cell::new(0),
            repoll: Cell::new(false),
        });
        EXECUTORS.with(|registry| {
            registry
                .borrow_mut()
                .insert(QueueWake::key(&inner.wake), Rc::downgrade(&inner));
        });
        Self { inner }
    }

    /// Schedules a local task, retaining it until completion or executor drop.
    ///
    /// Use an async block to await a result and notify your UI. Tasks may spawn
    /// more tasks on this executor. Waking never polls the future inline.
    pub(crate) fn spawn_local(&self, future: impl Future<Output = ()> + 'static) {
        self.inner.count.set(self.inner.count.get() + 1);
        self.inner.incoming.borrow_mut().push(Box::pin(future));
        self.inner.wake.wake_by_ref();
    }

    /// Whether all submitted tasks have completed, including session drivers.
    /// This may be inspected from a task; that task still counts as active.
    #[must_use]
    #[cfg(test)]
    #[allow(dead_code)] // Used by the standalone harness, not the bridge unit tests.
    pub(crate) fn is_idle(&self) -> bool {
        self.inner.count.get() == 0
    }
}
