//! A custom harness is required: Apple's main queue must run on the actual
//! process main thread, not a libtest worker.
use std::{
    cell::Cell,
    future::{Future, poll_fn},
    pin::Pin,
    rc::Rc,
    sync::{Arc, Mutex},
    task::{Poll, Waker},
    time::{Duration, Instant},
};

use core_foundation::runloop::{CFRunLoop, kCFRunLoopDefaultMode};
#[path = "../src/executor.rs"]
mod executor;
use executor::MainThreadExecutor;
use objc2::MainThreadMarker;

fn pump_until(mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !done() {
        assert!(Instant::now() < deadline, "main-thread task stalled");
        // SAFETY: Read-only framework constant, valid for the process lifetime.
        CFRunLoop::run_in_mode(
            unsafe { kCFRunLoopDefaultMode },
            Duration::from_millis(10),
            true,
        );
    }
}

struct Probe {
    polls: Rc<Cell<usize>>,
    dropped: Rc<Cell<bool>>,
    waker: Arc<Mutex<Option<Waker>>>,
    ready: Rc<Cell<bool>>,
}
impl Future for Probe {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<()> {
        assert!(MainThreadMarker::new().is_some());
        self.polls.set(self.polls.get() + 1);
        *self.waker.lock().unwrap() = Some(cx.waker().clone());
        if self.ready.get() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}
impl Drop for Probe {
    fn drop(&mut self) {
        assert!(MainThreadMarker::new().is_some());
        self.dropped.set(true);
    }
}

fn main() {
    let mtm = MainThreadMarker::new().expect("custom harness runs on the main thread");
    let executor = Rc::new(MainThreadExecutor::new(mtm));
    let polls = Rc::new(Cell::new(0));
    let dropped = Rc::new(Cell::new(false));
    let ready = Rc::new(Cell::new(false));
    let waker = Arc::new(Mutex::new(None));
    executor.spawn_local(Probe {
        polls: polls.clone(),
        dropped: dropped.clone(),
        ready: ready.clone(),
        waker: waker.clone(),
    });
    assert_eq!(polls.get(), 0, "spawn must not poll inline");
    pump_until(|| polls.get() == 1);
    assert!(!executor.is_idle());

    // Wake many times on a worker. They must coalesce into one poll, on main.
    let worker_waker = waker.lock().unwrap().clone().unwrap();
    std::thread::spawn(move || {
        for _ in 0..100 {
            worker_waker.wake_by_ref();
        }
    })
    .join()
    .unwrap();
    pump_until(|| polls.get() == 2);
    let main_turn = Rc::new(Cell::new(false));
    let done = main_turn.clone();
    executor.spawn_local(async move { done.set(true) });
    pump_until(|| main_turn.get());
    assert_eq!(
        polls.get(),
        2,
        "idle tasks must not be polled on unrelated wakes"
    );

    ready.set(true);
    waker.lock().unwrap().as_ref().unwrap().wake_by_ref();
    pump_until(|| executor.is_idle());
    assert!(dropped.get());

    // Spawn from within a task and self-wake while polling without reentrancy.
    let nested_executor = executor.clone();
    let completed = Rc::new(Cell::new(false));
    let done = completed.clone();
    executor.spawn_local(async move {
        nested_executor.spawn_local(async move {
            let mut first = true;
            poll_fn(|cx| {
                if first {
                    first = false;
                    cx.waker().wake_by_ref();
                    Poll::Pending
                } else {
                    done.set(true);
                    Poll::Ready(())
                }
            })
            .await;
        });
    });
    pump_until(|| completed.get() && executor.is_idle());

    // Tokio timers need an independently running runtime, entered per poll.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_time()
        .build()
        .unwrap();
    let handle = runtime.handle().clone();
    let timer_done = Rc::new(Cell::new(false));
    let done = timer_done.clone();
    let mut timer = Box::pin(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(MainThreadMarker::new().is_some());
        done.set(true);
    });
    executor.spawn_local(poll_fn(move |cx| {
        let _entered = handle.enter();
        timer.as_mut().poll(cx)
    }));
    pump_until(|| timer_done.get() && executor.is_idle());

    // Dropping the owner destroys pending local futures on main. Stale worker
    // wakes and native callbacks must not keep them alive or access them again.
    dropped.set(false);
    ready.set(false);
    executor.spawn_local(Probe {
        polls: polls.clone(),
        dropped: dropped.clone(),
        ready,
        waker: waker.clone(),
    });
    pump_until(|| polls.get() == 4);
    let stale = waker.lock().unwrap().clone().unwrap();
    stale.wake_by_ref();
    drop(executor);
    assert!(dropped.get());
    std::thread::spawn(move || stale.wake()).join().unwrap();
    let executor = MainThreadExecutor::new(mtm);
    executor.spawn_local(async {});
    pump_until(|| executor.is_idle());
    assert_eq!(polls.get(), 4);
    println!(
        "main-thread executor: worker wakes, coalescing, idle behavior, nested spawn, self-wake, timers, and drop passed"
    );
}
