//! Main-thread-only C bridge for the interactive macOS smoke application.
use std::{
    cell::RefCell,
    future::{Future, poll_fn},
    pin::Pin,
    task::Poll,
};

use huskarl::grant::authorization_code::{AuthorizationCodeGrant, StartInput};
use huskarl_apple::{
    urlsession::UrlSessionClient,
    web_authentication::{PresentationAnchor, WebAuthenticationError, WebAuthenticationSession},
};
use huskarl_core::client_auth::NoAuth;
use objc2::{MainThreadMarker, rc::Retained};

type LoginTask = Pin<Box<dyn Future<Output = Result<(), String>>>>;

thread_local! {
    static TASK: RefCell<Option<LoginTask>> = RefCell::new(None);
    static SESSION: RefCell<Option<WebAuthenticationSession>> = const { RefCell::new(None) };
    static RUNTIME: tokio::runtime::Runtime = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
}

fn main_thread() {
    assert!(
        MainThreadMarker::new().is_some(),
        "UI bridge requires the main thread"
    );
}

/// Starts a login in the smoke application.
///
/// # Safety
/// `window` must point to a live NSWindow, and the call must occur on the main thread.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn huskarl_browser_start(window: *mut PresentationAnchor, ephemeral: i32) {
    main_thread();
    huskarl_browser_drop();
    // SAFETY: App.swift passes its live NSWindow on the main thread. Retain it
    // for the entire flow, including the asynchronous token exchange.
    let Some(window) = (unsafe { Retained::retain(window) }) else {
        return;
    };
    TASK.with(|task| {
        *task.borrow_mut() = Some(Box::pin(async move {
            let result = async {
                let issuer = std::env::var("HUSKARL_BROWSER_ISSUER")?;
                let client = UrlSessionClient::builder().build()?;
                let grant = AuthorizationCodeGrant::builder()
                    .client_id("huskarl-browser")
                    .client_auth(NoAuth)
                    .http_client(client)
                    .authorization_endpoint(
                        format!("{issuer}/protocol/openid-connect/auth").parse()?,
                    )
                    .token_endpoint(format!("{issuer}/protocol/openid-connect/token").parse()?)
                    .redirect_uri("io.huskarl.browser-smoke:/callback")
                    .build()
                    .await?;
                let started = grant.start(StartInput::builder().build()).await?;
                let session = WebAuthenticationSession::start()
                    .authorization_url(&started.authorization_url.to_string())
                    .redirect_uri(&started.pending_state.redirect_uri)
                    .window(&window)
                    .prefers_ephemeral(ephemeral != 0)
                    .call()?;
                SESSION.with(|slot| *slot.borrow_mut() = Some(session));
                println!("BROWSER_SMOKE browser_started ephemeral={}", ephemeral != 0);
                let callback = poll_fn(|cx| {
                    SESSION.with(|slot| {
                        slot.borrow_mut().as_mut().map_or(
                            Poll::Ready(Err(WebAuthenticationError::Cancelled)),
                            |session| Pin::new(session).poll(cx),
                        )
                    })
                })
                .await?;
                SESSION.with(|slot| slot.borrow_mut().take());
                println!("BROWSER_SMOKE callback_received");
                let _tokens = grant
                    .complete(&started.pending_state, callback.parse()?)
                    .await?;
                println!("BROWSER_SMOKE success: state validated and PKCE code exchanged");
                Ok::<(), Box<dyn std::error::Error>>(())
            }
            .await;
            result.map_err(|error| error.to_string())
        }))
    });
}

#[unsafe(no_mangle)]
pub extern "C" fn huskarl_browser_poll() -> i32 {
    main_thread();
    TASK.with(|task| {
        let mut task = task.borrow_mut();
        let Some(future) = task.as_mut() else {
            return 0;
        };
        // Poll once while servicing Tokio, then return immediately to AppKit.
        // The app's timer drives subsequent polls; no UI thread blocking wait.
        let result = RUNTIME
            .with(|runtime| runtime.block_on(poll_fn(|cx| Poll::Ready(future.as_mut().poll(cx)))));
        match result {
            Poll::Pending => 1,
            Poll::Ready(result) => {
                task.take();
                SESSION.with(|slot| slot.borrow_mut().take());
                match result {
                    Ok(()) => 2,
                    Err(error) => {
                        println!("BROWSER_SMOKE completed: {error}");
                        3
                    }
                }
            }
        }
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn huskarl_browser_cancel() {
    main_thread();
    SESSION.with(|slot| {
        if let Some(session) = slot.borrow_mut().as_mut() {
            session.cancel();
        }
    });
    println!("BROWSER_SMOKE explicit_cancel");
}

#[unsafe(no_mangle)]
pub extern "C" fn huskarl_browser_drop() {
    main_thread();
    TASK.with(|task| {
        task.borrow_mut().take();
    });
    SESSION.with(|slot| {
        if slot.borrow_mut().take().is_some() {
            println!("BROWSER_SMOKE dropped_pending_session");
        }
    });
}
