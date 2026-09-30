//! Integer-only C bridge for the Apple example; no secret crosses the FFI boundary.
use huskarl::{cache::RefreshTokenStore as _, token::RefreshToken};
use huskarl_core::secrets::SecretString;
use huskarl_apple::keychain::{KeychainRefreshTokenStore, KeychainSecretStore};
use snafu::{ResultExt as _, Snafu};

#[derive(Debug, Snafu)]
enum Error {
    #[snafu(display("Keychain operation failed: {source}"))]
    Storage { source: huskarl_core::Error },
    #[snafu(display("The stored token did not match the example token"))]
    UnexpectedToken,
    #[snafu(display("Unknown example operation"))]
    Operation,
}

async fn operation(action: i32) -> Result<i32, Error> {
    let storage = KeychainSecretStore::builder()
        .service(env!("HUSKARL_EXAMPLE_SERVICE"))
        .account("disposable-refresh-token")
        .access_group(env!("HUSKARL_EXAMPLE_ACCESS_GROUP"))
        .build();
    let tokens = KeychainRefreshTokenStore::builder()
        .storage(storage)
        .build();
    let example = RefreshToken::new(SecretString::new("disposable-simulator-token"), None);
    match action {
        0 => match tokens.get().await.context(StorageSnafu)? {
            None => Ok(0),
            Some(token) if token == example => Ok(1),
            Some(_) => UnexpectedTokenSnafu.fail(),
        },
        1 => {
            tokens.set(&example).await.context(StorageSnafu)?;
            Ok(2)
        }
        2 => {
            tokens.clear().await.context(StorageSnafu)?;
            Ok(0)
        }
        _ => OperationSnafu.fail(),
    }
}

/// 0 = load, 1 = store, 2 = clear. Returns 0 = absent, 1 = loaded, 2 = stored,
/// -1 = operation error, -2 = panic. Call from a background thread.
// This uniquely named exported symbol has a C ABI and accepts no pointers.
// The unsafe attribute is confined to this example; the library forbids unsafe code.
#[unsafe(no_mangle)]
pub extern "C" fn huskarl_example_token_operation(action: i32) -> i32 {
    match std::panic::catch_unwind(|| futures_lite::future::block_on(operation(action))) {
        Ok(Ok(status)) => status,
        Ok(Err(error)) => {
            eprintln!("{error}");
            -1
        }
        Err(_) => -2,
    }
}
