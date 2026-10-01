use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use huskarl::{
    cache::{InMemoryRefreshTokenStore, RefreshTokenStore},
    token::RefreshToken,
};
use huskarl_core::{Error, platform::MaybeSendBoxFuture};

// Authenticate the persisted read once, then use zeroizing session memory.
// Server rotation cannot be rolled back if the subsequent Keychain write fails.
pub struct SessionRefreshTokens<S> {
    pub disk: S,
    pub memory: InMemoryRefreshTokenStore,
    pub persistence_failed: Arc<AtomicBool>,
}

impl<S: RefreshTokenStore> RefreshTokenStore for SessionRefreshTokens<S> {
    fn get(&self) -> MaybeSendBoxFuture<'_, Result<Option<RefreshToken>, Error>> {
        self.memory.get()
    }

    fn set<'a>(&'a self, token: &'a RefreshToken) -> MaybeSendBoxFuture<'a, Result<(), Error>> {
        Box::pin(async move {
            self.memory.set(token).await?;
            let result = self.disk.set(token).await;
            self.persistence_failed
                .store(result.is_err(), Ordering::Relaxed);
            result
        })
    }

    fn clear(&self) -> MaybeSendBoxFuture<'_, Result<(), Error>> {
        Box::pin(async move {
            self.memory.clear().await?;
            let result = self.disk.clear().await;
            self.persistence_failed
                .store(result.is_err(), Ordering::Relaxed);
            result
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use huskarl_core::{RetryAdvice, secrets::SecretString};

    struct Unavailable;
    impl RefreshTokenStore for Unavailable {
        fn get(&self) -> MaybeSendBoxFuture<'_, Result<Option<RefreshToken>, Error>> {
            Box::pin(async {
                Err(Error::new(
                    RetryAdvice::No,
                    std::io::Error::other("unavailable"),
                ))
            })
        }
        fn set<'a>(&'a self, _: &'a RefreshToken) -> MaybeSendBoxFuture<'a, Result<(), Error>> {
            Box::pin(async {
                Err(Error::new(
                    RetryAdvice::No,
                    std::io::Error::other("unavailable"),
                ))
            })
        }
        fn clear(&self) -> MaybeSendBoxFuture<'_, Result<(), Error>> {
            Box::pin(async {
                Err(Error::new(
                    RetryAdvice::No,
                    std::io::Error::other("unavailable"),
                ))
            })
        }
    }

    #[tokio::test]
    async fn failed_persistence_retains_rotation_but_failed_logout_clears_memory() {
        let store = SessionRefreshTokens {
            disk: Unavailable,
            memory: InMemoryRefreshTokenStore::default(),
            persistence_failed: Arc::new(AtomicBool::new(false)),
        };
        let token = RefreshToken::new(SecretString::new("rotated"), Some("binding".into()));
        assert!(store.set(&token).await.is_err());
        assert_eq!(store.get().await.unwrap(), Some(token));
        assert!(store.persistence_failed.load(Ordering::Relaxed));
        assert!(store.clear().await.is_err());
        assert_eq!(store.get().await.unwrap(), None);
    }
}
