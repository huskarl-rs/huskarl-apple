use std::sync::{
    Arc,
    atomic::{AtomicU8, Ordering},
};

use huskarl::{
    cache::{InMemoryRefreshTokenStore, RefreshTokenStore},
    token::RefreshToken,
};
use huskarl_core::{Error, platform::MaybeSendBoxFuture};

use super::PersistenceState;

pub(super) struct SessionStore<S> {
    disk: Arc<S>,
    memory: Arc<InMemoryRefreshTokenStore>,
    persistence: Arc<AtomicU8>,
}

impl<S> Clone for SessionStore<S> {
    fn clone(&self) -> Self {
        Self {
            disk: self.disk.clone(),
            memory: self.memory.clone(),
            persistence: self.persistence.clone(),
        }
    }
}

impl<S> SessionStore<S> {
    pub(super) fn new(disk: Arc<S>) -> Self {
        Self {
            disk,
            memory: Arc::default(),
            persistence: Arc::new(AtomicU8::new(0)),
        }
    }
    pub(super) fn persistence(&self) -> PersistenceState {
        match self.persistence.load(Ordering::Relaxed) {
            0 => PersistenceState::Absent,
            1 => PersistenceState::Saved,
            _ => PersistenceState::UnsavedChanges,
        }
    }
    pub(super) async fn restore(&self, token: RefreshToken) -> Result<(), Error> {
        self.memory.set(&token).await?;
        self.persistence.store(1, Ordering::Relaxed);
        Ok(())
    }
}

impl<S: RefreshTokenStore> RefreshTokenStore for SessionStore<S> {
    fn get(&self) -> MaybeSendBoxFuture<'_, Result<Option<RefreshToken>, Error>> {
        self.memory.get()
    }
    fn set<'a>(&'a self, token: &'a RefreshToken) -> MaybeSendBoxFuture<'a, Result<(), Error>> {
        Box::pin(async move {
            self.memory.set(token).await?;
            let result = self.disk.set(token).await;
            self.persistence
                .store(if result.is_ok() { 1 } else { 2 }, Ordering::Relaxed);
            result
        })
    }
    fn clear(&self) -> MaybeSendBoxFuture<'_, Result<(), Error>> {
        Box::pin(async move {
            self.memory.clear().await?;
            let result = self.disk.clear().await;
            self.persistence
                .store(if result.is_ok() { 0 } else { 2 }, Ordering::Relaxed);
            result
        })
    }
}
