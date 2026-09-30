//! Shared names for disposable example and test resources.
use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, SystemTimeError, UNIX_EPOCH},
};

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

pub(crate) fn unique_label(prefix: &str) -> Result<String, SystemTimeError> {
    Ok(format!(
        "{prefix}-{}-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    ))
}
