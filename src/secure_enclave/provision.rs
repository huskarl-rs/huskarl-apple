use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt as _, path::Path};

use security_framework::key::SecKey;
use security_framework_sys::base::errSecDuplicateItem;
use snafu::ResultExt as _;

use super::{CoordinationSnafu, KeyAccessPolicy, KeyPurpose, SetupError, generate_key, load_key};

pub(super) fn load_or_generate(
    label: &str,
    purpose: KeyPurpose,
    access_group: &str,
    policy: KeyAccessPolicy,
    lock_path: &Path,
) -> Result<SecKey, SetupError> {
    coordinated(lock_path, || {
        load_or_create(
            || load_key(label, purpose, Some(access_group)),
            || generate_key(label, purpose, policy, Some(access_group)),
        )
    })
}

fn coordinated<T>(
    path: &Path,
    operation: impl FnOnce() -> Result<T, SetupError>,
) -> Result<T, SetupError> {
    // Open independently per invocation: cloned descriptors may share a lock.
    // Keep the file itself on disk so waiting/new callers always lock one inode.
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .context(CoordinationSnafu)?;
    file.lock().context(CoordinationSnafu)?;
    // Closing releases the OS lock on success, error, panic, and process exit.
    operation()
}

fn load_or_create<T>(
    mut load: impl FnMut() -> Result<T, SetupError>,
    generate: impl FnOnce() -> Result<T, SetupError>,
) -> Result<T, SetupError> {
    match load() {
        Err(SetupError::KeyNotFound) => {}
        result => return result,
    }
    match generate() {
        // Defensive handling for a creator outside our coordination protocol.
        // Do not retry other domains, authorization errors, or validation errors.
        Err(SetupError::KeyGeneration { source })
            if source.domain == "NSOSStatusErrorDomain"
                && source.code == errSecDuplicateItem as isize =>
        {
            load()
        }
        result => result,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::sync::{
        Arc, Barrier,
        atomic::{AtomicUsize, Ordering},
    };

    use super::*;
    use crate::PlatformError;

    fn generation_error(domain: &str, code: i32) -> SetupError {
        SetupError::KeyGeneration {
            source: PlatformError {
                domain: domain.into(),
                code: code as isize,
                message: "test".into(),
            },
        }
    }

    #[test]
    fn creates_only_after_definite_absence() {
        let mut generated = false;
        assert_eq!(
            load_or_create(
                || Ok(7),
                || {
                    generated = true;
                    Ok(9)
                }
            )
            .ok(),
            Some(7)
        );
        assert!(!generated);
        assert_eq!(
            load_or_create(|| Err(SetupError::KeyNotFound), || Ok(9)).ok(),
            Some(9)
        );
        for error in [
            SetupError::AmbiguousKey,
            SetupError::InvalidKeyResult,
            SetupError::KeyPurposeMismatch,
            SetupError::NotSecureEnclave,
            SetupError::PublicKeyExtraction,
            SetupError::KeychainSearch {
                source: security_framework::base::Error::from_code(
                    crate::platform::ERR_SEC_INTERACTION_NOT_ALLOWED,
                ),
            },
            SetupError::KeychainSearch {
                source: security_framework::base::Error::from_code(-25293),
            },
            SetupError::KeychainSearch {
                source: security_framework::base::Error::from_code(-34018),
            },
            SetupError::KeychainSearch {
                source: security_framework::base::Error::from_code(-128),
            },
            // Metadata disappearing after the initial match is not definite absence.
            SetupError::KeychainSearch {
                source: security_framework::base::Error::from_code(-25300),
            },
        ] {
            let mut error = Some(error);
            let result = load_or_create(
                || Err(error.take().unwrap()),
                || {
                    generated = true;
                    Ok(9)
                },
            );
            assert!(result.is_err());
            assert!(!generated);
        }
    }

    #[test]
    fn duplicate_creation_reloads_once_and_preserves_reload_failure() {
        for second in [
            Ok(7),
            Err(SetupError::KeyNotFound),
            Err(SetupError::AmbiguousKey),
        ] {
            let expected = format!("{second:?}");
            let mut replies = [Err(SetupError::KeyNotFound), second].into_iter();
            let result = load_or_create(|| replies.next().unwrap(), generation_error_result);
            assert_eq!(format!("{result:?}"), expected);
            assert!(replies.next().is_none());
        }
    }

    fn generation_error_result() -> Result<i32, SetupError> {
        Err(generation_error(
            "NSOSStatusErrorDomain",
            errSecDuplicateItem,
        ))
    }

    #[test]
    fn other_creation_errors_do_not_reload() {
        for (domain, code) in [
            (
                "NSOSStatusErrorDomain",
                crate::platform::ERR_SEC_INTERACTION_NOT_ALLOWED,
            ),
            ("another.domain", errSecDuplicateItem),
        ] {
            let mut loads = 0;
            let result: Result<(), _> = load_or_create(
                || {
                    loads += 1;
                    Err(SetupError::KeyNotFound)
                },
                || Err(generation_error(domain, code)),
            );
            assert!(matches!(result, Err(SetupError::KeyGeneration { .. })));
            assert_eq!(loads, 1);
        }
    }

    #[test]
    fn concurrent_callers_create_once_and_errors_release_lock()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir =
            std::env::temp_dir().join(crate::test_support::unique_label("huskarl-provision")?);
        std::fs::create_dir(&dir)?;
        let path = dir.join("creation.lock");
        let barrier = Arc::new(Barrier::new(8));
        let count = Arc::new(AtomicUsize::new(0));
        let mut workers = Vec::new();
        for _ in 0..8 {
            let (path, barrier, count) = (path.clone(), barrier.clone(), count.clone());
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                coordinated(&path, || {
                    load_or_create(
                        || {
                            if count.load(Ordering::SeqCst) == 0 {
                                Err(SetupError::KeyNotFound)
                            } else {
                                Ok(7)
                            }
                        },
                        || {
                            count.fetch_add(1, Ordering::SeqCst);
                            Ok(7)
                        },
                    )
                })
            }));
        }
        for worker in workers {
            assert_eq!(worker.join().unwrap().unwrap(), 7);
        }
        assert_eq!(count.load(Ordering::SeqCst), 1);
        let failed: Result<(), _> = coordinated(&path, || Err(SetupError::KeyPurposeMismatch));
        assert!(failed.is_err());
        assert!(coordinated(&path, || Ok(())).is_ok());
        std::fs::remove_file(&path)?;
        std::fs::remove_dir(&dir)?;
        Ok(())
    }

    #[test]
    fn processes_share_the_lock_and_exit_releases_it() -> Result<(), Box<dyn std::error::Error>> {
        const CHILD_DIR: &str = "HUSKARL_PROVISION_TEST_CHILD_DIR";
        if let Some(directory) = std::env::var_os(CHILD_DIR) {
            let directory = std::path::PathBuf::from(directory);
            let marker = directory.join("key");
            let result: Result<(), SetupError> =
                coordinated(&directory.join("creation.lock"), || {
                    let result = load_or_create(
                        || match std::fs::read(&marker) {
                            Ok(bytes) => Ok(bytes),
                            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                                Err(SetupError::KeyNotFound)
                            }
                            Err(source) => Err(SetupError::Coordination { source }),
                        },
                        || {
                            std::fs::write(
                                directory.join(format!("generated-{}", std::process::id())),
                                [],
                            )
                            .context(CoordinationSnafu)?;
                            std::fs::write(&marker, b"key").context(CoordinationSnafu)?;
                            Ok(b"key".to_vec())
                        },
                    )?;
                    assert_eq!(result, b"key");
                    // Deliberately bypass Rust destructors while holding the lock.
                    std::process::exit(0);
                });
            result?;
            return Ok(());
        }
        let directory = std::env::temp_dir().join(crate::test_support::unique_label(
            "huskarl-provision-processes",
        )?);
        std::fs::create_dir(&directory)?;
        let mut children = Vec::new();
        for _ in 0..4 {
            children.push(std::process::Command::new(std::env::current_exe()?)
                .args(["--exact", "secure_enclave::provision::tests::processes_share_the_lock_and_exit_releases_it"])
                .env(CHILD_DIR, &directory).stdout(std::process::Stdio::null()).spawn()?);
        }
        for mut child in children {
            assert!(child.wait()?.success());
        }
        let entries: Vec<_> = std::fs::read_dir(&directory)?.collect::<Result<_, _>>()?;
        assert_eq!(
            entries
                .iter()
                .filter(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("generated-"))
                .count(),
            1
        );
        for entry in entries {
            std::fs::remove_file(entry.path())?;
        }
        std::fs::remove_dir(directory)?;
        Ok(())
    }
}
