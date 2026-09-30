//! Development-only discovery and cleanup of this repository's enclave test keys.
use huskarl_apple::{Es256PrivateKey, SetupError, secure_enclave::SealingKey};
use security_framework::item::{ItemClass, ItemSearchOptions, KeyClass, Limit};
use security_framework_sys::base::errSecItemNotFound;
use snafu::{ResultExt as _, Snafu, ensure};

#[derive(Debug, Snafu)]
enum Error {
    #[snafu(display("usage: cleanup-test-keys [--delete] ACCESS_GROUP ..."))]
    Arguments,
    #[snafu(display("cannot enumerate keys in {group}"))]
    Search {
        group: String,
        source: security_framework::base::Error,
    },
    #[snafu(display("cannot delete {label} in {group}"))]
    Delete {
        label: String,
        group: String,
        source: SetupError,
    },
}

// Only the exact naming schemes used by the integration tests are disposable.
// Examples and arbitrary application labels are deliberately excluded.
fn test_label(label: &str) -> bool {
    [
        "huskarl-apple-test-",
        "huskarl-apple-groups-",
        "huskarl-provision-",
        "huskarl-apple-presence-sign-huskarl-apple-presence-",
        "huskarl-apple-presence-seal-huskarl-apple-presence-",
    ]
    .iter()
    .any(|prefix| {
        label.strip_prefix(prefix).is_some_and(|suffix| {
            let parts: Vec<_> = suffix.split('-').collect();
            parts.len() == 3
                && parts
                    .iter()
                    .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
        })
    })
}

fn candidate<'a>(tag: &str, stored_label: &'a str, token: &str) -> Option<&'a str> {
    if !matches!(tag, "huskarl-apple/sign" | "huskarl-apple/seal") || token != "com.apple.setoken" {
        return None;
    }
    stored_label
        .strip_prefix(tag)?
        .strip_prefix('/')
        .filter(|label| test_label(label))
}

#[bon::builder]
fn cleanup(groups: &[String], delete: bool) -> Result<(), Error> {
    let mut count = 0;
    for group in groups {
        let results = ItemSearchOptions::new()
            .ignore_legacy_keychains()
            .class(ItemClass::key())
            .key_class(KeyClass::private())
            .access_group(group)
            .load_attributes(true)
            .limit(Limit::All)
            .search();
        let results = match results {
            Err(error) if error.code() == errSecItemNotFound => continue,
            result => result.context(SearchSnafu { group })?,
        };
        for result in results {
            let Some(attrs) = result.simplify_dict() else {
                continue;
            };
            let (Some(tag), Some(stored), Some(token)) =
                (attrs.get("atag"), attrs.get("labl"), attrs.get("tkid"))
            else {
                continue;
            };
            let Some(label) = candidate(tag, stored, token) else {
                continue;
            };
            println!(
                "{} group={group:?} purpose={tag:?} label={label:?}",
                if delete { "Deleting" } else { "Would delete" }
            );
            if delete {
                // Reload through the crate to revalidate purpose and enclave provenance.
                let result = if tag == "huskarl-apple/sign" {
                    Es256PrivateKey::load_with()
                        .label(label)
                        .access_group(group)
                        .load()
                        .and_then(|key| key.delete())
                } else {
                    SealingKey::load_with()
                        .label(label)
                        .access_group(group)
                        .load()
                        .and_then(|key| key.delete())
                };
                match result {
                    Err(SetupError::KeyNotFound) => {}
                    result => result.context(DeleteSnafu { label, group })?,
                }
            }
            count += 1;
        }
    }
    println!(
        "{count} matching test key(s). {}",
        if delete {
            "Cleanup complete."
        } else {
            "Preview only; use mise run test:cleanup --delete to remove them."
        }
    );
    Ok(())
}

fn main() -> Result<(), Error> {
    let mut groups: Vec<_> = std::env::args().skip(1).collect();
    let delete = groups.first().is_some_and(|arg| arg == "--delete");
    if delete {
        groups.remove(0);
    }
    ensure!(
        !groups.is_empty() && groups.iter().all(|g| !g.is_empty() && !g.starts_with('-')),
        ArgumentsSnafu
    );
    cleanup().groups(&groups).delete(delete).call()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_requires_purpose_enclave_and_exact_test_name() {
        let label = "huskarl-apple/sign/huskarl-apple-test-42-123456789-0";
        assert!(candidate("huskarl-apple/sign", label, "com.apple.setoken").is_some());
        assert!(candidate("huskarl-apple/seal", label, "com.apple.setoken").is_none());
        assert!(candidate("huskarl-apple/sign", label, "software").is_none());
        for name in [
            "production",
            "huskarl-apple-test-account",
            "huskarl-apple-test-1-2",
            "huskarl-apple-test-1-2-3-extra",
            "huskarl-apple-test-1--3",
            "huskarl-apple-signing-example-1-2-3",
        ] {
            assert!(!test_label(name), "{name}");
        }
        for name in [
            "huskarl-provision-1-2-3",
            "huskarl-apple-groups-1-2-3",
            "huskarl-apple-presence-sign-huskarl-apple-presence-1-2-3",
            "huskarl-apple-presence-seal-huskarl-apple-presence-1-2-3",
        ] {
            assert!(test_label(name), "{name}");
        }
    }
}
