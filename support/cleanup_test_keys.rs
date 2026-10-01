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
    #[snafu(display("cannot delete public key {label} in {group}"))]
    DeletePublic {
        label: String,
        group: String,
        source: security_framework::base::Error,
    },
    #[snafu(display("cannot delete certificates {label} in {group}"))]
    DeleteCertificates {
        label: String,
        group: String,
        source: security_framework::base::Error,
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

// Public halves carry the stored label but no purpose tag or token.
fn public_candidate(stored_label: &str) -> bool {
    ["huskarl-apple/sign/", "huskarl-apple/seal/"]
        .iter()
        .any(|prefix| stored_label.strip_prefix(prefix).is_some_and(test_label))
}

// Earlier versions deleted only the private key, orphaning its public half.
// Run after private-key cleanup, which now removes both halves itself.
fn cleanup_public(group: &str, delete: bool) -> Result<usize, Error> {
    let results = ItemSearchOptions::new()
        .ignore_legacy_keychains()
        .class(ItemClass::key())
        .key_class(KeyClass::public())
        .access_group(group)
        .load_attributes(true)
        .limit(Limit::All)
        .search();
    let results = match results {
        Err(error) if error.code() == errSecItemNotFound => return Ok(0),
        result => result.context(SearchSnafu { group })?,
    };
    let mut labels: Vec<_> = results
        .iter()
        .filter_map(|result| result.simplify_dict()?.get("labl").cloned())
        .filter(|label| public_candidate(label))
        .collect();
    labels.sort_unstable();
    labels.dedup();
    for label in &labels {
        println!(
            "{} orphaned public key group={group:?} label={label:?}",
            if delete { "Deleting" } else { "Would delete" }
        );
        if delete {
            let result = ItemSearchOptions::new()
                .ignore_legacy_keychains()
                .class(ItemClass::key())
                .key_class(KeyClass::public())
                .access_group(group)
                .label(label)
                .delete();
            match result {
                Err(error) if error.code() == errSecItemNotFound => {}
                result => result.context(DeletePublicSnafu { label, group })?,
            }
        }
    }
    Ok(labels.len())
}

fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    if hex.is_empty() || !hex.len().is_multiple_of(2) {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok())
        .collect()
}

// TLS certificates are labelled by their key's public-key hash, so the label
// alone cannot say whether they belong to a test. Only those whose private
// key no longer exists in the group are removed: they can never form an
// identity again. Deleting a key now removes its certificates; this sweeps
// ones left by earlier versions or by tests that crashed before cleanup.
fn cleanup_certificates(group: &str, delete: bool) -> Result<usize, Error> {
    let results = ItemSearchOptions::new()
        .ignore_legacy_keychains()
        .class(ItemClass::certificate())
        .access_group(group)
        .load_attributes(true)
        .limit(Limit::All)
        .search();
    let results = match results {
        Err(error) if error.code() == errSecItemNotFound => return Ok(0),
        result => result.context(SearchSnafu { group })?,
    };
    let mut labels: Vec<_> = results
        .iter()
        .filter_map(|result| result.simplify_dict()?.get("labl").cloned())
        .filter(|label| label.starts_with("huskarl-apple/tls/"))
        .collect();
    labels.sort_unstable();
    labels.dedup();
    let mut count = 0;
    for label in &labels {
        let Some(key_hash) = label
            .strip_prefix("huskarl-apple/tls/")
            .and_then(decode_hex)
        else {
            continue;
        };
        let key = ItemSearchOptions::new()
            .ignore_legacy_keychains()
            .class(ItemClass::key())
            .key_class(KeyClass::private())
            .application_label(&key_hash)
            .access_group(group)
            .search();
        match key {
            Err(error) if error.code() == errSecItemNotFound => {}
            result => {
                result.context(SearchSnafu { group })?;
                continue;
            }
        }
        println!(
            "{} orphaned TLS certificates group={group:?} label={label:?}",
            if delete { "Deleting" } else { "Would delete" }
        );
        if delete {
            let result = ItemSearchOptions::new()
                .ignore_legacy_keychains()
                .class(ItemClass::certificate())
                .access_group(group)
                .label(label)
                .delete();
            match result {
                Err(error) if error.code() == errSecItemNotFound => {}
                result => result.context(DeleteCertificatesSnafu { label, group })?,
            }
        }
        count += 1;
    }
    Ok(count)
}

#[bon::builder]
async fn cleanup(groups: &[String], delete: bool) -> Result<(), Error> {
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
                    async {
                        let key = Es256PrivateKey::load_with()
                            .label(label)
                            .access_group(group)
                            .load()
                            .await?;
                        key.delete_key_and_associated_items().await
                    }
                    .await
                } else {
                    async {
                        let key = SealingKey::load_with()
                            .label(label)
                            .access_group(group)
                            .load()
                            .await?;
                        key.delete_key_and_associated_items().await
                    }
                    .await
                };
                match result {
                    Err(SetupError::KeyNotFound) => {}
                    result => result.context(DeleteSnafu { label, group })?,
                }
            }
            count += 1;
        }
    }
    // In preview mode this also lists public halves of the private keys above.
    for group in groups {
        count += cleanup_public(group, delete)?;
        count += cleanup_certificates(group, delete)?;
    }
    println!(
        "{count} matching test key(s) and certificate label(s). {}",
        if delete {
            "Cleanup complete."
        } else {
            "Preview only; use mise run test:cleanup --delete to remove them."
        }
    );
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let mut groups: Vec<_> = std::env::args().skip(1).collect();
    let delete = groups.first().is_some_and(|arg| arg == "--delete");
    if delete {
        groups.remove(0);
    }
    ensure!(
        !groups.is_empty() && groups.iter().all(|g| !g.is_empty() && !g.starts_with('-')),
        ArgumentsSnafu
    );
    cleanup().groups(&groups).delete(delete).call().await
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
        assert!(public_candidate(
            "huskarl-apple/seal/huskarl-apple-test-42-123456789-0"
        ));
        assert!(!public_candidate("huskarl-apple/seal/production"));
        assert!(!public_candidate(
            "huskarl-apple/other/huskarl-apple-test-42-123456789-0"
        ));
        assert_eq!(decode_hex("00ff7a"), Some(vec![0x00, 0xff, 0x7a]));
        for invalid in ["", "abc", "zz", "é0"] {
            assert_eq!(decode_hex(invalid), None, "{invalid}");
        }
    }
}
