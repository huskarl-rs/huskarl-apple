//! Opt-in concurrent enclave provisioning with an explicit access group.
#[path = "../support/unique_label.rs"]
mod support;

use std::sync::{Arc, Barrier};

use huskarl_apple::{
    Es256PrivateKey,
    secure_enclave::{KeyAccessPolicy, KeyAuthentication, SealingKey},
};
use huskarl_core::crypto::signer::AsymmetricJwsSigner as _;

type TestResult = Result<(), Box<dyn std::error::Error>>;

macro_rules! provision_test {
    ($name:ident, $key:ty, $identity:expr) => {
        #[test]
        #[ignore = "requires signed executable, Secure Enclave, and HUSKARL_TEST_ACCESS_GROUP"]
        fn $name() -> TestResult {
            let group = std::env::var("HUSKARL_TEST_ACCESS_GROUP")?;
            let label = support::unique_label("huskarl-provision")?;
            let directory = std::env::temp_dir().join(&label);
            std::fs::create_dir(&directory)?;
            let lock = directory.join("creation.lock");
            let barrier = Arc::new(Barrier::new(4));
            let mut workers = Vec::new();
            for _ in 0..4 {
                let (label, group, lock, barrier) =
                    (label.clone(), group.clone(), lock.clone(), barrier.clone());
                workers.push(std::thread::spawn(move || {
                    barrier.wait();
                    <$key>::load_or_generate()
                        .label(&label)
                        .access_group(group)
                        .lock_path(&lock)
                        .call()
                }));
            }
            let outcomes: Vec<_> = workers
                .into_iter()
                .map(std::thread::JoinHandle::join)
                .collect();
            let result: TestResult = (|| {
                let identity = $identity;
                let loaded = <$key>::load_with()
                    .label(&label)
                    .access_group(&group)
                    .load()?;
                for outcome in outcomes {
                    let key = outcome.map_err(|_| "provisioning thread panicked")??;
                    assert_eq!(identity(&key), identity(&loaded));
                }
                // A different creation policy must not replace an existing key.
                let again = <$key>::load_or_generate()
                    .label(&label)
                    .access_group(&group)
                    .lock_path(&lock)
                    .access_policy(
                        KeyAccessPolicy::builder()
                            .authentication(KeyAuthentication::UserPresence)
                            .build(),
                    )
                    .call()?;
                assert_eq!(identity(&again), identity(&loaded));
                Ok(())
            })();
            let cleanup = <$key>::load_with()
                .label(&label)
                .access_group(group)
                .load()
                .and_then(|key| key.delete());
            std::fs::remove_file(lock)?;
            std::fs::remove_dir(directory)?;
            result?;
            cleanup?;
            Ok(())
        }
    };
}

provision_test!(
    concurrent_signers_share_one_key,
    Es256PrivateKey,
    |key: &Es256PrivateKey| key.public_key_jwk().thumbprint()
);
provision_test!(
    concurrent_sealers_share_one_key,
    SealingKey,
    |key: &SealingKey| key.key_id().to_owned()
);
