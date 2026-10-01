//! Opt-in concurrent enclave provisioning with an explicit access group.
#[path = "../support/unique_label.rs"]
mod support;

use std::sync::Arc;

use huskarl_apple::{
    Es256PrivateKey,
    secure_enclave::{KeyAccessPolicy, KeyAuthentication, SealingKey},
};
use huskarl_core::crypto::signer::AsymmetricJwsSigner as _;
use tokio::{sync::Barrier, task::JoinSet};

type TestResult = Result<(), Box<dyn std::error::Error>>;

macro_rules! provision_test {
    ($name:ident, $key:ty, $identity:expr) => {
        #[tokio::test]
        #[ignore = "requires signed executable, Secure Enclave, and HUSKARL_TEST_ACCESS_GROUP"]
        async fn $name() -> TestResult {
            let group = std::env::var("HUSKARL_TEST_ACCESS_GROUP")?;
            let label = support::unique_label("huskarl-provision")?;
            let directory = std::env::temp_dir().join(&label);
            std::fs::create_dir(&directory)?;
            let lock = directory.join("creation.lock");
            let barrier = Arc::new(Barrier::new(4));
            let mut workers = JoinSet::new();
            for _ in 0..4 {
                let (label, group, lock, barrier) =
                    (label.clone(), group.clone(), lock.clone(), barrier.clone());
                workers.spawn(async move {
                    barrier.wait().await;
                    <$key>::load_or_generate()
                        .label(&label)
                        .access_group(group)
                        .lock_path(&lock)
                        .load_or_generate()
                        .await
                });
            }
            let mut outcomes = Vec::new();
            while let Some(outcome) = workers.join_next().await {
                outcomes.push(outcome);
            }
            let result: TestResult = async {
                let identity = $identity;
                let loaded = <$key>::load_with()
                    .label(&label)
                    .access_group(&group)
                    .load()
                    .await?;
                for outcome in outcomes {
                    let key = outcome.map_err(|_| "provisioning task failed")??;
                    assert_eq!(identity(&key), identity(&loaded));
                }
                // A different creation policy must not replace an existing key.
                let again = <$key>::load_or_generate()
                    .label(&label)
                    .access_group(&group)
                    .lock_path(&lock)
                    .creation_policy(
                        KeyAccessPolicy::builder()
                            .authentication(KeyAuthentication::UserPresence)
                            .build(),
                    )
                    .load_or_generate()
                    .await?;
                assert_eq!(identity(&again), identity(&loaded));
                Ok(())
            }
            .await;
            let cleanup = async {
                let key = <$key>::load_with()
                    .label(&label)
                    .access_group(group)
                    .load()
                    .await?;
                key.delete_key_and_associated_items().await
            }
            .await;
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
