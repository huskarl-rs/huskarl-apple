//! Opt-in isolation tests requiring two entitled Keychain access groups.
#[path = "../support/unique_label.rs"]
mod support;

use huskarl_apple::{Es256PrivateKey, SetupError, secure_enclave::SealingKey};
use huskarl_core::crypto::signer::AsymmetricJwsSigner as _;

type TestResult = Result<(), Box<dyn std::error::Error>>;

macro_rules! group_test {
    ($name:ident, $key:ty, $identity:expr) => {
        #[tokio::test]
        #[ignore = "requires signed executable, Secure Enclave, and two configured entitled groups"]
        async fn $name() -> TestResult {
            let group_a = std::env::var("HUSKARL_TEST_ACCESS_GROUP_A")?;
            let group_b = std::env::var("HUSKARL_TEST_ACCESS_GROUP_B")?;
            assert_ne!(group_a, group_b);
            let label = support::unique_label("huskarl-apple-groups")?;
            let identity = $identity;
            let first = <$key>::generate_with()
                .label(&label)
                .access_group(&group_a)
                .generate()
                .await?;
            let result: TestResult = async {
                assert!(matches!(
                    <$key>::load_with()
                        .label(&label)
                        .access_group(&group_b)
                        .load()
                        .await,
                    Err(SetupError::KeyNotFound)
                ));
                let second = <$key>::generate_with()
                    .label(&label)
                    .access_group(&group_b)
                    .generate()
                    .await?;
                let result: TestResult = async {
                    assert!(matches!(
                        <$key>::load(&label).await,
                        Err(SetupError::AmbiguousKey)
                    ));
                    let loaded_a = <$key>::load_with()
                        .label(&label)
                        .access_group(&group_a)
                        .load()
                        .await?;
                    let loaded_b = <$key>::load_with()
                        .label(&label)
                        .access_group(&group_b)
                        .load()
                        .await?;
                    assert_eq!(identity(&loaded_a), identity(&first));
                    assert_eq!(identity(&loaded_b), identity(&second));
                    assert_ne!(identity(&loaded_a), identity(&loaded_b));
                    Ok(())
                }
                .await;
                let cleanup = second.delete_key_and_associated_items().await;
                result?;
                cleanup?;
                assert!(matches!(
                    <$key>::load_with()
                        .label(&label)
                        .access_group(&group_b)
                        .load()
                        .await,
                    Err(SetupError::KeyNotFound)
                ));
                assert_eq!(identity(&<$key>::load(&label).await?), identity(&first));
                Ok(())
            }
            .await;
            let cleanup = first.delete_key_and_associated_items().await;
            result?;
            cleanup?;
            Ok(())
        }
    };
}

group_test!(
    signing_groups_are_isolated,
    Es256PrivateKey,
    |key: &Es256PrivateKey| key.public_key_jwk().thumbprint()
);
group_test!(
    sealing_groups_are_isolated,
    SealingKey,
    |key: &SealingKey| key.key_id().to_owned()
);

#[tokio::test]
#[ignore = "requires signed executable and two configured entitled groups"]
async fn secret_writes_and_deletes_are_group_scoped() -> TestResult {
    use huskarl_apple::keychain::DataProtectionKeychain;
    use huskarl_core::secrets::{Secret as _, SecretBytes};
    let group_a = std::env::var("HUSKARL_TEST_ACCESS_GROUP_A")?;
    let group_b = std::env::var("HUSKARL_TEST_ACCESS_GROUP_B")?;
    assert_ne!(group_a, group_b);
    let service = support::unique_label("huskarl-apple-secret-groups")?;
    let a = DataProtectionKeychain::new(group_a)?
        .secret(&service, "same-account")?
        .store()
        .build();
    let b = DataProtectionKeychain::new(group_b)?
        .secret(&service, "same-account")?
        .store()
        .build();
    let result: TestResult = async {
        a.set(&SecretBytes::new(vec![1])).await?;
        b.set(&SecretBytes::new(vec![2])).await?;
        a.set(&SecretBytes::new(vec![3])).await?;
        assert_eq!(a.get_secret_value().await?.value.expose_secret(), &[3]);
        assert_eq!(b.get_secret_value().await?.value.expose_secret(), &[2]);
        a.clear().await?;
        assert!(a.get().await?.is_none());
        assert_eq!(b.get_secret_value().await?.value.expose_secret(), &[2]);
        Ok(())
    }
    .await;
    let cleanup_a = a.clear().await;
    let cleanup_b = b.clear().await;
    result?;
    cleanup_a?;
    cleanup_b?;
    Ok(())
}
