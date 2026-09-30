//! Opt-in isolation tests requiring two entitled Keychain access groups.
#[path = "../support/unique_label.rs"]
mod support;

use huskarl_apple::{Es256PrivateKey, SetupError, secure_enclave::SealingKey};
use huskarl_core::crypto::signer::AsymmetricJwsSigner as _;

type TestResult = Result<(), Box<dyn std::error::Error>>;

macro_rules! group_test {
    ($name:ident, $key:ty, $identity:expr) => {
        #[test]
        #[ignore = "requires signed executable, Secure Enclave, and two configured entitled groups"]
        fn $name() -> TestResult {
            let group_a = std::env::var("HUSKARL_TEST_ACCESS_GROUP_A")?;
            let group_b = std::env::var("HUSKARL_TEST_ACCESS_GROUP_B")?;
            assert_ne!(group_a, group_b);
            let label = support::unique_label("huskarl-apple-groups")?;
            let identity = $identity;
            let first = <$key>::generate_with()
                .label(&label)
                .access_group(&group_a)
                .generate()?;
            let result: TestResult = (|| {
                assert!(matches!(
                    <$key>::load_with()
                        .label(&label)
                        .access_group(&group_b)
                        .load(),
                    Err(SetupError::KeyNotFound)
                ));
                let second = <$key>::generate_with()
                    .label(&label)
                    .access_group(&group_b)
                    .generate()?;
                let result: TestResult = (|| {
                    assert!(matches!(
                        <$key>::load(&label),
                        Err(SetupError::AmbiguousKey)
                    ));
                    let loaded_a = <$key>::load_with()
                        .label(&label)
                        .access_group(&group_a)
                        .load()?;
                    let loaded_b = <$key>::load_with()
                        .label(&label)
                        .access_group(&group_b)
                        .load()?;
                    assert_eq!(identity(&loaded_a), identity(&first));
                    assert_eq!(identity(&loaded_b), identity(&second));
                    assert_ne!(identity(&loaded_a), identity(&loaded_b));
                    Ok(())
                })();
                let cleanup = second.delete();
                result?;
                cleanup?;
                assert!(matches!(
                    <$key>::load_with()
                        .label(&label)
                        .access_group(&group_b)
                        .load(),
                    Err(SetupError::KeyNotFound)
                ));
                assert_eq!(identity(&<$key>::load(&label)?), identity(&first));
                Ok(())
            })();
            let cleanup = first.delete();
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
    use huskarl_apple::keychain::KeychainSecretStore;
    use huskarl_core::secrets::{Secret as _, SecretBytes};
    let group_a = std::env::var("HUSKARL_TEST_ACCESS_GROUP_A")?;
    let group_b = std::env::var("HUSKARL_TEST_ACCESS_GROUP_B")?;
    assert_ne!(group_a, group_b);
    let service = support::unique_label("huskarl-apple-secret-groups")?;
    let a = KeychainSecretStore::builder()
        .service(&service)
        .account("same-account")
        .access_group(group_a)
        .build();
    let b = KeychainSecretStore::builder()
        .service(&service)
        .account("same-account")
        .access_group(group_b)
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
