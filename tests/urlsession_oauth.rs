//! Opt-in OAuth interoperability test. Run with `mise run test:oauth`.
#![cfg(feature = "urlsession")]
#![allow(clippy::unwrap_used, clippy::panic)]

#[path = "../support/unique_label.rs"]
mod support;

use std::{fs, path::PathBuf};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use http::{Request, StatusCode};
use huskarl::grant::{
    client_credentials::{ClientCredentialsGrant, ClientCredentialsGrantParameters},
    core::OAuth2ExchangeGrant as _,
};
use huskarl_apple::{Es256PrivateKey, urlsession::UrlSessionClient};
use huskarl_core::{
    client_auth::NoAuth,
    crypto::signer::AsymmetricJwsSigner as _,
    http::{HttpClient as _, Idempotency},
    jwk::PublicKey,
    server_metadata::AuthorizationServerMetadata,
};
use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, Issuer, KeyPair, PublicKeyData};
use sha2::{Digest as _, Sha256};
use time::{Duration, OffsetDateTime};

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct EnclavePublicKey(Vec<u8>);

impl PublicKeyData for EnclavePublicKey {
    fn der_bytes(&self) -> &[u8] {
        &self.0
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

fn issue(key: &Es256PrivateKey, issuer: &Issuer<'_, KeyPair>) -> Vec<u8> {
    let jwk = key.public_key_jwk();
    let PublicKey::Ec(ec) = &jwk.key else {
        panic!("expected a P-256 enclave key");
    };
    let public = EnclavePublicKey([&[4][..], &ec.x, &ec.y].concat());
    let mut leaf = CertificateParams::new(Vec::<String>::new()).unwrap();
    leaf.distinguished_name
        .push(DnType::CommonName, "huskarl-apple-test");
    leaf.not_before = OffsetDateTime::now_utc() - Duration::hours(1);
    leaf.not_after = OffsetDateTime::now_utc() + Duration::days(1);
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    leaf.signed_by(&public, issuer).unwrap().der().to_vec()
}

#[tokio::test]
#[ignore = "requires local Keycloak, signing, and Secure Enclave; run mise run test:oauth"]
async fn keycloak_issues_certificate_bound_token_to_enclave_identity() -> TestResult {
    let directory = match std::env::var("HUSKARL_OAUTH_TEST_DIR") {
        Ok(directory) => PathBuf::from(directory),
        Err(_) => std::env::current_exe()?
            .parent()
            .ok_or("missing app bundle directory")?
            .join("oauth-fixture"),
    };
    let root = fs::read(directory.join("root.der"))?;
    let intermediate = fs::read(directory.join("issuer.der"))?;
    let metadata: AuthorizationServerMetadata =
        serde_json::from_slice(&fs::read(directory.join("metadata.json"))?)?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params
        .distinguished_name
        .push(DnType::CommonName, "Huskarl OAuth Test Issuer");
    let issuer = Issuer::new(
        params,
        KeyPair::from_pem(&fs::read_to_string(directory.join("issuer.key"))?)?,
    );
    let key = Es256PrivateKey::generate(&support::unique_label("huskarl-apple-test")?).await?;
    let result: TestResult = async {
        let certificate = issue(&key, &issuer);
        let identity = key.install_client_identity_with()
            .certificate_der(&certificate)
            .intermediates([intermediate.clone()])
            .install().await?;
        let result: TestResult = async {
            let anonymous = UrlSessionClient::builder().trust_anchors(vec![root.clone()]).build()?;
            let request = Request::post(metadata.token_endpoint.as_uri())
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Bytes::from_static(b"grant_type=client_credentials&client_id=huskarl-enclave"))?;
            let rejected = anonymous.execute(request, Idempotency::Unknown).await?;
            assert_eq!(rejected.status, StatusCode::UNAUTHORIZED);
            let error: serde_json::Value = serde_json::from_slice(&rejected.body)?;
            assert_eq!(error["error"], "invalid_client");

            let client = UrlSessionClient::builder()
                .client_identity(identity.clone())
                .trust_anchors(vec![root.clone()])
                .build()?;
            let grant = ClientCredentialsGrant::builder_from_metadata(&metadata)
                .client_id("huskarl-enclave")
                .client_auth(NoAuth)
                .http_client(client.clone())
                .build();
            let response = grant.exchange(ClientCredentialsGrantParameters::builder().build()).await?;
            let token = response.access_token().token().expose_secret();
            // Inspect the token returned over authenticated TLS without logging it.
            // This is an interoperability assertion, not resource-server JWT validation.
            let payload = token.split('.').nth(1).ok_or("expected a JWT access token")?;
            let claims: serde_json::Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload)?)?;
            assert_eq!(claims["cnf"]["x5t#S256"], URL_SAFE_NO_PAD.encode(Sha256::digest(&certificate)));
            let resource = fs::read_to_string(directory.join("resource-url.txt"))?;
            assert_resource(&client, &resource, token, StatusCode::OK).await?;
            assert_resource(&anonymous, &resource, token, StatusCode::UNAUTHORIZED).await?;
            assert_resource(&client, &resource, "invalid-token", StatusCode::UNAUTHORIZED).await?;
            reject_copied_token(&issuer, &intermediate, root, &resource, token).await?;
            println!("OAuth mTLS: matching certificate accepted; copied token with another/no certificate and invalid token rejected.");
            Ok(())
        }.await;
        let cleanup = identity.remove_certificates().await;
        result?;
        cleanup?;
        Ok(())
    }.await;
    let cleanup = key.delete_key_and_associated_items().await;
    result?;
    cleanup?;
    Ok(())
}

async fn assert_resource(
    client: &UrlSessionClient,
    resource: &str,
    token: &str,
    status: StatusCode,
) -> TestResult {
    let request = Request::get(resource)
        .header("authorization", format!("Bearer {token}"))
        .body(Bytes::new())?;
    let response = client.execute(request, Idempotency::Idempotent).await?;
    assert_eq!(response.status, status);
    if status == StatusCode::OK {
        assert_eq!(response.body, "certificate-bound resource\n");
    }
    Ok(())
}

async fn reject_copied_token(
    issuer: &Issuer<'_, KeyPair>,
    intermediate: &[u8],
    root: Vec<u8>,
    resource: &str,
    token: &str,
) -> TestResult {
    let other = Es256PrivateKey::generate(&support::unique_label("huskarl-apple-test")?).await?;
    let result: TestResult = async {
        // This certificate has the same subject and a valid chain. TLS must
        // succeed so the resource rejects the token specifically for its binding.
        let certificate = issue(&other, issuer);
        let identity = other
            .install_client_identity_with()
            .certificate_der(&certificate)
            .intermediates([intermediate.to_vec()])
            .install()
            .await?;
        let result: TestResult = async {
            let client = UrlSessionClient::builder()
                .client_identity(identity.clone())
                .trust_anchors(vec![root])
                .build()?;
            assert_resource(&client, resource, token, StatusCode::UNAUTHORIZED).await
        }
        .await;
        let cleanup = identity.remove_certificates().await;
        result?;
        cleanup?;
        Ok(())
    }
    .await;
    let cleanup = other.delete_key_and_associated_items().await;
    result?;
    cleanup?;
    Ok(())
}
