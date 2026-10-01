//! Mutual TLS through URLSession, with the client key in the Secure Enclave.
//!
//! A local rustls server requires a client certificate issued by a test CA
//! and echoes back the certificate it verified. The Secure Enclave test is
//! opt-in because it needs a signed executable with Keychain entitlements.
#![cfg(feature = "urlsession")]
#![allow(clippy::unwrap_used, clippy::panic)]

#[path = "../support/unique_label.rs"]
mod support;

use std::{net::SocketAddr, sync::Arc};

use bytes::Bytes;
use http::{Request, StatusCode};
use huskarl_apple::{
    Es256PrivateKey,
    urlsession::{ClientIdentityError, UrlSessionClient},
};
use huskarl_core::{
    crypto::signer::AsymmetricJwsSigner as _,
    http::{HttpClient as _, Idempotency},
    jwk::PublicKey,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, PublicKeyData, SignatureAlgorithm,
};
use rustls::{
    RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    server::WebPkiClientVerifier,
};
use security_framework::{
    certificate::SecCertificate,
    item::{
        AddRef, ItemAddOptions, ItemAddValue, ItemClass, ItemSearchOptions, KeyClass, Limit,
        Location, Reference, SearchResult,
    },
};
use security_framework_sys::base::errSecItemNotFound;
use time::{Duration, OffsetDateTime};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpListener,
};
use tokio_rustls::TlsAcceptor;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A public key certified without access to its private key.
struct CertifiedPublicKey(Vec<u8>);

impl PublicKeyData for CertifiedPublicKey {
    fn der_bytes(&self) -> &[u8] {
        &self.0
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

fn enclave_public_key(key: &Es256PrivateKey) -> CertifiedPublicKey {
    let jwk = key.public_key_jwk();
    let PublicKey::Ec(ec) = &jwk.key else {
        panic!("enclave keys are P-256");
    };
    CertifiedPublicKey([&[0x04][..], &ec.x, &ec.y].concat())
}

// Apple rejects TLS server certificates valid for more than 825 days.
fn params(common_name: &str, names: Vec<String>) -> CertificateParams {
    let mut params = CertificateParams::new(names).unwrap();
    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::days(1);
    params.not_after = now + Duration::days(7);
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params
}

struct Pki {
    ca: CertifiedIssuer<'static, KeyPair>,
}

impl Pki {
    fn new() -> Self {
        let mut ca = params("huskarl-apple test CA", Vec::new());
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        Self {
            ca: CertifiedIssuer::self_signed(ca, KeyPair::generate().unwrap()).unwrap(),
        }
    }

    fn ca_der(&self) -> Vec<u8> {
        self.ca.der().to_vec()
    }

    fn intermediate(&self, name: &str) -> Self {
        let mut ca = params(name, Vec::new());
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        Self {
            ca: CertifiedIssuer::signed_by(ca, KeyPair::generate().unwrap(), &self.ca).unwrap(),
        }
    }

    fn client_certificate(&self, public_key: &impl PublicKeyData) -> Vec<u8> {
        let mut params = params("huskarl-apple test device", Vec::new());
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params
            .signed_by(public_key, &self.ca)
            .unwrap()
            .der()
            .to_vec()
    }

    /// Starts a server that requires a client certificate from this CA and
    /// answers every request with the DER of the certificate it verified.
    async fn serve(&self) -> SocketAddr {
        let key = KeyPair::generate().unwrap();
        let mut params = params("localhost", vec!["localhost".into()]);
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let certificate = params.signed_by(&key, &self.ca).unwrap();

        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(self.ca_der())).unwrap();
        let verifier = WebPkiClientVerifier::builder_with_provider(roots.into(), provider.clone())
            .build()
            .unwrap();
        let config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![certificate.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let mut stream = match acceptor.accept(stream).await {
                        Ok(stream) => stream,
                        Err(error) => {
                            // URLSession reports only a generic TLS failure.
                            eprintln!("test server: TLS handshake failed: {error}");
                            return;
                        }
                    };
                    let mut request = Vec::new();
                    let mut buffer = [0; 1024];
                    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                        match stream.read(&mut buffer).await {
                            Ok(0) | Err(_) => return,
                            Ok(read) => request.extend_from_slice(&buffer[..read]),
                        }
                    }
                    let chain = stream.get_ref().1.peer_certificates();
                    let peer = chain
                        .and_then(|chain| chain.first())
                        .map(|c| c.to_vec())
                        .unwrap_or_default();
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nX-Client-Chain-Length: {}\r\nConnection: close\r\n\r\n",
                        peer.len(),
                        chain.map_or(0, <[_]>::len),
                    );
                    let _ = stream.write_all(&[head.into_bytes(), peer].concat()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        address
    }
}

fn get(address: SocketAddr) -> Request<Bytes> {
    Request::get(format!("https://localhost:{}/", address.port()))
        .body(Bytes::new())
        .unwrap()
}

fn stored_certificates() -> Result<Vec<Vec<u8>>, security_framework::base::Error> {
    let mut query = ItemSearchOptions::new();
    #[cfg(target_os = "macos")]
    query.ignore_legacy_keychains();
    let results = query
        .class(ItemClass::certificate())
        .load_refs(true)
        .limit(Limit::All)
        .search();
    let results = match results {
        Err(error) if error.code() == errSecItemNotFound => return Ok(Vec::new()),
        result => result?,
    };
    Ok(results
        .into_iter()
        .filter_map(|item| match item {
            SearchResult::Ref(Reference::Certificate(certificate)) => Some(certificate.to_der()),
            _ => None,
        })
        .collect())
}

#[tokio::test]
#[ignore = "requires a signed test executable, Keychain entitlements, and Secure Enclave"]
async fn enclave_identity_sends_intermediates_without_storing_them() -> TestResult {
    let root = Pki::new();
    let parent = root.intermediate("test parent CA");
    let issuer = parent.intermediate("test issuing CA");
    // The server knows only the root, so the client must send both intermediates.
    let address = root.serve().await;
    let key = Es256PrivateKey::generate(&support::unique_label("huskarl-apple-test")?).await?;
    let result: TestResult = async {
        let certificate = issuer.client_certificate(&enclave_public_key(&key));
        let invalid = key
            .install_client_identity_with()
            .certificate_der(&certificate)
            .intermediates([issuer.ca_der(), b"invalid DER".to_vec()])
            .install()
            .await;
        assert!(matches!(
            invalid,
            Err(ClientIdentityError::InvalidIntermediate { index: 1, .. })
        ));
        let stored = stored_certificates()?;
        assert!(
            !stored.contains(&certificate),
            "leaf stored before validation"
        );
        assert!(!stored.contains(&issuer.ca_der()));

        let identity = key
            .install_client_identity_with()
            .certificate_der(&certificate)
            .intermediates([issuer.ca_der(), parent.ca_der()])
            .install()
            .await?;
        let result: TestResult = async {
            let stored = stored_certificates()?;
            assert!(stored.contains(&certificate));
            assert!(!stored.contains(&issuer.ca_der()));
            assert!(!stored.contains(&parent.ca_der()));

            // Omitted and incomplete chains must fail before the complete
            // chain is used, avoiding any dependence on cached intermediates.
            for intermediates in [vec![], vec![issuer.ca_der()]] {
                let incomplete = key
                    .install_client_identity_with()
                    .certificate_der(&certificate)
                    .intermediates(intermediates)
                    .install()
                    .await?;
                let client = UrlSessionClient::builder()
                    .client_identity(incomplete)
                    .trust_anchors(vec![root.ca_der()])
                    .build()?;
                let error = client
                    .execute(get(address), Idempotency::Idempotent)
                    .await
                    .unwrap_err();
                assert!(error.to_string().contains("URLSession transport failure"));
            }

            let client = UrlSessionClient::builder()
                .client_identity(identity.clone())
                .trust_anchors(vec![root.ca_der()])
                .build()?;
            let response = client
                .execute(get(address), Idempotency::Idempotent)
                .await?;
            assert_eq!(response.status, StatusCode::OK);
            assert_eq!(response.body, certificate);
            assert_eq!(response.headers["x-client-chain-length"], "3");
            Ok(())
        }
        .await;
        let cleanup = identity.remove_certificates().await;
        result?;
        cleanup?;
        Ok(())
    }
    .await;
    let cleanup = key.delete_key_and_associated_items().await;
    result?;
    cleanup?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires a signed test executable, Keychain entitlements, and Secure Enclave"]
async fn enclave_key_authenticates_over_mutual_tls() -> TestResult {
    let pki = Pki::new();
    let address = pki.serve().await;
    let label = support::unique_label("huskarl-apple-test")?;
    let key = Es256PrivateKey::generate(&label).await?;
    let result: TestResult = async {
        let certificate = pki.client_certificate(&enclave_public_key(&key));
        let identity = key.install_client_identity(&certificate).await?;
        let result: TestResult = async {
            // Failed installation must remove only the new certificate,
            // preserving the valid identity that was already installed.
            let other = KeyPair::generate()?;
            let mismatched = pki.client_certificate(&other);
            assert!(matches!(
                key.install_client_identity(&mismatched).await,
                Err(ClientIdentityError::CertificateKeyMismatch)
            ));
            let stored = stored_certificates()?;
            assert!(
                stored.contains(&certificate),
                "existing certificate was deleted"
            );
            assert!(
                !stored.contains(&mismatched),
                "failed installation was not rolled back"
            );

            let client = UrlSessionClient::builder()
                .client_identity(identity.clone())
                .trust_anchors(vec![pki.ca_der()])
                .build()?;
            assert!(client.uses_mtls());
            let response = client
                .execute(get(address), Idempotency::Idempotent)
                .await?;
            assert_eq!(response.status, StatusCode::OK);
            assert_eq!(
                response.body, certificate,
                "server verified a different client certificate"
            );
            Ok(())
        }
        .await;
        let cleanup = identity.remove_certificates().await;
        result?;
        cleanup?;
        Ok(())
    }
    .await;
    let cleanup = key.delete_key_and_associated_items().await;
    result?;
    cleanup?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires a signed test executable, Keychain entitlements, and Secure Enclave"]
async fn deleting_the_key_removes_its_certificates() -> TestResult {
    let pki = Pki::new();
    let key = Es256PrivateKey::generate(&support::unique_label("huskarl-apple-test")?).await?;
    let public_key = enclave_public_key(&key);
    // A renewal from a different issuer, so the Keychain cannot treat the two
    // certificates as duplicates.
    let original = pki.client_certificate(&public_key);
    let renewed = pki
        .intermediate("test renewal CA")
        .client_certificate(&public_key);
    let identity = match async {
        key.install_client_identity(&original).await?;
        key.install_client_identity(&renewed).await
    }
    .await
    {
        Ok(identity) => identity,
        Err(error) => {
            let _ = key.delete_key_and_associated_items().await;
            return Err(error.into());
        }
    };
    // Return errors rather than panicking so the cleanup below always runs.
    let result: TestResult = async {
        let stored = stored_certificates()?;
        if !(stored.contains(&original) && stored.contains(&renewed)) {
            return Err("certificates were not installed".into());
        }
        key.delete_key_and_associated_items().await?;
        let stored = stored_certificates()?;
        if stored.contains(&original) || stored.contains(&renewed) {
            return Err("certificates remain after key deletion".into());
        }
        Ok(())
    }
    .await;
    // Normally a no-op; cleans up if deletion failed or left certificates.
    if result.is_err() {
        let _ = key.delete_key_and_associated_items().await;
    }
    let cleanup = identity.remove_certificates().await;
    result?;
    cleanup?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires a signed test executable, Keychain entitlements, and Secure Enclave"]
async fn deletion_resumes_after_the_private_key_is_gone() -> TestResult {
    let label = support::unique_label("huskarl-apple-test")?;
    let key = Es256PrivateKey::generate(&label).await?;
    let certificate = Pki::new().client_certificate(&enclave_public_key(&key));
    let result: TestResult = async {
        let identity = key.install_client_identity(&certificate).await?;
        let mut query = ItemSearchOptions::new();
        #[cfg(target_os = "macos")]
        query.ignore_legacy_keychains();
        query
            .key_class(KeyClass::private())
            .label(&format!("huskarl-apple/sign/{label}"));
        // Simulate interruption after the first step of delete(), leaving the
        // public half and certificate behind for a later attempt to clean up.
        query.delete()?;
        if !stored_certificates()?.contains(&certificate) {
            return Err("certificate missing before cleanup retry".into());
        }
        // Also exercise the clone path that changes the JWT key ID.
        key.clone()
            .with_key_id("custom")
            .delete_key_and_associated_items()
            .await?;
        key.delete_key_and_associated_items().await?;
        if stored_certificates()?.contains(&certificate) {
            return Err("certificate remains after cleanup retry".into());
        }
        let mut public = ItemSearchOptions::new();
        #[cfg(target_os = "macos")]
        public.ignore_legacy_keychains();
        let remaining = public
            .key_class(KeyClass::public())
            .label(&format!("huskarl-apple/sign/{label}"))
            .search();
        if !matches!(remaining, Err(error) if error.code() == errSecItemNotFound) {
            return Err("public key remains after cleanup retry".into());
        }
        identity.remove_certificates().await?;
        Ok(())
    }
    .await;
    let cleanup = key.delete_key_and_associated_items().await;
    result?;
    cleanup?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires a signed test executable, Keychain entitlements, and Secure Enclave"]
async fn foreign_duplicate_certificates_are_rejected_and_preserved() -> TestResult {
    let key = Es256PrivateKey::generate(&support::unique_label("huskarl-apple-test")?).await?;
    let der = Pki::new().client_certificate(&enclave_public_key(&key));
    let certificate = SecCertificate::from_der(&der)?;
    let foreign_label = support::unique_label("huskarl-apple-foreign-certificate")?;
    let result: TestResult = async {
        let mut options =
            ItemAddOptions::new(ItemAddValue::Ref(AddRef::Certificate(certificate.clone())));
        options
            .set_location(Location::DataProtectionKeychain)
            .set_label(&foreign_label);
        options.add()?;
        if !matches!(
            key.install_client_identity(&der).await,
            Err(ClientIdentityError::CertificateOwnershipConflict)
        ) {
            return Err("foreign duplicate was adopted".into());
        }
        key.delete_key_and_associated_items().await?;
        let mut query = ItemSearchOptions::new();
        #[cfg(target_os = "macos")]
        query.ignore_legacy_keychains();
        let stored = query
            .class(ItemClass::certificate())
            .label(&foreign_label)
            .load_refs(true)
            .search()?;
        if !stored.iter().any(|item| matches!(item, SearchResult::Ref(Reference::Certificate(c)) if c.to_der() == der)) {
            return Err("foreign certificate was relabeled or deleted".into());
        }
        Ok(())
    }.await;
    // The test owns this foreign item; production cleanup must not remove it.
    let certificate_cleanup = certificate.delete();
    let key_cleanup = key.delete_key_and_associated_items().await;
    result?;
    certificate_cleanup?;
    key_cleanup?;
    Ok(())
}

#[tokio::test]
async fn server_requiring_a_certificate_rejects_anonymous_clients() -> TestResult {
    let pki = Pki::new();
    let address = pki.serve().await;
    let client = UrlSessionClient::builder()
        .trust_anchors(vec![pki.ca_der()])
        .build()?;
    assert!(!client.uses_mtls());
    let error = client
        .execute(get(address), Idempotency::Idempotent)
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("URLSession transport failure"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[tokio::test]
async fn servers_outside_the_trust_anchors_are_rejected() -> TestResult {
    let address = Pki::new().serve().await;
    let client = UrlSessionClient::builder()
        .trust_anchors(vec![Pki::new().ca_der()])
        .build()?;
    let error = client
        .execute(get(address), Idempotency::Idempotent)
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("server certificate rejected"),
        "unexpected error: {error}"
    );
    Ok(())
}
