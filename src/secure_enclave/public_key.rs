use huskarl_core::jwk::{EcPublicKey, PublicJwk};
use p256::elliptic_curve::sec1::ToSec1Point as _;
use security_framework::key::SecKey;
use snafu::OptionExt as _;

use super::{PublicKeyExtractionSnafu, SetupError};

/// Export public coordinates without assigning a signing or encryption purpose.
pub(super) fn extract(public: &SecKey) -> Result<PublicJwk, SetupError> {
    let bytes = public
        .external_representation()
        .context(PublicKeyExtractionSnafu)?;
    let key = p256::PublicKey::from_sec1_bytes(&bytes)
        .ok()
        .context(PublicKeyExtractionSnafu)?;
    let point = key.to_sec1_point(false);
    Ok(PublicJwk::builder()
        .key(
            EcPublicKey::builder()
                .crv("P-256")
                .x(point.x().context(PublicKeyExtractionSnafu)?.to_vec())
                .y(point.y().context(PublicKeyExtractionSnafu)?.to_vec()),
        )
        .build())
}

#[cfg(test)]
mod tests {
    use huskarl_core::jwk::KeyUse;
    use security_framework::key::{GenerateKeyOptions, KeyType};

    use super::*;

    #[test]
    fn neutral_thumbprint_preserves_existing_key_ids() -> Result<(), Box<dyn std::error::Error>> {
        let mut options = GenerateKeyOptions::default();
        options.set_key_type(KeyType::ec()).set_size_in_bits(256);
        let key = SecKey::new(&options)?;
        let public = key.public_key().context(PublicKeyExtractionSnafu)?;
        let neutral = extract(&public)?;
        assert!(neutral.algorithm.is_none());
        assert!(neutral.key_use.is_none());
        let mut signing = neutral.clone();
        signing.algorithm = Some("ES256".into());
        signing.key_use = Some(KeyUse::Sign);
        assert_eq!(neutral.thumbprint(), signing.thumbprint());
        Ok(())
    }
}
