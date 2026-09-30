use bon::Builder;
use huskarl::{cache::RefreshTokenStore, token::RefreshToken};
use huskarl_core::{platform::MaybeSendBoxFuture, secrets::SecretBytes};
use snafu::prelude::*;
use zeroize::Zeroizing;

use super::KeychainSecretStore;

const FORMAT: &[u8] = b"huskarl-apple/refresh-token/v1\0";

struct SerializedSize(usize);

impl std::io::Write for SerializedSize {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.checked_add(bytes.len()).ok_or_else(|| {
            std::io::Error::other("serialized refresh token exceeds addressable size")
        })?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Errors encoding or decoding a persisted refresh token.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum RefreshTokenStoreError {
    /// The item is not in the supported versioned refresh-token format.
    UnsupportedFormat,
    /// Serialization failed.
    Encode {
        /// Serialization error, without the token value.
        source: serde_json::Error,
    },
    /// The stored payload is malformed. Contents are deliberately not reported.
    InvalidPayload,
}

impl From<RefreshTokenStoreError> for huskarl_core::Error {
    fn from(error: RefreshTokenStoreError) -> Self {
        Self::new(huskarl_core::RetryAdvice::No, error)
    }
}

/// Persistent refresh-token storage, including the token's `DPoP` key binding.
///
/// Reserve the backing item's service/account for this format. Missing items
/// return `None`; locked, denied, corrupt, and unsupported items return errors.
/// New items use the backing store's backend and protection policy. Replacing a token
/// preserves the stored policy, and clearing an absent token succeeds.
///
/// This store provides no cross-process refresh coordination. Follow huskarl's
/// single-owner guidance for rotation-only public clients; concurrent writes
/// are last-writer-wins. Keep a DPoP-bound token's enclave key across restarts.
#[derive(Debug, Clone, Builder)]
pub struct KeychainRefreshTokenStore {
    /// The exact Keychain item and creation policy to use.
    storage: KeychainSecretStore,
}

fn encode(token: &RefreshToken) -> Result<SecretBytes, RefreshTokenStoreError> {
    // Measure without retaining plaintext, including JSON escaping and metadata.
    let mut size = SerializedSize(FORMAT.len());
    serde_json::to_writer(&mut size, token).context(EncodeSnafu)?;
    // Allocate once before writing secrets. A fixed slice cannot reallocate,
    // and the fully sized Vec needs no shrink when converted to SecretBytes.
    let mut bytes = Zeroizing::new(vec![0; size.0]);
    bytes[..FORMAT.len()].copy_from_slice(FORMAT);
    serde_json::to_writer(&mut &mut bytes[FORMAT.len()..], token).context(EncodeSnafu)?;
    Ok(SecretBytes::new(std::mem::take(&mut *bytes)))
}

fn decode(bytes: &SecretBytes) -> Result<RefreshToken, RefreshTokenStoreError> {
    let json = bytes
        .expose_secret()
        .strip_prefix(FORMAT)
        .context(UnsupportedFormatSnafu)?;
    // Avoid retaining serde diagnostics that might quote corrupt secret data.
    serde_json::from_slice(json)
        .ok()
        .context(InvalidPayloadSnafu)
}

impl RefreshTokenStore for KeychainRefreshTokenStore {
    fn get(&self) -> MaybeSendBoxFuture<'_, Result<Option<RefreshToken>, huskarl_core::Error>> {
        Box::pin(async move {
            self.storage
                .get()
                .await?
                .as_ref()
                .map(decode)
                .transpose()
                .map_err(Into::into)
        })
    }

    fn set<'a>(
        &'a self,
        token: &'a RefreshToken,
    ) -> MaybeSendBoxFuture<'a, Result<(), huskarl_core::Error>> {
        Box::pin(async move { self.storage.set(&encode(token)?).await.map_err(Into::into) })
    }

    fn clear(&self) -> MaybeSendBoxFuture<'_, Result<(), huskarl_core::Error>> {
        Box::pin(async move { self.storage.clear().await.map_err(Into::into) })
    }
}

#[cfg(test)]
mod tests {
    use huskarl_core::secrets::SecretString;

    use super::*;

    #[test]
    fn serialization_preserves_token_and_binding() -> Result<(), RefreshTokenStoreError> {
        for binding in [None, Some("thumbprint".to_owned())] {
            let token = RefreshToken::new(SecretString::new("a.token/with+symbols=\"\n"), binding);
            let bytes = encode(&token)?;
            assert_eq!(decode(&bytes)?, token);
            assert!(!format!("{bytes:?}").contains("a.token"));
        }
        Ok(())
    }

    #[test]
    fn fixed_buffer_fits_large_escaped_tokens() -> Result<(), RefreshTokenStoreError> {
        for binding in [None, Some("binding\"\\\n\0é".repeat(1024))] {
            let token =
                RefreshToken::new(SecretString::new("token\"\\\n\0é".repeat(8192)), binding);
            let bytes = encode(&token)?;
            assert_eq!(decode(&bytes)?, token);
            // Exact bytes also catch surplus zero padding from an overestimate.
            let expected = serde_json::to_vec(&token).context(EncodeSnafu)?;
            assert_eq!(&bytes.expose_secret()[FORMAT.len()..], expected);
        }
        Ok(())
    }

    #[test]
    fn corruption_and_unknown_versions_are_errors() {
        for bytes in [
            b"".as_slice(),
            b"huskarl-apple/refresh-token/v2\0{}",
            b"plain-token",
        ] {
            assert!(matches!(
                decode(&SecretBytes::new(bytes.to_vec())),
                Err(RefreshTokenStoreError::UnsupportedFormat)
            ));
        }
        for json in [
            b"{".as_slice(),
            b"{}",
            b"null",
            b"{\"token\":\"sensitive\",\"dpop_jkt\":{}}",
        ] {
            let mut bytes = FORMAT.to_vec();
            bytes.extend_from_slice(json);
            let result = decode(&SecretBytes::new(bytes));
            assert!(matches!(
                result,
                Err(RefreshTokenStoreError::InvalidPayload)
            ));
            assert!(!format!("{result:?}").contains("sensitive"));
        }
    }
}
