//! RSA cross-cert generation

use std::time::SystemTime;

use derive_more::{AsRef, Deref, Into};
use tor_bytes::Writer as _;
use tor_llcrypto::pk::{ed25519, rsa};

use crate::CertEncodeError;

/// An RSA cross certificate certificate,
/// created using [`EncodedRsaCrosscert::encode_and_sign`].
///
/// It corresponds to the type of certificate parsed with
/// [`RsaCrosscert`](super::RsaCrosscert).
/// It is used to prove that an Ed25519 identity speaks
/// on behalf of an RSA identity.
///
/// The certificate is encoded in the format specified
/// in Tor's [certificate specification](https://spec.torproject.org/cert-spec.html#rsa-cross-cert)
///
/// This certificate has already been validated.
#[derive(Clone, Debug, PartialEq, Into, AsRef, Deref)]
pub struct EncodedRsaCrosscert(Vec<u8>);

impl EncodedRsaCrosscert {
    /// Create a new [`EncodedRsaCrosscert`] certifying `ed_identity` as
    /// speaking on behalf of `rsa_identity`.
    ///
    /// The certificate will expire no earlier than `expiration`,
    /// and no more than one hour later.
    /// (Expiration times in these certificates have a one-hour granularity.)
    pub fn encode_and_sign(
        rsa_identity: &rsa::KeyPair,
        ed_identity: &ed25519::Ed25519Identity,
        expiration: SystemTime,
    ) -> Result<Self, CertEncodeError> {
        let mut cert = Vec::new();
        cert.write(ed_identity)?;
        let hours_since_epoch: u32 = expiration
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| CertEncodeError::InvalidExpiration)?
            .as_secs()
            .div_ceil(super::SECS_PER_HOUR)
            .try_into()
            .map_err(|_| CertEncodeError::InvalidExpiration)?;
        cert.write_u32(hours_since_epoch);
        {
            let signature = rsa_identity
                .sign(&super::compute_digest(&cert))
                .map_err(|_| CertEncodeError::RsaSignatureFailed)?;
            let mut inner = cert.write_nested_u8len();
            inner.write_and_consume(signature)?;
            inner.finish()?;
        }

        Ok(EncodedRsaCrosscert(cert))
    }
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use std::time::Duration;

    use tor_basic_utils::test_rng::testing_rng;
    use tor_checkable::{ExternallySigned, Timebound};

    use crate::rsa::{RsaCrosscert, SECS_PER_HOUR};

    use super::*;

    #[test]
    fn generate() {
        let mut rng = testing_rng();
        let keypair = rsa::KeyPair::generate(&mut rng).unwrap();
        let ed_id =
            ed25519::Ed25519Identity::from_base64("dGhhdW1hdHVyZ3kgaXMgc3RvcmVkIGluIHRoZSBvcmI")
                .unwrap();

        let now = SystemTime::now();
        let expiry = now + Duration::from_secs(24 * SECS_PER_HOUR);

        let cert = EncodedRsaCrosscert::encode_and_sign(&keypair, &ed_id, expiry).unwrap();

        let parsed = RsaCrosscert::decode(cert.as_ref()).unwrap();
        let parsed = parsed
            .check_signature(&keypair.to_public_key())
            .unwrap()
            .check_valid_at(&now)
            .unwrap();

        assert!(parsed.subject_key_matches(&ed_id));
        assert_eq!(parsed.subject_key, ed_id);
        let parsed_expiry = parsed.expiry();
        assert!(parsed_expiry >= expiry);
        assert!(parsed_expiry < expiry + Duration::new(3600, 0));
    }
}
