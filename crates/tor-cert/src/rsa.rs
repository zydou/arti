//! RSA->Ed25519 cross-certificates
//!
//! These are used in the Tor link handshake to prove that a given ed25519
//! key speaks for a given (deprecated) RSA identity.

use tor_bytes::Reader;
use tor_checkable::{ExternallySigned, timed::TimerangeBound};
use tor_llcrypto as ll;

use digest::Digest;

/// A RSA->Ed25519 cross-certificate
///
/// This kind of certificate is used in the channel handshake to prove
/// that the Ed25519 identity key speaks on behalf of the RSA identity key.
///
/// (There is no converse type for certifying Ed25519 identity keys with
/// RSA identity keys, since the RSA identity keys are too weak to trust.)
#[must_use]
pub struct RsaCrosscert {
    /// The key that is being certified
    subject_key: ll::pk::ed25519::Ed25519Identity,
    /// The expiration time of this certificate, in hours since the
    /// unix epoch.
    exp_hours: u32,
    /// The digest of the signed part of the certificate (for checking)
    digest: [u8; 32],
    /// The (alleged) signature on the certificate.
    signature: Vec<u8>,
}

impl RsaCrosscert {
    /// Return the time at which this certificate becomes expired
    pub fn expiry(&self) -> std::time::SystemTime {
        let d = std::time::Duration::new(u64::from(self.exp_hours) * 3600, 0);
        std::time::SystemTime::UNIX_EPOCH + d
    }

    /// Return a reference to the digest.
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Return true if the subject key in this certificate matches `other`
    pub fn subject_key_matches(&self, other: &ll::pk::ed25519::Ed25519Identity) -> bool {
        other == &self.subject_key
    }

    /// Decode a slice of bytes into an RSA crosscert.
    pub fn decode(bytes: &[u8]) -> tor_bytes::Result<UncheckedRsaCrosscert> {
        let mut r = Reader::from_slice(bytes);
        let signed_portion = r.peek(36)?; // TODO(nickm): a bit ugly.
        let subject_key = r.extract()?;
        let exp_hours = r.take_u32()?;
        let siglen = r.take_u8()?;
        let signature = r.take(siglen as usize)?.into();

        let mut d = ll::d::Sha256::new();
        d.update(&b"Tor TLS RSA/Ed25519 cross-certificate"[..]);
        d.update(signed_portion);
        let digest = d.finalize().into();

        let cc = RsaCrosscert {
            subject_key,
            exp_hours,
            digest,
            signature,
        };

        Ok(UncheckedRsaCrosscert(cc))
    }
}

/// An RsaCrosscert whose signature has not been checked.
pub struct UncheckedRsaCrosscert(RsaCrosscert);

impl ExternallySigned<TimerangeBound<RsaCrosscert>> for UncheckedRsaCrosscert {
    type Key = ll::pk::rsa::PublicKey;
    type KeyHint = ();
    type Error = tor_bytes::Error;

    fn key_is_correct(&self, _k: &Self::Key) -> Result<(), Self::KeyHint> {
        // there is no way to check except for trying to verify the signature
        Ok(())
    }

    fn is_well_signed(&self, k: &Self::Key) -> Result<(), Self::Error> {
        k.verify(&self.0.digest[..], &self.0.signature[..])
            .map_err(|_| {
                tor_bytes::Error::InvalidMessage(
                    "Invalid signature on RSA->Ed identity crosscert".into(),
                )
            })?;
        Ok(())
    }

    fn dangerously_assume_wellsigned(self) -> TimerangeBound<RsaCrosscert> {
        let expiration = self.0.expiry();
        TimerangeBound::new(self.0, ..expiration)
    }
}
