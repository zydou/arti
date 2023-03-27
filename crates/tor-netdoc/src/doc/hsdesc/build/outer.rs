//! Functionality for encoding the outer document of an onion service descriptor.
//!
//! NOTE: `HsDescOuter` is a private helper for building hidden service descriptors, and is
//! not meant to be used directly. Hidden services will use `HsDescBuilder` to build and encode
//! hidden service descriptors.

use crate::build::{NetdocBuilder, NetdocEncoder};
use crate::doc::hsdesc::outer::{HsOuterKwd, HS_DESC_SIGNATURE_PREFIX, HS_DESC_VERSION_CURRENT};

use tor_bytes::EncodeError;
use tor_cert::{CertType, CertifiedKey, Ed25519Cert};
use tor_error::into_bad_api_usage;
use tor_hscrypto::pk::HsBlindKeypair;
use tor_hscrypto::RevisionCounter;
use tor_llcrypto::pk::ed25519::{self, Ed25519PublicKey};
use tor_units::IntegerMinutes;

use base64ct::{Base64, Encoding};

use std::time::SystemTime;

/// The representation of the outer wrapper of an onion service descriptor.
///
/// The format of this document is described in section 2.4. of rend-spec-v3.
#[derive(Debug)]
pub(super) struct HsDescOuter<'a> {
    /// The blinded hidden service signing keys used to sign descriptor signing keys
    /// (KP_hs_blind_id, KS_hs_blind_id).
    pub(super) blinded_id: &'a HsBlindKeypair,
    /// The short-term descriptor signing key.
    pub(super) hs_desc_sign: &'a ed25519::Keypair,
    /// The expiration time of the descriptor signing key certificate.
    pub(super) hs_desc_sign_cert_expiry: SystemTime,
    /// The lifetime of this descriptor, in minutes.
    ///
    /// This doesn't actually list the starting time or the end time for the
    /// descriptor: presumably, because we didn't want to leak the onion
    /// service's view of the wallclock.
    pub(super) lifetime: IntegerMinutes<u16>,
    /// A revision counter to tell whether this descriptor is more or less recent
    /// than another one for the same blinded ID.
    pub(super) revision_counter: RevisionCounter,
    /// The (superencrypted) middle document of the onion service descriptor.
    ///
    /// The `superencrypted` field is created by encrypting a middle document built using
    /// [`crate::doc::hsdesc::build::middle::HsDescMiddle`] as described in sections
    /// 2.5.1.1. and 2.5.1.2. of rend-spec-v3.
    pub(super) superencrypted: Vec<u8>,
}

impl<'a> NetdocBuilder for HsDescOuter<'a> {
    fn build_sign(self) -> Result<String, EncodeError> {
        use HsOuterKwd::*;

        let HsDescOuter {
            blinded_id,
            hs_desc_sign,
            hs_desc_sign_cert_expiry,
            lifetime,
            revision_counter,
            superencrypted,
        } = self;

        let mut encoder = NetdocEncoder::new();
        let beginning = encoder.cursor();
        encoder.item(HS_DESCRIPTOR).arg(&HS_DESC_VERSION_CURRENT);
        encoder.item(DESCRIPTOR_LIFETIME).arg(&lifetime.to_string());

        // "The certificate cross-certifies the short-term descriptor signing key with the blinded
        // public key.  The certificate type must be [08], and the blinded public key must be
        // present as the signing-key extension."
        let desc_signing_key_cert = Ed25519Cert::constructor()
            .cert_type(CertType::HS_BLINDED_ID_V_SIGNING)
            .expiration(hs_desc_sign_cert_expiry)
            .signing_key(ed25519::Ed25519Identity::from(blinded_id.public_key()))
            .cert_key(CertifiedKey::Ed25519(hs_desc_sign.public.into()))
            .encode_and_sign(blinded_id)
            .map_err(into_bad_api_usage!(
                "failed to sign the descriptor signing key"
            ))?;

        encoder
            .item(DESCRIPTOR_SIGNING_KEY_CERT)
            .object("ED25519 CERT", desc_signing_key_cert);
        encoder.item(REVISION_COUNTER).arg(&*revision_counter);

        // TODO: According to section 2.4. of rend-spec-v3 this blob should _not_ end with a
        // newline character. We need to update the encoder to support this.
        encoder
            .item(SUPERENCRYPTED)
            .object("MESSAGE", superencrypted);
        let end = encoder.cursor();

        let mut text = HS_DESC_SIGNATURE_PREFIX.to_vec();
        text.extend_from_slice(encoder.slice(beginning, end)?.as_bytes());
        let signature = ed25519::ExpandedSecretKey::from(&hs_desc_sign.secret)
            .sign(&text, &hs_desc_sign.public);
        encoder
            .item(SIGNATURE)
            .arg(&Base64::encode_string(&signature.to_bytes()));

        encoder.finish().map_err(|e| e.into())
    }
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use std::time::UNIX_EPOCH;

    use super::*;
    use crate::doc::hsdesc::build::test::test_ed25519_keypair;
    use tor_hscrypto::pk::{HsBlindKeypair, HsIdSecretKey};
    use tor_hscrypto::time::TimePeriod;
    use tor_llcrypto::pk::keymanip::ExpandedSecretKey;
    use tor_units::IntegerMinutes;

    // Some dummy bytes, not actually encrypted.
    const TEST_SUPERENCRYPTED_VALUE: &[u8] = &[1, 2, 3, 4];

    #[test]
    fn outer_hsdesc() {
        let hs_id = test_ed25519_keypair();
        let hs_desc_sign = test_ed25519_keypair();
        let period = TimePeriod::new(
            humantime::parse_duration("24 hours").unwrap(),
            humantime::parse_rfc3339("2023-02-09T12:00:00Z").unwrap(),
            humantime::parse_duration("12 hours").unwrap(),
        )
        .unwrap();
        let (public, secret, _) = HsIdSecretKey::from(ExpandedSecretKey::from(&hs_id.secret))
            .compute_blinded_key(period)
            .unwrap();
        let blinded_id = HsBlindKeypair { public, secret };

        let hs_desc = HsDescOuter {
            blinded_id: &blinded_id,
            hs_desc_sign: &hs_desc_sign,
            hs_desc_sign_cert_expiry: UNIX_EPOCH,
            lifetime: IntegerMinutes::new(20),
            revision_counter: 9001.into(),
            superencrypted: TEST_SUPERENCRYPTED_VALUE.into(),
        }
        .build_sign()
        .unwrap();

        assert_eq!(
            hs_desc,
            r#"hs-descriptor 3
descriptor-lifetime 20
descriptor-signing-key-cert
-----BEGIN ED25519 CERT-----
AQgAAAAAAewZqL9VZkkLDGVQ4eYcCdB/2+XvKqaT6DfOOdIK1zY8AQAgBAA5Kj8d
eaTfk6qmBv21PruTnLxTYHXFQtkxOW0NP02fmIrKeS4bp6rX2iwdiUlvrpiL0f8/
nfSxLRFbU+fKTsIGc/+5sAxUC5LPFGw13BKg5kyPmpismNyQXqQmTrojJQ0=
-----END ED25519 CERT-----
revision-counter 9001
superencrypted
-----BEGIN MESSAGE-----
AQIDBA==
-----END MESSAGE-----
signature apVgqlvq1eUu50uVmfTmmT/Odlt2ra8Q9KDltOtD09j624GKWI4ran7XLkqg30jikqfe2rcYeTHOplA16XQTDQ==
"#
        );
    }
}
