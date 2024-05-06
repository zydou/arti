#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![doc = include_str!("../README.md")]
// @@ begin lint list maintained by maint/add_warning @@
#![allow(renamed_and_removed_lints)] // @@REMOVE_WHEN(ci_arti_stable)
#![allow(unknown_lints)] // @@REMOVE_WHEN(ci_arti_nightly)
#![warn(missing_docs)]
#![warn(noop_method_call)]
#![warn(unreachable_pub)]
#![warn(clippy::all)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::checked_conversions)]
#![warn(clippy::cognitive_complexity)]
#![deny(clippy::debug_assert_with_mut_call)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::expl_impl_clone_on_copy)]
#![deny(clippy::fallible_impl_from)]
#![deny(clippy::implicit_clone)]
#![deny(clippy::large_stack_arrays)]
#![warn(clippy::manual_ok_or)]
#![deny(clippy::missing_docs_in_private_items)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![deny(clippy::print_stderr)]
#![deny(clippy::print_stdout)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unchecked_duration_subtraction)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
#![allow(clippy::result_large_err)] // temporary workaround for arti#587
#![allow(clippy::needless_raw_string_hashes)] // complained-about code is fine, often best
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

mod err;
pub mod rsa;

use caret::caret_int;
use tor_bytes::{Error as BytesError, Result as BytesResult};
use tor_bytes::{Readable, Reader};
use tor_llcrypto::pk::ed25519::Verifier as _;
use tor_llcrypto::pk::*;

use std::time;

pub use err::CertError;

#[cfg(feature = "encode")]
mod encode;
#[cfg(feature = "encode")]
pub use encode::EncodedEd25519Cert;
#[cfg(feature = "encode")]
pub use err::CertEncodeError;

/// A Result defined to use CertError
type CertResult<T> = std::result::Result<T, CertError>;

caret_int! {
    /// Recognized values for Tor's certificate type field.
    ///
    /// In the names used here, "X_V_Y" means "key X verifying key Y",
    /// whereas "X_CC_Y" means "key X cross-certifying key Y".  In both
    /// cases, X is the key that is doing the signing, and Y is the key
    /// or object that is getting signed.
    ///
    /// Not every one of these types is valid for an Ed25519
    /// certificate.  Some are for X.509 certs in a CERTS cell; some
    /// are for RSA->Ed crosscerts in a CERTS cell.
    pub struct CertType(u8) {
        /// TLS link key, signed with RSA identity. X.509 format. (Obsolete)
        TLS_LINK_X509 = 0x01,
        /// Self-signed RSA identity certificate. X.509 format. (Legacy)
        RSA_ID_X509 = 0x02,
        /// RSA lnk authentication key signed with RSA identity
        /// key. X.509 format. (Obsolete)
        LINK_AUTH_X509 = 0x03,

        /// Identity verifying a signing key, directly.
        IDENTITY_V_SIGNING = 0x04,

        /// Signing key verifying a TLS certificate by digest.
        SIGNING_V_TLS_CERT = 0x05,

        /// Signing key verifying a link authentication key.
        SIGNING_V_LINK_AUTH = 0x06,

        /// RSA identity key certifying an Ed25519 identity key. RSA
        /// crosscert format. (Legacy)
        RSA_ID_V_IDENTITY = 0x07,

        /// For onion services: short-term descriptor signing key
        /// (`KP_hs_desc_sign`), signed with blinded onion service identity
        /// (`KP_hs_blind_id`).
        HS_BLINDED_ID_V_SIGNING = 0x08,

        /// For onion services: Introduction point authentication key
        /// (`KP_hs_ipt_sid`), signed with short term descriptor signing key
        /// (`KP_hs_desc_sign`).
        ///
        /// This one is, sadly, a bit complicated. In the original specification
        /// it was meant to be a cross-certificate, where the signature would be
        /// _on_ the descriptor signing key, _signed with_ the intro TID key.
        /// But we got it backwards in the C Tor implementation, and now, for
        /// compatibility, we are stuck doing it backwards in the future.
        ///
        /// If we find in the future that it is actually important to
        /// cross-certify these keys (as originally intended), then we should
        /// add a new certificate type, and put the new certificate in the onion
        /// service descriptor.
        HS_IP_V_SIGNING = 0x09,

        /// An ntor key converted to a ed25519 key, cross-certifying an
        /// identity key.
        NTOR_CC_IDENTITY = 0x0A,

        /// For onion services: Ntor encryption key (`KP_hss_ntor`),
        /// converted to ed25519, signed with the descriptor signing key
        /// (`KP_hs_desc_sign`).
        ///
        /// As with [`HS_IP_V_SIGNING`](CertType::HS_IP_V_SIGNING), this
        /// certificate type is backwards.  In the original specification it was
        /// meant to be a cross certificate, with the signing and signed keys
        /// reversed.
        HS_IP_CC_SIGNING = 0x0B,
    }
}

caret_int! {
    /// Extension identifiers for extensions in certificates.
    pub struct ExtType(u8) {
        /// Extension indicating an Ed25519 key that signed this certificate.
        ///
        /// Certificates do not always contain the key that signed them.
        SIGNED_WITH_ED25519_KEY = 0x04,
    }
}

caret_int! {
    /// Identifiers for the type of key or object getting signed.
    pub struct KeyType(u8) {
        /// Identifier for an Ed25519 key.
        ED25519_KEY = 0x01,
        /// Identifier for the SHA256 of an DER-encoded RSA key.
        SHA256_OF_RSA = 0x02,
        /// Identifies the SHA256 of an X.509 certificate.
        SHA256_OF_X509 = 0x03,
    }
}

/// Structure for an Ed25519-signed certificate as described in Tor's
/// cert-spec.txt.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "encode", derive(derive_builder::Builder))]
#[cfg_attr(
    feature = "encode",
    builder(name = "Ed25519CertConstructor", build_fn(skip))
)]
pub struct Ed25519Cert {
    /// How many _hours_ after the epoch will this certificate expire?
    #[cfg_attr(feature = "encode", builder(setter(custom)))]
    exp_hours: u32,
    /// Type of the certificate; recognized values are in certtype::*
    cert_type: CertType,
    /// The key or object being certified.
    cert_key: CertifiedKey,
    /// A list of extensions.
    #[allow(unused)]
    #[cfg_attr(feature = "encode", builder(setter(custom)))]
    extensions: Vec<CertExt>,
    /// The key that signed this cert.
    ///
    /// Once the cert has been unwrapped from an KeyUnknownCert, this field will
    /// be set.  If there is a `SignedWithEd25519` extension in
    /// `self.extensions`, this will match it.
    #[cfg_attr(feature = "encode", builder(setter(custom)))]
    signed_with: Option<ed25519::Ed25519Identity>,
}

/// One of the data types that can be certified by an Ed25519Cert.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum CertifiedKey {
    /// An Ed25519 public key, signed directly.
    Ed25519(ed25519::Ed25519Identity),
    /// The SHA256 digest of a DER-encoded RsaPublicKey
    RsaSha256Digest([u8; 32]),
    /// The SHA256 digest of an X.509 certificate.
    X509Sha256Digest([u8; 32]),
    /// Some unrecognized key type.
    Unrecognized(UnrecognizedKey),
}

/// A key whose type we didn't recognize.
#[derive(Debug, Clone)]
pub struct UnrecognizedKey {
    /// Actual type of the key.
    key_type: KeyType,
    /// digest of the key, or the key itself.
    key_digest: [u8; 32],
}

impl CertifiedKey {
    /// Return the byte that identifies the type of this key.
    pub fn key_type(&self) -> KeyType {
        match self {
            CertifiedKey::Ed25519(_) => KeyType::ED25519_KEY,
            CertifiedKey::RsaSha256Digest(_) => KeyType::SHA256_OF_RSA,
            CertifiedKey::X509Sha256Digest(_) => KeyType::SHA256_OF_X509,

            CertifiedKey::Unrecognized(u) => u.key_type,
        }
    }
    /// Return the bytes that are used for the body of this certified
    /// key or object.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            CertifiedKey::Ed25519(k) => k.as_bytes(),
            CertifiedKey::RsaSha256Digest(k) => &k[..],
            CertifiedKey::X509Sha256Digest(k) => &k[..],
            CertifiedKey::Unrecognized(u) => &u.key_digest[..],
        }
    }
    /// If this is an Ed25519 public key, return Some(key).
    /// Otherwise, return None.
    pub fn as_ed25519(&self) -> Option<&ed25519::Ed25519Identity> {
        match self {
            CertifiedKey::Ed25519(k) => Some(k),
            _ => None,
        }
    }
    /// Try to extract a CertifiedKey from a Reader, given that we have
    /// already read its type as `key_type`.
    fn from_reader(key_type: KeyType, r: &mut Reader<'_>) -> BytesResult<Self> {
        Ok(match key_type {
            KeyType::ED25519_KEY => CertifiedKey::Ed25519(r.extract()?),
            KeyType::SHA256_OF_RSA => CertifiedKey::RsaSha256Digest(r.extract()?),
            KeyType::SHA256_OF_X509 => CertifiedKey::X509Sha256Digest(r.extract()?),
            _ => CertifiedKey::Unrecognized(UnrecognizedKey {
                key_type,
                key_digest: r.extract()?,
            }),
        })
    }
}

/// An extension in a Tor certificate.
#[derive(Debug, Clone)]
enum CertExt {
    /// Indicates which Ed25519 public key signed this cert.
    SignedWithEd25519(SignedWithEd25519Ext),
    /// An extension whose identity we don't recognize.
    Unrecognized(UnrecognizedExt),
}

/// Any unrecognized extension on a Tor certificate.
#[derive(Debug, Clone)]
#[allow(unused)]
struct UnrecognizedExt {
    /// True iff this extension must be understand in order to validate the
    /// certificate.
    affects_validation: bool,
    /// The type of the extension
    ext_type: ExtType,
    /// The body of the extension.
    body: Vec<u8>,
}

impl CertExt {
    /// Return the identifier code for this Extension.
    fn ext_id(&self) -> ExtType {
        match self {
            CertExt::SignedWithEd25519(_) => ExtType::SIGNED_WITH_ED25519_KEY,
            CertExt::Unrecognized(u) => u.ext_type,
        }
    }
}

/// Extension indicating that a key that signed a given certificate.
#[derive(Debug, Clone)]
struct SignedWithEd25519Ext {
    /// The key that signed the certificate including this extension.
    pk: ed25519::Ed25519Identity,
}

impl Readable for CertExt {
    fn take_from(b: &mut Reader<'_>) -> BytesResult<Self> {
        let len = b.take_u16()?;
        let ext_type: ExtType = b.take_u8()?.into();
        let flags = b.take_u8()?;
        let body = b.take(len as usize)?;

        Ok(match ext_type {
            ExtType::SIGNED_WITH_ED25519_KEY => CertExt::SignedWithEd25519(SignedWithEd25519Ext {
                pk: ed25519::Ed25519Identity::from_bytes(body).ok_or_else(|| {
                    BytesError::InvalidMessage("wrong length on Ed25519 key".into())
                })?,
            }),
            _ => {
                if (flags & 1) != 0 {
                    return Err(BytesError::InvalidMessage(
                        "unrecognized certificate extension, with 'affects_validation' flag set."
                            .into(),
                    ));
                }
                CertExt::Unrecognized(UnrecognizedExt {
                    affects_validation: false,
                    ext_type,
                    body: body.into(),
                })
            }
        })
    }
}

impl Ed25519Cert {
    /// Try to decode a certificate from a byte slice.
    ///
    /// This function returns an error if the byte slice is not
    /// completely exhausted.
    ///
    /// Note that the resulting KeyUnknownCertificate is not checked
    /// for validity at all: you will need to provide it with an expected
    /// signing key, then check it for timeliness and well-signedness.
    pub fn decode(cert: &[u8]) -> BytesResult<KeyUnknownCert> {
        let mut r = Reader::from_slice(cert);
        let v = r.take_u8()?;
        if v != 1 {
            // This would be something other than a "v1" certificate. We don't
            // understand those.
            return Err(BytesError::InvalidMessage(
                "Unrecognized certificate version".into(),
            ));
        }
        let cert_type = r.take_u8()?.into();
        let exp_hours = r.take_u32()?;
        let mut cert_key_type = r.take_u8()?.into();

        // This is a workaround for a tor bug: the key type is
        // wrong. It was fixed in tor#40124, which got merged into Tor
        // 0.4.5.x and later.
        if cert_type == CertType::SIGNING_V_TLS_CERT && cert_key_type == KeyType::ED25519_KEY {
            cert_key_type = KeyType::SHA256_OF_X509;
        }

        let cert_key = CertifiedKey::from_reader(cert_key_type, &mut r)?;
        let n_exts = r.take_u8()?;
        let mut extensions = Vec::new();
        for _ in 0..n_exts {
            let e: CertExt = r.extract()?;
            extensions.push(e);
        }

        let sig_offset = r.consumed();
        let signature: ed25519::Signature = r.extract()?;
        r.should_be_exhausted()?;

        let keyext = extensions
            .iter()
            .find(|e| e.ext_id() == ExtType::SIGNED_WITH_ED25519_KEY);

        let included_pkey = match keyext {
            Some(CertExt::SignedWithEd25519(s)) => Some(s.pk),
            _ => None,
        };

        Ok(KeyUnknownCert {
            cert: UncheckedCert {
                cert: Ed25519Cert {
                    exp_hours,
                    cert_type,
                    cert_key,
                    extensions,

                    signed_with: included_pkey,
                },
                text: cert[0..sig_offset].into(),
                signature,
            },
        })
    }

    /// Return the time at which this certificate becomes expired
    pub fn expiry(&self) -> std::time::SystemTime {
        let d = std::time::Duration::new(u64::from(self.exp_hours) * 3600, 0);
        std::time::SystemTime::UNIX_EPOCH + d
    }

    /// Return true iff this certificate will be expired at the time `when`.
    pub fn is_expired_at(&self, when: std::time::SystemTime) -> bool {
        when >= self.expiry()
    }

    /// Return the signed key or object that is authenticated by this
    /// certificate.
    pub fn subject_key(&self) -> &CertifiedKey {
        &self.cert_key
    }

    /// Return the ed25519 key that signed this certificate.
    pub fn signing_key(&self) -> Option<&ed25519::Ed25519Identity> {
        self.signed_with.as_ref()
    }

    /// Return the type of this certificate.
    pub fn cert_type(&self) -> CertType {
        self.cert_type
    }
}

/// A parsed Ed25519 certificate. Maybe it includes its signing key;
/// maybe it doesn't.
///
/// To validate this cert, either it must contain its signing key,
/// or the caller must know the signing key.  In the first case, call
/// [`should_have_signing_key`](KeyUnknownCert::should_have_signing_key);
/// in the latter, call
/// [`should_be_signed_with`](KeyUnknownCert::should_be_signed_with).
#[derive(Clone, Debug)]
pub struct KeyUnknownCert {
    /// The certificate whose signing key might not be known.
    cert: UncheckedCert,
}

impl KeyUnknownCert {
    /// Return the certificate type of the underling cert.
    pub fn peek_cert_type(&self) -> CertType {
        self.cert.cert.cert_type
    }
    /// Return subject key of the underlying cert.
    pub fn peek_subject_key(&self) -> &CertifiedKey {
        &self.cert.cert.cert_key
    }

    /// Check whether a given pkey is (or might be) a key that has correctly
    /// signed this certificate.
    ///
    /// If pkey is None, this certificate must contain its signing key.
    ///
    /// On success, we can check whether the certificate is well-signed;
    /// otherwise, we can't check the certificate.
    #[deprecated(
        since = "0.7.1",
        note = "Use should_have_signing_key or should_be_signed_with instead."
    )]
    pub fn check_key(self, pkey: Option<&ed25519::Ed25519Identity>) -> CertResult<UncheckedCert> {
        match pkey {
            Some(wanted) => self.should_be_signed_with(wanted),
            None => self.should_have_signing_key(),
        }
    }

    /// Declare that this should be a self-contained certificate that contains its own
    /// signing key.
    ///
    /// On success, this certificate did indeed turn out to be self-contained, and so
    /// we can validate it.
    /// On failure, this certificate was not self-contained.
    pub fn should_have_signing_key(self) -> CertResult<UncheckedCert> {
        let real_key = match &self.cert.cert.signed_with {
            Some(a) => *a,
            None => return Err(CertError::MissingPubKey),
        };

        Ok(UncheckedCert {
            cert: Ed25519Cert {
                signed_with: Some(real_key),
                ..self.cert.cert
            },
            ..self.cert
        })
    }

    /// Declare that this should be a certificate signed with a given key.
    ///
    /// On success, this certificate either listed the provided key, or did not
    /// list any key: in either case, we can validate it.
    /// On failure, this certificate claims to be signed with a different key.
    pub fn should_be_signed_with(
        self,
        pkey: &ed25519::Ed25519Identity,
    ) -> CertResult<UncheckedCert> {
        let real_key = match &self.cert.cert.signed_with {
            Some(a) if a == pkey => *pkey,
            None => *pkey,
            Some(_) => return Err(CertError::KeyMismatch),
        };

        Ok(UncheckedCert {
            cert: Ed25519Cert {
                signed_with: Some(real_key),
                ..self.cert.cert
            },
            ..self.cert
        })
    }
}

/// A certificate that has been parsed, but whose signature and
/// timeliness have not been checked.
#[derive(Debug, Clone)]
pub struct UncheckedCert {
    /// The parsed certificate, possibly modified by inserting an externally
    /// supplied key as its signing key.
    cert: Ed25519Cert,

    /// The signed text of the certificate. (Checking ed25519 signatures
    /// forces us to store this.
    // TODO(nickm)  It would be better to store a hash here, but we
    // don't have the right Ed25519 API.
    text: Vec<u8>,

    /// The alleged signature
    signature: ed25519::Signature,
}

/// A certificate that has been parsed and signature-checked, but whose
/// timeliness has not been checked.
pub struct SigCheckedCert {
    /// The certificate that might or might not be timely
    cert: Ed25519Cert,
}

impl UncheckedCert {
    /// Split this unchecked cert into a component that assumes it has
    /// been checked, and a signature to validate.
    pub fn dangerously_split(
        self,
    ) -> CertResult<(SigCheckedCert, ed25519::ValidatableEd25519Signature)> {
        use tor_checkable::SelfSigned;
        let signing_key = self.cert.signed_with.ok_or(CertError::MissingPubKey)?;
        let signing_key = signing_key
            .try_into()
            .map_err(|_| CertError::BadSignature)?;
        let signature =
            ed25519::ValidatableEd25519Signature::new(signing_key, self.signature, &self.text[..]);
        Ok((self.dangerously_assume_wellsigned(), signature))
    }

    /// Return subject key of the underlying cert.
    pub fn peek_subject_key(&self) -> &CertifiedKey {
        &self.cert.cert_key
    }
    /// Return signing key of the underlying cert.
    pub fn peek_signing_key(&self) -> &ed25519::Ed25519Identity {
        self.cert
            .signed_with
            .as_ref()
            .expect("Made an UncheckedCert without a signing key")
    }
}

impl tor_checkable::SelfSigned<SigCheckedCert> for UncheckedCert {
    type Error = CertError;

    fn is_well_signed(&self) -> CertResult<()> {
        let pubkey = &self.cert.signed_with.ok_or(CertError::MissingPubKey)?;
        let pubkey: ed25519::PublicKey = pubkey.try_into().map_err(|_| CertError::BadSignature)?;

        pubkey
            .verify(&self.text[..], &self.signature)
            .map_err(|_| CertError::BadSignature)?;

        Ok(())
    }

    fn dangerously_assume_wellsigned(self) -> SigCheckedCert {
        SigCheckedCert { cert: self.cert }
    }
}

impl tor_checkable::Timebound<Ed25519Cert> for Ed25519Cert {
    type Error = tor_checkable::TimeValidityError;

    fn is_valid_at(&self, t: &time::SystemTime) -> Result<(), Self::Error> {
        if self.is_expired_at(*t) {
            let expiry = self.expiry();
            Err(Self::Error::Expired(
                t.duration_since(expiry)
                    .expect("certificate expiry time inconsistent"),
            ))
        } else {
            Ok(())
        }
    }

    fn dangerously_assume_timely(self) -> Ed25519Cert {
        self
    }
}

impl tor_checkable::Timebound<Ed25519Cert> for SigCheckedCert {
    type Error = tor_checkable::TimeValidityError;
    fn is_valid_at(&self, t: &time::SystemTime) -> std::result::Result<(), Self::Error> {
        self.cert.is_valid_at(t)
    }

    fn dangerously_assume_timely(self) -> Ed25519Cert {
        self.cert.dangerously_assume_timely()
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
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    use hex_literal::hex;

    #[test]
    fn parse_unrecognized_ext() -> BytesResult<()> {
        // case one: a flag is set but we don't know it
        let b = hex!("0009 99 10 657874656e73696f6e");
        let mut r = Reader::from_slice(&b);
        let e: CertExt = r.extract()?;
        r.should_be_exhausted()?;

        assert_eq!(e.ext_id(), 0x99.into());

        // case two: we've been told to ignore the cert if we can't
        // handle the extension.
        let b = hex!("0009 99 11 657874656e73696f6e");
        let mut r = Reader::from_slice(&b);
        let e: Result<CertExt, BytesError> = r.extract();
        assert!(e.is_err());
        assert_eq!(
            e.err().unwrap(),
            BytesError::InvalidMessage(
                "unrecognized certificate extension, with 'affects_validation' flag set.".into()
            )
        );

        Ok(())
    }

    #[test]
    fn certified_key() -> BytesResult<()> {
        let b =
            hex!("4c27616d6f757220756e6974206365757820717527656e636861c3ae6e616974206c6520666572");
        let mut r = Reader::from_slice(&b);

        let ck = CertifiedKey::from_reader(KeyType::SHA256_OF_RSA, &mut r)?;
        assert_eq!(ck.as_bytes(), &b[..32]);
        assert_eq!(ck.key_type(), KeyType::SHA256_OF_RSA);
        assert_eq!(r.remaining(), 7);

        let mut r = Reader::from_slice(&b);
        let ck = CertifiedKey::from_reader(42.into(), &mut r)?;
        assert_eq!(ck.as_bytes(), &b[..32]);
        assert_eq!(ck.key_type(), 42.into());
        assert_eq!(r.remaining(), 7);

        Ok(())
    }
}
