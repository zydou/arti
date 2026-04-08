//! Parsing implementation for Tor authority certificates
//!
//! An "authority certificate" is a short signed document that binds a
//! directory authority's permanent "identity key" to its medium-term
//! "signing key".  Using separate keys here enables the authorities
//! to keep their identity keys securely offline, while using the
//! signing keys to sign votes and consensuses.

use crate::batching_split_before::IteratorExt as _;
use crate::parse::keyword::Keyword;
use crate::parse::parser::{Section, SectionRules};
use crate::parse::tokenize::{ItemResult, NetDocReader};
use crate::types::misc::{Fingerprint, Iso8601TimeSp, RsaPublicParse1Helper, RsaSha1Signature};
use crate::util::str::Extent;
use crate::{NetdocErrorKind as EK, NormalItemArgument, Result};

use tor_basic_utils::impl_debug_hex;
use tor_checkable::{signed, timed};
use tor_llcrypto::pk::rsa;
use tor_llcrypto::{d, pk, pk::rsa::RsaIdentity};

use std::sync::LazyLock;

use std::result::Result as StdResult;
use std::{net, time, time::Duration, time::SystemTime};

use derive_deftly::Deftly;
use digest::Digest;

#[cfg(feature = "build_docs")]
mod build;

#[cfg(feature = "build_docs")]
#[allow(deprecated)]
pub use build::AuthCertBuilder;

#[cfg(feature = "parse2")]
use crate::parse2::{
    self, ItemObjectParseable, NetdocUnverified as _, sig_hashes::Sha1WholeKeywordLine,
};

#[cfg(feature = "encode")]
use {
    crate::encode::{Bug, ItemObjectEncodable, NetdocEncodable, NetdocEncoder},
    tor_error::into_internal,
};

// TODO DIRAUTH untangle these feature(s)
#[cfg(all(feature = "parse2", feature = "plain-consensus"))]
mod encoded;
#[cfg(all(feature = "parse2", feature = "plain-consensus"))]
pub use encoded::EncodedAuthCert;

decl_keyword! {
    pub(crate) AuthCertKwd {
        "dir-key-certificate-version" => DIR_KEY_CERTIFICATE_VERSION,
        "dir-address" => DIR_ADDRESS,
        "fingerprint" => FINGERPRINT,
        "dir-identity-key" => DIR_IDENTITY_KEY,
        "dir-key-published" => DIR_KEY_PUBLISHED,
        "dir-key-expires" => DIR_KEY_EXPIRES,
        "dir-signing-key" => DIR_SIGNING_KEY,
        "dir-key-crosscert" => DIR_KEY_CROSSCERT,
        "dir-key-certification" => DIR_KEY_CERTIFICATION,
    }
}

/// Rules about entries that must appear in an AuthCert, and how they must
/// be formed.
static AUTHCERT_RULES: LazyLock<SectionRules<AuthCertKwd>> = LazyLock::new(|| {
    use AuthCertKwd::*;

    let mut rules = SectionRules::builder();
    rules.add(DIR_KEY_CERTIFICATE_VERSION.rule().required().args(1..));
    rules.add(DIR_ADDRESS.rule().args(1..));
    rules.add(FINGERPRINT.rule().required().args(1..));
    rules.add(DIR_IDENTITY_KEY.rule().required().no_args().obj_required());
    rules.add(DIR_SIGNING_KEY.rule().required().no_args().obj_required());
    rules.add(DIR_KEY_PUBLISHED.rule().required());
    rules.add(DIR_KEY_EXPIRES.rule().required());
    rules.add(DIR_KEY_CROSSCERT.rule().required().no_args().obj_required());
    rules.add(UNRECOGNIZED.rule().may_repeat().obj_optional());
    rules.add(
        DIR_KEY_CERTIFICATION
            .rule()
            .required()
            .no_args()
            .obj_required(),
    );
    rules.build()
});

/// A single directory authority key certificate
///
/// This is the body, not including signatures.
///
/// <https://spec.torproject.org/dir-spec/creating-key-certificates.html>
///
/// To make a fresh `AuthCert`, use [`AuthCertConstructor`].
#[derive(Clone, Debug, Deftly)]
#[derive_deftly(Constructor)]
#[cfg_attr(feature = "parse2", derive_deftly(NetdocParseableUnverified))]
#[cfg_attr(feature = "encode", derive_deftly(NetdocEncodable))]
// derive_deftly_adhoc disables unused deftly attribute checking, so we needn't cfg_attr them all
#[cfg_attr(not(any(feature = "parse2", feature = "encode")), derive_deftly_adhoc)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[allow(clippy::exhaustive_structs)]
pub struct AuthCert {
    /// Intro line
    ///
    /// Currently must be version 3.
    ///
    /// <https://spec.torproject.org/dir-spec/creating-key-certificates.html#item:dir-key-certificate-version>
    #[deftly(constructor(default = "AuthCertVersion::V3"))]
    #[deftly(netdoc(single_arg))]
    pub dir_key_certificate_version: AuthCertVersion,

    /// An IPv4 address for this authority.
    #[deftly(netdoc(single_arg))]
    pub dir_address: Option<net::SocketAddrV4>,

    /// H(KP_auth_id_rsa)
    ///
    /// <https://spec.torproject.org/dir-spec/creating-key-certificates.html#item:fingerprint>
    #[deftly(constructor)]
    #[deftly(netdoc(single_arg))]
    pub fingerprint: Fingerprint,

    /// Declared time when this certificate was published
    ///
    /// <https://spec.torproject.org/dir-spec/creating-key-certificates.html#item:dir-key-published>
    #[deftly(constructor)]
    #[deftly(netdoc(single_arg))]
    pub dir_key_published: Iso8601TimeSp,

    /// Declared time when this certificate expires.
    ///
    /// <https://spec.torproject.org/dir-spec/creating-key-certificates.html#item:dir-key-expires>
    #[deftly(constructor)]
    #[deftly(netdoc(single_arg))]
    pub dir_key_expires: Iso8601TimeSp,

    /// KP_auth_id_rsa
    ///
    /// The long-term RSA identity key for this authority
    ///
    /// <https://spec.torproject.org/dir-spec/creating-key-certificates.html#item:dir-identity-key>
    #[deftly(constructor)]
    pub dir_identity_key: rsa::PublicKey,

    /// KP_auth_sign_rsa
    ///
    /// The medium-term RSA signing key for this authority
    ///
    /// <https://spec.torproject.org/dir-spec/creating-key-certificates.html#item:dir-signing-key>
    #[deftly(constructor)]
    pub dir_signing_key: rsa::PublicKey,

    /// SHA1(DER(KP_auth_id_rsa)) signed by KP_auth_sign_rsa
    ///
    /// <https://spec.torproject.org/dir-spec/creating-key-certificates.html#item:dir-key-crosscert>
    #[deftly(constructor)]
    pub dir_key_crosscert: CrossCert,

    #[doc(hidden)]
    #[deftly(netdoc(skip))]
    pub __non_exhaustive: (),
}

/// Represents the version of an [`AuthCert`].
///
/// Single argument.
///
/// <https://spec.torproject.org/dir-spec/creating-key-certificates.html#item:dir-key-certificate-version>
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, strum::EnumString, strum::Display)]
#[non_exhaustive]
pub enum AuthCertVersion {
    /// The current and only version understood.
    #[strum(serialize = "3")]
    V3,
}

impl NormalItemArgument for AuthCertVersion {}

/// A pair of key identities that identifies a certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[allow(clippy::exhaustive_structs)]
pub struct AuthCertKeyIds {
    /// Fingerprint of identity key
    pub id_fingerprint: rsa::RsaIdentity,
    /// Fingerprint of signing key
    pub sk_fingerprint: rsa::RsaIdentity,
}

/// An authority certificate whose signature and validity time we
/// haven't checked.
pub struct UncheckedAuthCert {
    /// Where we found this AuthCert within the string containing it.
    location: Option<Extent>,

    /// The actual unchecked certificate.
    c: signed::SignatureGated<timed::TimerangeBound<AuthCert>>,
}

impl UncheckedAuthCert {
    /// If this AuthCert was originally parsed from `haystack`, return its
    /// text.
    ///
    /// TODO: This is a pretty bogus interface; there should be a
    /// better way to remember where to look for this thing if we want
    /// it without keeping the input alive forever.  We should
    /// refactor.
    pub fn within<'a>(&self, haystack: &'a str) -> Option<&'a str> {
        self.location
            .as_ref()
            .and_then(|ext| ext.reconstruct(haystack))
    }
}

impl AuthCert {
    /// Make an [`AuthCertBuilder`] object that can be used to
    /// construct authority certificates for testing.
    #[cfg(feature = "build_docs")]
    #[deprecated = "use AuthCertConstructor instead"]
    #[allow(deprecated)]
    pub fn builder() -> AuthCertBuilder {
        AuthCertBuilder::new()
    }

    /// Parse an authority certificate from a string.
    ///
    /// This function verifies the certificate's signatures, but doesn't
    /// check its expiration dates.
    pub fn parse(s: &str) -> Result<UncheckedAuthCert> {
        let mut reader = NetDocReader::new(s)?;
        let body = AUTHCERT_RULES.parse(&mut reader)?;
        reader.should_be_exhausted()?;
        AuthCert::from_body(&body, s).map_err(|e| e.within(s))
    }

    /// Return an iterator yielding authority certificates from a string.
    pub fn parse_multiple(s: &str) -> Result<impl Iterator<Item = Result<UncheckedAuthCert>> + '_> {
        use AuthCertKwd::*;
        let sections = NetDocReader::new(s)?
            .batching_split_before_loose(|item| item.is_ok_with_kwd(DIR_KEY_CERTIFICATE_VERSION));
        Ok(sections
            .map(|mut section| {
                let body = AUTHCERT_RULES.parse(&mut section)?;
                AuthCert::from_body(&body, s)
            })
            .map(|r| r.map_err(|e| e.within(s))))
    }
    /*
        /// Return true if this certificate is expired at a given time, or
        /// not yet valid at that time.
        pub fn is_expired_at(&self, when: time::SystemTime) -> bool {
            when < self.published || when > self.expires
        }
    */
    /// Return the signing key certified by this certificate.
    pub fn signing_key(&self) -> &rsa::PublicKey {
        &self.dir_signing_key
    }

    /// Return an AuthCertKeyIds object describing the keys in this
    /// certificate.
    pub fn key_ids(&self) -> AuthCertKeyIds {
        AuthCertKeyIds {
            id_fingerprint: self.fingerprint.0,
            sk_fingerprint: self.dir_signing_key.to_rsa_identity(),
        }
    }

    /// Return an RsaIdentity for this certificate's identity key.
    pub fn id_fingerprint(&self) -> &rsa::RsaIdentity {
        &self.fingerprint
    }

    /// Return the time when this certificate says it was published.
    pub fn published(&self) -> time::SystemTime {
        *self.dir_key_published
    }

    /// Return the time when this certificate says it should expire.
    pub fn expires(&self) -> time::SystemTime {
        *self.dir_key_expires
    }

    /// Parse an authority certificate from a reader.
    fn from_body(body: &Section<'_, AuthCertKwd>, s: &str) -> Result<UncheckedAuthCert> {
        use AuthCertKwd::*;

        // Make sure first and last element are correct types.  We can
        // safely call unwrap() on first and last, since there are required
        // tokens in the rules, so we know that at least one token will have
        // been parsed.
        let start_pos = {
            // Unwrap should be safe because `.parse()` would have already
            // returned an Error
            #[allow(clippy::unwrap_used)]
            let first_item = body.first_item().unwrap();
            if first_item.kwd() != DIR_KEY_CERTIFICATE_VERSION {
                return Err(EK::WrongStartingToken
                    .with_msg(first_item.kwd_str().to_string())
                    .at_pos(first_item.pos()));
            }
            first_item.pos()
        };
        let end_pos = {
            // Unwrap should be safe because `.parse()` would have already
            // returned an Error
            #[allow(clippy::unwrap_used)]
            let last_item = body.last_item().unwrap();
            if last_item.kwd() != DIR_KEY_CERTIFICATION {
                return Err(EK::WrongEndingToken
                    .with_msg(last_item.kwd_str().to_string())
                    .at_pos(last_item.pos()));
            }
            last_item.end_pos()
        };

        let version = body
            .required(DIR_KEY_CERTIFICATE_VERSION)?
            .parse_arg::<u32>(0)?;
        if version != 3 {
            return Err(EK::BadDocumentVersion.with_msg(format!("unexpected version {}", version)));
        }
        let dir_key_certificate_version = AuthCertVersion::V3;

        let dir_signing_key: rsa::PublicKey = body
            .required(DIR_SIGNING_KEY)?
            .parse_obj::<RsaPublicParse1Helper>("RSA PUBLIC KEY")?
            .check_len(1024..)?
            .check_exponent(65537)?
            .into();

        let dir_identity_key: rsa::PublicKey = body
            .required(DIR_IDENTITY_KEY)?
            .parse_obj::<RsaPublicParse1Helper>("RSA PUBLIC KEY")?
            .check_len(1024..)?
            .check_exponent(65537)?
            .into();

        let dir_key_published = body
            .required(DIR_KEY_PUBLISHED)?
            .args_as_str()
            .parse::<Iso8601TimeSp>()?;

        let dir_key_expires = body
            .required(DIR_KEY_EXPIRES)?
            .args_as_str()
            .parse::<Iso8601TimeSp>()?;

        {
            // Check fingerprint for consistency with key.
            let fp_tok = body.required(FINGERPRINT)?;
            let fingerprint: RsaIdentity = fp_tok.args_as_str().parse::<Fingerprint>()?.into();
            if fingerprint != dir_identity_key.to_rsa_identity() {
                return Err(EK::BadArgument
                    .at_pos(fp_tok.pos())
                    .with_msg("fingerprint does not match RSA identity"));
            }
        }

        let dir_address = body
            .maybe(DIR_ADDRESS)
            .parse_args_as_str::<net::SocketAddrV4>()?;

        // check crosscert
        let dir_key_crosscert;
        let v_crosscert = {
            let crosscert = body.required(DIR_KEY_CROSSCERT)?;
            // Unwrap should be safe because `.parse()` and `required()` would
            // have already returned an Error
            #[allow(clippy::unwrap_used)]
            let mut tag = crosscert.obj_tag().unwrap();
            // we are required to support both.
            if tag != "ID SIGNATURE" && tag != "SIGNATURE" {
                tag = "ID SIGNATURE";
            }
            let sig = crosscert.obj(tag)?;

            let signed = dir_identity_key.to_rsa_identity();
            // TODO: we need to accept prefixes here. COMPAT BLOCKER.

            let v = rsa::ValidatableRsaSignature::new(&dir_signing_key, &sig, signed.as_bytes());

            dir_key_crosscert = CrossCert {
                signature: CrossCertObject(sig),
            };

            v
        };

        // check the signature
        let v_sig = {
            let signature = body.required(DIR_KEY_CERTIFICATION)?;
            let sig = signature.obj("SIGNATURE")?;

            let mut sha1 = d::Sha1::new();
            // Unwrap should be safe because `.parse()` would have already
            // returned an Error
            #[allow(clippy::unwrap_used)]
            let start_offset = body.first_item().unwrap().offset_in(s).unwrap();
            #[allow(clippy::unwrap_used)]
            let end_offset = body.last_item().unwrap().offset_in(s).unwrap();
            let end_offset = end_offset + "dir-key-certification\n".len();
            sha1.update(&s[start_offset..end_offset]);
            let sha1 = sha1.finalize();
            // TODO: we need to accept prefixes here. COMPAT BLOCKER.

            rsa::ValidatableRsaSignature::new(&dir_identity_key, &sig, &sha1)
        };

        let id_fingerprint = dir_identity_key.to_rsa_identity();

        let location = {
            let start_idx = start_pos.offset_within(s);
            let end_idx = end_pos.offset_within(s);
            match (start_idx, end_idx) {
                (Some(a), Some(b)) => Extent::new(s, &s[a..b + 1]),
                _ => None,
            }
        };

        let authcert = AuthCert {
            dir_key_certificate_version,
            dir_address,
            dir_identity_key,
            dir_signing_key,
            dir_key_published,
            dir_key_expires,
            dir_key_crosscert,
            fingerprint: Fingerprint(id_fingerprint),
            __non_exhaustive: (),
        };

        let signatures: Vec<Box<dyn pk::ValidatableSignature>> =
            vec![Box::new(v_crosscert), Box::new(v_sig)];

        let timed = timed::TimerangeBound::new(authcert, *dir_key_published..*dir_key_expires);
        let signed = signed::SignatureGated::new(timed, signatures);
        let unchecked = UncheckedAuthCert {
            location,
            c: signed,
        };
        Ok(unchecked)
    }
}

/// Pseudo-Signature of the long-term identity key by the medium-term key.
///
/// This type does not implement `SignatureItemParseable` because that trait
/// is reserved for signatures on *netdocs*, such as [`AuthCertSignature`].
/// As `CrossCert` does not sign a full document, it implements only
/// `ItemValueParseable`, instead.
///
/// Verification of this signature is done in `AuthCertUnverified::verify`,
/// and during parsing by the old parser.
/// So a `CrossCert` in [`AuthCert::dir_key_crosscert`] in a bare `AuthCert` has been validated.
//
// TODO SPEC (Diziet): it is far from clear to me that this cert serves any useful purpose.
// However, we are far too busy now with rewriting the universe to consider transitioning it away.
#[derive(Debug, Clone, PartialEq, Eq, Deftly)]
#[cfg_attr(
    feature = "parse2",
    derive_deftly(ItemValueParseable),
    deftly(netdoc(no_extra_args))
)]
#[cfg_attr(feature = "encode", derive_deftly(ItemValueEncodable))]
// derive_deftly_adhoc disables unused deftly attribute checking, so we needn't cfg_attr them all
#[cfg_attr(not(any(feature = "parse2", feature = "encode")), derive_deftly_adhoc)]
#[non_exhaustive]
pub struct CrossCert {
    /// The bytes of the signature (base64-decoded).
    #[deftly(netdoc(object))]
    pub signature: CrossCertObject,
}

/// Wrapper around [`Vec<u8>`] implementing [`ItemObjectParseable`] properly.
///
/// Unfortunately, this wrapper is necessary, because the specification
/// demands that these certificate objects must accept two labels:
/// `SIGNATURE` and `ID SIGNATURE`.  Because the deftly template for
/// `ItemValueParseable` only allows for a single label
/// (`#[deftly(netdoc(object(label = "LABEL")))]`), we must implement this
/// trait ourselves in order to allow multiple ones.
///
/// TODO: In the future, it might be nice to let the respective fmeta
/// accept a pattern, as pattern matching would allow trivially for one
/// to infinity different combinations.
/// TODO SPEC: Alternatively we could abolish the wrong labels,
/// or we could abolish Objects completely and just have long lines.
///
/// # Specifications
///
/// <https://spec.torproject.org/dir-spec/creating-key-certificates.html#item:dir-key-crosscert>
#[derive(Clone, PartialEq, Eq, derive_more::Deref)]
#[non_exhaustive]
pub struct CrossCertObject(pub Vec<u8>);
impl_debug_hex! { CrossCertObject . 0 }

#[cfg(feature = "encode")]
impl CrossCert {
    /// Make a `CrossCert`
    pub fn new(
        k_auth_sign_rsa: &rsa::KeyPair,
        h_kp_auth_id_rsa: &RsaIdentity,
    ) -> StdResult<Self, Bug> {
        let signature = k_auth_sign_rsa
            .sign(h_kp_auth_id_rsa.as_bytes())
            .map_err(into_internal!("failed to sign cross-cert"))?;
        Ok(CrossCert {
            signature: CrossCertObject(signature),
        })
    }
}

/// Signatures for [`AuthCert`]
///
/// Signed by [`AuthCert::dir_identity_key`] in order to prove ownership.
/// Can be seen as the opposite of [`AuthCert::dir_key_crosscert`].
///
/// # Specifications
///
/// * <https://spec.torproject.org/dir-spec/creating-key-certificates.html#item:dir-key-certification>
/// * <https://spec.torproject.org/dir-spec/netdoc.html#signing>
#[derive(Debug, Clone, PartialEq, Eq, Deftly)]
#[cfg_attr(
    feature = "parse2",
    derive_deftly(NetdocParseableSignatures),
    deftly(netdoc(signatures(hashes_accu = "Sha1WholeKeywordLine")))
)]
#[cfg_attr(feature = "encode", derive_deftly(NetdocEncodable))]
#[non_exhaustive]
pub struct AuthCertSignatures {
    /// Contains the actual signature, see [`AuthCertSignatures`].
    pub dir_key_certification: RsaSha1Signature,
}

/// RSA signature for data in [`AuthCert`]
///
/// <https://spec.torproject.org/dir-spec/netdoc.html#signing>
///
/// Compatibility type alias for [`RsaSha1Signature`].
#[deprecated = "use RsaSha1Signature"]
pub type AuthCertSignature = RsaSha1Signature;

#[cfg(feature = "parse2")]
impl ItemObjectParseable for CrossCertObject {
    fn check_label(label: &str) -> StdResult<(), parse2::EP> {
        match label {
            "SIGNATURE" | "ID SIGNATURE" => Ok(()),
            _ => Err(parse2::EP::ObjectIncorrectLabel),
        }
    }

    fn from_bytes(input: &[u8]) -> StdResult<Self, parse2::EP> {
        Ok(Self(input.to_vec()))
    }
}

#[cfg(feature = "encode")]
impl ItemObjectEncodable for CrossCertObject {
    fn label(&self) -> &str {
        "ID SIGNATURE"
    }

    fn write_object_onto(&self, b: &mut Vec<u8>) -> StdResult<(), Bug> {
        b.extend(&self.0);
        Ok(())
    }
}

impl tor_checkable::SelfSigned<timed::TimerangeBound<AuthCert>> for UncheckedAuthCert {
    type Error = signature::Error;

    fn dangerously_assume_wellsigned(self) -> timed::TimerangeBound<AuthCert> {
        self.c.dangerously_assume_wellsigned()
    }
    fn is_well_signed(&self) -> std::result::Result<(), Self::Error> {
        self.c.is_well_signed()
    }
}

#[cfg(feature = "parse2")]
impl AuthCertUnverified {
    /// Verifies the signature of a [`AuthCert`]
    ///
    /// # Algorithm
    ///
    /// 1. Check whether this comes from a valid authority in `v3idents`.
    /// 2. Check whether the timestamps are valid (± tolerance).
    /// 3. Check whether the fingerprint and long-term identity key match.
    /// 4. Check the cross-certificate (proof-of-ownership of signing key).
    /// 5. Check the outer certificate (proof-of-ownership of identity key).
    ///
    /// TODO: Replace `pre_tolerance` and `post_tolerance` with
    /// `tor_dircommon::config::DirTolerance` which is not possible at the
    /// moment due to a circular dependency of `tor-dircommon` depending
    /// upon `tor-netdoc`.
    ///
    /// TODO: Consider whether to try to deduplicate this signature checking
    /// somehow, wrt to [`UncheckedAuthCert`].
    pub fn verify(
        self,
        v3idents: &[RsaIdentity],
        pre_tolerance: Duration,
        post_tolerance: Duration,
        now: SystemTime,
    ) -> StdResult<AuthCert, parse2::VerifyFailed> {
        let (body, sigs) = (self.body, self.sigs);

        // (1) Check whether this comes from a valid authority in `v3idents`.
        if !v3idents.contains(&body.fingerprint.0) {
            return Err(parse2::VerifyFailed::InsufficientTrustedSigners);
        }

        // (2) Check whether the timestamps are valid (± tolerance).
        let validity = *body.dir_key_published..=*body.dir_key_expires;
        parse2::check_validity_time_tolerance(now, validity, pre_tolerance, post_tolerance)?;

        // (3) Check whether the fingerprint and long-term identity key match.
        if body.dir_identity_key.to_rsa_identity() != *body.fingerprint {
            return Err(parse2::VerifyFailed::Inconsistent);
        }

        // (4) Check the cross-certificate (proof-of-ownership of signing key).
        body.dir_signing_key.verify(
            body.fingerprint.0.as_bytes(),
            &body.dir_key_crosscert.signature,
        )?;

        // (5) Check the outer certificate (proof-of-ownership of identity key).
        body.dir_identity_key.verify(
            &sigs.hashes.0.ok_or(parse2::VerifyFailed::Bug)?,
            &sigs.sigs.dir_key_certification.signature,
        )?;

        Ok(body)
    }

    /// Verify the signatures (and check validity times)
    ///
    /// The pre and post tolerance (time check allowances) used are both zero.
    ///
    /// # Security considerations
    ///
    /// The caller must check that the KP_auth_id is correct/relevant.
    pub fn verify_selfcert(self, now: SystemTime) -> StdResult<AuthCert, parse2::VerifyFailed> {
        let h_kp_auth_id_rsa = self.inspect_unverified().0.fingerprint.0;
        self.verify(&[h_kp_auth_id_rsa], Duration::ZERO, Duration::ZERO, now)
    }
}

#[cfg(feature = "encode")]
impl AuthCert {
    /// Make the base for a new `AuthCert`
    ///
    /// This contains only the mandatory fields (the ones in `AuthCertConstructor`).
    /// This method is an alternative to providing a `AuthCertConstructor` value display,
    /// and is convenient because an authcert contains much recapitulated information.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn main() -> Result<(), anyhow::Error> {
    /// use tor_netdoc::doc::authcert::AuthCert;
    /// let (k_auth_id_rsa, k_auth_sign_rsa, published, expires) = todo!();
    /// let authcert = AuthCert {
    ///     dir_address: Some("192.0.2.17:7000".parse()?),
    ///     ..AuthCert::new_base(&k_auth_id_rsa, &k_auth_sign_rsa, published, expires)?
    /// };
    /// # Ok(())
    /// # }
    /// ```
    pub fn new_base(
        k_auth_id_rsa: &rsa::KeyPair,
        k_auth_sign_rsa: &rsa::KeyPair,
        published: SystemTime,
        expires: SystemTime,
    ) -> StdResult<Self, Bug> {
        let fingerprint = k_auth_id_rsa.to_public_key().to_rsa_identity();
        let dir_key_crosscert = CrossCert::new(k_auth_sign_rsa, &fingerprint)?;

        let base = AuthCertConstructor {
            fingerprint: fingerprint.into(),
            dir_key_published: published.into(),
            dir_key_expires: expires.into(),
            dir_identity_key: k_auth_id_rsa.to_public_key(),
            dir_signing_key: k_auth_sign_rsa.to_public_key(),
            dir_key_crosscert,
        }
        .construct();

        Ok(base)
    }

    /// Encode this `AuthCert` and sign it with `k_auth_id_rsa`
    ///
    /// Yields the string representation of the signed, encoded, document,
    /// as an [`EncodedAuthCert`].
    // TODO these features are quite tangled
    // `EncodedAuthCert` is only available with `parse2` and `plain-consensus`
    #[cfg(all(feature = "parse2", feature = "plain-consensus"))]
    pub fn encode_sign(&self, k_auth_id_rsa: &rsa::KeyPair) -> StdResult<EncodedAuthCert, Bug> {
        let mut encoder = NetdocEncoder::new();
        self.encode_unsigned(&mut encoder)?;

        let signature =
            RsaSha1Signature::new_sign_netdoc(k_auth_id_rsa, &encoder, "dir-key-certification")?;
        let sigs = AuthCertSignatures {
            dir_key_certification: signature,
        };
        sigs.encode_unsigned(&mut encoder)?;

        let encoded = encoder.finish()?;
        // This rechecks the invariants which ought to be true by construction.
        // That is convenient for the code here, and the perf implications are irrelevant.
        let encoded = encoded
            .try_into()
            .map_err(into_internal!("generated broken authcert"))?;
        Ok(encoded)
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
    use super::*;
    use crate::{Error, Pos};
    const TESTDATA: &str = include_str!("../../testdata/authcert1.txt");

    fn bad_data(fname: &str) -> String {
        use std::fs;
        use std::path::PathBuf;
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("testdata");
        path.push("bad-certs");
        path.push(fname);

        fs::read_to_string(path).unwrap()
    }

    #[test]
    fn parse_one() -> Result<()> {
        use tor_checkable::{SelfSigned, Timebound};
        let cert = AuthCert::parse(TESTDATA)?
            .check_signature()
            .unwrap()
            .dangerously_assume_timely();

        // Taken from TESTDATA
        assert_eq!(
            cert.id_fingerprint().to_string(),
            "$ed03bb616eb2f60bec80151114bb25cef515b226"
        );
        assert_eq!(
            cert.key_ids().sk_fingerprint.to_string(),
            "$c4f720e2c59f9ddd4867fff465ca04031e35648f"
        );

        Ok(())
    }

    #[test]
    fn parse_bad() {
        fn check(fname: &str, err: &Error) {
            let contents = bad_data(fname);
            let cert = AuthCert::parse(&contents);
            assert!(cert.is_err());
            assert_eq!(&cert.err().unwrap(), err);
        }

        check(
            "bad-cc-tag",
            &EK::WrongObject.at_pos(Pos::from_line(27, 12)),
        );
        check(
            "bad-fingerprint",
            &EK::BadArgument
                .at_pos(Pos::from_line(2, 1))
                .with_msg("fingerprint does not match RSA identity"),
        );
        check(
            "bad-version",
            &EK::BadDocumentVersion.with_msg("unexpected version 4"),
        );
        check(
            "wrong-end",
            &EK::WrongEndingToken
                .with_msg("dir-key-crosscert")
                .at_pos(Pos::from_line(37, 1)),
        );
        check(
            "wrong-start",
            &EK::WrongStartingToken
                .with_msg("fingerprint")
                .at_pos(Pos::from_line(1, 1)),
        );
    }

    #[test]
    fn test_recovery_1() {
        let mut data = "<><><<><>\nfingerprint ABC\n".to_string();
        data += TESTDATA;

        let res: Vec<Result<_>> = AuthCert::parse_multiple(&data).unwrap().collect();

        // We should recover from the failed case and read the next data fine.
        assert!(res[0].is_err());
        assert!(res[1].is_ok());
        assert_eq!(res.len(), 2);
    }

    #[test]
    fn test_recovery_2() {
        let mut data = bad_data("bad-version");
        data += TESTDATA;

        let res: Vec<Result<_>> = AuthCert::parse_multiple(&data).unwrap().collect();

        // We should recover from the failed case and read the next data fine.
        assert!(res[0].is_err());
        assert!(res[1].is_ok());
        assert_eq!(res.len(), 2);
    }

    #[cfg(feature = "parse2")]
    mod parse2_test {
        use super::{AuthCert, AuthCertUnverified, AuthCertVersion, CrossCert, CrossCertObject};

        use std::{
            net::{Ipv4Addr, SocketAddrV4},
            str::FromStr,
            time::{Duration, SystemTime},
        };

        use crate::{
            parse2::{self, ErrorProblem, NetdocUnverified, ParseError, ParseInput, VerifyFailed},
            types::{self, Iso8601TimeSp},
        };

        use derive_deftly::Deftly;
        use tor_llcrypto::pk::rsa::{self, RsaIdentity};

        // === AUTHCERT D190BF3B00E311A9AEB6D62B51980E9B2109BAD1 ===
        // These values come from testdata2/keys/authority_certificate.
        const DIR_KEY_PUBLISHED: &str = "2000-01-01 00:00:05";
        const DIR_KEY_EXPIRES: &str = "2001-01-01 00:00:05";
        const FINGERPRINT: &str = "D190BF3B00E311A9AEB6D62B51980E9B2109BAD1";
        const DIR_ADDRESS: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 7100);
        const DIR_IDENTITY_KEY: &str = "
-----BEGIN RSA PUBLIC KEY-----
MIIBigKCAYEAt0rXD+1gYwKFAxrO4uNHQ9dQVUOGx5FxkioYNSct5Z3JU00dTKNJ
jt4OGkFYwixWwk6KLDOiB+I/q9YIdA1NlQ5R3Hz8jjvFPVl0JQQm2LYzdSzv7/CZ
U1qq5rYeeoYKx8qMQg4q3WgR251GEnOG+rVqzFSs0oyC+SDfYn9iMt00/pmN3HXf
wmasY6BescVrYoDbnpkwKATizd4lzx5K8V8aXUXtd8qnYzSyHLlhiO1eufVX07YC
+AVHV7W7qCTY/4I5Sm0dQ9jF/r04JBHnpH+aae48JOjWDCZj9AINi3rCKS8XClGb
BB/LJidoQAZraQEEtu3Ql1mjdLreeyWfXpfZFvwKuYn44FtQsOT2TVAVNqNF8N4v
yfwfiPN6FQWlPyMCEB81HerCn03Zi5WgQLGo7PAeO4LFrLrU16DUC5/oJENeHs0T
27FZQyrlf0rAxiHh7TJKcjLmzeyxCQVQlr2AXXs28gKHV0AQnEcdrVOpTrquSCQQ
hWBehR+ct4OJAgMBAAE=
-----END RSA PUBLIC KEY-----
    ";
        const DIR_SIGNING_KEY: &str = "
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAtPF94+bThLI28kn6e+MmUECMMJ5UBlnQ+Mvwn8Zd85awPQTDz5Wu
13sZDN3nWnhgSuP5q/WDYc5GPPtQdSWBiG1nJA2XLgEHTHf29iGZ+jAoGfIMJvBV
1xN8baTnsha5LGx5BQ4UqzlUmoaPzwbjehnPd00FgVkpcCvKZu1HU7fGMVwn4MMh
zuxJTqTgfcuFWTEu0H0ukOFX+51ih6WO3GWYqRiqgU0Q5/Ets8ccCTq7ND9d2u1P
d7kQzUHbVP0KmYGK4qYntGDfP4g9SmpBoUUHyP3j9en9S6PMYv8m1YFO7M7JKu6Q
dQZfGTxj9C/0b/jRklgn5JlKAl9eJQvCdwIDAQAB
-----END RSA PUBLIC KEY-----
";
        const DIR_CROSS_CERT_OBJECT: &str = "
-----BEGIN ID SIGNATURE-----
NBaPdBNCNMah6cklrALzj0RdHymF/jPGOv9NmeqaXc0uTN06S/BlVM/xTjilu+dj
sjPuT0BQL4/ZWyZR+R+gJJojKYILSId4IQ1elzRSxpFN+u2u/ZEmS6SR2SwpA05A
btOYBKAmYkY6rLsTCbXGx3lAH2kAXfcrltCNKZXV6gqW7X379fiOnSId1OWhKPe1
/1p3pQGZxgb8FOT1kpHxOMRBClF9Ulm3d9fQZr80Wn73gZ2Bp1RXn9c7c/71HD1c
mzMT023bleZ574az+117yNAr6XbIgqQfzbySzVLPXM8ZN9BrGR40KDZ2638ZJjRu
8HK5TzuknWlkRv3hCyRX+g==
-----END ID SIGNATURE-----
";
        const AUTHCERT_RAW: &str = include_str!("../../testdata2/keys/authority_certificate");
        /// A system time in the range of [`DIR_KEY_PUBLISHED`] and [`DIR_KEY_EXPIRES`].
        ///
        /// Constructed by ourselves to have a time point we can use for testing
        /// timestamp verification.
        const VALID_SYSTEM_TIME: &str = "2000-06-01 00:00:00";

        // === AUTHCERT 0B8997614EC647C1C6B6A044E2B5408F0B823FB0 ===
        // This values come from ../../testdata2/cached-certs--1
        // A different authority certificate different from the one above.
        const ALTERNATIVE_AUTHCERT_RAW: &str = include_str!("../../testdata2/cached-certs--1");

        /// Converts a string in the [`Iso8601TimeSp`] format to [`SystemTime`].
        ///
        /// This functions panics in the case the input is malformatted.
        fn to_system_time(s: &str) -> SystemTime {
            Iso8601TimeSp::from_str(s).unwrap().0
        }

        /// Converts a PEM encoded RSA Public key to an [`rsa::PublicKey`].
        ///
        /// This function panics in the case the input is malformatted.
        fn pem_to_rsa_pk(s: &str) -> rsa::PublicKey {
            rsa::PublicKey::from_der(pem::parse(s).unwrap().contents()).unwrap()
        }

        /// Converts a hex-encoded RSA identity to an [`RsaIdentity`].
        ///
        /// This function panics in the case the input is malformatted.
        fn to_rsa_id(s: &str) -> RsaIdentity {
            RsaIdentity::from_hex(s).unwrap()
        }

        /// Tests whether a [`DirKeyCrossCert`] can be parsed properly.
        #[test]
        fn dir_auth_cross_cert() {
            #[derive(Debug, Clone, PartialEq, Eq, Deftly)]
            #[derive_deftly(NetdocParseable)]
            struct Dummy {
                dir_key_crosscert: CrossCert,
            }

            // "Encodes" a DIR_CROSS_CERT_OBJECT by simply removing the lines
            // indicating the BEGIN and END, as the purpose is to test multiple
            // labels.
            let encoded = DIR_CROSS_CERT_OBJECT
                .lines()
                .filter(|line| !line.starts_with("-----"))
                .collect::<Vec<_>>()
                .join("\n");
            let decoded = pem::parse(DIR_CROSS_CERT_OBJECT)
                .unwrap()
                .contents()
                .to_vec();

            // Try with `SIGNATURE`.
            let cert = format!(
                "dir-key-crosscert\n-----BEGIN SIGNATURE-----\n{encoded}\n-----END SIGNATURE-----"
            );
            let res = parse2::parse_netdoc::<Dummy>(&ParseInput::new(&cert, "")).unwrap();
            assert_eq!(
                res,
                Dummy {
                    dir_key_crosscert: CrossCert {
                        signature: CrossCertObject(decoded.clone())
                    }
                }
            );

            // Try with `ID SIGNATURE`.
            let cert = format!(
                "dir-key-crosscert\n-----BEGIN ID SIGNATURE-----\n{encoded}\n-----END ID SIGNATURE-----"
            );
            let res = parse2::parse_netdoc::<Dummy>(&ParseInput::new(&cert, "")).unwrap();
            assert_eq!(
                res,
                Dummy {
                    dir_key_crosscert: CrossCert {
                        signature: CrossCertObject(decoded.clone())
                    }
                }
            );

            // Try with different label and fail.
            let cert =
                format!("dir-key-crosscert\n-----BEGIN WHAT-----\n{encoded}\n-----END WHAT-----");
            let res = parse2::parse_netdoc::<Dummy>(&ParseInput::new(&cert, ""));
            match res {
                Err(ParseError {
                    problem: ErrorProblem::ObjectIncorrectLabel,
                    doctype: "dir-key-crosscert",
                    file: _,
                    lno: 1,
                    column: None,
                }) => {}
                other => panic!("not expected error {other:#?}"),
            }

            // Try with extra args.
            let cert = format!(
                "dir-key-crosscert arg1\n-----BEGIN ID SIGNATURE-----\n{encoded}\n-----END ID SIGNATURE-----"
            );
            let res = parse2::parse_netdoc::<Dummy>(&ParseInput::new(&cert, ""));
            match res {
                Err(ParseError {
                    problem: ErrorProblem::UnexpectedArgument { column: 19 },
                    doctype: "dir-key-crosscert",
                    file: _,
                    lno: 1,
                    column: Some(19),
                }) => {}
                other => panic!("not expected error {other:#?}"),
            }
        }

        #[test]
        fn dir_auth_cert() {
            let res =
                parse2::parse_netdoc::<AuthCertUnverified>(&ParseInput::new(AUTHCERT_RAW, ""))
                    .unwrap();
            assert_eq!(
                *res.inspect_unverified().0,
                AuthCert {
                    dir_key_certificate_version: AuthCertVersion::V3,
                    dir_address: Some(DIR_ADDRESS),
                    fingerprint: types::Fingerprint(to_rsa_id(FINGERPRINT)),
                    dir_key_published: Iso8601TimeSp(to_system_time(DIR_KEY_PUBLISHED)),
                    dir_key_expires: Iso8601TimeSp(to_system_time(DIR_KEY_EXPIRES)),
                    dir_identity_key: pem_to_rsa_pk(DIR_IDENTITY_KEY),
                    dir_signing_key: pem_to_rsa_pk(DIR_SIGNING_KEY),
                    dir_key_crosscert: CrossCert {
                        signature: CrossCertObject(
                            pem::parse(DIR_CROSS_CERT_OBJECT)
                                .unwrap()
                                .contents()
                                .to_vec()
                        )
                    },
                    __non_exhaustive: (),
                }
            );
        }

        #[test]
        fn dir_auth_signature() {
            let res =
                parse2::parse_netdoc::<AuthCertUnverified>(&ParseInput::new(AUTHCERT_RAW, ""))
                    .unwrap();

            // Test a valid signature.
            res.clone()
                .verify(
                    &[to_rsa_id(FINGERPRINT)],
                    Duration::ZERO,
                    Duration::ZERO,
                    to_system_time(VALID_SYSTEM_TIME),
                )
                .unwrap();

            // Test with an invalid authority.
            assert_eq!(
                res.clone()
                    .verify(
                        &[],
                        Duration::ZERO,
                        Duration::ZERO,
                        to_system_time(VALID_SYSTEM_TIME),
                    )
                    .unwrap_err(),
                VerifyFailed::InsufficientTrustedSigners
            );

            // Test a key too far in the future.
            assert_eq!(
                res.clone()
                    .verify(
                        &[to_rsa_id(FINGERPRINT)],
                        Duration::ZERO,
                        Duration::ZERO,
                        SystemTime::UNIX_EPOCH,
                    )
                    .unwrap_err(),
                VerifyFailed::TooNew
            );

            // Test an almost too new.
            res.clone()
                .verify(
                    &[to_rsa_id(FINGERPRINT)],
                    Duration::ZERO,
                    Duration::ZERO,
                    to_system_time(DIR_KEY_PUBLISHED),
                )
                .unwrap();

            // Now fail when we are 1s below ...
            assert_eq!(
                res.clone()
                    .verify(
                        &[to_rsa_id(FINGERPRINT)],
                        Duration::ZERO,
                        Duration::ZERO,
                        to_system_time(DIR_KEY_PUBLISHED) - Duration::from_secs(1),
                    )
                    .unwrap_err(),
                VerifyFailed::TooNew
            );

            // ... but succeed again with a clock skew tolerance.
            res.clone()
                .verify(
                    &[to_rsa_id(FINGERPRINT)],
                    Duration::from_secs(1),
                    Duration::ZERO,
                    to_system_time(DIR_KEY_PUBLISHED) - Duration::from_secs(1),
                )
                .unwrap();

            // Test a key too old.
            assert_eq!(
                res.clone()
                    .verify(
                        &[to_rsa_id(FINGERPRINT)],
                        Duration::ZERO,
                        Duration::ZERO,
                        SystemTime::UNIX_EPOCH
                            .checked_add(Duration::from_secs(2000000000))
                            .unwrap(),
                    )
                    .unwrap_err(),
                VerifyFailed::TooOld
            );

            // Test an almost too old.
            res.clone()
                .verify(
                    &[to_rsa_id(FINGERPRINT)],
                    Duration::ZERO,
                    Duration::ZERO,
                    to_system_time(DIR_KEY_EXPIRES),
                )
                .unwrap();

            // Now fail when we are 1s above ...
            assert_eq!(
                res.clone()
                    .verify(
                        &[to_rsa_id(FINGERPRINT)],
                        Duration::ZERO,
                        Duration::ZERO,
                        to_system_time(DIR_KEY_EXPIRES) + Duration::from_secs(1),
                    )
                    .unwrap_err(),
                VerifyFailed::TooOld
            );

            // ... but succeed again with a clock skew tolerance.
            res.clone()
                .verify(
                    &[to_rsa_id(FINGERPRINT)],
                    Duration::ZERO,
                    Duration::from_secs(1),
                    to_system_time(DIR_KEY_EXPIRES) + Duration::from_secs(1),
                )
                .unwrap();

            // Check with non-matching fingerprint and long-term identity key.
            let mut cert =
                parse2::parse_netdoc::<AuthCertUnverified>(&ParseInput::new(AUTHCERT_RAW, ""))
                    .unwrap();
            let alternative_cert = parse2::parse_netdoc::<AuthCertUnverified>(&ParseInput::new(
                ALTERNATIVE_AUTHCERT_RAW,
                "",
            ))
            .unwrap();
            cert.body.dir_identity_key = alternative_cert.body.dir_identity_key.clone();
            assert_eq!(
                cert.verify(
                    &[to_rsa_id(FINGERPRINT)],
                    Duration::ZERO,
                    Duration::ZERO,
                    to_system_time(VALID_SYSTEM_TIME),
                )
                .unwrap_err(),
                VerifyFailed::Inconsistent
            );

            // Check invalid cross-cert.
            let mut cert =
                parse2::parse_netdoc::<AuthCertUnverified>(&ParseInput::new(AUTHCERT_RAW, ""))
                    .unwrap();
            cert.body.dir_key_crosscert = alternative_cert.body.dir_key_crosscert.clone();
            assert_eq!(
                cert.verify(
                    &[to_rsa_id(FINGERPRINT)],
                    Duration::ZERO,
                    Duration::ZERO,
                    to_system_time(VALID_SYSTEM_TIME),
                )
                .unwrap_err(),
                VerifyFailed::VerifyFailed
            );

            // Check outer signature.
            let mut cert =
                parse2::parse_netdoc::<AuthCertUnverified>(&ParseInput::new(AUTHCERT_RAW, ""))
                    .unwrap();
            cert.sigs = alternative_cert.sigs.clone();
            assert_eq!(
                cert.verify(
                    &[to_rsa_id(FINGERPRINT)],
                    Duration::ZERO,
                    Duration::ZERO,
                    to_system_time(VALID_SYSTEM_TIME),
                )
                .unwrap_err(),
                VerifyFailed::VerifyFailed
            );
        }
    }

    #[cfg(all(feature = "encode", feature = "parse2", feature = "plain-consensus"))]
    mod encode_test {
        use super::*;
        use crate::parse2::{ParseInput, parse_netdoc};
        use humantime::parse_rfc3339;
        use std::result::Result;
        use tor_basic_utils::test_rng;

        #[test]
        fn roundtrip() -> Result<(), anyhow::Error> {
            let mut rng = test_rng::testing_rng();
            let k_auth_id_rsa = rsa::KeyPair::generate(&mut rng)?;
            let k_auth_sign_rsa = rsa::KeyPair::generate(&mut rng)?;

            let secs = |s| Duration::from_secs(s);
            let now = parse_rfc3339("1993-01-01T00:00:00Z")?;
            let published = now - secs(1000);
            let expires = published + secs(86400);
            let tolerance = secs(10);

            let input_value = AuthCert {
                dir_address: Some("192.0.2.17:7000".parse()?),
                ..AuthCert::new_base(&k_auth_id_rsa, &k_auth_sign_rsa, published, expires)?
            };
            dbg!(&input_value);

            let encoded = input_value.encode_sign(&k_auth_id_rsa)?;

            let reparsed_uv: AuthCertUnverified =
                parse_netdoc(&ParseInput::new(encoded.as_ref(), "<encoded>"))?;
            let reparsed_value = reparsed_uv.verify(
                &[k_auth_id_rsa.to_public_key().to_rsa_identity()],
                tolerance,
                tolerance,
                now,
            )?;
            dbg!(&reparsed_value);

            assert_eq!(input_value, reparsed_value);
            Ok(())
        }
    }
}
