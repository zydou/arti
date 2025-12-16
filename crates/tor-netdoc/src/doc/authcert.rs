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
use crate::types::misc::{Fingerprint, Iso8601TimeSp, RsaPublic};
use crate::util::str::Extent;
use crate::{NetdocErrorKind as EK, Result};

use tor_checkable::{signed, timed};
use tor_llcrypto::pk::rsa;
use tor_llcrypto::{d, pk, pk::rsa::RsaIdentity};

use std::sync::LazyLock;

use std::{net, time};

use digest::Digest;

#[cfg(feature = "build_docs")]
mod build;

#[cfg(feature = "build_docs")]
pub use build::AuthCertBuilder;

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

/// A single authority certificate.
///
/// Authority certificates bind a long-term RSA identity key from a
/// directory authority to a medium-term signing key.  The signing
/// keys are the ones used to sign votes and consensuses; the identity
/// keys can be kept offline.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct AuthCert {
    /// An IPv4 address for this authority.
    address: Option<net::SocketAddrV4>,
    /// Declared time when this certificate was published
    published: time::SystemTime,
    /// Declared time when this certificate expires.
    expires: time::SystemTime,
    /// The long-term RSA identity key for this authority
    identity_key: rsa::PublicKey,
    /// The medium-term RSA signing key for this authority
    signing_key: rsa::PublicKey,

    /// Derived field: fingerprints of the certificate's keys
    key_ids: AuthCertKeyIds,
}

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
        &self.signing_key
    }

    /// Return an AuthCertKeyIds object describing the keys in this
    /// certificate.
    pub fn key_ids(&self) -> &AuthCertKeyIds {
        &self.key_ids
    }

    /// Return an RsaIdentity for this certificate's identity key.
    pub fn id_fingerprint(&self) -> &rsa::RsaIdentity {
        &self.key_ids.id_fingerprint
    }

    /// Return an RsaIdentity for this certificate's signing key.
    pub fn sk_fingerprint(&self) -> &rsa::RsaIdentity {
        &self.key_ids.sk_fingerprint
    }

    /// Return the time when this certificate says it was published.
    pub fn published(&self) -> time::SystemTime {
        self.published
    }

    /// Return the time when this certificate says it should expire.
    pub fn expires(&self) -> time::SystemTime {
        self.expires
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

        let signing_key: rsa::PublicKey = body
            .required(DIR_SIGNING_KEY)?
            .parse_obj::<RsaPublic>("RSA PUBLIC KEY")?
            .check_len(1024..)?
            .check_exponent(65537)?
            .into();

        let identity_key: rsa::PublicKey = body
            .required(DIR_IDENTITY_KEY)?
            .parse_obj::<RsaPublic>("RSA PUBLIC KEY")?
            .check_len(1024..)?
            .check_exponent(65537)?
            .into();

        let published = body
            .required(DIR_KEY_PUBLISHED)?
            .args_as_str()
            .parse::<Iso8601TimeSp>()?
            .into();

        let expires = body
            .required(DIR_KEY_EXPIRES)?
            .args_as_str()
            .parse::<Iso8601TimeSp>()?
            .into();

        {
            // Check fingerprint for consistency with key.
            let fp_tok = body.required(FINGERPRINT)?;
            let fingerprint: RsaIdentity = fp_tok.args_as_str().parse::<Fingerprint>()?.into();
            if fingerprint != identity_key.to_rsa_identity() {
                return Err(EK::BadArgument
                    .at_pos(fp_tok.pos())
                    .with_msg("fingerprint does not match RSA identity"));
            }
        }

        let address = body
            .maybe(DIR_ADDRESS)
            .parse_args_as_str::<net::SocketAddrV4>()?;

        // check crosscert
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

            let signed = identity_key.to_rsa_identity();
            // TODO: we need to accept prefixes here. COMPAT BLOCKER.

            rsa::ValidatableRsaSignature::new(&signing_key, &sig, signed.as_bytes())
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

            rsa::ValidatableRsaSignature::new(&identity_key, &sig, &sha1)
        };

        let id_fingerprint = identity_key.to_rsa_identity();
        let sk_fingerprint = signing_key.to_rsa_identity();
        let key_ids = AuthCertKeyIds {
            id_fingerprint,
            sk_fingerprint,
        };

        let location = {
            let start_idx = start_pos.offset_within(s);
            let end_idx = end_pos.offset_within(s);
            match (start_idx, end_idx) {
                (Some(a), Some(b)) => Extent::new(s, &s[a..b + 1]),
                _ => None,
            }
        };

        let authcert = AuthCert {
            address,
            identity_key,
            signing_key,
            published,
            expires,
            key_ids,
        };

        let signatures: Vec<Box<dyn pk::ValidatableSignature>> =
            vec![Box::new(v_crosscert), Box::new(v_sig)];

        let timed = timed::TimerangeBound::new(authcert, published..expires);
        let signed = signed::SignatureGated::new(timed, signatures);
        let unchecked = UncheckedAuthCert {
            location,
            c: signed,
        };
        Ok(unchecked)
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

/// Temporary module to gradually implement types using `parse2`.
///
/// Eventually, those will get merged into the main module.
#[cfg(feature = "parse2")]
pub mod tmp {
    use std::time::{Duration, SystemTime};

    use derive_deftly::Deftly;

    use crate::{
        NormalItemArgument,
        parse2::{
            ErrorProblem, ItemObjectParseable, SignatureHashInputs, VerifyFailed,
            check_validity_time_tolerance,
        },
        types::{self, Iso8601TimeSp},
    };

    use tor_llcrypto::pk::rsa::{self, RsaIdentity};

    /// The body of a directory authority key certificate.
    ///
    /// Directory authorities create key certificates to certify their
    /// medium-term signing keys with their long-term authority identity key.
    ///
    /// # Specifications
    ///
    /// * <https://spec.torproject.org/dir-spec/creating-key-certificates.html>
    #[derive(Debug, Clone, PartialEq, Eq, Deftly)]
    #[derive_deftly(NetdocParseable, NetdocSigned)]
    #[non_exhaustive]
    pub struct DirAuthKeyCert {
        /// Introduces an authority key certificate.
        ///
        /// At the moment, the version **MUST** be `3`.
        /// Implementations **MUST** reject formats they do not understand.
        ///
        /// # Syntax
        ///
        /// * `dir-key-certificate-version <version>`
        /// * At start, exactly once.
        ///
        /// # Specifications
        ///
        /// * <https://spec.torproject.org/dir-spec/creating-key-certificates.html#item:dir-key-certificate-version>
        #[deftly(netdoc(single_arg))]
        pub dir_key_certificate_version: DirKeyCertificateVersion,

        /// Uppercase base16 SHA-1 hash (fingerprint) of the long-term identity key.
        ///
        /// # Syntax
        ///
        /// * `fingerprint <SHA1(DER(kp_auth_id_rsa))>`
        /// * Exactly once.
        ///
        /// # Specifications
        ///
        /// * <https://spec.torproject.org/dir-spec/creating-key-certificates.html#item:fingerprint>
        #[deftly(netdoc(single_arg))]
        pub fingerprint: types::Fingerprint,

        /// Certifies the generation time of the certificate in ISO-8601.
        ///
        /// Implementations **SHOULD** reject certificates too far in the future.
        ///
        /// # Syntax
        ///
        /// * `dir-key-published <ISO8601>`
        /// * Exactly once.
        ///
        /// # Specifications
        ///
        /// * <https://spec.torproject.org/dir-spec/creating-key-certificates.html#item:fingerprint>
        #[deftly(netdoc(single_arg))]
        pub dir_key_published: Iso8601TimeSp,

        /// Certifies the expiration time of the certificate in ISO-8601.
        ///
        /// Implementations **SHOULD** reject expired certificates.
        ///
        /// # Syntax
        ///
        /// * `dir-key-expires <ISO8601>`
        /// * Exactly once.
        ///
        /// # Specifications
        ///
        /// * <https://spec.torproject.org/dir-spec/creating-key-certificates.html#item:dir-key-expires>
        #[deftly(netdoc(single_arg))]
        pub dir_key_expires: Iso8601TimeSp,

        /// Certifies the long-term authority identity key.
        ///
        /// # Syntax
        ///
        /// ```text
        /// dir-identity-key
        /// -----BEGIN RSA PUBLIC KEY-----
        /// <DER PKCS#1 RSA Public Key>
        /// -----END RSA PUBLIC KEY-----
        /// ```
        ///
        /// Exactly once.
        ///
        /// # Specifications
        ///
        /// * <https://spec.torproject.org/dir-spec/creating-key-certificates.html#item:dir-identity-key>
        pub dir_identity_key: rsa::PublicKey,

        /// Certifies the medium-term authority signing key.
        ///
        /// This is in fact the most critical piece of the certificate as it
        /// contains the only real data the client was not previously aware of.
        ///
        /// # Syntax
        ///
        /// ```text
        /// dir-signing-key
        /// -----BEGIN RSA PUBLIC KEY-----
        /// <DER PKCS#1 RSA Public Key>
        /// -----END RSA PUBLIC KEY-----
        /// ```
        ///
        /// Exactly once.
        ///
        /// # Specifications
        ///
        /// * <https://spec.torproject.org/dir-spec/creating-key-certificates.html#item:dir-signing-key>
        pub dir_signing_key: rsa::PublicKey,

        /// Certifies ownership of the medium-term signing key.
        ///
        /// This certificate represents a signature made using `kp_auth_sign_rsa`
        /// of `h_kp_auth_id_rsa`.
        ///
        /// # Syntax
        ///
        /// ```text
        /// dir-key-crosscert
        /// -----BEGIN ID SIGNATURE-----
        /// <Base64 encoded RSA signature of SHA1(DER(kp_auth_id_rsa))>
        /// -----END ID SIGNATURE-----
        /// ```
        ///
        /// # Specifications
        ///
        /// * <https://spec.torproject.org/dir-spec/creating-key-certificates.html#item:dir-key-crosscert>
        pub dir_key_crosscert: DirKeyCrossCert,
    }

    /// Signatures for [`DirAuthKeyCert`].
    ///
    /// Signed by [`DirAuthKeyCert::dir_identity_key`] in order to prove ownership.
    /// Can be seen as the opposite of [`DirAuthKeyCert::dir_key_crosscert`].
    ///
    /// # Syntax
    ///
    /// ```text
    /// dir-key-certification
    /// -----BEGIN SIGNATURE-----
    /// <Base64 encoded RSA signature of SHA1(PKCS_1_1_5(version to crosscert))>
    /// -----END SIGNATURE-----
    /// ```
    ///
    /// # Specifications
    ///
    /// * <https://spec.torproject.org/dir-spec/creating-key-certificates.html#item:dir-key-certification>
    /// * <https://spec.torproject.org/dir-spec/netdoc.html#signing>
    #[derive(Debug, Clone, PartialEq, Eq, Deftly)]
    #[derive_deftly(NetdocParseable)]
    #[deftly(netdoc(signatures))]
    #[non_exhaustive]
    pub struct DirAuthKeyCertSignatures {
        /// Contains the actual signature, see [`DirAuthKeyCertSignatures`].
        pub dir_key_certification: DirKeyCertification,
    }

    /// RSA signature for data in [`DirAuthKeyCert`] and related structures.
    ///
    /// # Syntax
    ///
    /// ```text
    /// -----BEGIN SIGNATURE-----
    /// <Base64 encoded RSA signature of something depending on the item>
    /// -----END SIGNATURE-----
    /// ```
    ///
    /// # Specifications
    ///
    /// * <https://spec.torproject.org/dir-spec/netdoc.html#signing>
    ///
    /// # Caveats
    ///
    /// This type **MUST NOT** be used for [`DirAuthKeyCert::dir_key_crosscert`]
    /// because its set of object labels is a strict superset of the object
    /// labels used by this type.
    #[derive(Debug, Clone, PartialEq, Eq, Deftly)]
    #[derive_deftly(ItemValueParseable)]
    #[deftly(netdoc(no_extra_args))]
    #[non_exhaustive]
    pub struct DirKeyCertification {
        /// The bytes of the signature (base64-decoded).
        #[deftly(netdoc(object(label = "SIGNATURE"), with = "crate::parse2::raw_data_object"))]
        pub signature: Vec<u8>,

        /// The SHA1 hash of the document.
        #[deftly(netdoc(sig_hash = "whole_keyword_line_sha1"))]
        pub hash: [u8; 20],
    }

    /// Represents the version of a [`DirAuthKeyCert`].
    ///
    /// # See More
    ///
    /// See [`DirAuthKeyCert::dir_key_certificate_version`] for the syntax and the specs.
    #[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, strum::EnumString, strum::Display)]
    #[non_exhaustive]
    pub enum DirKeyCertificateVersion {
        /// The current and only version understood.
        #[strum(serialize = "3")]
        V3,
    }

    /// Pseudo-Signature of the long-term identity key by the medium-term key.
    ///
    /// This type does not implement `SignatureItemParseable` because this type
    /// is reserved for full-body signatures, such as [`DirKeyCertification`].
    /// As this types does not sign a full document, it has to implement
    /// `ItemValueParseable` only instead.
    ///
    /// This means that **signature validation must be done with extra care**!
    /// In other words, the structure storing the (SHA1 hash of the) long-term
    /// identity key alongside the [`DirKeyCrossCert`] must perform proper
    /// steps to hold the signature contained in this structure against the data
    /// that is certified by it.
    ///
    /// # See More
    ///
    /// See [`DirAuthKeyCert::dir_key_crosscert`] for the syntax and the specs.
    #[derive(Debug, Clone, PartialEq, Eq, Deftly)]
    #[derive_deftly(ItemValueParseable)]
    #[deftly(netdoc(no_extra_args))]
    #[non_exhaustive]
    pub struct DirKeyCrossCert {
        /// The bytes of the signature (base64-decoded).
        #[deftly(netdoc(object))]
        pub signature: DirKeyCrossCertObject,
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
    ///
    /// # Syntax
    ///
    /// Version 1:
    /// ```text
    /// -----BEGIN ID SIGNATURE-----
    /// <Base64 encoded RSA signature of SHA1(DER(kp_auth_id_rsa))>
    /// -----END ID SIGNATURE-----
    /// ```
    ///
    /// Version 2:
    /// ```text
    /// -----BEGIN SIGNATURE-----
    /// <Base64 encoded RSA signature of SHA1(DER(kp_auth_id_rsa))>
    /// -----END SIGNATURE-----
    /// ```
    ///
    /// # Specifications
    ///
    /// * <https://spec.torproject.org/dir-spec/creating-key-certificates.html#item:dir-key-crosscert>
    #[derive(Debug, Clone, PartialEq, Eq, derive_more::Deref)]
    #[non_exhaustive]
    pub struct DirKeyCrossCertObject(pub Vec<u8>);

    impl DirAuthKeyCertSigned {
        /// Verifies the signature of a [`DirAuthKeyCert`].
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
        /// somehow, wrt to [`super::UncheckedAuthCert`].
        pub fn verify_selfcert(
            self,
            v3idents: &[RsaIdentity],
            pre_tolerance: Duration,
            post_tolerance: Duration,
            now: SystemTime,
        ) -> Result<DirAuthKeyCert, VerifyFailed> {
            let (body, signatures) = (self.body, self.signatures);

            // (1) Check whether this comes from a valid authority in `v3idents`.
            if !v3idents.contains(&body.fingerprint.0) {
                return Err(VerifyFailed::InsufficientTrustedSigners);
            }

            // (2) Check whether the timestamps are valid (± tolerance).
            let validity = *body.dir_key_published..=*body.dir_key_expires;
            check_validity_time_tolerance(now, validity, pre_tolerance, post_tolerance)?;

            // (3) Check whether the fingerprint and long-term identity key match.
            if body.dir_identity_key.to_rsa_identity() != *body.fingerprint {
                return Err(VerifyFailed::Inconsistent);
            }

            // (4) Check the cross-certificate (proof-of-ownership of signing key).
            body.dir_signing_key.verify(
                body.fingerprint.0.as_bytes(),
                &body.dir_key_crosscert.signature,
            )?;

            // (5) Check the outer certificate (proof-of-ownership of identity key).
            body.dir_identity_key.verify(
                &signatures.dir_key_certification.hash,
                &signatures.dir_key_certification.signature,
            )?;

            Ok(body)
        }
    }

    impl NormalItemArgument for DirKeyCertificateVersion {}

    impl ItemObjectParseable for DirKeyCrossCertObject {
        fn check_label(label: &str) -> Result<(), ErrorProblem> {
            match label {
                "SIGNATURE" | "ID SIGNATURE" => Ok(()),
                _ => Err(ErrorProblem::ObjectIncorrectLabel),
            }
        }

        fn from_bytes(input: &[u8]) -> Result<Self, ErrorProblem> {
            Ok(Self(input.to_vec()))
        }
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
            cert.sk_fingerprint().to_string(),
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
    mod tmp {
        use std::{
            fs::File,
            io::Read,
            path::Path,
            str::FromStr,
            time::{Duration, SystemTime},
        };

        use crate::{
            parse2::{self, ErrorProblem, ParseError, ParseInput, VerifyFailed},
            types::{self, Iso8601TimeSp},
        };

        use super::super::tmp::*;
        use base64ct::{Base64, Encoding};
        use derive_deftly::Deftly;
        use digest::Digest;
        use tor_llcrypto::{
            d::Sha1,
            pk::rsa::{self, RsaIdentity},
        };

        /// Reads a b64 encoded file and returns its content encoded and decoded.
        fn read_b64<P: AsRef<Path>>(path: P) -> (String, Vec<u8>) {
            let mut encoded = String::new();
            File::open(path)
                .unwrap()
                .read_to_string(&mut encoded)
                .unwrap();
            let mut decoded = Vec::new();
            base64ct::Decoder::<Base64>::new_wrapped(encoded.as_bytes(), 64)
                .unwrap()
                .decode_to_end(&mut decoded)
                .unwrap();

            (encoded, decoded)
        }

        /// Converts PEM to DER (without BEGIN and END lines).
        fn to_der(s: &str) -> Vec<u8> {
            let mut r = Vec::new();
            for line in s.lines() {
                r.extend(Base64::decode_vec(line).unwrap());
            }
            r
        }

        /// Tests whether a [`DirKeyCrossCert`] can be parsed properly.
        #[test]
        fn dir_auth_cross_cert() {
            #[derive(Debug, Clone, PartialEq, Eq, Deftly)]
            #[derive_deftly(NetdocParseable)]
            struct Dummy {
                dir_key_crosscert: DirKeyCrossCert,
            }

            let (encoded, decoded) = read_b64("testdata2/authcert-longclaw-crosscert-b64");

            // Try with `SIGNATURE`.
            let cert = format!(
                "dir-key-crosscert\n-----BEGIN SIGNATURE-----\n{encoded}\n-----END SIGNATURE-----"
            );
            let res = parse2::parse_netdoc::<Dummy>(&ParseInput::new(&cert, "")).unwrap();
            assert_eq!(
                res,
                Dummy {
                    dir_key_crosscert: DirKeyCrossCert {
                        signature: DirKeyCrossCertObject(decoded.clone())
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
                    dir_key_crosscert: DirKeyCrossCert {
                        signature: DirKeyCrossCertObject(decoded.clone())
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
        fn dir_auth_key_cert_signatures() {
            let (encoded, decoded) = read_b64("testdata2/authcert-longclaw-signature-b64");
            let cert = format!(
                "dir-key-certification\n-----BEGIN SIGNATURE-----\n{encoded}\n-----END SIGNATURE-----"
            );
            let hash: [u8; 20] = Sha1::digest("dir-key-certification\n").into();

            let res = parse2::parse_netdoc::<DirAuthKeyCertSignatures>(&ParseInput::new(&cert, ""))
                .unwrap();
            assert_eq!(
                res,
                DirAuthKeyCertSignatures {
                    dir_key_certification: DirKeyCertification {
                        signature: decoded.clone(),
                        hash
                    }
                }
            );

            // Test incorrect label.
            let cert = format!(
                "dir-key-certification\n-----BEGIN ID SIGNATURE-----\n{encoded}\n-----END ID SIGNATURE-----"
            );
            let res = parse2::parse_netdoc::<DirAuthKeyCertSignatures>(&ParseInput::new(&cert, ""));
            match res {
                Err(ParseError {
                    problem: ErrorProblem::ObjectIncorrectLabel,
                    doctype: "",
                    file: _,
                    lno: 1,
                    column: None,
                }) => {}
                other => panic!("not expected error {other:#?}"),
            }

            // Test additional args.
            let cert = format!(
                "dir-key-certification arg1\n-----BEGIN SIGNATURE-----\n{encoded}\n-----END SIGNATURE-----"
            );
            let res = parse2::parse_netdoc::<DirAuthKeyCertSignatures>(&ParseInput::new(&cert, ""));
            match res {
                Err(ParseError {
                    problem: ErrorProblem::UnexpectedArgument { column: 23 },
                    doctype: "",
                    file: _,
                    lno: 1,
                    column: Some(23),
                }) => {}
                other => panic!("not expected error {other:#?}"),
            }
        }

        #[test]
        fn dir_auth_cert() {
            // This is longclaw.

            let mut input = String::new();
            File::open("testdata2/authcert-longclaw-full")
                .unwrap()
                .read_to_string(&mut input)
                .unwrap();

            let res = parse2::parse_netdoc::<DirAuthKeyCert>(&ParseInput::new(&input, "")).unwrap();
            assert_eq!(
                res,
                DirAuthKeyCert {
                    dir_key_certificate_version: DirKeyCertificateVersion::V3,
                    fingerprint: types::Fingerprint(
                        RsaIdentity::from_hex("23D15D965BC35114467363C165C4F724B64B4F66").unwrap()
                    ),
                    dir_key_published: Iso8601TimeSp::from_str("2025-08-17 20:34:03").unwrap(),
                    dir_key_expires: Iso8601TimeSp::from_str("2026-08-17 20:34:03").unwrap(),
                    dir_identity_key: rsa::PublicKey::from_der(&to_der(include_str!(
                        "../../testdata2/authcert-longclaw-id-rsa"
                    )))
                    .unwrap(),
                    dir_signing_key: rsa::PublicKey::from_der(&to_der(include_str!(
                        "../../testdata2/authcert-longclaw-sign-rsa"
                    )))
                    .unwrap(),
                    dir_key_crosscert: DirKeyCrossCert {
                        signature: DirKeyCrossCertObject(
                            read_b64("testdata2/authcert-longclaw-crosscert-b64").1
                        )
                    }
                }
            );
        }

        #[test]
        fn dir_auth_signature() {
            let res = parse2::parse_netdoc::<DirAuthKeyCertSigned>(&ParseInput::new(
                include_str!("../../testdata2/authcert-longclaw-full"),
                "",
            ))
            .unwrap();

            // Test a valid signature.
            res.clone()
                .verify_selfcert(
                    &[RsaIdentity::from_hex("23D15D965BC35114467363C165C4F724B64B4F66").unwrap()],
                    Duration::ZERO,
                    Duration::ZERO,
                    SystemTime::UNIX_EPOCH
                        .checked_add(Duration::from_secs(1762946693)) // Wed Nov 12 12:24:53 CET 2025
                        .unwrap(),
                )
                .unwrap();

            // Test with an invalid authority.
            assert_eq!(
                res.clone()
                    .verify_selfcert(
                        &[],
                        Duration::ZERO,
                        Duration::ZERO,
                        SystemTime::UNIX_EPOCH
                            .checked_add(Duration::from_secs(1762946693)) // Wed Nov 12 12:24:53 CET 2025
                            .unwrap(),
                    )
                    .unwrap_err(),
                VerifyFailed::InsufficientTrustedSigners
            );

            // Test a key too far in the future.
            assert_eq!(
                res.clone()
                    .verify_selfcert(
                        &[
                            RsaIdentity::from_hex("23D15D965BC35114467363C165C4F724B64B4F66")
                                .unwrap()
                        ],
                        Duration::ZERO,
                        Duration::ZERO,
                        SystemTime::UNIX_EPOCH,
                    )
                    .unwrap_err(),
                VerifyFailed::TooNew
            );

            // Test an almost too new.
            res.clone()
                .verify_selfcert(
                    &[RsaIdentity::from_hex("23D15D965BC35114467363C165C4F724B64B4F66").unwrap()],
                    Duration::ZERO,
                    Duration::ZERO,
                    SystemTime::UNIX_EPOCH
                        .checked_add(Duration::from_secs(1755462843)) // 2025-08-17 20:34:03
                        .unwrap(),
                )
                .unwrap();

            // Now fail when we are 1s below ...
            assert_eq!(
                res.clone()
                    .verify_selfcert(
                        &[
                            RsaIdentity::from_hex("23D15D965BC35114467363C165C4F724B64B4F66")
                                .unwrap()
                        ],
                        Duration::ZERO,
                        Duration::ZERO,
                        SystemTime::UNIX_EPOCH
                            .checked_add(Duration::from_secs(1755462842)) // 2025-08-17 20:34:02
                            .unwrap(),
                    )
                    .unwrap_err(),
                VerifyFailed::TooNew
            );

            // ... but succeed again with a clock skew tolerance.
            res.clone()
                .verify_selfcert(
                    &[RsaIdentity::from_hex("23D15D965BC35114467363C165C4F724B64B4F66").unwrap()],
                    Duration::from_secs(1),
                    Duration::ZERO,
                    SystemTime::UNIX_EPOCH
                        .checked_add(Duration::from_secs(1755462842)) // 2025-08-17 20:34:02
                        .unwrap(),
                )
                .unwrap();

            // Test a key too old.
            assert_eq!(
                res.clone()
                    .verify_selfcert(
                        &[
                            RsaIdentity::from_hex("23D15D965BC35114467363C165C4F724B64B4F66")
                                .unwrap()
                        ],
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
                .verify_selfcert(
                    &[RsaIdentity::from_hex("23D15D965BC35114467363C165C4F724B64B4F66").unwrap()],
                    Duration::ZERO,
                    Duration::ZERO,
                    SystemTime::UNIX_EPOCH
                        .checked_add(Duration::from_secs(1786998843)) // 2026-08-17 20:34:03
                        .unwrap(),
                )
                .unwrap();

            // Now fail when we are 1s above ...
            assert_eq!(
                res.clone()
                    .verify_selfcert(
                        &[
                            RsaIdentity::from_hex("23D15D965BC35114467363C165C4F724B64B4F66")
                                .unwrap()
                        ],
                        Duration::ZERO,
                        Duration::ZERO,
                        SystemTime::UNIX_EPOCH
                            .checked_add(Duration::from_secs(1786998844)) // 2026-08-17 20:34:04
                            .unwrap(),
                    )
                    .unwrap_err(),
                VerifyFailed::TooOld
            );

            // ... but succeed again with a clock skew tolerance.
            res.clone()
                .verify_selfcert(
                    &[RsaIdentity::from_hex("23D15D965BC35114467363C165C4F724B64B4F66").unwrap()],
                    Duration::ZERO,
                    Duration::from_secs(1),
                    SystemTime::UNIX_EPOCH
                        .checked_add(Duration::from_secs(1786998844)) // 2026-08-17 20:34:04
                        .unwrap(),
                )
                .unwrap();

            // Check with non-matching fingerprint and long-term identity key.
            let res = parse2::parse_netdoc::<DirAuthKeyCertSigned>(&ParseInput::new(
                include_str!("../../testdata2/authcert-longclaw-full-invalid-id-rsa"),
                "",
            ))
            .unwrap();
            assert_eq!(
                res.verify_selfcert(
                    &[RsaIdentity::from_hex("23D15D965BC35114467363C165C4F724B64B4F66").unwrap()],
                    Duration::ZERO,
                    Duration::ZERO,
                    SystemTime::UNIX_EPOCH
                        .checked_add(Duration::from_secs(1762946693)) // Wed Nov 12 12:24:53 CET 2025
                        .unwrap(),
                )
                .unwrap_err(),
                VerifyFailed::Inconsistent
            );

            // Check invalid cross-cert.
            let res = parse2::parse_netdoc::<DirAuthKeyCertSigned>(&ParseInput::new(
                include_str!("../../testdata2/authcert-longclaw-full-invalid-cross"),
                "",
            ))
            .unwrap();
            assert_eq!(
                res.verify_selfcert(
                    &[RsaIdentity::from_hex("23D15D965BC35114467363C165C4F724B64B4F66").unwrap()],
                    Duration::ZERO,
                    Duration::ZERO,
                    SystemTime::UNIX_EPOCH
                        .checked_add(Duration::from_secs(1762946693)) // Wed Nov 12 12:24:53 CET 2025
                        .unwrap(),
                )
                .unwrap_err(),
                VerifyFailed::VerifyFailed
            );

            // Check outer signature.
            let res = parse2::parse_netdoc::<DirAuthKeyCertSigned>(&ParseInput::new(
                include_str!("../../testdata2/authcert-longclaw-full-invalid-certification"),
                "",
            ))
            .unwrap();
            assert_eq!(
                res.verify_selfcert(
                    &[RsaIdentity::from_hex("23D15D965BC35114467363C165C4F724B64B4F66").unwrap()],
                    Duration::ZERO,
                    Duration::ZERO,
                    SystemTime::UNIX_EPOCH
                        .checked_add(Duration::from_secs(1762946693)) // Wed Nov 12 12:24:53 CET 2025
                        .unwrap(),
                )
                .unwrap_err(),
                VerifyFailed::VerifyFailed
            );
        }
    }
}
