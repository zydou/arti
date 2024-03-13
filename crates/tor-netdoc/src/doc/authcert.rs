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

use once_cell::sync::Lazy;

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
static AUTHCERT_RULES: Lazy<SectionRules<AuthCertKwd>> = Lazy::new(|| {
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
    /// The long-term RSA identity key for this authority
    identity_key: rsa::PublicKey,
    /// The medium-term RSA signing key for this authority
    signing_key: rsa::PublicKey,
    /// Declared time when this certificate was published
    published: time::SystemTime,
    /// Declared time when this certificate expires.
    expires: time::SystemTime,

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
        let mut reader = NetDocReader::new(s);
        let body = AUTHCERT_RULES.parse(&mut reader)?;
        reader.should_be_exhausted()?;
        AuthCert::from_body(&body, s).map_err(|e| e.within(s))
    }

    /// Return an iterator yielding authority certificates from a string.
    pub fn parse_multiple(s: &str) -> impl Iterator<Item = Result<UncheckedAuthCert>> + '_ {
        use AuthCertKwd::*;
        let sections = NetDocReader::new(s)
            .batching_split_before_loose(|item| item.is_ok_with_kwd(DIR_KEY_CERTIFICATE_VERSION));
        sections
            .map(|mut section| {
                let body = AUTHCERT_RULES.parse(&mut section)?;
                AuthCert::from_body(&body, s)
            })
            .map(|r| r.map_err(|e| e.within(s)))
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

        let res: Vec<Result<_>> = AuthCert::parse_multiple(&data).collect();

        // We should recover from the failed case and read the next data fine.
        assert!(res[0].is_err());
        assert!(res[1].is_ok());
        assert_eq!(res.len(), 2);
    }

    #[test]
    fn test_recovery_2() {
        let mut data = bad_data("bad-version");
        data += TESTDATA;

        let res: Vec<Result<_>> = AuthCert::parse_multiple(&data).collect();

        // We should recover from the failed case and read the next data fine.
        assert!(res[0].is_err());
        assert!(res[1].is_ok());
        assert_eq!(res.len(), 2);
    }
}
