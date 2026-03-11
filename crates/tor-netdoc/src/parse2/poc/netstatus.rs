//! network status documents: shared between votes, consensuses and md consensuses

use super::*;

use crate::types;
use authcert::DirAuthKeyCert;

mod ns_per_flavour_macros;
pub use ns_per_flavour_macros::*;

ns_per_flavour_macros::ns_export_flavoured_types! {
    NetworkStatus, NetworkStatusUnverified, Router,
}

/// `network-status-version` version value
#[derive(Debug, Clone, Copy, Eq, PartialEq, strum::EnumString, strum::Display)]
#[non_exhaustive]
pub enum NdaNetworkStatusVersion {
    /// The currently supported version, `3`
    #[strum(serialize = "3")]
    V3,
}

impl NormalItemArgument for NdaNetworkStatusVersion {}

/// `params` value
#[derive(Clone, Debug, Default, Deftly)]
#[derive_deftly(ItemValueParseable)]
#[non_exhaustive]
pub struct NdiParams {
    // Not implemented.
}

/// `r` sub-document
#[derive(Deftly, Clone, Debug)]
#[derive_deftly(ItemValueParseable)]
#[non_exhaustive]
pub struct NdiR {
    /// nickname
    pub nickname: types::Nickname,
    /// identity
    pub identity: String, // In non-demo, use a better type
}

/// `directory-signature` value
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum NdiDirectorySignature {
    /// Known "hash function" name
    Known {
        /// Hash algorithm
        hash_algo: DirectorySignatureHashAlgo,
        /// H(KP\_auth\_id\_rsa)
        h_kp_auth_id_rsa: pk::rsa::RsaIdentity,
        /// H(kp\_auth\_sign\_rsa)
        h_kp_auth_sign_rsa: pk::rsa::RsaIdentity,
        /// RSA signature
        rsa_signature: Vec<u8>,
    },
    /// Unknown "hash function" name
    ///
    /// TODO torspec#350;
    /// might have been an unknown algorithm, or might be invalid hex, or soemthing.
    Unknown {},
}
define_derive_deftly! {
    /// Ad-hoc derives for [`DirectorySignatureHash`] impls, avoiding copypasta bugs
    ///
    /// # Input
    ///
    ///  * `pub enum DirectorySignatureHashAlgo`
    ///  * Unit variants
    ///  * Each variant with `#[deftly(hash_len = "N")]`
    ///    where `N` is the digest length in bytes.
    ///
    /// # Generated code
    ///
    ///  * `pub enum DirectorySignaturesHashesAccu`,
    ///    with each variant a 1-tuple containing `Option<[u8; N]>`.
    ///    (These are `None` if this hash has not been computed yet.)
    ///
    ///  * `DirectorySignaturesHashesAccu::parse_keyword_and_hash`
    ///
    ///  * `DirectorySignaturesHashesAccu::hash_slice_for_verification`
    DirectorySignatureHashesAccu expect items, beta_deftly:

    ${define FNAME ${paste ${snake_case $vname}} }

    /// `directory-signature`a hash algorithm argument
    #[derive(Clone, Copy, Default, Debug, Eq, PartialEq, Deftly)]
    #[derive_deftly(AsMutSelf)]
    #[non_exhaustive]
    pub struct DirectorySignaturesHashesAccu {
      $(
        ${vattrs doc}
        $FNAME: Option<[u8; ${vmeta(hash_len) as expr}]>,
      )
    }

    impl DirectorySignaturesHashesAccu {
        /// If `algorithm` is an algorithm name, calculate the hash
        ///
        /// Otherwise, return `None`.
        fn parse_keyword_and_hash(
            &mut self,
            algorithm: &str,
            body: &SignatureHashInputs,
        ) -> Option<$ttype> {
            Some(match algorithm {
              $(
                ${concat $FNAME} => {
                    let mut h = tor_llcrypto::d::$vname::new();
                    h.update(body.body().body());
                    h.update(body.signature_item_kw_spc);
                    self.$FNAME = Some(h.finalize().into());
                    $vtype
                }
              )
                _ => return None,
            })
        }

        /// Return the hash value for this algorithm, as a slice
        ///
        /// `None` if the value wasn't computed.
        /// That shouldn't happen.
        fn hash_slice_for_verification(&self, algo: $ttype) -> Option<&[u8]> {
            match algo { $(
                $vtype => Some(self.$FNAME.as_ref()?),
            ) }
        }
    }
}

/// `directory-signature` hash algorithm argument
#[derive(Clone, Copy, Debug, Eq, PartialEq, strum::EnumString, Deftly)]
#[derive_deftly(DirectorySignatureHashesAccu)]
#[non_exhaustive]
pub enum DirectorySignatureHashAlgo {
    /// SHA-1
    #[deftly(hash_len = "20")]
    Sha1,
    /// SHA-256
    #[deftly(hash_len = "32")]
    Sha256,
}

/// Unsupported `vote-status` value
///
/// This message is not normally actually shown since our `ErrorProblem` doesn't contain it.
#[derive(Clone, Debug, Error)]
#[non_exhaustive]
#[error("invalid value for vote-status in network status document")]
pub struct InvalidNetworkStatusVoteStatus {}

impl SignatureItemParseable for NdiDirectorySignature {
    type HashAccu = DirectorySignaturesHashesAccu;

    // TODO torspec#350.  That's why this manual impl is needed
    fn from_unparsed_and_body<'s>(
        mut input: UnparsedItem<'s>,
        document_body: &SignatureHashInputs<'_>,
        hashes: &mut DirectorySignaturesHashesAccu,
    ) -> Result<Self, EP> {
        let object = input.object();
        let args = input.args_mut();
        let maybe_algorithm = args.clone().next().ok_or(EP::MissingArgument {
            field: "algorithm/h_kp_auth_id_rsa",
        })?;

        let hash_algo =
            if let Some(algo) = hashes.parse_keyword_and_hash(maybe_algorithm, document_body) {
                let _: &str = args.next().expect("we just peeked");
                algo
            } else if maybe_algorithm
                .find(|c: char| !c.is_ascii_hexdigit())
                .is_some()
            {
                // Not hex.  Must be some unknown algorithm.
                // There might be Object, but don't worry if not.
                return Ok(NdiDirectorySignature::Unknown {});
            } else {
                hashes
                    .parse_keyword_and_hash("sha1", document_body)
                    .expect("sha1 is not valid?")
            };

        let rsa_signature = object.ok_or(EP::MissingObject)?.decode_data()?;

        let mut fingerprint_arg = |field: &'static str| {
            (|| {
                args.next()
                    .ok_or(AE::Missing)?
                    .parse::<types::Fingerprint>()
                    .map_err(|_e| AE::Invalid)
                    .map(pk::rsa::RsaIdentity::from)
            })()
            .map_err(args.error_handler(field))
        };

        Ok(NdiDirectorySignature::Known {
            hash_algo,
            rsa_signature,
            h_kp_auth_id_rsa: fingerprint_arg("h_kp_auth_id_rsa")?,
            h_kp_auth_sign_rsa: fingerprint_arg("h_kp_auth_sign_rsa")?,
        })
    }
}

/// Meat of the verification functions for network documents
///
/// Checks that at least `threshold` members of `trusted`
/// have signed this document (in `signatures`),
/// via some cert(s) in `certs`.
///
/// Does not check validity time.
fn verify_general_timeless(
    hashes: &DirectorySignaturesHashesAccu,
    signatures: &[NdiDirectorySignature],
    trusted: &[pk::rsa::RsaIdentity],
    certs: &[&DirAuthKeyCert],
    threshold: usize,
) -> Result<(), VF> {
    let mut ok = HashSet::<pk::rsa::RsaIdentity>::new();

    for sig in signatures {
        match sig {
            NdiDirectorySignature::Known {
                hash_algo,
                h_kp_auth_id_rsa,
                h_kp_auth_sign_rsa,
                rsa_signature,
            } => {
                let Some(authority) = ({
                    trusted
                        .iter()
                        .find(|trusted| **trusted == *h_kp_auth_id_rsa)
                }) else {
                    // unknown kp_auth_id_rsa, ignore it
                    continue;
                };
                let Some(cert) = ({
                    certs
                        .iter()
                        .find(|cert| cert.dir_signing_key.to_rsa_identity() == *h_kp_auth_sign_rsa)
                }) else {
                    // no cert for this kp_auth_sign_rsa, ignore it
                    continue;
                };

                let h = hashes
                    .hash_slice_for_verification(*hash_algo)
                    .ok_or(VF::Bug)?;

                let () = cert.dir_signing_key.verify(h, rsa_signature)?;

                ok.insert(*authority);
            }
            NdiDirectorySignature::Unknown { .. } => {}
        }
    }

    if ok.len() < threshold {
        return Err(VF::InsufficientTrustedSigners);
    }

    Ok(())
}
