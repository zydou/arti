//! network status documents: shared between votes, consensuses and md consensuses

use super::*;

use crate::types;
use authcert::DirAuthKeyCert;

mod ns_per_flavour_macros;
pub use ns_per_flavour_macros::*;

ns_per_flavour_macros::ns_export_flavoured_types! {
    NetworkStatus, NetworkStatusSigned, Router,
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
        /// H(KP\_auth\_id\_rsa)
        h_kp_auth_id_rsa: pk::rsa::RsaIdentity,
        /// H(kp\_auth\_sign\_rsa)
        h_kp_auth_sign_rsa: pk::rsa::RsaIdentity,
        /// RSA signature
        rsa_signature: Vec<u8>,
        /// Hash of the covered text
        hash: DirectorySignatureHash,
    },
    /// Unknown "hash function" name
    ///
    /// TODO torspec#350;
    /// might have been an unknown algorithm, or might be invalid hex, or soemthing.
    Unknown {},
}
define_derive_deftly! {
    /// Ad-hoc derives for [`DirectorySignatureHash`] impls, avoiding copypasta bugs
    DirectorySignatureHash expect items, beta_deftly:

    impl $ttype {
        /// If `algorithm` is an algorithm name, calculate the hash
        fn parse_keyword_and_hash(algorithm: &str, body: &SignatureHashInputs) -> Option<Self> {
            Some(match algorithm {
              $(
                ${concat ${kebab_case $vname}} => {
                    let mut h = tor_llcrypto::d::$vname::new();
                    h.update(body.body().body());
                    h.update(body.signature_item_kw_spc);
                    Self::$vname(h.finalize().into())
                }
              )
                _ => return None,
            })
        }

        fn hash_slice_for_verification(&self) -> &[u8] {
            match self { $(
                $vpat => f_0,
            ) }
        }
    }
}

/// `directory-signature` hash algorithm argument
#[derive(Clone, Copy, Debug, Eq, PartialEq, strum::EnumString, Deftly)]
#[derive_deftly(DirectorySignatureHash)]
#[non_exhaustive]
pub enum DirectorySignatureHash {
    /// SHA-1
    Sha1([u8; 20]),
    /// SHA-256
    Sha256([u8; 32]),
}

/// Unsupported `vote-status` value
///
/// This message is not normally actually shown since our `ErrorProblem` doesn't contain it.
#[derive(Clone, Debug, Error)]
#[non_exhaustive]
#[error("invalid value for vote-status in network status document")]
pub struct InvalidNetworkStatusVoteStatus {}

impl SignatureItemParseable for NdiDirectorySignature {
    // TODO torspec#350.  That's why this manual impl is needed
    fn from_unparsed_and_body<'s>(
        mut input: UnparsedItem<'s>,
        document_body: &SignatureHashInputs<'_>,
    ) -> Result<Self, EP> {
        let object = input.object();
        let args = input.args_mut();
        let maybe_algorithm = args.clone().next().ok_or(EP::MissingArgument {
            field: "algorithm/h_kp_auth_id_rsa",
        })?;

        let hash = if let Some(hash) =
            DirectorySignatureHash::parse_keyword_and_hash(maybe_algorithm, document_body)
        {
            let _: &str = args.next().expect("we just peeked");
            hash
        } else if maybe_algorithm
            .find(|c: char| !c.is_ascii_hexdigit())
            .is_some()
        {
            // Not hex.  Must be some unknown algorithm.
            // There might be Object, but don't worry if not.
            return Ok(NdiDirectorySignature::Unknown {});
        } else {
            DirectorySignatureHash::parse_keyword_and_hash("sha1", document_body)
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
            rsa_signature,
            h_kp_auth_id_rsa: fingerprint_arg("h_kp_auth_id_rsa")?,
            h_kp_auth_sign_rsa: fingerprint_arg("h_kp_auth_sign_rsa")?,
            hash,
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
    signatures: &[NdiDirectorySignature],
    trusted: &[pk::rsa::RsaIdentity],
    certs: &[&DirAuthKeyCert],
    threshold: usize,
) -> Result<(), VF> {
    let mut ok = HashSet::<pk::rsa::RsaIdentity>::new();

    for sig in signatures {
        match sig {
            NdiDirectorySignature::Known {
                hash,
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

                let h = hash.hash_slice_for_verification();

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
