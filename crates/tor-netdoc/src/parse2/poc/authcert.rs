//! Directory Authority Key Certificates

use super::*;

use crate::types;

/// SHA1 hash as used in directory authority certificates
//
// We don't have a better name for this!
type DirKeyCertificateHash = [u8; 20];

/// A directory authority key certificate (body)
///
/// <https://spec.torproject.org/dir-spec/creating-key-certificates.html>
#[derive(Clone, Debug, Deftly)]
#[derive_deftly(NetdocParseable, NetdocSigned)]
#[non_exhaustive]
pub struct DirAuthKeyCert {
    /// Heading line
    pub dir_key_certificate_version: (NdaDirKeyCertificateVersion,),

    /// H(KP_auth_id_rsa)
    #[deftly(netdoc(keyword = "fingerprint"))]
    pub h_kp_auth_id_rsa: (types::Fingerprint,),

    /// KP_auth_id_rsa
    #[deftly(netdoc(keyword = "dir-identity-key"))]
    pub kp_auth_id_rsa: pk::rsa::PublicKey,

    /// cert generation time
    pub dir_key_published: (NdaSystemTimeDeprecatedSyntax,),

    /// cert expiration time
    pub dir_key_expires: (NdaSystemTimeDeprecatedSyntax,),

    /// KP_auth_sign_rsa
    #[deftly(netdoc(keyword = "dir-signing-key"))]
    pub kp_auth_sign_rsa: pk::rsa::PublicKey,

    /// Reverse certificate ("cross certificate"), by KP_auth_sign_rsa on KP_auth_id_rsa
    pub dir_key_crosscert: DirAuthCrossCert,
}

/// Signature section of a directory authority key certificate
#[derive(Clone, Debug, Deftly)]
#[derive_deftly(NetdocParseable)]
#[deftly(netdoc(signatures))]
#[non_exhaustive]
pub struct DirAuthKeyCertSignatures {
    /// Signature by KP_auth_id_rsa
    pub dir_key_certification: DirAuthCertRsaSignature,
}

/// `network-status-version` version value
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, strum::EnumString, strum::Display)]
#[non_exhaustive]
pub enum NdaDirKeyCertificateVersion {
    /// The currently supported version, `3`
    #[strum(serialize = "3")]
    V3,
}

impl NormalItemArgument for NdaDirKeyCertificateVersion {}

/// RSA signature
///
/// Used for `dir-key-certification`
///
/// <https://spec.torproject.org/dir-spec/netdoc.html#signing>
#[derive(Deftly)]
#[derive_deftly(ItemValueParseable)]
#[deftly(netdoc(no_extra_args))]
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
#[non_exhaustive]
pub struct DirAuthCertRsaSignature {
    /// The bytes of the signature (base64-decoded)
    #[deftly(netdoc(object(label = "SIGNATURE"), with = "crate::parse2::raw_data_object"))]
    pub signature: Vec<u8>,

    /// The hash of the document
    #[deftly(netdoc(sig_hash = "whole_keyword_line_sha1"))]
    pub hash: DirKeyCertificateHash,
}

impl DirAuthKeyCertSigned {
    /// Verify the signatures (and check validity times)
    ///
    /// # Security considerations
    ///
    /// The caller must check that the KP_auth_id is correct/relevant.
    pub fn verify_selfcert(self, now: SystemTime) -> Result<DirAuthKeyCert, VF> {
        // verify main document signature (and timestamp)
        let hash = self.signatures.dir_key_certification.hash;

        let validity = *self.body.dir_key_published.0..=*self.body.dir_key_expires.0;
        check_validity_time(now, validity)?;
        self.body
            .kp_auth_id_rsa
            .verify(&hash, &self.signatures.dir_key_certification.signature)?;

        // double-check the id hash
        if *self.body.h_kp_auth_id_rsa.0 != self.body.kp_auth_id_rsa.to_rsa_identity() {
            return Err(VF::Inconsistent);
        }

        // verify cross-cert
        let h_kp_auth_id_rsa: DirKeyCertificateHash =
            tor_llcrypto::d::Sha1::digest(self.body.kp_auth_id_rsa.to_der()).into();
        // Cross-cert has no timestamp.  Whatever.
        self.body
            .kp_auth_sign_rsa
            .verify(&h_kp_auth_id_rsa, &self.body.dir_key_crosscert.signature)?;

        Ok(self.body)
    }
}

/// RSA signature of subset of the document data, with anomalous label
///
/// Used for `dir-key-crosscert`
#[derive(Debug, Clone, Hash, Eq, PartialEq, derive_more::Deref)]
#[non_exhaustive]
pub struct DirAuthCrossCert {
    /// The bytes of the signature (base64-decoded)
    pub signature: Vec<u8>,
}

impl ItemValueParseable for DirAuthCrossCert {
    fn from_unparsed(mut item: UnparsedItem<'_>) -> Result<Self, ErrorProblem> {
        item.args_mut().reject_extra_args()?;

        let object = item.object().ok_or(EP::MissingObject)?;
        match object.label() {
            "SIGNATURE" | "ID SIGNATURE" => Ok(()),
            _other => Err(EP::ObjectIncorrectLabel),
        }?;
        let signature = object.decode_data()?;
        Ok(DirAuthCrossCert { signature })
    }
}
