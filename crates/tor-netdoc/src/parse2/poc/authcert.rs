//! Directory Authority Key Certificates

use super::*;

/// SHA1 hash as used in directory authority certificates
//
// We don't have a better name for this!
type DirKeyCertificateHash = [u8; 20];

pub use crate::doc::authcert::AuthCert as DirAuthKeyCert;
pub use crate::doc::authcert::AuthCertSigned as DirAuthKeyCertSigned;

impl DirAuthKeyCertSigned {
    /// Verify the signatures (and check validity times)
    ///
    /// # Security considerations
    ///
    /// The caller must check that the KP_auth_id is correct/relevant.
    pub fn verify_selfcert(self, now: SystemTime) -> Result<DirAuthKeyCert, VF> {
        // verify main document signature (and timestamp)
        let hash = self.signatures.dir_key_certification.hash;
        let body = &self.inspect_unverified().0;

        let validity = body.dir_key_published.0..=body.dir_key_expires.0;
        check_validity_time(now, validity)?;
        body.dir_identity_key
            .verify(&hash, &self.signatures.dir_key_certification.signature)?;

        // double-check the id hash
        if *body.fingerprint != body.dir_identity_key.to_rsa_identity() {
            return Err(VF::Inconsistent);
        }

        // verify cross-cert
        let h_kp_auth_id_rsa: DirKeyCertificateHash =
            tor_llcrypto::d::Sha1::digest(body.dir_identity_key.to_der()).into();
        // Cross-cert has no timestamp.  Whatever.
        body.dir_signing_key
            .verify(&h_kp_auth_id_rsa, &body.dir_key_crosscert.signature)?;

        Ok(self.unwrap_unverified().0)
    }
}
