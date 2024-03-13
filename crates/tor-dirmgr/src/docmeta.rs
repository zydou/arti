//! Types to describe information about other downloaded directory
//! documents, without necessarily having the full document.
//!
//! These types are all local within tor-dirmgr.  They're used so that
//! the storage code doesn't need to know about all of the parsed
//! types from tor-netdoc.

use digest::Digest;
use tor_llcrypto as ll;
use tor_netdoc::doc::{
    authcert::{AuthCert, AuthCertKeyIds},
    netstatus::{Lifetime, MdConsensus, UnvalidatedMdConsensus},
};

use std::time::SystemTime;

/// Information about a consensus that we have in storage.
///
/// This information is ordinarily derived from the consensus, but doesn't
/// have to be.
#[derive(Debug, Clone)]
pub(crate) struct ConsensusMeta {
    /// The time over which the consensus is valid.
    lifetime: Lifetime,
    /// A sha3-256 digest of the signed portion of the consensus: used for
    /// fetching diffs.
    sha3_256_of_signed: [u8; 32],
    /// A sha3-256 digest of the entirety of the consensus: used for
    /// naming the file.
    sha3_256_of_whole: [u8; 32],
}

impl ConsensusMeta {
    /// Create a new ConsensusMeta
    pub(crate) fn new(
        lifetime: Lifetime,
        sha3_256_of_signed: [u8; 32],
        sha3_256_of_whole: [u8; 32],
    ) -> Self {
        ConsensusMeta {
            lifetime,
            sha3_256_of_signed,
            sha3_256_of_whole,
        }
    }
    /// Derive a new ConsensusMeta from an UnvalidatedMdConsensus and the
    /// text of its signed portion.
    pub(crate) fn from_unvalidated(
        signed_part: &str,
        remainder: &str,
        con: &UnvalidatedMdConsensus,
    ) -> Self {
        let lifetime = con.peek_lifetime().clone();
        let (sd, wd) = sha3_dual(signed_part, remainder);
        ConsensusMeta::new(lifetime, sd, wd)
    }
    /// Derive a new ConsensusMeta from a MdConsensus and the text of its
    /// signed portion.
    #[allow(unused)]
    pub(crate) fn from_consensus(signed_part: &str, remainder: &str, con: &MdConsensus) -> Self {
        let lifetime = con.lifetime().clone();
        let (sd, wd) = sha3_dual(signed_part, remainder);
        ConsensusMeta::new(lifetime, sd, wd)
    }
    /// Return the lifetime of this ConsensusMeta
    pub(crate) fn lifetime(&self) -> &Lifetime {
        &self.lifetime
    }
    /// Return the sha3-256 of the signed portion of this consensus.
    pub(crate) fn sha3_256_of_signed(&self) -> &[u8; 32] {
        &self.sha3_256_of_signed
    }
    /// Return the sha3-256 of the entirety of this consensus.
    pub(crate) fn sha3_256_of_whole(&self) -> &[u8; 32] {
        &self.sha3_256_of_whole
    }
}

/// Compute the sha3-256 digests of signed_part on its own, and of
/// signed_part concatenated with remainder.
fn sha3_dual(signed_part: impl AsRef<[u8]>, remainder: impl AsRef<[u8]>) -> ([u8; 32], [u8; 32]) {
    let mut d = ll::d::Sha3_256::new();
    d.update(signed_part.as_ref());
    let sha3_of_signed = d.clone().finalize().into();
    d.update(remainder.as_ref());
    let sha3_of_whole = d.finalize().into();
    (sha3_of_signed, sha3_of_whole)
}

/// Information about an authority certificate that we have in storage.
///
/// This information is ordinarily derived from the authority cert, but it
/// doesn't have to be.
#[derive(Clone, Debug)]
pub(crate) struct AuthCertMeta {
    /// Key IDs (identity and signing) for the certificate.
    ids: AuthCertKeyIds,
    /// Time of publication.
    published: SystemTime,
    /// Expiration time.
    expires: SystemTime,
}

impl AuthCertMeta {
    /// Construct a new AuthCertMeta from its components
    pub(crate) fn new(ids: AuthCertKeyIds, published: SystemTime, expires: SystemTime) -> Self {
        AuthCertMeta {
            ids,
            published,
            expires,
        }
    }

    /// Construct a new AuthCertMeta from a certificate.
    pub(crate) fn from_authcert(cert: &AuthCert) -> Self {
        AuthCertMeta::new(*cert.key_ids(), cert.published(), cert.expires())
    }

    /// Return the key IDs for this certificate
    pub(crate) fn key_ids(&self) -> &AuthCertKeyIds {
        &self.ids
    }
    /// Return the published time for this certificate
    pub(crate) fn published(&self) -> SystemTime {
        self.published
    }
    /// Return the expiration time for this certificate
    pub(crate) fn expires(&self) -> SystemTime {
        self.expires
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

    #[test]
    fn t_sha3_dual() {
        let s = b"Loarax ipsum gruvvulus thneed amet, snergelly once-ler lerkim, sed do barbaloot tempor gluppitus ut labore et truffula magna aliqua. Ut enim ad grickle-grass veniam, quis miff-muffered ga-zumpco laboris nisi ut cruffulus ex ea schloppity consequat. Duis aute snarggle in swomeeswans in voluptate axe-hacker esse rippulus crummii eu moof nulla snuvv.";

        let sha3_of_whole: [u8; 32] = ll::d::Sha3_256::digest(s).into();

        for idx in 0..s.len() {
            let sha3_of_part: [u8; 32] = ll::d::Sha3_256::digest(&s[..idx]).into();
            let (a, b) = sha3_dual(&s[..idx], &s[idx..]);
            assert_eq!(a, sha3_of_part);
            assert_eq!(b, sha3_of_whole);
        }
    }
}
