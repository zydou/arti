//! General collection of types.
//!
//! This module serves as a collection of types useful for the operation of a
//! directory server that are not related to the database, in which case they
//! belong to the respective [`crate::database`] module.

use tor_checkable::TimeRangeBound;
use tor_llcrypto::pk::rsa::RsaIdentity;
use tor_netdoc::{
    doc::{
        authcert::{AuthCert, AuthCertKeyIds},
        netstatus::{
            ConsensusFlavor, ConsensusVerifiabilityError, ConsensusVerifyFailed, Lifetime, md,
            plain,
        },
    },
    parse2::{NetdocParseable, NetdocParseableUnverified},
};

use crate::database::{Sha1, Sha256};

/// Generic trait representing a flavored verified consensus.
///
/// Similar to [`FlavoredConsensusUnverified`] and obtained from it.
pub(crate) trait FlavoredConsensusBody: Clone {
    /// Returns the [`Lifetime`] of this body.
    fn lifetime(&self) -> &Lifetime;

    /// Returns the doc digests for every router.
    ///
    /// These may be duplicate so ensure to properly handle conflicts.
    // TODO DIRMIRROR: This module should probably be moved into a submodule
    // of database.rs alongside other types found in database.rs.
    //
    // Orginally, the types here had no relation to database implementations,
    // but this does not work out long-term, as we see by this signature.
    fn doc_digests(&self) -> impl Iterator<Item = (Option<Sha1>, Option<Sha256>)>;
}

/// Generic trait representing the signatures of a consensus.
///
/// Similar to [`FlavoredConsensusUnverified`] and obtained from it.
pub(crate) trait FlavoredConsensusSignatures: Clone {
    /// Returns the [`AuthCertKeyIds`] of all authority certificates in the signatures.
    // TODO DIRMIRROR: Obtain this from the respective error variant returned by
    // .can_verify().
    // TODO: The respective implementations are repetitive, can we do better?
    fn signatories(&self) -> Vec<AuthCertKeyIds>;
}

/// Generic trait representing a flavored unverified consensus.
///
/// Required because in certain parts of the code, the exact flavor of the
/// consensus does not matter.
///
/// See [`FlavoredConsensusBody`] for the verified variant of it.
pub(crate) trait FlavoredConsensusUnverified:
    NetdocParseableUnverified<Body: FlavoredConsensusBody, Signatures: FlavoredConsensusSignatures>
    + NetdocParseable
    + Clone
{
    /// Returns the [`ConsensusFlavor`] of this type.
    fn flavor() -> ConsensusFlavor;

    /// Whether or not we have all required authority certificates to verify
    /// the consensus.
    fn can_verify(
        &self,
        trusted_authorities: &[RsaIdentity],
        certs_already: &[AuthCert],
    ) -> Result<(), ConsensusVerifiabilityError>;

    /// Verifies the consensus, returning the body.
    fn verify(
        self,
        trusted_authorities: &[RsaIdentity],
        certs_already: &[AuthCert],
    ) -> Result<TimeRangeBound<Self::Body>, ConsensusVerifyFailed>;

    /// Returns the signatures contained inside.
    ///
    /// It corresponds to accessing the publicly available T::sigs which is
    /// guaranteed to be present due to derive logic.
    ///
    /// Functionally equivalent to accessing the signatures through
    /// [`NetdocParseableUnverified::inspect_unverified()`], yet it tries to
    /// provide a safer semantic around it.
    fn sigs(&self) -> &Self::Signatures {
        &self.inspect_unverified().1.sigs
    }
}

impl FlavoredConsensusBody for plain::NetworkStatus {
    fn lifetime(&self) -> &Lifetime {
        &self.preamble.lifetime
    }

    fn doc_digests(&self) -> impl Iterator<Item = (Option<Sha1>, Option<Sha256>)> {
        self.routers
            .iter()
            .map(|r| (Some(Sha1::from(*r.doc_digest())), None))
    }
}

impl FlavoredConsensusBody for md::NetworkStatus {
    fn lifetime(&self) -> &Lifetime {
        &self.preamble.lifetime
    }

    fn doc_digests(&self) -> impl Iterator<Item = (Option<Sha1>, Option<Sha256>)> {
        self.routers
            .iter()
            .map(|r| (None, Some(Sha256::from(*r.doc_digest()))))
    }
}

impl FlavoredConsensusSignatures for plain::NetworkStatusSignatures {
    fn signatories(&self) -> Vec<AuthCertKeyIds> {
        self.directory_signature
            .iter()
            .map(|sig| sig.key_ids)
            .collect()
    }
}

impl FlavoredConsensusSignatures for md::NetworkStatusSignatures {
    fn signatories(&self) -> Vec<AuthCertKeyIds> {
        self.directory_signature
            .iter()
            .map(|sig| sig.key_ids)
            .collect()
    }
}

impl FlavoredConsensusUnverified for plain::NetworkStatusUnverified {
    fn flavor() -> ConsensusFlavor {
        ConsensusFlavor::Plain
    }

    fn can_verify(
        &self,
        trusted_authorities: &[RsaIdentity],
        certs_already: &[AuthCert],
    ) -> Result<(), ConsensusVerifiabilityError> {
        self.can_verify(trusted_authorities, certs_already)
    }

    fn verify(
        self,
        trusted_authorities: &[RsaIdentity],
        certs_already: &[AuthCert],
    ) -> Result<TimeRangeBound<Self::Body>, ConsensusVerifyFailed> {
        self.verify(trusted_authorities, certs_already)
    }
}

impl FlavoredConsensusUnverified for md::NetworkStatusUnverified {
    fn flavor() -> ConsensusFlavor {
        ConsensusFlavor::Microdesc
    }

    fn can_verify(
        &self,
        trusted_authorities: &[RsaIdentity],
        certs_already: &[AuthCert],
    ) -> Result<(), ConsensusVerifiabilityError> {
        self.can_verify(trusted_authorities, certs_already)
    }

    fn verify(
        self,
        trusted_authorities: &[RsaIdentity],
        certs_already: &[AuthCert],
    ) -> Result<TimeRangeBound<Self::Body>, ConsensusVerifyFailed> {
        self.verify(trusted_authorities, certs_already)
    }
}
