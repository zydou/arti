//! General collection of types.
//!
//! This module serves as a collection of types useful for the operation of a
//! directory server that are not related to the database, in which case they
//! belong to the respective [`crate::database`] module.

use tor_netdoc::{
    doc::{
        authcert::AuthCertKeyIds,
        netstatus::{ConsensusFlavor, md, plain},
    },
    parse2::{NetdocParseable, NetdocParseableUnverified},
};

/// Generic trait representing a flavored verified consensus.
///
/// Similar to [`FlavoredConsensusUnverified`] and obtained from it.
pub(crate) trait FlavoredConsensusBody: Clone {}

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

impl FlavoredConsensusBody for plain::NetworkStatus {}

impl FlavoredConsensusBody for md::NetworkStatus {}

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
}

impl FlavoredConsensusUnverified for md::NetworkStatusUnverified {
    fn flavor() -> ConsensusFlavor {
        ConsensusFlavor::Microdesc
    }
}
