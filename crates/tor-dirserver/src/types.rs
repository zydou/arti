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
pub(crate) trait FlavoredConsensusBody: Clone {
}

/// Generic trait representing a flavored unverified consensus.
///
/// Required because in certain parts of the code, the exact flavor of the
/// consensus does not matter.
///
/// See [`FlavoredConsensusBody`] for the verified variant of it.
pub(crate) trait FlavoredConsensusUnverified:
    NetdocParseableUnverified<Body: FlavoredConsensusBody> + NetdocParseable + Clone
{
    /// Returns the [`ConsensusFlavor`] of this type.
    fn flavor() -> ConsensusFlavor;

    /// Returns the [`AuthCertKeyIds`] of all authority certificates in the signatures.
    // TODO DIRMIRROR: Obtain this from the respective error variant returned by
    // .can_verify().
    fn signatories(&self) -> Vec<AuthCertKeyIds>;
}

impl FlavoredConsensusBody for plain::NetworkStatus {
}

impl FlavoredConsensusBody for md::NetworkStatus {
}

impl FlavoredConsensusUnverified for plain::NetworkStatusUnverified {
    fn flavor() -> ConsensusFlavor {
        ConsensusFlavor::Plain
    }

    fn signatories(&self) -> Vec<AuthCertKeyIds> {
        self.sigs
            .sigs
            .directory_signature
            .iter()
            .map(|sig| sig.key_ids)
            .collect()
    }
}

impl FlavoredConsensusUnverified for md::NetworkStatusUnverified {
    fn flavor() -> ConsensusFlavor {
        ConsensusFlavor::Microdesc
    }

    fn signatories(&self) -> Vec<AuthCertKeyIds> {
        self.sigs
            .sigs
            .directory_signature
            .iter()
            .map(|sig| sig.key_ids)
            .collect()
    }
}
