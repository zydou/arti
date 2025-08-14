//! Implementation for the style of router descriptors used in
//! old-style "ns" consensus documents.

use super::*;

ns_do_species_plain! {}

use crate::doc::routerdesc::{RdDigest as DocDigest, DOC_DIGEST_LEN};

/// The flavor
const FLAVOR: ConsensusFlavor = ConsensusFlavor::Ns;

impl ConsensusRouterStatus {
    /// Return the expected router descriptor digest for this routerstatus
    pub fn rd_digest(&self) -> &DocDigest {
        self.doc_digest()
    }
}
