//! Implementation for the style of router descriptors used in
//! microdesc consensus documents.

use super::*;

ns_do_species_md! {}

use crate::doc::microdesc::{MdDigest as DocDigest, DOC_DIGEST_LEN};

/// The flavor
const FLAVOR: ConsensusFlavor = ConsensusFlavor::Microdesc;

impl ConsensusRouterStatus {
    /// Return the expected microdescriptor digest for this routerstatus
    pub fn md_digest(&self) -> &DocDigest {
        self.doc_digest()
    }
}
