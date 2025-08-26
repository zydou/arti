//! Implementation for the style of router descriptors used in
//! old-style "ns" consensus documents.
//
// Read this file in conjunction with `each_variety.rs`.
// See "module scope" ns_variety_definition_macros.rs.

use super::*;

// Import `each_variety.rs`, appropriately variegated
ns_do_variety_plain! {}

pub(crate) use crate::doc::routerdesc::{DOC_DIGEST_LEN, RdDigest as DocDigest};

/// The flavor
const FLAVOR: ConsensusFlavor = ConsensusFlavor::Plain;

impl RouterStatus {
    /// Return the expected router descriptor digest for this routerstatus
    pub fn rd_digest(&self) -> &DocDigest {
        self.doc_digest()
    }
}
