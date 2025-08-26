//! Implementation for the style of router descriptors used in
//! microdesc consensus documents.
//
// Read this file in conjunction with `each_variety.rs`.
// See "module scope" ns_variety_definition_macros.rs.

use super::*;

// Import `each_variety.rs`, appropriately variegated
ns_do_variety_md! {}

// We bind some variety-agnostic names for the benefit of `each_variety.rs`,
// which reimports the contents of this module with `use super::*`.
pub(crate) use crate::doc::microdesc::{DOC_DIGEST_LEN, MdDigest as DocDigest};

/// The flavor
const FLAVOR: ConsensusFlavor = ConsensusFlavor::Microdesc;

impl RouterStatus {
    /// Return the expected microdescriptor digest for this routerstatus
    pub fn md_digest(&self) -> &DocDigest {
        self.doc_digest()
    }
}
