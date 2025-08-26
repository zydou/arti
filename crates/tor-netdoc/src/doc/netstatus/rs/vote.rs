//! Implementation for the style of router descriptors used in
//! old-style "ns" consensus documents.
//
// Read this file in conjunction with `each_variety.rs`.
// See "module scope" ns_variety_definition_macros.rs.

use super::*;

// Import `each_variety.rs`, appropriately variegated
ns_do_variety_vote! {}

pub(crate) use crate::doc::routerdesc::RdDigest as DocDigest;
