//! Implementation for md router status entry builder.
//
// Read this file in conjunction with `each_variety.rs`.
// See "module scope" ns_variety_definition_macros.rs.

use super::*;

// Import `each_variety.rs`, appropriately variegated
ns_do_variety_md! {}

use crate::doc::netstatus::MdConsensusBuilder as ConsensusBuilder;
