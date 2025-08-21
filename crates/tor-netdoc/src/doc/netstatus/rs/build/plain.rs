//! Implementation for plain router status entry builder.
//
// Read this file in conjunction with `each_variety.rs`.
// See "module scope" ns_variety_definition_macros.rs.

use super::*;

// Import `each_variety.rs`, appropriately variegated
ns_do_variety_plain! {}

use crate::doc::netstatus::PlainConsensusBuilder as ConsensusBuilder;

#[cfg(feature = "plain-consensus")]
impl RouterStatusBuilder {
    /// Try to finish this builder and add its RouterStatus to a
    /// provided ConsensusBuilder.
    pub fn build_into(
        &self,
        builder: &mut ConsensusBuilder,
    ) -> Result<()> {
        builder.add_rs(self.build()?);
        Ok(())
    }
    /// Return a router status built by this object.
    pub fn build(&self) -> Result<PlainRouterStatus> {
        self.finish()
    }
}
