//! Configuration logic for `HsCircPool`.

use tor_basic_utils::define_accessor_trait;

define_accessor_trait! {
    /// Configuration for an `HsCircPool`.
    ///
    /// If the `HsCircPool` gains new configurabilities, this trait will gain additional
    /// supertraits, as an API break.
    ///
    /// Prefer to use `TorClientConfig`, which will always implement this trait.
    //
    // This arrangement is very like that for `CircMgrConfig`.
    pub trait HsCircPoolConfig {
        +
        // TODO HS-VANGUARDS: ideally this would be defined in the same way as `path_rules`,
        // `circuit_timing`, etc., but define_accessor_trait unconditionally adds
        // AsRef<VanguardsConfig> as a supertrait, which can't be cfg'd behind
        // the vanguards feature.

        /// Access the field
        #[cfg(all(feature = "vanguards", feature = "hs-common"))]
        fn vanguard_config(&self) -> &tor_guardmgr::vanguards::VanguardConfig;
    }
}
