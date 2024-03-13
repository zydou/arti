//! Configuration elements for the guard manager

use tor_basic_utils::define_accessor_trait;

use crate::bridge::BridgeConfig;
use crate::fallback::FallbackList;

define_accessor_trait! {
    /// Configuration for a guard manager
    ///
    /// If the guard manager gains new configurabilities, this trait will gain additional
    /// supertraits, as an API break.
    ///
    /// Prefer to use `TorClientConfig`, which will always implement this trait.
    pub trait GuardMgrConfig {
        fallbacks: FallbackList,
        bridges: [BridgeConfig],
        +
        /// Should the bridges be used?
        ///
        /// This is only allowed to return true if `bridges()` is nonempty.
        ///
        /// Therefore, it also requires `tor-guardmgr` cargo feature `bridge-client`,
        /// since without that feature `BridgeConfig` is uninhabited and therefore
        /// `bridges` is necessarily empty.
        //
        // Therefore, it is safe (from a "reject unsupported config" point of view)
        // to ctest this only in code which is #[cfg(feature = "bridge-client")].
        fn bridges_enabled(&self) -> bool;
    }
}

/// Helpers for testing configuration
#[cfg(any(test, feature = "testing"))]
pub(crate) mod testing {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;
    use derive_more::AsRef;

    /// A dummy test configuration, with transparent fields for testing
    #[derive(Default, Debug, AsRef)]
    #[allow(clippy::exhaustive_structs)]
    pub struct TestConfig {
        ///
        #[as_ref]
        pub fallbacks: FallbackList,

        ///
        pub bridges: Vec<BridgeConfig>,
    }
    impl AsRef<[BridgeConfig]> for TestConfig {
        fn as_ref(&self) -> &[BridgeConfig] {
            &self.bridges
        }
    }
    impl GuardMgrConfig for TestConfig {
        fn bridges_enabled(&self) -> bool {
            !self.bridges.is_empty()
        }
    }
}
