//! Configuration elements for the gaurd manager

use tor_basic_utils::define_accessor_trait;

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
    }
}

/// Helpers for testing configuration
#[cfg(feature = "testing")]
pub(crate) mod testing {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;
    use derive_more::AsRef;

    /// A dummy test copnfiguration, with transparent fields for testing
    #[derive(Default, Debug, AsRef)]
    #[allow(clippy::exhaustive_structs)]
    pub struct TestConfig {
        ///
        #[as_ref]
        pub fallbacks: FallbackList,
    }
    impl GuardMgrConfig for TestConfig {}
}
