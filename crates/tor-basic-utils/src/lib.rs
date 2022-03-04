#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![warn(noop_method_call)]
#![deny(unreachable_pub)]
#![warn(clippy::all)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::checked_conversions)]
#![warn(clippy::cognitive_complexity)]
#![deny(clippy::debug_assert_with_mut_call)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::expl_impl_clone_on_copy)]
#![deny(clippy::fallible_impl_from)]
#![deny(clippy::implicit_clone)]
#![deny(clippy::large_stack_arrays)]
#![warn(clippy::manual_ok_or)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(clippy::missing_panics_doc)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]

use std::fmt;

// ----------------------------------------------------------------------

/// Function with the signature of `Debug::fmt` that just prints `".."`
///
/// ```
/// use educe::Educe;
/// use tor_basic_utils::skip_fmt;
///
/// #[derive(Educe, Default)]
/// #[educe(Debug)]
/// struct Wombat {
///     visible: usize,
///
///     #[educe(Debug(method = "skip_fmt"))]
///     invisible: [u8; 2],
/// }
///
/// assert_eq!( format!("{:?}", &Wombat::default()),
///             "Wombat { visible: 0, invisible: .. }" );
/// ```
//
// This function is here in tor-bytes because crates that want to use it will largely
// be trying to avoid dumping packet data.
// But, it may at some point want to move to a lower-layer crate.
// If we do that, we should `pub use` it here, if we don't want a semver break.
pub fn skip_fmt<T>(_: &T, f: &mut fmt::Formatter) -> fmt::Result {
    /// Inner function avoids code bloat due to generics
    fn inner(f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "..")
    }
    inner(f)
}

// ----------------------------------------------------------------------
