#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
//! `tor-basic-utils`: Utilities (low-level) for Tor
//!
//! Miscellaneous utilities for `tor-*` and `arti-*`.
//!
//! This crate lives at the *bottom* of the Tor crate stack.
//! So it contains only utilities which have no `tor-*` (or `arti-*`) dependencies.
//!
//! There is no particular theme.
//! More substantial sets of functionality with particular themes
//! are to be found in other `tor-*` crates.

// @@ begin lint list maintained by maint/add_warning @@
#![cfg_attr(not(ci_arti_stable), allow(renamed_and_removed_lints))]
#![cfg_attr(not(ci_arti_nightly), allow(unknown_lints))]
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
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

use std::fmt;

pub mod futures;
pub mod iter;
pub mod n_key_set;
pub mod retry;
pub mod test_rng;

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
pub fn skip_fmt<T>(_: &T, f: &mut fmt::Formatter) -> fmt::Result {
    /// Inner function avoids code bloat due to generics
    fn inner(f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "..")
    }
    inner(f)
}

// ----------------------------------------------------------------------

/// Implementation of `ErrorKind::NotADirectory` that doesn't require Nightly
pub trait IoErrorExt {
    /// Is this `io::ErrorKind::NotADirectory` ?
    fn is_not_a_directory(&self) -> bool;
}
impl IoErrorExt for std::io::Error {
    fn is_not_a_directory(&self) -> bool {
        self.raw_os_error()
            == Some(
                #[cfg(target_family = "unix")]
                libc::ENOTDIR,
                #[cfg(target_family = "windows")]
                {
                    /// Obtained from Rust stdlib source code
                    /// See also:
                    ///   <https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499->
                    /// (although the documentation is anaemic) and
                    /// <https://github.com/rust-lang/rust/pull/79965>
                    const ERROR_DIRECTORY: i32 = 267;
                    ERROR_DIRECTORY
                },
            )
    }
}

// ----------------------------------------------------------------------

/// Define an "accessor trait", which describes structs that have fields of certain types
///
/// This can be useful if a large struct, living high up in the dependency graph,
/// contains fields that lower-lever crates want to be able to use without having
/// to copy the data about etc.
///
/// ```
/// // imagine this in the lower-level module
/// use tor_basic_utils::define_accessor_trait;
/// define_accessor_trait! {
///     pub trait View {
///         lorem: String,
///         ipsum: usize,
///    }
/// }
///
/// fn test_view<V: View>(v: &V) {
///     assert_eq!(v.lorem(), "sit");
///     assert_eq!(v.ipsum(), &42);
/// }
///
/// // imagine this in the higher-level module
/// use derive_more::AsRef;
/// #[derive(AsRef)]
/// struct Everything {
///     #[as_ref] lorem: String,
///     #[as_ref] ipsum: usize,
///     dolor: Vec<()>,
/// }
/// impl View for Everything { }
///
/// let everything = Everything {
///     lorem: "sit".into(),
///     ipsum: 42,
///     dolor: vec![()],
/// };
///
/// test_view(&everything);
/// ```
///
/// ### Generated code
///
/// ```
/// pub trait View: AsRef<String> + AsRef<usize> {
///     fn lorem(&self) -> &String { self.as_ref() }
///     fn ipsum(&self) -> &usize { self.as_ref() }
/// }
/// ```
#[macro_export]
macro_rules! define_accessor_trait {
    {
        $( #[ $attr:meta ])*
        $vis:vis trait $Trait:ident {
            $( $accessor:ident: $type:ty, )*
        }
    } => {
        $( #[ $attr ])*
        $vis trait $Trait: $( core::convert::AsRef<$type> + )* {
            $(
                /// Access the field
                fn $accessor(&self) -> &$type { core::convert::AsRef::as_ref(self) }
            )*
        }
    }
}

// ----------------------------------------------------------------------

/// Helper for assisting with macro "argument" defaulting
///
/// ```ignore
/// macro_coalesce_args!{ [ something ]  ... }  // =>   something
/// macro_coalesce_args!{ [ ], [ other ] ... }  // =>   other
/// // etc.
/// ```
///
/// ### Usage note
///
/// It is generally possible to avoid use of `macro_coalesce_args`, at the cost of
/// providing many alternative matcher patterns.  Using `macro_coalesce_args` can make
/// it possible to provide a single pattern with the optional items in `$( )?`.
///
/// This is valuable because a single pattern with some optional items
/// makes much better documentation than several patterns which the reader must compare
/// by eye - and it also simplifies the implementation.
///
/// `macro_coalesce_args` takes each of its possible expansions in `[ ]` and returns
/// the first nonempty one.
#[macro_export]
macro_rules! macro_first_nonempty {
    { [ $($yes:tt)+ ] $($rhs:tt)* } => { $($yes)* };
    { [ ]$(,)? [ $($otherwise:tt)* ] $($rhs:tt)* } => {
        $crate::macro_first_nonempty!{ [ $($otherwise)* ] $($rhs)* }
    };
}

// ----------------------------------------------------------------------
