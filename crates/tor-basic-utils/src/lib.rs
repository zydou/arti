#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![doc = include_str!("../README.md")]
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
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
#![allow(clippy::result_large_err)] // temporary workaround for arti#587
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

use std::collections::BinaryHeap;
use std::fmt;
use std::mem;

pub mod iter;
pub mod n_key_set;
pub mod retry;
pub mod test_rng;

pub use paste::paste;

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

/// Extension trait to provide `.strip_suffix_ignore_ascii_case()` etc.
// Using `.as_ref()` as a supertrait lets us make the method a provided one.
pub trait StrExt: AsRef<str> {
    /// Like `str.strip_suffix()` but ASCII-case-insensitive
    fn strip_suffix_ignore_ascii_case(&self, suffix: &str) -> Option<&str> {
        let whole = self.as_ref();
        let suffix_start = whole.len().checked_sub(suffix.len())?;
        whole[suffix_start..]
            .eq_ignore_ascii_case(suffix)
            .then(|| &whole[..suffix_start])
    }

    /// Like `str.ends_with()` but ASCII-case-insensitive
    fn ends_with_ignore_ascii_case(&self, suffix: &str) -> bool {
        self.strip_suffix_ignore_ascii_case(suffix).is_some()
    }
}
impl StrExt for str {}

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

/// Implementation of `BinaryHeap::retain` that doesn't require Nightly
pub trait BinaryHeapExt<T> {
    /// Remove all elements for which `f` returns `false`
    ///
    /// Performance is not great right now - the algorithm is `O(n*log(n))`
    /// where `n` is the number of elements in the heap (not the number removed).
    ///
    /// The name is `retain_ext` to avoid a name collision with the unstable function,
    /// which would require the use of UFCS and make this unergonomic.
    fn retain_ext<F: FnMut(&T) -> bool>(&mut self, f: F);
}
impl<T: Ord> BinaryHeapExt<T> for BinaryHeap<T> {
    fn retain_ext<F: FnMut(&T) -> bool>(&mut self, f: F) {
        let items = mem::take(self).into_iter();
        *self = items.filter(f).collect();
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
/// pub trait Supertrait {}
/// use tor_basic_utils::define_accessor_trait;
/// define_accessor_trait! {
///     pub trait View: Supertrait {
///         lorem: String,
///         ipsum: usize,
///         +
///         fn other_accessor(&self) -> bool;
///         // any other trait items can go here
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
/// impl Supertrait for Everything { }
/// impl View for Everything {
///     fn other_accessor(&self) -> bool { false }
/// }
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
/// # pub trait Supertrait { }
/// pub trait View: AsRef<String> + AsRef<usize> + Supertrait {
///     fn lorem(&self) -> &String { self.as_ref() }
///     fn ipsum(&self) -> &usize { self.as_ref() }
/// }
/// ```
#[macro_export]
macro_rules! define_accessor_trait {
    {
        $( #[ $attr:meta ])*
        $vis:vis trait $Trait:ident $( : $( $Super:path )* )? {
            $( $accessor:ident: $type:ty, )*
            $( + $( $rest:tt )* )?
        }
    } => {
        $( #[ $attr ])*
        $vis trait $Trait: $( core::convert::AsRef<$type> + )* $( $( $Super + )* )?
        {
            $(
                /// Access the field
                fn $accessor(&self) -> &$type { core::convert::AsRef::as_ref(self) }
            )*
            $(
                $( $rest )*
            )?
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

/// Define `Debug` to print as hex
///
/// # Usage
///
/// ```ignore
/// impl_debug_hex! { $type }
/// impl_debug_hex! { $type . $field_accessor }
/// impl_debug_hex! { $type , $accessor_fn }
/// ```
///
/// By default, this expects `$type` to implement `AsRef<[u8]>`.
///
/// Or, you can supply a series of tokens `$field_accessor`,
/// which will be used like this: `self.$field_accessor.as_ref()`
/// to get a `&[u8]`.
///
/// Or, you can supply `$accessor: fn(&$type) -> &[u8]`.
///
/// # Examples
///
/// ```
/// use tor_basic_utils::impl_debug_hex;
/// #[derive(Default)]
/// struct FourBytes([u8; 4]);
/// impl AsRef<[u8]> for FourBytes { fn as_ref(&self) -> &[u8] { &self.0 } }
/// impl_debug_hex! { FourBytes }
///
/// assert_eq!(
///     format!("{:?}", FourBytes::default()),
///     "FourBytes(00000000)",
/// );
/// ```
///
/// ```
/// use tor_basic_utils::impl_debug_hex;
/// #[derive(Default)]
/// struct FourBytes([u8; 4]);
/// impl_debug_hex! { FourBytes .0 }
///
/// assert_eq!(
///     format!("{:?}", FourBytes::default()),
///     "FourBytes(00000000)",
/// );
/// ```
///
/// ```
/// use tor_basic_utils::impl_debug_hex;
/// struct FourBytes([u8; 4]);
/// impl_debug_hex! { FourBytes, |self_| &self_.0 }
///
/// assert_eq!(
///     format!("{:?}", FourBytes([1,2,3,4])),
///     "FourBytes(01020304)",
/// )
/// ```
#[macro_export]
macro_rules! impl_debug_hex {
    { $type:ty $(,)? } => {
        $crate::impl_debug_hex! { $type, |self_| <$type as AsRef<[u8]>>::as_ref(&self_) }
    };
    { $type:ident . $($accessor:tt)+ } => {
        $crate::impl_debug_hex! { $type, |self_| self_ . $($accessor)* .as_ref() }
    };
    { $type:ty, $obtain:expr $(,)? } => {
        impl std::fmt::Debug for $type {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                use std::fmt::Write;
                let obtain: fn(&$type) -> &[u8] = $obtain;
                let bytes: &[u8] = obtain(self);
                write!(f, "{}(", stringify!($type))?;
                for b in bytes {
                    write!(f, "{:02x}", b)?;
                }
                write!(f, ")")?;
                Ok(())
            }
        }
    };
}

// ----------------------------------------------------------------------

/// Helper for defining a struct which can be (de)serialized several ways, including "natively"
///
/// Ideally we would have
/// ```rust ignore
/// #[derive(Deserialize)]
/// #[serde(try_from=Possibilities)]
/// struct Main { /* principal definition */ }
///
/// #[derive(Deserialize)]
/// #[serde(untagged)]
/// enum Possibilities { Main(Main), Other(OtherRepr) }
///
/// #[derive(Deserialize)]
/// struct OtherRepr { /* other representation we still want to read */ }
///
/// impl TryFrom<Possibilities> for Main { /* ... */ }
/// ```
///
/// But the impl for `Possibilities` ends up honouring the `try_from` on `Main`
/// so is recursive.
///
/// We solve that (ab)using serde's remote feature,
/// on a second copy of the struct definition.
///
/// See the Example for instructions.
/// It is important to **add test cases**
/// for all the representations you expect to parse and serialise,
/// since there are easy-to-write bugs,
/// for example omitting some of the necessary attributes.
///
/// # Generated output:
///
///  * The original struct definition, unmodified
///  * `#[derive(Serialize, Deserialize)] struct $main_Raw { }`
///
/// The `$main_Raw` struct ought not normally be to constructed anywhere,
/// and *isn't* convertible to or from the near-identical `$main` struct.
/// It exists only as a thing to feed to the serde remove derive,
/// and name in `with=`.
///
/// # Example
///
/// ```
/// use serde::{Deserialize, Serialize};
/// use tor_basic_utils::derive_serde_raw;
///
/// derive_serde_raw! {
///     #[derive(Deserialize, Serialize, Default, Clone, Debug)]
///     #[serde(try_from="BridgeConfigBuilderSerde", into="BridgeConfigBuilderSerde")]
///     pub struct BridgeConfigBuilder = "BridgeConfigBuilder" {
///         transport: Option<String>,
///         //...
///     }
/// }
///
/// #[derive(Serialize,Deserialize)]
/// #[serde(untagged)]
/// enum BridgeConfigBuilderSerde {
///     BridgeLine(String),
///     Dict(#[serde(with="BridgeConfigBuilder_Raw")] BridgeConfigBuilder),
/// }
///
/// impl TryFrom<BridgeConfigBuilderSerde> for BridgeConfigBuilder { //...
/// #    type Error = std::io::Error;
/// #    fn try_from(_: BridgeConfigBuilderSerde) -> Result<Self, Self::Error> { todo!() } }
/// impl From<BridgeConfigBuilder> for BridgeConfigBuilderSerde { //...
/// #    fn from(_: BridgeConfigBuilder) -> BridgeConfigBuilderSerde { todo!() } }
/// ```
#[macro_export]
macro_rules! derive_serde_raw { {
    $( #[ $($attrs:meta)* ] )*
    $vis:vis struct $main:ident=$main_s:literal
    $($body:tt)*
} => {
    $(#[ $($attrs)* ])*
    $vis struct $main
    $($body)*

    $crate::paste! {
        #[allow(non_camel_case_types)]
        #[derive(Serialize, Deserialize)]
        #[serde(remote=$main_s)]
        struct [< $main _Raw >]
        $($body)*
    }
} }

// ----------------------------------------------------------------------

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;

    #[test]
    fn test_strip_suffix_ignore_ascii_case() {
        assert_eq!(
            "hi there".strip_suffix_ignore_ascii_case("THERE"),
            Some("hi ")
        );
        assert_eq!("hi here".strip_suffix_ignore_ascii_case("THERE"), None);
        assert_eq!("THERE".strip_suffix_ignore_ascii_case("there"), Some(""));
        assert_eq!("hi".strip_suffix_ignore_ascii_case("THERE"), None);
    }
}
