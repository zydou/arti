#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![doc = include_str!("../README.md")]
// @@ begin lint list maintained by maint/add_warning @@
#![allow(renamed_and_removed_lints)] // @@REMOVE_WHEN(ci_arti_stable)
#![allow(unknown_lints)] // @@REMOVE_WHEN(ci_arti_nightly)
#![warn(missing_docs)]
#![warn(noop_method_call)]
#![warn(unreachable_pub)]
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
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![deny(clippy::print_stderr)]
#![deny(clippy::print_stdout)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unchecked_duration_subtraction)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
#![allow(clippy::result_large_err)] // temporary workaround for arti#587
#![allow(clippy::needless_raw_string_hashes)] // complained-about code is fine, often best
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

use std::collections::BinaryHeap;
use std::fmt;
use std::mem;
use std::ops::{RangeInclusive, RangeToInclusive};
use std::path::Path;
use std::time::Duration;

pub mod iter;
pub mod n_key_list;
pub mod n_key_set;
pub mod rangebounds;
pub mod retry;
pub mod test_rng;

mod byte_qty;
pub use byte_qty::ByteQty;

pub use paste::paste;

use rand::Rng;

/// Sealed
mod sealed {
    /// Sealed
    pub trait Sealed {}
}
use sealed::Sealed;

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

/// Extension trait to provide `.gen_range_checked()`
pub trait RngExt: Rng {
    /// Generate a random value in the given range.
    ///
    /// This function is optimised for the case that only a single sample is made from the given range. See also the [`Uniform`](rand::distributions::uniform::Uniform)  distribution type which may be faster if sampling from the same range repeatedly.
    ///
    /// If the supplied range is empty, returns `None`.
    ///
    /// (This is a non-panicking version of [`Rng::gen_range`].)
    ///
    /// ### Example
    ///
    /// ```
    /// use rand::thread_rng;
    /// use tor_basic_utils::RngExt as _;
    //
    // Fake plastic imitation tor_error, since that's actually higher up the stack
    /// # #[macro_use]
    /// # mod tor_error {
    /// #     #[derive(Debug)]
    /// #     pub struct Bug;
    /// #     pub fn internal() {} // makes `use` work
    /// # }
    /// # macro_rules! internal { { $x:expr } => { Bug } }
    //
    /// use tor_error::{Bug, internal};
    ///
    /// fn choose(slice: &[i32]) -> Result<i32, Bug> {
    ///     let index = thread_rng()
    ///         .gen_range_checked(0..slice.len())
    ///         .ok_or_else(|| internal!("empty slice"))?;
    ///     Ok(slice[index])
    /// }
    ///
    /// assert_eq!(choose(&[42]).unwrap(), 42);
    /// let _: Bug = choose(&[]).unwrap_err();
    /// ```
    fn gen_range_checked<T, R>(&mut self, range: R) -> Option<T>
    where
        T: rand::distributions::uniform::SampleUniform,
        R: rand::distributions::uniform::SampleRange<T>,
    {
        if range.is_empty() {
            None
        } else {
            #[allow(clippy::disallowed_methods)]
            Some(Rng::gen_range(self, range))
        }
    }

    /// Generate a random value in the given upper-bounded-only range.
    ///
    /// For use with an inclusive upper-bounded-only range,
    /// with types that implement `GenRangeInfallible`
    /// (that necessarily then implement the appropriate `rand` traits).
    ///
    /// This function is optimised for the case that only a single sample is made from the given range. See also the [`Uniform`](rand::distributions::uniform::Uniform)  distribution type which may be faster if sampling from the same range repeatedly.
    ///
    /// ### Example
    ///
    /// ```
    /// use std::time::Duration;
    /// use rand::thread_rng;
    /// use tor_basic_utils::RngExt as _;
    ///
    /// fn stochastic_sleep(max: Duration) {
    ///     let chosen_delay = thread_rng()
    ///         .gen_range_infallible(..=max);
    ///     std::thread::sleep(chosen_delay);
    /// }
    /// ```
    fn gen_range_infallible<T>(&mut self, range: RangeToInclusive<T>) -> T
    where
        T: GenRangeInfallible,
    {
        self.gen_range_checked(T::lower_bound()..=range.end)
            .expect("GenRangeInfallible type with an empty lower_bound()..=T range")
    }
}
impl<T: Rng> RngExt for T {}

/// Types that can be infallibly sampled using `gen_range_infallible`
///
/// In addition to the supertraits, the implementor of this trait must guarantee that:
///
/// `<Self as GenRangeInfallible>::lower_bound() ..= UPPER`
/// is a nonempty range for every value of `UPPER`.
//
// One might think that this trait is wrong because we might want to be able to
// implement gen_range_infallible for arguments other than RangeToInclusive<T>.
// However, double-ended ranges are inherently fallible because the actual values
// might be in the wrong order.  Non-inclusive ranges are fallible because the
// upper bound might be zero, unless a NonZero type is used, which seems like a further
// complication that we probably don't want to introduce here.  That leaves lower-bounded
// ranges, but those are very rare.
pub trait GenRangeInfallible: rand::distributions::uniform::SampleUniform + Ord
where
    RangeInclusive<Self>: rand::distributions::uniform::SampleRange<Self>,
{
    /// The usual lower bound, for converting a `RangeToInclusive` to a `RangeInclusive`
    ///
    /// Only makes sense with types with a sensible lower bound, such as zero.
    fn lower_bound() -> Self;
}

impl GenRangeInfallible for Duration {
    fn lower_bound() -> Self {
        Duration::ZERO
    }
}

// ----------------------------------------------------------------------

/// Implementation of `ErrorKind::NotADirectory` that doesn't require Nightly
pub trait IoErrorExt: Sealed {
    /// Is this `io::ErrorKind::NotADirectory` ?
    fn is_not_a_directory(&self) -> bool;
}
impl Sealed for std::io::Error {}
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

/// Renaming of `Path::display` as `display_lossy`
pub trait PathExt: Sealed {
    /// Display this `Path` as an approximate string, for human consumption in messages
    ///
    /// Operating system paths cannot always be faithfully represented as Rust strings,
    /// because they might not be valid Unicode.
    ///
    /// This helper method provides a way to display a string for human users.
    /// **This may lose information** so should only be used for error messages etc.
    ///
    /// This method is exactly the same as [`std::path::Path::display`],
    /// but with a different and more discouraging name.
    fn display_lossy(&self) -> std::path::Display<'_>;
}
impl Sealed for Path {}
impl PathExt for Path {
    #[allow(clippy::disallowed_methods)]
    fn display_lossy(&self) -> std::path::Display<'_> {
        self.display()
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
