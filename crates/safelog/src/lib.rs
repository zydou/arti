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
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
#![allow(clippy::result_large_err)] // temporary workaround for arti#587
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

// TODO: Try making it not Deref and having expose+expose_mut instead; how bad is it?

use educe::Educe;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

mod err;
mod flags;

pub use err::Error;
pub use flags::{disable_safe_logging, enforce_safe_logging, with_safe_logging_suppressed, Guard};

/// A `Result` returned by the flag-manipulation functions in `safelog`.
pub type Result<T> = std::result::Result<T, Error>;

/// A wrapper type for a sensitive value.
///
/// By default, a `Sensitive<T>` behaves the same as a regular `T`, except that
/// attempts to turn it into a string (via `Display`, `Debug`, etc) all produce
/// the string `[scrubbed]`.
///
/// This behavior can be overridden locally by using
/// [`with_safe_logging_suppressed`] and globally with [`disable_safe_logging`].
#[derive(Educe)]
#[educe(
    Clone(bound),
    Default(bound),
    Deref,
    DerefMut,
    Eq(bound),
    Hash(bound),
    Ord(bound),
    PartialEq(bound),
    PartialOrd(bound)
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct Sensitive<T>(T);

impl<T> Sensitive<T> {
    /// Create a new `Sensitive<T>`, wrapping a provided `value`.
    pub fn new(value: T) -> Self {
        Sensitive(value)
    }

    /// Extract the inner value from this `Sensitive<T>`.
    //
    // TODO(Diziet) shouldn't this be called `into_inner` ?
    pub fn unwrap(sensitive: Sensitive<T>) -> T {
        sensitive.0
    }

    /// Converts `&Sensitive<T>` to `Sensitive<&T>`
    pub fn as_ref(&self) -> Sensitive<&T> {
        Sensitive(&self.0)
    }

    /// Return a reference to the inner value
    //
    // This isn't `AsRef` or `as_ref` because we don't want to offer "de-sensitivisation"
    // via what is usually a semantically-neutral interface.
    pub fn as_inner(&self) -> &T {
        &self.0
    }
}

/// Wrap a value as `Sensitive`.
///
/// This function is an alias for [`Sensitive::new`].
pub fn sensitive<T>(value: T) -> Sensitive<T> {
    Sensitive(value)
}

impl<T> From<T> for Sensitive<T> {
    fn from(value: T) -> Self {
        Sensitive::new(value)
    }
}

/// Helper: Declare one or more Display-like implementations for a
/// Sensitive-like type.  These implementations will delegate to their std::fmt
/// types if safe logging is disabled, and write `[scrubbed]` otherwise.
macro_rules! impl_display_traits {
    { $($trait:ident),*  for $object:ident } => {
    $(
        impl<T: std::fmt::$trait> std::fmt::$trait for $object<T> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                if flags::unsafe_logging_enabled() {
                    std::fmt::$trait::fmt(&self.0, f)
                } else {
                    write!(f, "[scrubbed]")
                }
            }
        }
   )*
   }
}

impl_display_traits! {
    Display, Debug, Binary, Octal, LowerHex, UpperHex, LowerExp, UpperExp, Pointer for Sensitive
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use serial_test::serial;
    use static_assertions::{assert_impl_all, assert_not_impl_any};

    #[test]
    fn clone_bound() {
        // Here we'll make sure that educe bounds work about the way we expect.
        #[derive(Clone)]
        struct A;
        struct B;

        let _x = Sensitive(A).clone();
        let _y = Sensitive(B);

        assert_impl_all!(Sensitive<A> : Clone);
        assert_not_impl_any!(Sensitive<B> : Clone);
    }

    #[test]
    #[serial]
    fn debug_vec() {
        type SVec = Sensitive<Vec<u32>>;

        let mut sv = SVec::default();
        assert!(sv.is_empty());
        sv.push(104);
        sv.push(49);
        assert_eq!(sv.len(), 2);

        assert!(!flags::unsafe_logging_enabled());
        assert_eq!(format!("{:?}", &sv), "[scrubbed]");
        let normal = with_safe_logging_suppressed(|| format!("{:?}", &sv));
        assert_eq!(normal, "[104, 49]");

        let _g = disable_safe_logging().unwrap();
        assert_eq!(format!("{:?}", &sv), "[104, 49]");

        assert_eq!(sv, SVec::from(vec![104, 49]));
        assert_eq!(SVec::unwrap(sv.clone()), vec![104, 49]);
        assert_eq!(*sv, vec![104, 49]);
    }

    #[test]
    #[serial]
    fn display_various() {
        let val = Sensitive::<u32>::new(0x0ed19a);

        let closure1 = || {
            format!(
                "{:?}, {}, {:o}, {:x}, {:X}, {:b}",
                &val, &val, &val, &val, &val, &val,
            )
        };
        let s1 = closure1();
        let s2 = with_safe_logging_suppressed(closure1);
        assert_eq!(
            s1,
            "[scrubbed], [scrubbed], [scrubbed], [scrubbed], [scrubbed], [scrubbed]"
        );
        assert_eq!(
            s2,
            "971162, 971162, 3550632, ed19a, ED19A, 11101101000110011010"
        );

        let n = 1.0E32;
        let val = Sensitive::<f64>::new(n);
        let expect = format!("{:?}, {}, {:e}, {:E}", n, n, n, n);
        let closure2 = || format!("{:?}, {}, {:e}, {:E}", &val, &val, &val, &val);
        let s1 = closure2();
        let s2 = with_safe_logging_suppressed(closure2);
        assert_eq!(s1, "[scrubbed], [scrubbed], [scrubbed], [scrubbed]");
        assert_eq!(s2, expect);

        let ptr: *const u8 = std::ptr::null();
        let val = Sensitive::new(ptr);
        let expect = format!("{:?}, {:p}", ptr, ptr);
        let closure3 = || format!("{:?}, {:p}", val, val);
        let s1 = closure3();
        let s2 = with_safe_logging_suppressed(closure3);
        assert_eq!(s1, "[scrubbed], [scrubbed]");
        assert_eq!(s2, expect);
    }
}
