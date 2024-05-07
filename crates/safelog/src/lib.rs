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

// TODO: Try making it not Deref and having expose+expose_mut instead; how bad is it?

use educe::Educe;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

mod err;
mod flags;
mod impls;

pub use err::Error;
pub use flags::{disable_safe_logging, enforce_safe_logging, with_safe_logging_suppressed, Guard};

use std::ops::Deref;

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
    pub fn into_inner(self) -> T {
        self.0
    }

    /// Extract the inner value from this `Sensitive<T>`.
    #[deprecated = "Use the new into_inner method instead"]
    pub fn unwrap(sensitive: Sensitive<T>) -> T {
        sensitive.into_inner()
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
    { $($trait:ident),* } => {
    $(
        impl<T: std::fmt::$trait> std::fmt::$trait for Sensitive<T> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                if flags::unsafe_logging_enabled() {
                    std::fmt::$trait::fmt(&self.0, f)
                } else {
                    write!(f, "[scrubbed]")
                }
            }
        }

        impl<T: std::fmt::$trait> std::fmt::$trait for BoxSensitive<T> {
            #[inline]
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::fmt::$trait::fmt(&*self.0, f)
            }
        }
   )*
   }
}

/// A wrapper suitable for logging and including in errors
///
/// This is a newtype around `Box<Sensitive<T>>`.
///
/// This is useful particularly in errors,
/// where the box can help reduce the size of error variants
/// (for example ones containing large values like an `OwnedChanTarget`).
///
/// `BoxSensitive<T>` dereferences to [`Sensitive<T>`].
//
// Making it be a newtype rather than a type alias allows us to implement
// `into_inner` and `From<T>` and so on.
#[derive(Clone, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct BoxSensitive<T>(Box<Sensitive<T>>);

impl<T> From<T> for BoxSensitive<T> {
    fn from(t: T) -> BoxSensitive<T> {
        BoxSensitive(Box::new(sensitive(t)))
    }
}

impl<T> BoxSensitive<T> {
    /// Return the innermost `T`
    pub fn into_inner(self) -> T {
        // TODO want unstable Box::into_inner(self.0) rust-lang/rust/issues/80437
        let unboxed = *self.0;
        unboxed.into_inner()
    }
}

impl<T> Deref for BoxSensitive<T> {
    type Target = Sensitive<T>;

    fn deref(&self) -> &Sensitive<T> {
        &self.0
    }
}

impl_display_traits! {
    Display, Debug, Binary, Octal, LowerHex, UpperHex, LowerExp, UpperExp, Pointer
}

/// A `redactable` object is one where we know a way to display _part_ of it
/// when we are running with safe logging enabled.
///
/// For example, instead of referring to a user as `So-and-So` or `[scrubbed]`,
/// this trait would allow referring to the user as `S[...]`.
///
/// # Privacy notes
///
/// Displaying some information about an object is always less safe than
/// displaying no information about it!
///
/// For example, in an environment with only a small number of users, the first
/// letter of a user's name might be plenty of information to identify them
/// uniquely.
///
/// Even if a piece of redacted information is safe on its own, several pieces
/// of redacted information, when taken together, can be enough for an adversary
/// to infer more than you want.  For example, if you log somebody's first
/// initial, month of birth, and last-two-digits of ID number, you have just
/// discarded 99.9% of potential individuals from the attacker's consideration.
pub trait Redactable: std::fmt::Display + std::fmt::Debug {
    /// As `Display::fmt`, but produce a redacted representation.
    fn display_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result;
    /// As `Debug::fmt`, but produce a redacted representation.
    fn debug_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.display_redacted(f)
    }
    /// Return a smart pointer that will display or debug this object as its
    /// redacted form.
    fn redacted(&self) -> Redacted<&Self> {
        Redacted(self)
    }
    /// Return a smart pointer that redacts this object if `redact` is true.
    fn maybe_redacted(&self, redact: bool) -> MaybeRedacted<&Self> {
        if redact {
            MaybeRedacted(either::Either::Right(Redacted(self)))
        } else {
            MaybeRedacted(either::Either::Left(self))
        }
    }
}

impl<'a, T: Redactable + ?Sized> Redactable for &'a T {
    fn display_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        (*self).display_redacted(f)
    }
}

/// A wrapper around a `Redactable` that displays it in redacted format.
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
#[derive(derive_more::From)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct Redacted<T: Redactable>(T);

impl<T: Redactable> Redacted<T> {
    /// Create a new `Redacted`.
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// Consume this wrapper and return its inner value.
    pub fn unwrap(self) -> T {
        self.0
    }

    /// Converts `&Redacted<T>` to `Redacted<&T>`
    pub fn as_ref(&self) -> Redacted<&T> {
        Redacted(&self.0)
    }

    /// Return a reference to the inner value
    //
    // This isn't `AsRef` or `as_ref` because we don't want to offer "de-redaction"
    // via what is usually a semantically-neutral interface.
    pub fn as_inner(&self) -> &T {
        &self.0
    }
}

impl<T: Redactable> std::fmt::Display for Redacted<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if flags::unsafe_logging_enabled() {
            std::fmt::Display::fmt(&self.0, f)
        } else {
            self.0.display_redacted(f)
        }
    }
}

impl<T: Redactable> std::fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if flags::unsafe_logging_enabled() {
            std::fmt::Debug::fmt(&self.0, f)
        } else {
            self.0.debug_redacted(f)
        }
    }
}

/// An object that may or may not be redacted.
///
/// Used to implement conditional redaction
#[derive(Clone, derive_more::Display)]
pub struct MaybeRedacted<T: Redactable>(either::Either<T, Redacted<T>>);

impl<T: Redactable> std::fmt::Debug for MaybeRedacted<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use std::fmt::Debug;
        match &self.0 {
            either::Either::Left(v) => Debug::fmt(v, f),
            either::Either::Right(v) => Debug::fmt(v, f),
        }
    }
}

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
        assert_eq!(format!("{:?}", sv.as_ref()), "[scrubbed]");
        assert_eq!(format!("{:?}", sv.as_inner()), "[104, 49]");
        let normal = with_safe_logging_suppressed(|| format!("{:?}", &sv));
        assert_eq!(normal, "[104, 49]");

        let _g = disable_safe_logging().unwrap();
        assert_eq!(format!("{:?}", &sv), "[104, 49]");

        assert_eq!(sv, SVec::from(vec![104, 49]));
        assert_eq!(sv.clone().into_inner(), vec![104, 49]);
        assert_eq!(*sv, vec![104, 49]);
    }

    #[test]
    #[serial]
    #[allow(deprecated)]
    fn deprecated() {
        type SVec = Sensitive<Vec<u32>>;
        let sv = Sensitive(vec![104, 49]);

        assert_eq!(SVec::unwrap(sv), vec![104, 49]);
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

    #[test]
    #[serial]
    fn box_sensitive() {
        let b: BoxSensitive<_> = "hello world".into();

        assert_eq!(b.clone().into_inner(), "hello world");

        let closure = || format!("{} {:?}", b, b);
        assert_eq!(closure(), "[scrubbed] [scrubbed]");
        assert_eq!(
            with_safe_logging_suppressed(closure),
            r#"hello world "hello world""#
        );

        assert_eq!(b.len(), 11);
    }

    #[test]
    #[serial]
    fn test_redacted() {
        let localhost = std::net::Ipv4Addr::LOCALHOST;
        let closure = || format!("{} {:?}", localhost.redacted(), localhost.redacted());

        assert_eq!(closure(), "127.x.x.x 127.x.x.x");
        assert_eq!(with_safe_logging_suppressed(closure), "127.0.0.1 127.0.0.1");

        let closure = |b| {
            format!(
                "{} {:?}",
                localhost.maybe_redacted(b),
                localhost.maybe_redacted(b)
            )
        };
        assert_eq!(closure(true), "127.x.x.x 127.x.x.x");
        assert_eq!(closure(false), "127.0.0.1 127.0.0.1");

        assert_eq!(Redacted::new(localhost).unwrap(), localhost);
    }
}
