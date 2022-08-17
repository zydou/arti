#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
//! # `safelog`: Mark data as sensitive for logging purposes.
//!
//! Some information is too sensitive to routinely write to system logs, but
//! must nonetheless sometimes be displayed.  This crate provides a way to mark
//! such information, and log it conditionally, but not by default.
//!
//! ## Examples
//!
//! There are two main ways to mark a piece of data as sensitive: by storing it
//! within a [`Sensitive`] object long-term, or by wrapping it in a
//! [`Sensitive`] object right before passing it to a formatter:
//!
//! ```
//! use safelog::{Sensitive, sensitive};
//!
//! // With this declaration, a student's name and gpa will be suppressed by default
//! // when passing the student to Debug.
//! #[derive(Debug)]
//! struct Student {
//!    name: Sensitive<String>,
//!    grade: u8,
//!    homeroom: String,
//!    gpa: Sensitive<f32>,
//! }
//!
//! // In this function, a user's IP will not be printed by default.
//! fn record_login(username: &str, ip: &std::net::IpAddr) {
//!     println!("Login from {} at {}", username, sensitive(ip));
//! }
//! ```
//!
//! You can disable safe-logging globally (across all threads) or locally
//! (across a single thread).
//!
//! ```
//! use safelog::{disable_safe_logging, with_safe_logging_suppressed};
//! # let debug_mode = false;
//! # fn log_encrypted_data(s: &str) {}
//! # let big_secret = "swordfish";
//!
//! // If we're running in debug mode, turn off safe logging
//! // globally.  Safe logging will remain disabled until the
//! // guard object is dropped.
//! let guard = if debug_mode {
//!    // This call can fail if safe logging has already been enforced.
//!    disable_safe_logging().ok()
//! } else {
//!    None
//! };
//!
//! // If we know that it's safe to record sensitive data with a given API,
//! // we can disable safe logging temporarily. This affects only the current thread.
//! with_safe_logging_suppressed(|| log_encrypted_data(big_secret));
//! ```
//!
//! ## An example deployment
//!
//! This crate was originally created for use in the `arti` project, which tries
//! to implements the Tor anonymity protocol in Rust.  In `arti`, we want to
//! avoid logging information by default if it could compromise users'
//! anonymity, or create an incentive for attacking users and relays in order to
//! access their logs.
//!
//! In general, Arti treats the following information as [`Sensitive`]:
//!   * Client addresses.
//!   * The destinations (target addresses) of client requests.
//!
//! Arti does _not_ label all private information as `Sensitive`: when
//! information isn't _ever_ suitable for logging, we omit it entirely.

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
    pub fn unwrap(sensitive: Sensitive<T>) -> T {
        sensitive.0
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
