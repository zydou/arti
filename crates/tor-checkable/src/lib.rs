#![cfg_attr(docsrs, feature(doc_cfg))]
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
#![allow(clippy::cognitive_complexity)] // See arti#2556
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
#![deny(clippy::unchecked_time_subtraction)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::mod_module_files)]
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
#![allow(clippy::result_large_err)] // temporary workaround for arti#587
#![allow(clippy::needless_raw_string_hashes)] // complained-about code is fine, often best
#![allow(clippy::needless_lifetimes)] // See arti#1765
#![allow(mismatched_lifetime_syntaxes)] // temporary workaround for arti#2060
#![allow(clippy::collapsible_if)] // See arti#2342
#![deny(clippy::unused_async)]
#![deny(clippy::string_slice)] // See arti#2571
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

use std::time::{self, Duration};
use thiserror::Error;
use web_time_compat::{SystemTime, SystemTimeExt};

pub mod signed;
pub mod timed;

pub use timed::{TimeRange, TimeRangeBound, TimeRangeBoundBuilder};

/// An error that can occur when checking whether a TimeBound object is
/// currently valid.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum TimeValidityError {
    /// The object is not yet valid
    #[error("Object will not be valid for {}", humantime::format_duration(*.0))]
    NotYetValid(Duration),
    /// The object is expired
    #[error("Object has been expired for {}", humantime::format_duration(*.0))]
    Expired(Duration),
    /// The object isn't timely, and we don't know why, or won't say.
    #[error("Object is not currently valid")]
    Unspecified,
}

/// A `TimeBound` object is one that is only valid for a given range of time.
///
/// It's better to wrap things in a TimeBound than to give them an is_valid()
/// valid method, so that you can make sure that nobody uses the object before
/// checking it.
///
/// [`TimeBound`] implementations are required to be **inclusive** of the
/// bounds when performing a verification.  Mathematically speaking, this means
/// that implementations must check whether `x ∊ [start; end]` but *not*
/// `x ∊ (start; end)`.
pub trait TimeBound: Sized {
    /// The inner, wrapped type, which is being protected by this `TimeBound` implementation
    type Inner;

    /// Get the bounds, in the form of a `TimeRangeBound<()>`
    ///
    /// It is permissible for the start to be after the end.
    /// In that case, it's simply never valid: either expired, or too soon, or both.
    //
    // We don't return an `impl RangeBounds` because an `impl RangeBounds` would seems to
    // imply we support open (exclusive) ranges, which we don't.
    // We don't actually need to be generic here; returning a concrete type which
    // is just a pair of Option is fine.
    fn bounds(&self) -> TimeRange;

    /// Check whether this object is valid at a given time.
    ///
    /// Return Ok if the object is valid, and an error if the object is not.
    ///
    /// Generally, do not implement this method yourself:
    /// the provided implementation (which uses `bounds`) will be correct.
    //
    // The actual implementation is the overridden impl on `TimeRangeBounds`.
    fn check_valid_at(&self, t: &time::SystemTime) -> Result<(), TimeValidityError> {
        // This calls the implemented for `TimeRangeBound`
        self.bounds().check_valid_at(t)
    }

    /// Return the underlying object without checking whether it's valid.
    fn dangerously_assume_timely(self) -> Self::Inner;

    /// Unwrap this TimeBound object if it is valid at a given time.
    fn if_valid_at(self, t: &time::SystemTime) -> Result<Self::Inner, TimeValidityError> {
        self.check_valid_at(t)?;
        Ok(self.dangerously_assume_timely())
    }

    /// Unwrap this TimeBound object if it is valid now.
    fn if_valid_now(self) -> Result<Self::Inner, TimeValidityError> {
        self.if_valid_at(&SystemTime::get())
    }

    /// Gain access to the `Inner`, handling the timeout with a `TimeRangeBoundBuilder`
    ///
    /// Unwraps `self`, giving access to `Self::Inner`.
    /// Time time bounds are recorded in the `TimeRangeBoundBuilder`,
    /// and will be applied to the `T` overall return value
    /// from the `logic` closure supplied to [`TimeRangeBound::build_intersect`].
    ///
    /// Can only be called within the `logic` closure to `TimeRangeBound::build_intersect`.
    ///
    /// # CORRECTNESS
    ///
    /// Information from the `Inner` returned from `unwrap_with`
    /// should only be used to help construct the return value from `logic`.
    /// See [`TimeRangeBound::build_intersect`] for more details.
    fn unwrap_with(self, builder: &mut TimeRangeBoundBuilder) -> Self::Inner {
        builder.incorporate_unwrap(self)
    }

    /// Unwrap this object if it is valid at the provided time t.
    /// If no time is provided, check the object at the current time.
    ///
    /// # Deprecated
    ///
    /// We do not believe runtime-selectable current time overrides,
    /// via `Option<SystemTime>`, make sense.
    /// We use `tor_rtcompat::Runtime` for mocking.
    #[deprecated = "use check_valid_at"]
    #[allow(clippy::disallowed_methods)]
    fn check_valid_at_opt(
        self,
        t: Option<time::SystemTime>,
    ) -> Result<Self::Inner, TimeValidityError> {
        match t {
            Some(when) => self.if_valid_at(&when),
            None => self.if_valid_now(),
        }
    }
}

#[deprecated = "use the new name, TimeBound, instead"]
pub use TimeBound as Timebound;

/// A cryptographically signed object that can be validated without
/// additional public keys.
///
/// It's better to wrap things in a SelfSigned than to give them an is_valid()
/// method, so that you can make sure that nobody uses the object before
/// checking it.  It's better to wrap things in a SelfSigned than to check
/// them immediately, since you might want to defer the signature checking
/// operation to another thread.
pub trait SelfSigned<T>: Sized {
    /// An error type that's returned when the object is _not_ well-signed.
    type Error;
    /// Check the signature on this object
    fn is_well_signed(&self) -> Result<(), Self::Error>;
    /// Return the underlying object without checking its signature.
    fn dangerously_assume_wellsigned(self) -> T;

    /// Unwrap this object if the signature is valid
    fn check_signature(self) -> Result<T, Self::Error> {
        self.is_well_signed()?;
        Ok(self.dangerously_assume_wellsigned())
    }
}

/// A cryptographically signed object that needs an external public
/// key to validate it.
pub trait ExternallySigned<T>: Sized {
    /// The type of the public key object.
    ///
    /// You can use a tuple or a vector here if the object is signed
    /// with multiple keys.
    type Key: ?Sized;

    /// A type that describes what keys are missing for this object.
    type KeyHint;

    /// An error type that's returned when the object is _not_ well-signed.
    type Error;

    /// Check whether k is the right key for this object.  If not, return
    /// an error describing what key would be right.
    ///
    /// This function is allowed to return 'true' for a bad key, but never
    /// 'false' for a good key.
    fn key_is_correct(&self, k: &Self::Key) -> Result<(), Self::KeyHint>;

    /// Check the signature on this object
    fn is_well_signed(&self, k: &Self::Key) -> Result<(), Self::Error>;

    /// Unwrap this object without checking any signatures on it.
    fn dangerously_assume_wellsigned(self) -> T;

    /// Unwrap this object if it's correctly signed by a provided key.
    fn check_signature(self, k: &Self::Key) -> Result<T, Self::Error> {
        self.is_well_signed(k)?;
        Ok(self.dangerously_assume_wellsigned())
    }
}
