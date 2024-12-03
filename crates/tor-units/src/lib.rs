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
#![allow(clippy::needless_lifetimes)] // See arti#1765
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

use derive_more::{Add, Display, Div, From, FromStr, Mul};

use std::time::Duration;
use thiserror::Error;

#[cfg(feature = "memquota-memcost")]
use {derive_deftly::Deftly, tor_memquota::derive_deftly_template_HasMemoryCost};

/// Conversion errors from converting a value into a [`BoundedInt32`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum Error {
    /// A passed value was below the lower bound for the type.
    #[error("Value {0} was below the lower bound {1} for this type")]
    BelowLowerBound(i32, i32),
    /// A passed value was above the upper bound for the type.
    #[error("Value {0} was above the lower bound {1} for this type")]
    AboveUpperBound(i32, i32),
    /// Tried to convert a negative value to an unsigned type.
    #[error("Tried to convert a negative value to an unsigned type")]
    Negative,
    /// Tried to parse a value that was not representable as the
    /// underlying type.
    #[error("Value could not be represented as an i32")]
    Unrepresentable,
    /// We encountered some kind of integer overflow when converting a number.
    #[error("Integer overflow")]
    Overflow,
    /// Tried to instantiate an uninhabited type.
    #[error("No value is valid for this type")]
    Uninhabited,
}

/// A 32-bit signed integer with a restricted range.
///
/// This type holds an i32 value such that `LOWER` <= value <= `UPPER`
///
/// # Limitations
///
/// If you try to instantiate this type with LOWER > UPPER, you will
/// get an uninhabitable type.  It would be better if we could check that at
/// compile time, and prevent such types from being named.
//
// [TODO: If you need a Bounded* for some type other than i32, ask nickm:
// he has an implementation kicking around.]
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
#[cfg_attr(
    feature = "memquota-memcost",
    derive(Deftly),
    derive_deftly(HasMemoryCost)
)]
pub struct BoundedInt32<const LOWER: i32, const UPPER: i32> {
    /// Interior Value
    value: i32,
}

impl<const LOWER: i32, const UPPER: i32> BoundedInt32<LOWER, UPPER> {
    /// Lower bound
    pub const LOWER: i32 = LOWER;
    /// Upper bound
    pub const UPPER: i32 = UPPER;

    /// Private constructor function for this type.
    fn unchecked_new(value: i32) -> Self {
        assert!(LOWER <= UPPER); //The compiler optimizes this out, no run-time cost.

        BoundedInt32 { value }
    }

    /// Return the underlying i32 value.
    ///
    /// This value will always be between [`Self::LOWER`] and [`Self::UPPER`],
    /// inclusive.
    pub fn get(&self) -> i32 {
        self.value
    }

    /// If `val` is within range, return a new `BoundedInt32` wrapping
    /// it; otherwise, clamp it to the upper or lower bound as
    /// appropriate.
    pub fn saturating_new(val: i32) -> Self {
        Self::unchecked_new(Self::clamp(val))
    }

    /// If `val` is an acceptable value inside the range for this type,
    /// return a new [`BoundedInt32`].  Otherwise return an error.
    pub fn checked_new(val: i32) -> Result<Self, Error> {
        if val > UPPER {
            Err(Error::AboveUpperBound(val, UPPER))
        } else if val < LOWER {
            Err(Error::BelowLowerBound(val, LOWER))
        } else {
            Ok(BoundedInt32::unchecked_new(val))
        }
    }

    /// This private function clamps an input to the acceptable range.
    fn clamp(val: i32) -> i32 {
        Ord::clamp(val, LOWER, UPPER)
    }

    /// Convert from the underlying type, clamping to the upper or
    /// lower bound if needed.
    ///
    /// # Panics
    ///
    /// This function will panic if UPPER < LOWER.
    pub fn saturating_from(val: i32) -> Self {
        Self::unchecked_new(Self::clamp(val))
    }

    /// Convert from a string, clamping to the upper or lower bound if needed.
    ///
    /// # Limitations
    ///
    /// If the input is a number that cannot be represented as an i32,
    /// then we return an error instead of clamping it.
    pub fn saturating_from_str(s: &str) -> Result<Self, Error> {
        if UPPER < LOWER {
            // The compiler should optimize this block out at compile time.
            return Err(Error::Uninhabited);
        }
        let val: i32 = s.parse().map_err(|_| Error::Unrepresentable)?;
        Ok(Self::saturating_from(val))
    }
}

impl<const L: i32, const U: i32> std::fmt::Display for BoundedInt32<L, U> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}

impl<const L: i32, const U: i32> From<BoundedInt32<L, U>> for i32 {
    fn from(val: BoundedInt32<L, U>) -> i32 {
        val.value
    }
}

impl<const L: i32, const U: i32> From<BoundedInt32<L, U>> for f64 {
    fn from(val: BoundedInt32<L, U>) -> f64 {
        val.value.into()
    }
}

impl<const L: i32, const H: i32> TryFrom<i32> for BoundedInt32<L, H> {
    type Error = Error;
    fn try_from(val: i32) -> Result<Self, Self::Error> {
        Self::checked_new(val)
    }
}

impl<const L: i32, const H: i32> std::str::FromStr for BoundedInt32<L, H> {
    type Err = Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::checked_new(s.parse().map_err(|_| Error::Unrepresentable)?)
    }
}

impl From<BoundedInt32<0, 1>> for bool {
    fn from(val: BoundedInt32<0, 1>) -> bool {
        val.value == 1
    }
}

impl From<BoundedInt32<0, 255>> for u8 {
    fn from(val: BoundedInt32<0, 255>) -> u8 {
        val.value as u8
    }
}

impl<const H: i32> From<BoundedInt32<0, H>> for u32 {
    fn from(val: BoundedInt32<0, H>) -> u32 {
        val.value as u32
    }
}

impl<const H: i32> From<BoundedInt32<1, H>> for u32 {
    fn from(val: BoundedInt32<1, H>) -> u32 {
        val.value as u32
    }
}

impl<const L: i32, const H: i32> TryFrom<BoundedInt32<L, H>> for u64 {
    type Error = Error;
    fn try_from(val: BoundedInt32<L, H>) -> Result<Self, Self::Error> {
        if val.value < 0 {
            Err(Error::Negative)
        } else {
            Ok(val.value as u64)
        }
    }
}

impl<const L: i32, const H: i32> TryFrom<BoundedInt32<L, H>> for usize {
    type Error = Error;
    fn try_from(val: BoundedInt32<L, H>) -> Result<Self, Self::Error> {
        if val.value < 0 {
            Err(Error::Negative)
        } else {
            Ok(val.value as usize)
        }
    }
}

/// A percentage value represented as a number.
///
/// This type wraps an underlying numeric type, and ensures that callers
/// are clear whether they want a _fraction_, or a _percentage_.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct Percentage<T: Copy + Into<f64>> {
    /// The underlying percentage value.
    value: T,
}

impl<T: Copy + Into<f64>> Percentage<T> {
    /// Create a new `IntPercentage` from the underlying percentage.
    pub fn new(value: T) -> Self {
        Self { value }
    }

    /// Return this value as a (possibly improper) fraction.
    ///
    /// ```
    /// use tor_units::Percentage;
    /// let pct_200 = Percentage::<u8>::new(200);
    /// let pct_100 = Percentage::<u8>::new(100);
    /// let pct_50 = Percentage::<u8>::new(50);
    ///
    /// assert_eq!(pct_200.as_fraction(), 2.0);
    /// assert_eq!(pct_100.as_fraction(), 1.0);
    /// assert_eq!(pct_50.as_fraction(), 0.5);
    /// // Note: don't actually compare f64 with ==.
    /// ```
    pub fn as_fraction(self) -> f64 {
        self.value.into() / 100.0
    }

    /// Return this value as a percentage.
    ///
    /// ```
    /// use tor_units::Percentage;
    /// let pct_200 = Percentage::<u8>::new(200);
    /// let pct_100 = Percentage::<u8>::new(100);
    /// let pct_50 = Percentage::<u8>::new(50);
    ///
    /// assert_eq!(pct_200.as_percent(), 200);
    /// assert_eq!(pct_100.as_percent(), 100);
    /// assert_eq!(pct_50.as_percent(), 50);
    /// ```
    pub fn as_percent(self) -> T {
        self.value
    }
}

impl<const H: i32, const L: i32> TryFrom<i32> for Percentage<BoundedInt32<H, L>> {
    type Error = Error;
    fn try_from(v: i32) -> Result<Self, Error> {
        Ok(Percentage::new(v.try_into()?))
    }
}

// TODO: There is a bunch of code duplication among these "IntegerTimeUnits"
// section.

#[derive(
    Add, Copy, Clone, Mul, Div, From, FromStr, Display, Debug, PartialEq, Eq, Ord, PartialOrd, Hash,
)]
/// This type represents an integer number of milliseconds.
///
/// The underlying type should usually implement `TryInto<u64>`.
pub struct IntegerMilliseconds<T> {
    /// Interior Value. Should implement `TryInto<u64>` to be useful.
    value: T,
}

impl<T> IntegerMilliseconds<T> {
    /// Public Constructor
    pub fn new(value: T) -> Self {
        IntegerMilliseconds { value }
    }

    /// Deconstructor
    ///
    /// Use only in contexts where it's no longer possible to
    /// use the Rust type system to ensure secs vs ms vs us correctness.
    pub fn as_millis(self) -> T {
        self.value
    }

    /// Map the inner value (useful for conversion)
    ///
    /// # Example
    ///
    /// ```
    /// use tor_units::{BoundedInt32, IntegerMilliseconds};
    ///
    /// let value: IntegerMilliseconds<i32> = 42.into();
    /// let value: IntegerMilliseconds<BoundedInt32<0,1000>>
    ///     = value.try_map(TryInto::try_into).unwrap();
    /// ```
    pub fn try_map<U, F, E>(self, f: F) -> Result<IntegerMilliseconds<U>, E>
    where
        F: FnOnce(T) -> Result<U, E>,
    {
        Ok(IntegerMilliseconds::new(f(self.value)?))
    }
}

impl<T: TryInto<u64>> TryFrom<IntegerMilliseconds<T>> for Duration {
    type Error = <T as TryInto<u64>>::Error;
    fn try_from(val: IntegerMilliseconds<T>) -> Result<Self, <T as TryInto<u64>>::Error> {
        Ok(Self::from_millis(val.value.try_into()?))
    }
}

impl<const H: i32, const L: i32> TryFrom<i32> for IntegerMilliseconds<BoundedInt32<H, L>> {
    type Error = Error;
    fn try_from(v: i32) -> Result<Self, Error> {
        Ok(IntegerMilliseconds::new(v.try_into()?))
    }
}

#[derive(
    Add, Copy, Clone, Mul, Div, From, FromStr, Display, Debug, PartialEq, Eq, Ord, PartialOrd, Hash,
)]
/// This type represents an integer number of seconds.
///
/// The underlying type should usually implement `TryInto<u64>`.
pub struct IntegerSeconds<T> {
    /// Interior Value. Should implement `TryInto<u64>` to be useful.
    value: T,
}

impl<T> IntegerSeconds<T> {
    /// Public Constructor
    pub fn new(value: T) -> Self {
        IntegerSeconds { value }
    }

    /// Deconstructor
    ///
    /// Use only in contexts where it's no longer possible to
    /// use the Rust type system to ensure secs vs ms vs us correctness.
    pub fn as_secs(self) -> T {
        self.value
    }

    /// Map the inner value (useful for conversion)
    ///
    /// ```
    /// use tor_units::{BoundedInt32, IntegerSeconds};
    ///
    /// let value: IntegerSeconds<i32> = 42.into();
    /// let value: IntegerSeconds<BoundedInt32<0,1000>>
    ///     = value.try_map(TryInto::try_into).unwrap();
    /// ```
    pub fn try_map<U, F, E>(self, f: F) -> Result<IntegerSeconds<U>, E>
    where
        F: FnOnce(T) -> Result<U, E>,
    {
        Ok(IntegerSeconds::new(f(self.value)?))
    }
}

impl<T: TryInto<u64>> TryFrom<IntegerSeconds<T>> for Duration {
    type Error = <T as TryInto<u64>>::Error;
    fn try_from(val: IntegerSeconds<T>) -> Result<Self, <T as TryInto<u64>>::Error> {
        Ok(Self::from_secs(val.value.try_into()?))
    }
}

impl<const H: i32, const L: i32> TryFrom<i32> for IntegerSeconds<BoundedInt32<H, L>> {
    type Error = Error;
    fn try_from(v: i32) -> Result<Self, Error> {
        Ok(IntegerSeconds::new(v.try_into()?))
    }
}

#[derive(Copy, Clone, From, FromStr, Display, Debug, PartialEq, Eq, Ord, PartialOrd, Hash)]
/// This type represents an integer number of minutes.
///
/// The underlying type should usually implement `TryInto<u64>`.
pub struct IntegerMinutes<T> {
    /// Interior Value. Should Implement `TryInto<u64>` to be useful.
    value: T,
}

impl<T> IntegerMinutes<T> {
    /// Public Constructor
    pub fn new(value: T) -> Self {
        IntegerMinutes { value }
    }

    /// Deconstructor
    ///
    /// Use only in contexts where it's no longer possible to
    /// use the Rust type system to ensure secs vs ms vs us correctness.
    pub fn as_minutes(self) -> T {
        self.value
    }

    /// Map the inner value (useful for conversion)
    ///
    /// ```
    /// use tor_units::{BoundedInt32, IntegerMinutes};
    ///
    /// let value: IntegerMinutes<i32> = 42.into();
    /// let value: IntegerMinutes<BoundedInt32<0,1000>>
    ///     = value.try_map(TryInto::try_into).unwrap();
    /// ```
    pub fn try_map<U, F, E>(self, f: F) -> Result<IntegerMinutes<U>, E>
    where
        F: FnOnce(T) -> Result<U, E>,
    {
        Ok(IntegerMinutes::new(f(self.value)?))
    }
}

impl<T: TryInto<u64>> TryFrom<IntegerMinutes<T>> for Duration {
    type Error = Error;
    fn try_from(val: IntegerMinutes<T>) -> Result<Self, Error> {
        /// Number of seconds in a single minute.
        const SECONDS_PER_MINUTE: u64 = 60;
        let minutes: u64 = val.value.try_into().map_err(|_| Error::Overflow)?;
        let seconds = minutes
            .checked_mul(SECONDS_PER_MINUTE)
            .ok_or(Error::Overflow)?;
        Ok(Self::from_secs(seconds))
    }
}

impl<const H: i32, const L: i32> TryFrom<i32> for IntegerMinutes<BoundedInt32<H, L>> {
    type Error = Error;
    fn try_from(v: i32) -> Result<Self, Error> {
        Ok(IntegerMinutes::new(v.try_into()?))
    }
}

#[derive(Copy, Clone, From, FromStr, Display, Debug, PartialEq, Eq, Ord, PartialOrd, Hash)]
/// This type represents an integer number of days.
///
/// The underlying type should usually implement `TryInto<u64>`.
pub struct IntegerDays<T> {
    /// Interior Value. Should Implement `TryInto<u64>` to be useful.
    value: T,
}

impl<T> IntegerDays<T> {
    /// Public Constructor
    pub fn new(value: T) -> Self {
        IntegerDays { value }
    }

    /// Deconstructor
    ///
    /// Use only in contexts where it's no longer possible to
    /// use the Rust type system to ensure secs vs ms vs us correctness.
    pub fn as_days(self) -> T {
        self.value
    }

    /// Map the inner value (useful for conversion)
    ///
    /// ```
    /// use tor_units::{BoundedInt32, IntegerDays};
    ///
    /// let value: IntegerDays<i32> = 42.into();
    /// let value: IntegerDays<BoundedInt32<0,1000>>
    ///     = value.try_map(TryInto::try_into).unwrap();
    /// ```
    pub fn try_map<U, F, E>(self, f: F) -> Result<IntegerDays<U>, E>
    where
        F: FnOnce(T) -> Result<U, E>,
    {
        Ok(IntegerDays::new(f(self.value)?))
    }
}

impl<T: TryInto<u64>> TryFrom<IntegerDays<T>> for Duration {
    type Error = Error;
    fn try_from(val: IntegerDays<T>) -> Result<Self, Error> {
        /// Number of seconds in a single day.
        const SECONDS_PER_DAY: u64 = 86400;
        let days: u64 = val.value.try_into().map_err(|_| Error::Overflow)?;
        let seconds = days.checked_mul(SECONDS_PER_DAY).ok_or(Error::Overflow)?;
        Ok(Self::from_secs(seconds))
    }
}

impl<const H: i32, const L: i32> TryFrom<i32> for IntegerDays<BoundedInt32<H, L>> {
    type Error = Error;
    fn try_from(v: i32) -> Result<Self, Error> {
        Ok(IntegerDays::new(v.try_into()?))
    }
}

/// A SendMe Version
///
/// DOCDOC: Explain why this needs to have its own type, or remove it.
#[derive(Clone, Copy, From, FromStr, Display, Debug, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub struct SendMeVersion(u8);

impl SendMeVersion {
    /// Public Constructor
    pub fn new(value: u8) -> Self {
        SendMeVersion(value)
    }

    /// Helper
    pub fn get(&self) -> u8 {
        self.0
    }
}

impl TryFrom<i32> for SendMeVersion {
    type Error = Error;
    fn try_from(v: i32) -> Result<Self, Error> {
        let val_u8 = BoundedInt32::<0, 255>::checked_new(v)?;
        Ok(SendMeVersion::new(val_u8.get() as u8))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use float_cmp::assert_approx_eq;

    use super::*;

    type TestFoo = BoundedInt32<1, 5>;
    type TestBar = BoundedInt32<-45, 17>;

    //make_parameter_type! {TestFoo(3,)}
    #[test]
    fn entire_range_parsed() {
        let x: TestFoo = "1".parse().unwrap();
        assert!(x.get() == 1);
        let x: TestFoo = "2".parse().unwrap();
        assert!(x.get() == 2);
        let x: TestFoo = "3".parse().unwrap();
        assert!(x.get() == 3);
        let x: TestFoo = "4".parse().unwrap();
        assert!(x.get() == 4);
        let x: TestFoo = "5".parse().unwrap();
        assert!(x.get() == 5);
    }

    #[test]
    fn saturating() {
        let x: TestFoo = TestFoo::saturating_new(1000);
        let x_val: i32 = x.into();
        assert!(x_val == TestFoo::UPPER);
        let x: TestFoo = TestFoo::saturating_new(0);
        let x_val: i32 = x.into();
        assert!(x_val == TestFoo::LOWER);
    }
    #[test]
    fn saturating_string() {
        let x: TestFoo = TestFoo::saturating_from_str("1000").unwrap();
        let x_val: i32 = x.into();
        assert!(x_val == TestFoo::UPPER);
        let x: TestFoo = TestFoo::saturating_from_str("0").unwrap();
        let x_val: i32 = x.into();
        assert!(x_val == TestFoo::LOWER);
    }

    #[test]
    #[should_panic]
    fn uninhabited_saturating_new() {
        // This value should be uncreatable.
        let _: BoundedInt32<10, 5> = BoundedInt32::saturating_new(7);
    }

    #[test]
    fn uninhabited_from_string() {
        let v: Result<BoundedInt32<10, 5>, Error> = BoundedInt32::saturating_from_str("7");
        assert!(matches!(v, Err(Error::Uninhabited)));
    }

    #[test]
    fn errors_correct() {
        let x: Result<TestBar, Error> = "1000".parse();
        assert!(x.unwrap_err() == Error::AboveUpperBound(1000, TestBar::UPPER));
        let x: Result<TestBar, Error> = "-1000".parse();
        assert!(x.unwrap_err() == Error::BelowLowerBound(-1000, TestBar::LOWER));
        let x: Result<TestBar, Error> = "xyz".parse();
        assert!(x.unwrap_err() == Error::Unrepresentable);
    }

    #[test]
    fn display() {
        let v = BoundedInt32::<99, 1000>::checked_new(345).unwrap();
        assert_eq!(v.to_string(), "345".to_string());
    }

    #[test]
    #[should_panic]
    fn checked_too_high() {
        let _: TestBar = "1000".parse().unwrap();
    }

    #[test]
    #[should_panic]
    fn checked_too_low() {
        let _: TestBar = "-46".parse().unwrap();
    }

    #[test]
    fn bounded_to_u64() {
        let b: BoundedInt32<-100, 100> = BoundedInt32::checked_new(77).unwrap();
        let u: u64 = b.try_into().unwrap();
        assert_eq!(u, 77);

        let b: BoundedInt32<-100, 100> = BoundedInt32::checked_new(-77).unwrap();
        let u: Result<u64, Error> = b.try_into();
        assert!(u.is_err());
    }

    #[test]
    fn bounded_to_f64() {
        let x: BoundedInt32<-100, 100> = BoundedInt32::checked_new(77).unwrap();
        let f: f64 = x.into();
        assert_approx_eq!(f64, f, 77.0);
    }

    #[test]
    fn bounded_from_i32() {
        let x: Result<BoundedInt32<-100, 100>, _> = 50.try_into();
        let y: i32 = x.unwrap().into();
        assert_eq!(y, 50);

        let x: Result<BoundedInt32<-100, 100>, _> = 1000.try_into();
        assert!(x.is_err());
    }

    #[test]
    fn into_bool() {
        let zero: BoundedInt32<0, 1> = BoundedInt32::saturating_from(0);
        let one: BoundedInt32<0, 1> = BoundedInt32::saturating_from(1);

        let f: bool = zero.into();
        let t: bool = one.into();
        assert!(!f);
        assert!(t);
    }

    #[test]
    fn into_u8() {
        let zero: BoundedInt32<0, 255> = BoundedInt32::saturating_from(0);
        let one: BoundedInt32<0, 255> = BoundedInt32::saturating_from(1);
        let ninety: BoundedInt32<0, 255> = BoundedInt32::saturating_from(90);
        let max: BoundedInt32<0, 255> = BoundedInt32::saturating_from(1000);

        let a: u8 = zero.into();
        let b: u8 = one.into();
        let c: u8 = ninety.into();
        let d: u8 = max.into();

        assert_eq!(a, 0);
        assert_eq!(b, 1);
        assert_eq!(c, 90);
        assert_eq!(d, 255);
    }

    #[test]
    fn into_u32() {
        let zero: BoundedInt32<0, 1000> = BoundedInt32::saturating_from(0);
        let one: BoundedInt32<0, 1000> = BoundedInt32::saturating_from(1);
        let ninety: BoundedInt32<0, 1000> = BoundedInt32::saturating_from(90);
        let max: BoundedInt32<0, 1000> = BoundedInt32::saturating_from(1000);

        assert_eq!(u32::from(zero), 0);
        assert_eq!(u32::from(one), 1);
        assert_eq!(u32::from(ninety), 90);
        assert_eq!(u32::from(max), 1000);

        let zero: BoundedInt32<1, 1000> = BoundedInt32::saturating_from(0);
        let one: BoundedInt32<1, 1000> = BoundedInt32::saturating_from(1);
        let ninety: BoundedInt32<1, 1000> = BoundedInt32::saturating_from(90);
        let max: BoundedInt32<1, 1000> = BoundedInt32::saturating_from(1000);

        assert_eq!(u32::from(zero), 1);
        assert_eq!(u32::from(one), 1);
        assert_eq!(u32::from(ninety), 90);
        assert_eq!(u32::from(max), 1000);
    }

    #[test]
    fn try_into_usize() {
        let b0: BoundedInt32<-10, 300> = BoundedInt32::saturating_from(0);
        let b100: BoundedInt32<-10, 300> = BoundedInt32::saturating_from(100);
        let bn5: BoundedInt32<-10, 300> = BoundedInt32::saturating_from(-5);
        assert_eq!(usize::try_from(b0), Ok(0_usize));
        assert_eq!(usize::try_from(b100), Ok(100_usize));
        assert_eq!(usize::try_from(bn5), Err(Error::Negative));
    }

    #[test]
    fn percents() {
        type Pct = Percentage<u8>;
        let p = Pct::new(100);
        assert_eq!(p.as_percent(), 100);
        assert_approx_eq!(f64, p.as_fraction(), 1.0);

        let p = Pct::new(0);
        assert_eq!(p.as_percent(), 0);
        assert_approx_eq!(f64, p.as_fraction(), 0.0);

        let p = Pct::new(25);
        assert_eq!(p.as_percent(), 25);
        assert_eq!(p.clone(), p);
        assert_approx_eq!(f64, p.as_fraction(), 0.25);

        type BPct = Percentage<BoundedInt32<0, 100>>;
        assert_eq!(BPct::try_from(99).unwrap().as_percent().get(), 99);
    }

    #[test]
    fn milliseconds() {
        type Msec = IntegerMilliseconds<i32>;

        let ms = Msec::new(500);
        let d: Result<Duration, _> = ms.try_into();
        assert_eq!(d.unwrap(), Duration::from_millis(500));
        assert_eq!(Duration::try_from(ms * 2).unwrap(), Duration::from_secs(1));

        let ms = Msec::new(-100);
        let d: Result<Duration, _> = ms.try_into();
        assert!(d.is_err());

        type BMSec = IntegerMilliseconds<BoundedInt32<0, 1000>>;
        let half_sec = BMSec::try_from(500).unwrap();
        assert_eq!(
            Duration::try_from(half_sec).unwrap(),
            Duration::from_millis(500)
        );
        assert!(BMSec::try_from(1001).is_err());
    }

    #[test]
    fn seconds() {
        type Sec = IntegerSeconds<i32>;

        let ms = Sec::new(500);
        let d: Result<Duration, _> = ms.try_into();
        assert_eq!(d.unwrap(), Duration::from_secs(500));

        let ms = Sec::new(-100);
        let d: Result<Duration, _> = ms.try_into();
        assert!(d.is_err());

        type BSec = IntegerSeconds<BoundedInt32<0, 3600>>;
        let half_hour = BSec::try_from(1800).unwrap();
        assert_eq!(
            Duration::try_from(half_hour).unwrap(),
            Duration::from_secs(1800)
        );
        assert!(BSec::try_from(9999).is_err());
        assert_eq!(half_hour.clone(), half_hour);
    }

    #[test]
    fn minutes() {
        type Min = IntegerMinutes<i32>;

        let t = Min::new(500);
        let d: Duration = t.try_into().unwrap();
        assert_eq!(d, Duration::from_secs(500 * 60));

        let t = Min::new(-100);
        let d: Result<Duration, _> = t.try_into();
        assert_eq!(d, Err(Error::Overflow));

        let t = IntegerMinutes::<u64>::new(u64::MAX);
        let d: Result<Duration, _> = t.try_into();
        assert_eq!(d, Err(Error::Overflow));

        type BMin = IntegerMinutes<BoundedInt32<10, 30>>;
        assert_eq!(
            BMin::new(17_i32.try_into().unwrap()),
            BMin::try_from(17).unwrap()
        );
    }

    #[test]
    fn days() {
        type Days = IntegerDays<i32>;

        let t = Days::new(500);
        let d: Duration = t.try_into().unwrap();
        assert_eq!(d, Duration::from_secs(500 * 86400));

        let t = Days::new(-100);
        let d: Result<Duration, _> = t.try_into();
        assert_eq!(d, Err(Error::Overflow));

        let t = IntegerDays::<u64>::new(u64::MAX);
        let d: Result<Duration, _> = t.try_into();
        assert_eq!(d, Err(Error::Overflow));

        type BDays = IntegerDays<BoundedInt32<10, 30>>;
        assert_eq!(
            BDays::new(17_i32.try_into().unwrap()),
            BDays::try_from(17).unwrap()
        );
    }

    #[test]
    fn sendme() {
        let smv = SendMeVersion::new(5);
        assert_eq!(smv.get(), 5);
        assert_eq!(smv.clone().get(), 5);
        assert_eq!(smv, SendMeVersion::try_from(5).unwrap());
    }
}
