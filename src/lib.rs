#![doc = include_str!("../README.md")]

use std::time::{Duration, Instant, SystemTime};

mod internal;

/// The core trait of this trait, [`SaturatingTime`].
///
/// This trait provides methods for performing saturating arithmetic on those
/// types in [`std::time`] that not already come with such a functionality,
/// such as [`SystemTime`] or [`Instant`].
///
/// The trait itself is not implementable from the outside, because it is sealed
/// by an internal trait.
///
/// See the methods or the top-level documentation for concrete code examples.
pub trait SaturatingTime: internal::SaturatingTime {
    /// Returns the maximum value for this type on the current platform.
    ///
    /// This limit is highly platform specific.  It differs heavily between
    /// Unix, Windows, and other operating systems.
    ///
    /// The limit itself is calculated dynamically during runtime with a correct
    /// algorithm.  Afterwards, it gets stored in a lazy static value, meaning
    /// that only the first call to it will be slightly more expensive, whereas
    /// all latter calls will result in an immediate return of the value.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::{Duration, SystemTime};
    /// use saturating_time::SaturatingTime;
    ///
    /// let max = SystemTime::max_value();
    ///
    /// // Adding zero to the maximum value will change nothing.
    /// assert!(max.checked_add(Duration::ZERO).is_some());
    ///
    /// // Adding 1ns to the maximum value will fail.
    /// assert!(max.checked_add(Duration::new(0, 1)).is_none());
    ///
    /// // Subtracting 1ns from the maximum value will work of course.
    /// assert!(max.checked_sub(Duration::new(0, 1)).is_some());
    /// ```
    fn max_value() -> Self {
        internal::SaturatingTime::max_value()
    }

    /// Returns the minimum value for this type on the current platform.
    ///
    /// This limit is highly platform specific.  It differs heavily between
    /// Unix, Windows, and other operating systems.
    ///
    /// The limit itself is calculated dynamically during runtime with a correct
    /// algorithm.  Afterwards, it gets stored in a lazy static value, meaning
    /// that only the first call to it will be slightly more expensive, whereas
    /// all latter calls will result in an immediate return of the value.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::{Duration, SystemTime};
    /// use saturating_time::SaturatingTime;
    ///
    /// let min = SystemTime::min_value();
    ///
    /// // Subtracting a zero from the minimum value will change nothing.
    /// assert!(min.checked_sub(Duration::ZERO).is_some());
    ///
    /// // Subtracting 1ns from the minimum value will fail.
    /// assert!(min.checked_sub(Duration::new(0, 1)).is_none());
    ///
    /// // Adding 1ns to the minimum value will work of course.
    /// assert!(min.checked_add(Duration::new(0, 1)).is_some());
    /// ```
    fn min_value() -> Self {
        internal::SaturatingTime::min_value()
    }

    /// Performs a saturating addition of a [`Duration`].
    ///
    /// The resulting value will saturate to [`SaturatingTime::max_value()`] in
    /// the case the addition would have caused an overflow of value.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::{Duration, SystemTime};
    /// use saturating_time::SaturatingTime;
    ///
    /// let max = SystemTime::max_value();
    ///
    /// // Adding zero will change nothing.
    /// assert_eq!(max.saturating_add(Duration::ZERO), max);
    ///
    /// // Adding 1ns would overflow so we saturate to the maximum.
    /// assert_eq!(max.saturating_add(Duration::new(0, 1)), max);
    /// ```
    fn saturating_add(&self, duration: Duration) -> Self {
        self.checked_add(duration)
            .unwrap_or(SaturatingTime::max_value())
    }

    /// Performs a saturating subtraction of a [`Duration`].
    ///
    /// The resulting value will saturate to [`SaturatingTime::min_value()`] in
    /// the case the subtraction would have caused an overflow of value.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::{Duration, SystemTime};
    /// use saturating_time::SaturatingTime;
    ///
    /// let min = SystemTime::min_value();
    ///
    /// // Subtracting zero will change nothing.
    /// assert_eq!(min.saturating_sub(Duration::ZERO), min);
    ///
    /// // Subtracting 1ns would overflow so we saturate to the minimum.
    /// assert_eq!(min.saturating_sub(Duration::new(0, 1)), min);
    /// ```
    fn saturating_sub(&self, duration: Duration) -> Self {
        self.checked_sub(duration)
            .unwrap_or(SaturatingTime::min_value())
    }
}

impl SaturatingTime for SystemTime {}

impl SaturatingTime for Instant {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal;
    use std::{
        fmt::Debug,
        ops::{Add, Sub},
        time::{Instant, SystemTime},
    };

    /// Verifies the maximum and minimum values of [`SaturatingTime`] equal
    /// their pedant in [`internal::SaturatingTime`].
    fn min_max<T: SaturatingTime + PartialEq + Debug>() {
        assert_eq!(
            <T as SaturatingTime>::max_value(),
            <T as internal::SaturatingTime>::max_value()
        );
        assert_eq!(
            <T as SaturatingTime>::min_value(),
            <T as internal::SaturatingTime>::min_value()
        );
    }

    /// Verifies the saturating arithmetic for [`SaturatingTime`].
    fn saturating<
        T: SaturatingTime + PartialEq + Debug + Add<Duration, Output = T> + Sub<Duration, Output = T>,
    >() {
        let max = <T as SaturatingTime>::max_value();
        assert_eq!(max.saturating_add(Duration::ZERO), max);
        assert_eq!(max.saturating_add(Duration::new(0, 1)), max);
        assert_eq!(max.saturating_sub(Duration::ZERO), max);
        assert_eq!(
            max.saturating_sub(Duration::new(0, 1)),
            max - Duration::new(0, 1)
        );

        let min = <T as SaturatingTime>::min_value();
        assert_eq!(min.saturating_sub(Duration::ZERO), min);
        assert_eq!(min.saturating_sub(Duration::new(0, 1)), min);
        assert_eq!(min.saturating_add(Duration::ZERO), min);
        assert_eq!(
            min.saturating_add(Duration::new(0, 1)),
            min + Duration::new(0, 1)
        );
    }

    /// Calls [`min_max()`] using [`SystemTime`].
    #[test]
    fn system_time_min_max() {
        min_max::<SystemTime>();
    }

    /// Calls [`min_max()`] using [`Instant`].
    #[test]
    fn instant_min_max() {
        min_max::<Instant>();
    }

    /// Calls [`saturating()`] using [`SystemTime`].
    #[test]
    fn system_time_saturating() {
        saturating::<SystemTime>();
    }

    /// Calls [`saturating()`] using [`Instant`].
    #[test]
    fn instant_saturating() {
        saturating::<Instant>();
    }
}
