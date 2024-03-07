//! Convenience implementation of a TimeBound object.

use std::ops::{Bound, Deref, RangeBounds};
use std::time;

/// A TimeBound object that is valid for a specified range of time.
///
/// The range is given as an argument, as in `t1..t2`.
///
///
/// ```
/// use std::time::{SystemTime, Duration};
/// use tor_checkable::{Timebound, TimeValidityError, timed::TimerangeBound};
///
/// let now = SystemTime::now();
/// let one_hour = Duration::new(3600, 0);
///
/// // This seven is only valid for another hour!
/// let seven = TimerangeBound::new(7_u32, ..now+one_hour);
///
/// assert_eq!(seven.check_valid_at(&now).unwrap(), 7);
///
/// // That consumed the previous seven. Try another one.
/// let seven = TimerangeBound::new(7_u32, ..now+one_hour);
/// assert_eq!(seven.check_valid_at(&(now+2*one_hour)),
///            Err(TimeValidityError::Expired(one_hour)));
///
/// ```
#[derive(Debug, Clone)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct TimerangeBound<T> {
    /// The underlying object, which we only want to expose if it is
    /// currently timely.
    obj: T,
    /// If present, when the object first became valid.
    start: Option<time::SystemTime>,
    /// If present, when the object will no longer be valid.
    end: Option<time::SystemTime>,
}

/// Helper: convert a Bound to its underlying value, if any.
///
/// This helper discards information about whether the bound was
/// inclusive or exclusive.  However, since SystemTime has sub-second
/// precision, we really don't care about what happens when the
/// nanoseconds are equal to exactly 0.
fn unwrap_bound(b: Bound<&'_ time::SystemTime>) -> Option<time::SystemTime> {
    match b {
        Bound::Included(x) => Some(*x),
        Bound::Excluded(x) => Some(*x),
        _ => None,
    }
}

impl<T> TimerangeBound<T> {
    /// Construct a new TimerangeBound object from a given object and range.
    ///
    /// Note that we do not distinguish between inclusive and
    /// exclusive bounds: `x..y` and `x..=y` are treated the same
    /// here.
    pub fn new<U>(obj: T, range: U) -> Self
    where
        U: RangeBounds<time::SystemTime>,
    {
        let start = unwrap_bound(range.start_bound());
        let end = unwrap_bound(range.end_bound());
        Self { obj, start, end }
    }

    /// Adjust this time-range bound to tolerate an expiration time farther
    /// in the future.
    #[must_use]
    pub fn extend_tolerance(self, d: time::Duration) -> Self {
        let end = match self.end {
            Some(t) => t.checked_add(d),
            _ => None,
        };
        Self { end, ..self }
    }
    /// Adjust this time-range bound to tolerate an initial validity
    /// time farther in the past.
    #[must_use]
    pub fn extend_pre_tolerance(self, d: time::Duration) -> Self {
        let start = match self.start {
            Some(t) => t.checked_sub(d),
            _ => None,
        };
        Self { start, ..self }
    }
    /// Consume this [`TimerangeBound`], and return a new one with the same
    /// bounds, applying `f` to its protected value.
    ///
    /// The caller must ensure that `f` does not make any assumptions about the
    /// timeliness of the protected value, or leak any of its contents in
    /// an inappropriate way.
    #[must_use]
    pub fn dangerously_map<F, U>(self, f: F) -> TimerangeBound<U>
    where
        F: FnOnce(T) -> U,
    {
        TimerangeBound {
            obj: f(self.obj),
            start: self.start,
            end: self.end,
        }
    }

    /// Consume this TimeRangeBound, and return its underlying time bounds and
    /// object.
    ///
    /// The caller takes responsibility for making sure that the bounds are
    /// actually checked.
    pub fn dangerously_into_parts(self) -> (T, (Bound<time::SystemTime>, Bound<time::SystemTime>)) {
        let bounds = self.bounds();

        (self.obj, bounds)
    }

    /// Return a reference to the inner object of this TimeRangeBound, without
    /// checking the time interval.
    ///
    /// The caller takes responsibility for making sure that nothing is actually
    /// done with the inner object that would rely on the bounds being correct, until
    /// the bounds are (eventually) checked.
    pub fn dangerously_peek(&self) -> &T {
        &self.obj
    }

    /// Return a `TimerangeBound` containing a reference
    ///
    /// This can be useful to call methods like `.check_valid_at`
    /// without consuming the inner `T`.
    pub fn as_ref(&self) -> TimerangeBound<&T> {
        TimerangeBound {
            obj: &self.obj,
            start: self.start,
            end: self.end,
        }
    }

    /// Return a `TimerangeBound` containing a reference to `T`'s `Deref`
    pub fn as_deref(&self) -> TimerangeBound<&T::Target>
    where
        T: Deref,
    {
        self.as_ref().dangerously_map(|t| &**t)
    }

    /// Return the underlying time bounds of this object.
    pub fn bounds(&self) -> (Bound<time::SystemTime>, Bound<time::SystemTime>) {
        (self.start_bound().cloned(), self.end_bound().cloned())
    }
}

impl<T> RangeBounds<time::SystemTime> for TimerangeBound<T> {
    fn start_bound(&self) -> Bound<&time::SystemTime> {
        self.start
            .as_ref()
            .map(Bound::Included)
            .unwrap_or(Bound::Unbounded)
    }

    fn end_bound(&self) -> Bound<&time::SystemTime> {
        self.end
            .as_ref()
            .map(Bound::Included)
            .unwrap_or(Bound::Unbounded)
    }
}

impl<T> crate::Timebound<T> for TimerangeBound<T> {
    type Error = crate::TimeValidityError;

    fn is_valid_at(&self, t: &time::SystemTime) -> Result<(), Self::Error> {
        use crate::TimeValidityError;
        if let Some(start) = self.start {
            if let Ok(d) = start.duration_since(*t) {
                return Err(TimeValidityError::NotYetValid(d));
            }
        }

        if let Some(end) = self.end {
            if let Ok(d) = t.duration_since(end) {
                return Err(TimeValidityError::Expired(d));
            }
        }

        Ok(())
    }

    fn dangerously_assume_timely(self) -> T {
        self.obj
    }
}

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
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    use crate::{TimeValidityError, Timebound};
    use humantime::parse_rfc3339;
    use std::time::{Duration, SystemTime};

    #[test]
    fn test_bounds() {
        #![allow(clippy::unwrap_used)]
        let one_day = Duration::new(86400, 0);
        let mixminion_v0_0_1 = parse_rfc3339("2003-01-07T00:00:00Z").unwrap();
        let tor_v0_0_2pre13 = parse_rfc3339("2003-10-19T00:00:00Z").unwrap();
        let cussed_nougat = parse_rfc3339("2008-08-02T00:00:00Z").unwrap();
        let tor_v0_4_4_5 = parse_rfc3339("2020-09-15T00:00:00Z").unwrap();
        let today = parse_rfc3339("2020-09-22T00:00:00Z").unwrap();

        let tr = TimerangeBound::new((), ..tor_v0_4_4_5);
        assert_eq!(tr.start, None);
        assert_eq!(tr.end, Some(tor_v0_4_4_5));
        assert!(tr.is_valid_at(&mixminion_v0_0_1).is_ok());
        assert!(tr.is_valid_at(&tor_v0_0_2pre13).is_ok());
        assert_eq!(
            tr.is_valid_at(&today),
            Err(TimeValidityError::Expired(7 * one_day))
        );

        let tr = TimerangeBound::new((), tor_v0_0_2pre13..=tor_v0_4_4_5);
        assert_eq!(tr.start, Some(tor_v0_0_2pre13));
        assert_eq!(tr.end, Some(tor_v0_4_4_5));
        assert_eq!(
            tr.is_valid_at(&mixminion_v0_0_1),
            Err(TimeValidityError::NotYetValid(285 * one_day))
        );
        assert!(tr.is_valid_at(&cussed_nougat).is_ok());
        assert_eq!(
            tr.is_valid_at(&today),
            Err(TimeValidityError::Expired(7 * one_day))
        );

        let tr = tr
            .extend_pre_tolerance(5 * one_day)
            .extend_tolerance(2 * one_day);
        assert_eq!(tr.start, Some(tor_v0_0_2pre13 - 5 * one_day));
        assert_eq!(tr.end, Some(tor_v0_4_4_5 + 2 * one_day));

        let tr = tr
            .extend_pre_tolerance(Duration::MAX)
            .extend_tolerance(Duration::MAX);
        assert_eq!(tr.start, None);
        assert_eq!(tr.end, None);

        let tr = TimerangeBound::new((), tor_v0_4_4_5..);
        assert_eq!(tr.start, Some(tor_v0_4_4_5));
        assert_eq!(tr.end, None);
        assert_eq!(
            tr.is_valid_at(&cussed_nougat),
            Err(TimeValidityError::NotYetValid(4427 * one_day))
        );
        assert!(tr.is_valid_at(&today).is_ok());
    }

    #[test]
    fn test_checking() {
        // West and East Germany reunified
        let de = humantime::parse_rfc3339("1990-10-03T00:00:00Z").unwrap();
        // Czechoslovakia separates into Czech Republic (Bohemia) & Slovakia
        let cz_sk = humantime::parse_rfc3339("1993-01-01T00:00:00Z").unwrap();
        // European Union created
        let eu = humantime::parse_rfc3339("1993-11-01T00:00:00Z").unwrap();
        // South Africa holds first free and fair elections
        let za = humantime::parse_rfc3339("1994-04-27T00:00:00Z").unwrap();

        // check_valid_at
        let tr = TimerangeBound::new("Hello world", cz_sk..eu);
        assert!(tr.check_valid_at(&za).is_err());

        let tr = TimerangeBound::new("Hello world", cz_sk..za);
        assert_eq!(tr.check_valid_at(&eu), Ok("Hello world"));

        // check_valid_now
        let tr = TimerangeBound::new("hello world", de..);
        assert_eq!(tr.check_valid_now(), Ok("hello world"));

        let tr = TimerangeBound::new("hello world", ..za);
        assert!(tr.check_valid_now().is_err());

        // Now try check_valid_at_opt() api
        let tr = TimerangeBound::new("hello world", de..);
        assert_eq!(tr.check_valid_at_opt(None), Ok("hello world"));
        let tr = TimerangeBound::new("hello world", de..);
        assert_eq!(
            tr.check_valid_at_opt(Some(SystemTime::now())),
            Ok("hello world")
        );
        let tr = TimerangeBound::new("hello world", ..za);
        assert!(tr.check_valid_at_opt(None).is_err());
    }

    #[test]
    fn test_dangerous() {
        let t1 = SystemTime::now();
        let t2 = t1 + Duration::from_secs(60 * 525600);
        let tr = TimerangeBound::new("cups of coffee", t1..=t2);

        assert_eq!(tr.dangerously_peek(), &"cups of coffee");

        let (a, b) = tr.dangerously_into_parts();
        assert_eq!(a, "cups of coffee");
        assert_eq!(b.0, Bound::Included(t1));
        assert_eq!(b.1, Bound::Included(t2));
    }

    #[test]
    fn test_map() {
        let t1 = SystemTime::now();
        let min = Duration::from_secs(60);

        let tb = TimerangeBound::new(17_u32, t1..t1 + 5 * min);
        let tb = tb.dangerously_map(|v| v * v);
        assert!(tb.is_valid_at(&(t1 + 1 * min)).is_ok());
        assert!(tb.is_valid_at(&(t1 + 10 * min)).is_err());

        let val = tb.check_valid_at(&(t1 + 1 * min)).unwrap();
        assert_eq!(val, 289);
    }

    #[test]
    fn test_as_ref() {
        let t1 = SystemTime::now();
        let min = Duration::from_secs(60);

        let tb1: TimerangeBound<String> = TimerangeBound::new("hi".into(), t1..t1 + 5 * min);
        let tb2: TimerangeBound<&String> = tb1.as_ref();
        let tb3: TimerangeBound<&str> = tb1.as_deref();
        assert_eq!(tb1, tb2.dangerously_map(|s| s.clone()));
        assert_eq!(tb1, tb3.dangerously_map(|s| s.to_owned()));
    }
}
