//! Manipulate time periods (as used in the onion service system)

use std::time::{Duration, SystemTime};

use tor_units::IntegerMinutes;

/// A period of time, as used in the onion service system.
///
/// A `TimePeriod` is defined as a duration (in seconds), and the number of such
/// durations that have elapsed since a given offset from the Unix epoch.  So
/// for example, the interval "(86400 seconds length, 15 intervals, 12 hours
/// offset)", covers `1970-01-16T12:00:00` up to but not including
/// `1970-01-17T12:00:00`.
///
/// These time periods are used to derive a different `BlindedOnionIdKey` during
/// each period from each `OnionIdKey`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TimePeriod {
    /// Index of the time periods that have passed since the unix epoch.
    pub(crate) interval_num: u64,
    /// The length of a time period, in **minutes**.
    ///
    /// The spec admits only periods which are a whole number of minutes.
    pub(crate) length: IntegerMinutes<u32>,
    /// Our offset from the epoch, in seconds.
    ///
    /// This is the amount of time after the Unix epoch when our epoch begins,
    /// rounded down to the nearest second.
    pub(crate) epoch_offset_in_sec: u32,
}

/// Two [`TimePeriod`]s are ordered with respect to one another if they have the
/// same interval length and offset.
impl PartialOrd for TimePeriod {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        if self.length == other.length && self.epoch_offset_in_sec == other.epoch_offset_in_sec {
            Some(self.interval_num.cmp(&other.interval_num))
        } else {
            None
        }
    }
}

impl TimePeriod {
    /// Construct a time period of a given `length` that contains `when`.
    ///
    /// The `length` value is rounded down to the nearest second,
    /// and must then be a whole number of minutes.
    ///
    /// The `epoch_offset` value is the amount of time after the Unix epoch when
    /// our epoch begins.  It is also rounded down to the nearest second.
    ///
    /// Return None if the Duration is too large or too small, or if `when`
    /// cannot be represented as a time period.
    pub fn new(
        length: Duration,
        when: SystemTime,
        epoch_offset: Duration,
    ) -> Result<Self, TimePeriodError> {
        // The algorithm here is specified in rend-spec-v3 section 2.2.1
        let length_in_sec =
            u32::try_from(length.as_secs()).map_err(|_| TimePeriodError::IntervalInvalid)?;
        if length_in_sec % 60 != 0 || length.subsec_nanos() != 0 {
            return Err(TimePeriodError::IntervalInvalid);
        }
        let length_in_minutes = length_in_sec / 60;
        let length = IntegerMinutes::new(length_in_minutes);
        let epoch_offset_in_sec =
            u32::try_from(epoch_offset.as_secs()).map_err(|_| TimePeriodError::OffsetInvalid)?;
        let interval_num = when
            .duration_since(SystemTime::UNIX_EPOCH + epoch_offset)
            .map_err(|_| TimePeriodError::OutOfRange)?
            .as_secs()
            / u64::from(length_in_sec);
        Ok(TimePeriod {
            interval_num,
            length,
            epoch_offset_in_sec,
        })
    }

    /// Compute the `TimePeriod`, given its length (in **minutes**), index (the number of time
    /// periods that have passed since the unix epoch), and offset from the epoch (in seconds).
    ///
    /// The `epoch_offset_in_sec` value is the number of seconds after the Unix epoch when our
    /// epoch begins, rounded down to the nearest second.
    /// Note that this is *not* the time_t at which this *Time Period* begins.
    ///
    /// The returned TP begins at the time_t `interval_num * length * 60 + epoch_offset_in_sec`
    /// and ends `length * 60` seconds later.
    pub fn from_parts(length: u32, interval_num: u64, epoch_offset_in_sec: u32) -> Self {
        let length_in_sec = length * 60;

        Self {
            interval_num,
            length: length.into(),
            epoch_offset_in_sec,
        }
    }

    /// Return the time period after this one.
    ///
    /// Return None if this is the last representable time period.
    pub fn next(&self) -> Option<Self> {
        Some(TimePeriod {
            interval_num: self.interval_num.checked_add(1)?,
            ..*self
        })
    }
    /// Return the time period before this one.
    ///
    /// Return None if this is the first representable time period.
    pub fn prev(&self) -> Option<Self> {
        Some(TimePeriod {
            interval_num: self.interval_num.checked_sub(1)?,
            ..*self
        })
    }
    /// Return true if this time period contains `when`.
    ///
    /// # Limitations
    ///
    /// This function always returns false if the time period contains any times
    /// that cannot be represented as a `SystemTime`.
    pub fn contains(&self, when: SystemTime) -> bool {
        match self.range() {
            Ok(r) => r.contains(&when),
            Err(_) => false,
        }
    }
    /// Return a range representing the [`SystemTime`] values contained within
    /// this time period.
    ///
    /// Return None if this time period contains any times that can be
    /// represented as a `SystemTime`.
    pub fn range(&self) -> Result<std::ops::Range<SystemTime>, TimePeriodError> {
        (|| {
            let length_in_sec = u64::from(self.length.as_minutes()) * 60;
            let start_sec = length_in_sec.checked_mul(self.interval_num)?;
            let end_sec = start_sec.checked_add(length_in_sec)?;
            let epoch_offset = Duration::new(self.epoch_offset_in_sec.into(), 0);
            let start = (SystemTime::UNIX_EPOCH + epoch_offset)
                .checked_add(Duration::from_secs(start_sec))?;
            let end = (SystemTime::UNIX_EPOCH + epoch_offset)
                .checked_add(Duration::from_secs(end_sec))?;
            Some(start..end)
        })()
        .ok_or(TimePeriodError::OutOfRange)
    }

    /// Return the numeric index of this time period.
    ///
    /// This function should only be used when encoding the time period for
    /// cryptographic purposes.
    pub fn interval_num(&self) -> u64 {
        self.interval_num
    }

    /// Return the length of this time period as a number of seconds.
    ///
    /// This function should only be used when encoding the time period for
    /// cryptographic purposes.
    pub fn length(&self) -> IntegerMinutes<u32> {
        self.length
    }

    /// Return our offset from the epoch, in seconds.
    ///
    /// Note that this is *not* the start of the TP.
    /// See `TimePeriod::from_parts`.
    pub fn epoch_offset_in_sec(&self) -> u32 {
        self.epoch_offset_in_sec
    }
}

/// An error that occurs when creating or manipulating a [`TimePeriod`]
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TimePeriodError {
    /// We couldn't represent the time period in the way we were trying to
    /// represent it, since it outside of the range supported by the data type.
    #[error("Time period out was out of range")]
    OutOfRange,

    /// The time period couldn't be constructed because its interval was
    /// invalid.
    ///
    /// (We require that intervals are a multiple of 60 seconds, and that they
    /// can be represented in a `u32`.)
    #[error("Invalid time period interval")]
    IntervalInvalid,

    /// The time period couldn't be constructed because its offset was invalid.
    ///
    /// (We require that offsets can be represented in a `u32`.)
    #[error("Invalid time period offset")]
    OffsetInvalid,
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
    use humantime::{parse_duration, parse_rfc3339};

    /// Check reconstructing `period` from parts produces an identical `TimePeriod`.
    fn assert_eq_from_parts(period: TimePeriod) {
        assert_eq!(
            period,
            TimePeriod::from_parts(
                period.length().as_minutes(),
                period.interval_num(),
                period.epoch_offset_in_sec()
            )
        );
    }

    #[test]
    fn check_testvec() {
        // Test case from C tor, taken from rend-spec.
        let offset = Duration::new(12 * 60 * 60, 0);
        let time = parse_rfc3339("2016-04-13T11:00:00Z").unwrap();
        let one_day = parse_duration("1day").unwrap();
        let period = TimePeriod::new(one_day, time, offset).unwrap();
        assert_eq!(period.interval_num, 16903);
        assert!(period.contains(time));
        assert_eq_from_parts(period);

        let time = parse_rfc3339("2016-04-13T11:59:59Z").unwrap();
        let period = TimePeriod::new(one_day, time, offset).unwrap();
        assert_eq!(period.interval_num, 16903); // still the same.
        assert!(period.contains(time));
        assert_eq_from_parts(period);

        assert_eq!(period.prev().unwrap().interval_num, 16902);
        assert_eq!(period.next().unwrap().interval_num, 16904);

        let time2 = parse_rfc3339("2016-04-13T12:00:00Z").unwrap();
        let period2 = TimePeriod::new(one_day, time2, offset).unwrap();
        assert_eq!(period2.interval_num, 16904);
        assert!(period < period2);
        assert!(period2 > period);
        assert_eq!(period.next().unwrap(), period2);
        assert_eq!(period2.prev().unwrap(), period);
        assert!(period2.contains(time2));
        assert!(!period2.contains(time));
        assert!(!period.contains(time2));

        assert_eq!(
            period.range().unwrap(),
            parse_rfc3339("2016-04-12T12:00:00Z").unwrap()
                ..parse_rfc3339("2016-04-13T12:00:00Z").unwrap()
        );
        assert_eq!(
            period2.range().unwrap(),
            parse_rfc3339("2016-04-13T12:00:00Z").unwrap()
                ..parse_rfc3339("2016-04-14T12:00:00Z").unwrap()
        );
        assert_eq_from_parts(period2);
    }
}
