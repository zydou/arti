//! Manipulate time periods (as used in the onion service system)

use std::time::{Duration, SystemTime};

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
///
/// # Compatibility Note
///
/// Although `rend-spec-v3.txt` says that the offset is a constant "12 hours", C
/// Tor doesn't behave that way.  Instead, the offset is set to twelve voting
/// intervals.  Since this module doesn't (and shouldn't!) have access to the
/// voting interval, we store the offset as part of the TimePeriod.
///
/// TODO hs: remove or revise this note once the spec is updated; see prop342.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TimePeriod {
    /// Index of the time periods that have passed since the unix epoch.
    pub(crate) interval_num: u64,
    /// The length of a time period, in seconds.
    pub(crate) length_in_sec: u32,
    /// Our offset from the epoch, in seconds.
    pub(crate) offset_in_sec: u32,
}

/// Two [`TimePeriod`]s are ordered with respect to one another if they have the
/// same interval length and offset.
impl PartialOrd for TimePeriod {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        if self.length_in_sec == other.length_in_sec && self.offset_in_sec == other.offset_in_sec {
            Some(self.interval_num.cmp(&other.interval_num))
        } else {
            None
        }
    }
}

impl TimePeriod {
    /// Construct a time period of a given `length` that contains `when`.
    ///
    /// The `length` value is rounded down to the nearest second.
    ///
    /// The `epoch_offset` value is the amount of time after the Unix epoch when
    /// our epoch begins.  It is also rounded down to the nearest second.
    ///
    /// Return None if the Duration is too large or too small, or if `when`
    /// cannot be represented as a time period.
    //
    // TODO hs: Make this, and other functions in this module, return a Result
    // instead of an Option. (I'll do that after we merge the pending code in
    // !987, since otherwise the change would break that code. -nickm)
    //
    // TODO hs: perhaps we should take an IntegerSeconds or such rathe than a
    // duration, since these values are restricted. Or perhaps we should give an
    // error if the Duration doesn't divide evenly by seconds as
    // appropriate.
    //
    // TODO hs: conceivably this should take a voting interval instead of an
    // epoch offset.
    pub fn new(length: Duration, when: SystemTime, epoch_offset: Duration) -> Option<Self> {
        // The algorithm here is specified in rend-spec-v3 section 2.2.1
        let length_in_sec = u32::try_from(length.as_secs()).ok()?;
        let offset_in_sec = u32::try_from(epoch_offset.as_secs()).ok()?;
        let interval_num = when
            .duration_since(SystemTime::UNIX_EPOCH + epoch_offset)
            .ok()?
            .as_secs()
            / u64::from(length_in_sec);
        Some(TimePeriod {
            interval_num,
            length_in_sec,
            offset_in_sec,
        })
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
    /// Return the time period after this one.
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
            Some(r) => r.contains(&when),
            None => false,
        }
    }
    /// Return a range representing the [`SystemTime`] values contained within
    /// this time period.
    ///
    /// Return None if this time period contains any times that can be
    /// represented as a `SystemTime`.
    pub fn range(&self) -> Option<std::ops::Range<SystemTime>> {
        let start_sec = u64::from(self.length_in_sec).checked_mul(self.interval_num)?;
        let end_sec = start_sec.checked_add(self.length_in_sec.into())?;
        let epoch_offset = Duration::new(self.offset_in_sec.into(), 0);
        let start =
            (SystemTime::UNIX_EPOCH + epoch_offset).checked_add(Duration::from_secs(start_sec))?;
        let end =
            (SystemTime::UNIX_EPOCH + epoch_offset).checked_add(Duration::from_secs(end_sec))?;
        Some(start..end)
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
    pub fn length_in_sec(&self) -> u64 {
        self.length_in_sec.into()
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
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;
    use humantime::{parse_duration, parse_rfc3339};

    #[test]
    fn check_testvec() {
        // Test case from C tor, taken from rend-spec.
        let offset = Duration::new(12 * 60 * 60, 0);
        let time = parse_rfc3339("2016-04-13T11:00:00Z").unwrap();
        let one_day = parse_duration("1day").unwrap();
        let period = TimePeriod::new(one_day, time, offset).unwrap();
        assert_eq!(period.interval_num, 16903);
        assert!(period.contains(time));

        let time = parse_rfc3339("2016-04-13T11:59:59Z").unwrap();
        let period = TimePeriod::new(one_day, time, offset).unwrap();
        assert_eq!(period.interval_num, 16903); // still the same.
        assert!(period.contains(time));

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
    }
}
