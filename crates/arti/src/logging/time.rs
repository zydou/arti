//! Support logging the time with different levels of precision.
//
// TODO: We might want to move this to a lower-level crate if it turns out to be
// generally useful: and it might, if we are encouraging the use of `tracing`
// with arti!  If we do this, we need to clean up the API a little.

use std::num::NonZeroU8;

use time::format_description;

/// Construct a new [`FormatTime`](tracing_subscriber::fmt::time::FormatTime)
/// from a given user-supplied description of the desired log granularity.
pub(super) fn new_formatter(
    granularity: std::time::Duration,
) -> impl tracing_subscriber::fmt::time::FormatTime {
    LogPrecision::from_duration(granularity).timer()
}

/// Instructions for what degree of precision to use for our log times.
//
// (This is a separate type from `LogTimer` so that we can test our parsing
// and our implementation independently.)
#[derive(Clone, Debug)]
#[cfg_attr(test, derive(Copy, Eq, PartialEq))]
enum LogPrecision {
    /// Display up to this many significant digits when logging.
    ///
    /// System limitations will also limit the number of digits displayed.
    ///
    /// Must be in range 1..9.
    Subseconds(u8),
    /// Before logging, round the number of seconds down to the nearest
    /// multiple of this number within the current minute.
    ///
    /// Must be in range 1..59.
    Seconds(u8),
    /// Before logging, round the number of minutes down to the nearest multiple
    /// of this number within the current hour.
    ///
    /// Must be in range 1..59.
    Minutes(u8),

    /// Before logging, round to down to the nearest hour.
    Hours,
}

/// Compute the smallest n such that 10^n >= x.
///
/// Since the input is a u32, this will return a value in the range 0..10.
fn ilog10_roundup(x: u32) -> u8 {
    x.saturating_sub(1)
        .checked_ilog10()
        .map(|x| (x + 1) as u8)
        .unwrap_or(0)
}

/// Describe how to compute the current time.
#[derive(Clone, Debug)]
enum TimeRounder {
    /// Just take the current time; any transformation will be done by the
    /// formatter.
    Verbatim,
    /// Round the minutes within the hours down to the nearest multiple of
    /// this granularity.
    RoundMinutes(NonZeroU8),
    /// Round the seconds within the minute down to the nearest multiple of
    /// this granularity.
    RoundSeconds(NonZeroU8),
}

/// Actual type to implement log formatting.
struct LogTimer {
    /// Source that knows how to compute a time, rounded as necessary.
    rounder: TimeRounder,
    /// Formatter that knows how to format the time, discarding fields as
    /// necessary.
    formatter: format_description::OwnedFormatItem,
}

impl LogPrecision {
    /// Convert a `Duration` into a LogPrecision that rounds the time displayed
    /// in log messages to intervals _no more precise_ than the interval
    /// specified in Duration.
    ///
    /// (As an exception, we do not support granularities greater than 1 hour.
    /// If you specify a granularity greater than an hour, we just give you a
    /// one-hour granularity.)
    fn from_duration(dur: std::time::Duration) -> Self {
        // Round any fraction greater than 1 up to next second.
        let seconds = match (dur.as_secs(), dur.subsec_nanos()) {
            (0, _) => 0,
            (a, 0) => a,
            (a, _) => a + 1,
        };

        // Anything above one hour minus one minute will round to one hour.
        if seconds >= 3541 {
            // This is the lowest precision we have.
            LogPrecision::Hours
        } else if seconds >= 60 {
            let minutes = seconds.div_ceil(60);
            assert!((1..=59).contains(&minutes));
            LogPrecision::Minutes(minutes.try_into().expect("Math bug"))
        } else if seconds >= 1 {
            assert!((1..=59).contains(&seconds));
            LogPrecision::Seconds(seconds.try_into().expect("Math bug"))
        } else {
            let ilog10 = ilog10_roundup(dur.subsec_nanos());
            if ilog10 >= 9 {
                LogPrecision::Seconds(1)
            } else {
                LogPrecision::Subseconds(9 - ilog10)
            }
        }
    }

    /// Convert a LogPrecision (which specifies the precision we want) into a
    /// LogTimer (which can be used to format times in the log)
    fn timer(&self) -> LogTimer {
        use LogPrecision::*;
        let format_str = match self {
            Hours => "[year]-[month]-[day]T[hour repr:24]:00:00Z".to_string(),
            Minutes(_) => "[year]-[month]-[day]T[hour repr:24]:[minute]:00Z".to_string(),
            Seconds(_) => "[year]-[month]-[day]T[hour repr:24]:[minute]:[second]Z".to_string(),
            Subseconds(significant_digits) => {
                assert!(*significant_digits >= 1 && *significant_digits <= 9);
                format!(
                    "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:{}]Z",
                    significant_digits
                )
            }
        };
        let formatter = format_description::parse_owned::<2>(&format_str)
            .expect("Couldn't parse a built-in time format string");
        let rounder = match self {
            Hours | Minutes(1) | Seconds(1) | Subseconds(_) => TimeRounder::Verbatim,
            Minutes(granularity) => {
                TimeRounder::RoundMinutes((*granularity).try_into().expect("Math bug"))
            }
            Seconds(granularity) => {
                TimeRounder::RoundSeconds((*granularity).try_into().expect("Math bug"))
            }
        };

        LogTimer { rounder, formatter }
    }
}

/// An error that occurs while trying to format the time.
///
/// Internal.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
enum TimeFmtError {
    /// The time crate wouldn't let us replace a field.
    ///
    /// This indicates that the value we were trying to use there was invalid,
    /// and so our math must have been wrong.
    #[error("Internal error while trying to round the time.")]
    Rounding(#[from] time::error::ComponentRange),

    /// The time crate wouldn't let us format a value.
    ///
    /// This indicates that our formatters were busted, and so we probably have
    /// a programming error.
    #[error("`time` couldn't format this time.")]
    TimeFmt(#[from] time::error::Format),
}

impl TimeRounder {
    /// Round `when` down according to this `TimeRounder`.
    ///
    /// Note that we round fields minimally: we don't round any fields that the
    /// associated formatter will not display.
    fn round(&self, when: time::OffsetDateTime) -> Result<time::OffsetDateTime, TimeFmtError> {
        // NOTE: This function really mustn't panic.  We try to log any panics
        // that we encounter, and if logging itself can panic, we're in a
        // potential heap of trouble.
        //
        // This danger is somewhat ameliorated by the behavior of the default
        // panic handler, which detects nested panics and aborts in response.
        // Thus, if we ever discard that handler, we need to be sure to
        // reimplement nested panic detection.
        //
        // Alternatively, we _could_ nest this functionality within
        // `catch_unwind`.  But I'm not sure that the overhead there would be
        // acceptable: Logging can be performance sensitive.

        use TimeRounder::*;
        /// Round `inp` down to the nearest multiple of `granularity`.
        fn round_down(inp: u8, granularity: NonZeroU8) -> u8 {
            inp - (inp % granularity)
        }

        Ok(match self {
            Verbatim => when,
            RoundMinutes(granularity) => {
                when.replace_minute(round_down(when.minute(), *granularity))?
            }
            RoundSeconds(granularity) => {
                when.replace_second(round_down(when.second(), *granularity))?
            }
        })
    }
}

impl LogTimer {
    /// Convert `when` to a string with appropriate rounding.
    fn time_to_string(&self, when: time::OffsetDateTime) -> Result<String, TimeFmtError> {
        // See NOTE above: This function mustn't panic.
        Ok(self.rounder.round(when)?.format(&self.formatter)?)
    }
}

impl tracing_subscriber::fmt::time::FormatTime for LogTimer {
    fn format_time(&self, w: &mut tracing_subscriber::fmt::format::Writer<'_>) -> std::fmt::Result {
        // See NOTE above: This function mustn't panic.
        w.write_str(
            &self
                .time_to_string(time::OffsetDateTime::now_utc())
                .map_err(|_| std::fmt::Error)?,
        )
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
    use std::time::Duration;

    #[test]
    fn ilog() {
        assert_eq!(ilog10_roundup(0), 0);
        assert_eq!(ilog10_roundup(1), 0);
        assert_eq!(ilog10_roundup(2), 1);
        assert_eq!(ilog10_roundup(9), 1);
        assert_eq!(ilog10_roundup(10), 1);
        assert_eq!(ilog10_roundup(11), 2);
        assert_eq!(ilog10_roundup(99), 2);
        assert_eq!(ilog10_roundup(100), 2);
        assert_eq!(ilog10_roundup(101), 3);
        assert_eq!(ilog10_roundup(99_999_999), 8);
        assert_eq!(ilog10_roundup(100_000_000), 8);
        assert_eq!(ilog10_roundup(100_000_001), 9);
        assert_eq!(ilog10_roundup(999_999_999), 9);
        assert_eq!(ilog10_roundup(1_000_000_000), 9);
        assert_eq!(ilog10_roundup(1_000_000_001), 10);

        assert_eq!(ilog10_roundup(u32::MAX), 10);
    }

    #[test]
    fn precision_from_duration() {
        use LogPrecision::*;
        fn check(sec: u64, nanos: u32, expected: LogPrecision) {
            assert_eq!(
                LogPrecision::from_duration(Duration::new(sec, nanos)),
                expected,
            );
        }

        check(0, 0, Subseconds(9));
        check(0, 1, Subseconds(9));
        check(0, 5, Subseconds(8));
        check(0, 10, Subseconds(8));
        check(0, 1_000, Subseconds(6));
        check(0, 1_000_000, Subseconds(3));
        check(0, 99_000_000, Subseconds(1));
        check(0, 100_000_000, Subseconds(1));
        check(0, 200_000_000, Seconds(1));

        check(1, 0, Seconds(1));
        check(1, 1, Seconds(2));
        check(30, 0, Seconds(30));
        check(59, 0, Seconds(59));

        check(59, 1, Minutes(1));
        check(60, 0, Minutes(1));
        check(60, 1, Minutes(2));
        check(60 * 59, 0, Minutes(59));

        check(60 * 59, 1, Hours);
        check(3600, 0, Hours);
        check(86400 * 365, 0, Hours);
    }

    #[test]
    fn test_formatting() {
        let when = humantime::parse_rfc3339("2023-07-05T04:15:36.123456789Z")
            .unwrap()
            .into();
        let check = |precision: LogPrecision, expected| {
            assert_eq!(&precision.timer().time_to_string(when).unwrap(), expected);
        };
        check(LogPrecision::Hours, "2023-07-05T04:00:00Z");
        check(LogPrecision::Minutes(15), "2023-07-05T04:15:00Z");
        check(LogPrecision::Minutes(10), "2023-07-05T04:10:00Z");
        check(LogPrecision::Minutes(4), "2023-07-05T04:12:00Z");
        check(LogPrecision::Minutes(1), "2023-07-05T04:15:00Z");
        check(LogPrecision::Seconds(50), "2023-07-05T04:15:00Z");
        check(LogPrecision::Seconds(30), "2023-07-05T04:15:30Z");
        check(LogPrecision::Seconds(20), "2023-07-05T04:15:20Z");
        check(LogPrecision::Seconds(1), "2023-07-05T04:15:36Z");
        check(LogPrecision::Subseconds(1), "2023-07-05T04:15:36.1Z");
        check(LogPrecision::Subseconds(2), "2023-07-05T04:15:36.12Z");
        check(LogPrecision::Subseconds(7), "2023-07-05T04:15:36.1234567Z");
        cfg_if::cfg_if! {
            if #[cfg(windows)] {
                // Windows has a 100-nanosecond precision, see
                // https://learn.microsoft.com/en-us/windows/win32/sysinfo/about-time
                let expected = "2023-07-05T04:15:36.123456700Z";
            } else {
                let expected = "2023-07-05T04:15:36.123456789Z";
            }
        }
        check(LogPrecision::Subseconds(9), expected);
    }
}
