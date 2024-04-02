//! Saving/loading timestamps to disk
//!
//! Storing timestamps on disk is not so straightforward.
//! We need to use wall clock time in order to survive restarts.
//! But wall clocks can be wrong,
//! so we need at least to apply some sanity checks.
//!
//! This module encapsulates those checks, and some error handling choices.
//! It allows `Instant`s to be used while the system is running,
//! with bespoke types for loading/saving.
//! See [`Loading::load_future`] for the load/save guarantees provided.
//!
//! The initial entrypoints are [`Storing::start`] and [`Loading::start`].
//!
//! Granularity is 1 second and the precise rounding behaviour is not specified.
//!
//! ### Data model
//!
//! To mitigate clock skew, we store the wall clock time at which
//! each timestamp was saved to disk ([`Reference`])
//! and the offset from now to that timestamp ([`FutureTimestamp`]).
//!
//! The same storage time can be used for multiple timestamps that are stored together.
//!
//! ### Example
//!
//! ```
//! use serde::{Serialize, Deserialize};
//! use std::time::{Duration, Instant};
//! use tor_rtcompat::{PreferredRuntime, SleepProvider as _};
//!
//! # use tor_hsservice::time_store_for_doctests_unstable_no_semver_guarantees as time_store;
//! # #[cfg(all)] // works like #[cfg(FALSE)].  Instead, we have this workaround ^.
//! use crate::time_store;
//!
//! let runtime = PreferredRuntime::create().unwrap();
//!
//! #[derive(Serialize, Deserialize, Debug)]
//! struct Stored {
//!     time_ref: time_store::Reference,
//!     t0: time_store::FutureTimestamp,
//! }
//!
//! let t0: Instant = runtime.now() + Duration::from_secs(60);
//!
//! let storing = time_store::Storing::start(&runtime);
//! let data = Stored {
//!     time_ref: storing.store_ref(),
//!     t0: storing.store_future(t0),
//! };
//!
//! let json = serde_json::to_string(&data).unwrap();
//!
//! // later:
//!
//! let data: Stored = serde_json::from_str(&json).unwrap();
//! let loading = time_store::Loading::start(&runtime, data.time_ref);
//! let t0: Instant = loading.load_future(data.t0);
//!
//! assert!(t0 - runtime.now() <= Duration::from_secs(60));
//! ```
//!
//! ### Time arithmetic overflows and stupid system time settings
//!
//! Arithmetic is done with signed 64-bit numbers of seconds.
//! So overflow cannot occur unless the clock is completely ludicrous.
//! If the clock is ludicrous, time calculations are going to be a mess.
//! We treat this as clock skew, using saturating arithmetic, rather than returning errors.
//! Reasonable operation will resume when the clock becomes sane.
//
// We generally use u64 for values that can't, for our algorithms, be negative,
// but i64 for time_t's (even though negative time_t's can't happen on Unix).

// TODO - eventually we hope this will become pub, in another crate

// Rustdoc can complains if we link to these private docs from these docs which are
// themselves only formatted with --document-private-items.
// TODO - Remove when this is actually public
#![allow(rustdoc::private_intra_doc_links)]

use std::fmt::{self, Display};
use std::str::FromStr;
use std::time::{Duration, Instant, SystemTime};

use derive_deftly::{define_derive_deftly, Deftly};
use serde::{Deserialize, Serialize};
use serde::{Deserializer, Serializer};
use thiserror::Error;
use tracing::warn;

use tor_rtcompat::SleepProvider;

//---------- derive-adhoc macro for raw accessors, must come first ----------

define_derive_deftly! {
    /// Define `as_raw` and `from_raw` methods (for a struct with a single field)
    //
    // We provide these for the types which are serde, since we are already exposing
    // and documenting their innards (and we don't want to force people to use serde
    // trickery if they want to do something unusual).
    RawConversions expect items =

    impl $ttype {
      ${for fields { // we have only one field; but d-a wants a context for "a specific field"
        /// Returns the raw value, as would be serialised
        pub fn as_raw(self) -> $ftype {
            self.$fname
        }
        #[doc = concat!("/// Constructs a ",stringify!($tname)," from a raw value")]
        pub fn from_raw(seconds: $ftype) -> $ttype {
            Self { $fname: seconds }
        }
      }}
    }
}

define_derive_deftly! {
    /// Define [`Serialize`] and [`Deserialize`] via string rep or transparently, depending
    ///
    /// In human-readable formats, uses the [`Display`] and [`FromStr`].
    /// In non-human-readable formats, serialises as the single field.
    ///
    /// Uses serde's `is_human_readable` to decide.
    /// structs which don't have exactly one field will cause a compile error.
    //
    // This has to be a macro rather than simply a helper newtype
    // to implement the "transparent" binary version,
    // since that involves looking into the struct's field.
    SerdeStringOrTransparent for struct, expect items =

    impl Serialize for $ttype {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            if s.is_human_readable() {
                s.collect_str(self)
            } else {
                let Self { $( $fname: raw, ) } = self;
                raw.serialize(s)
            }
        }
    }

    ${define STRING_VISITOR { $<Deserialize $ttype StringVisitor> }}

    impl<'de> Deserialize<'de> for $ttype {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            if d.is_human_readable() {
                d.deserialize_str($STRING_VISITOR)
            } else {
                let raw = Deserialize::deserialize(d)?;
                Ok(Self { $( $fname: raw, ) })
            }
        }
    }

    /// Visitor for deserializing from a string
    struct $STRING_VISITOR;

    impl<'de> serde::de::Visitor<'de> for $STRING_VISITOR {
        type Value = $ttype;
        fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<$ttype, E> {
            s.parse().map_err(|e| E::custom(e))
        }
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, concat!("string representing ", stringify!($tname)))
        }
    }
}

//---------- data types ----------

/// Representation of an absolute time, in the future, suitable for storing to disk
///
/// Only meaningful in combination with a [`Reference`].
///
/// Obtain one of these from an `Instant` using [`Storing::store_future()`],
/// and convert it back to an `Instant` with [`Loading::load_future()`],
///
/// (Serialises as a representation of how many seconds this was into the future,
/// when it was stored - ie, with respect to the corresponding [`Reference`];
/// in binary as a `u64`, in human readable formats as
/// `T+` plus [`humantime`]'s formatting of the `Duration` in seconds.)
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Deftly)]
#[derive_deftly(RawConversions, SerdeStringOrTransparent)]
pub struct FutureTimestamp {
    /// How far this timestamp was in the future, when we stored it
    offset: u64,
}

/// On-disk representation of a reference time, used as context for stored timestamps
///
/// During store, obtained by [`Storing::store_ref`], and should then be serialised
/// along with the [`FutureTimestamp`]s.
///
/// During load, should be passed to [`Loading::start`], to build a [`Loading`]
/// which is then used to convert the [`FutureTimestamp`]s back to `Instant`s.
///
/// (Serialises as an absolute time:
/// in binary, as an `i64` representing the `time_t` (Unix Time);
/// in human-readable formats, an RFC3339 string with seconds precision and timezone `Z`.)
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, derive_more::Display)]
#[display(
    fmt = "{}",
    "humantime::format_rfc3339_seconds(time_t_to_system_time(*time_t))"
)]
#[derive(Deftly)]
#[derive_deftly(RawConversions, SerdeStringOrTransparent)]
pub struct Reference {
    /// Unix time (at which the other timestamps were stored)
    time_t: i64,
}

/// Context for storing `Instant`s to disk
///
/// Obtained from [`Storing::start`].
///
/// Contains a reference time, which must also be serialised,
/// as `Reference` obtained from [`Storing::store_ref`],
/// and stored alongside the converted timestamps.
pub struct Storing(Now);

/// The two notions of the current time, for internal use
//
// This is a separate type from Storing so that Loading::start can call Now::new,
// without having to temporarily create a semantically inappropriate Storing.
struct Now {
    /// Represents the current time as an opaque `Instant`
    inst: Instant,
    /// Represents the current time as a `time_t`
    time_t: i64,
}

/// Context for loading `Instant`s from disk
///
/// Obtained by [`Loading::start`],
/// from a [`Reference`]
/// (loaded from disk alongside the converted timestamps).
pub struct Loading {
    /// The current time when this `Loading` was created
    inst: Instant,
    /// How long has elapsed, at `inst`, since the timestamps were stored
    elapsed: u64,
}

//---------- implementation ----------

/// Convert a `SystemTime` to an `i64` `time_t`
fn system_time_to_time_t(st: SystemTime) -> i64 {
    if let Ok(d) = st.duration_since(SystemTime::UNIX_EPOCH) {
        d.as_secs().try_into().unwrap_or(i64::MAX)
    } else if let Ok(d) = SystemTime::UNIX_EPOCH.duration_since(st) {
        d.as_secs().try_into().map(|v: i64| -v).unwrap_or(i64::MIN)
    } else {
        panic!("two SystemTimes are neither <= nor >=")
    }
}

/// Minimum value of SystemTime
///
/// Not a tight bound but tests guarantee no runtime panics.
fn system_time_min() -> SystemTime {
    for attempt in [
        //
        0x7fff_ffff_ffff_ffff,
        0x7fff_ffff,
        0,
    ] {
        if let Some(r) = SystemTime::UNIX_EPOCH.checked_sub(Duration::from_secs(attempt)) {
            return r;
        }
    }
    panic!("cannot calculate a minimum value for the SystemTime!");
}

/// Maximum value of SystemTime
///
/// Not a tight bound but tests guarantee no runtime panics.
fn system_time_max() -> SystemTime {
    for attempt in [
        //
        0x7fff_ffff_ffff_ffff,
        0x7fff_ffff,
    ] {
        if let Some(r) = SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(attempt)) {
            return r;
        }
    }
    panic!("cannot calculate a maximum value for the SystemTime!");
}

/// Convert a `SystemTime` to an `i64` `time_t`
//
// We need this to make the RFC3339 string using humantime.
// Otherwise we'd have to implement the whole calendar and leap days stuff ourselves.
// Probably there doesn't end up being any actual code here on Unix at least...
fn time_t_to_system_time(time_t: i64) -> SystemTime {
    if let Ok(time_t) = u64::try_from(time_t) {
        let d = Duration::from_secs(time_t);
        SystemTime::UNIX_EPOCH
            .checked_add(d)
            .unwrap_or_else(system_time_max)
    } else {
        let rev: u64 = time_t
            .saturating_neg()
            .try_into()
            .expect("-(-ve i64) not u64");
        let d = Duration::from_secs(rev);
        SystemTime::UNIX_EPOCH
            .checked_sub(d)
            .unwrap_or_else(system_time_min)
    }
}

impl Now {
    /// Obtain `Now` from a runtime
    fn new(runtime: &impl SleepProvider) -> Self {
        let inst = runtime.now();
        let st = runtime.wallclock();
        let time_t = system_time_to_time_t(st);
        Self { inst, time_t }
    }
}

impl Storing {
    /// Prepare to store timestamps, returning a context for serialising `Instant`s
    ///
    /// Incorporates reference times obtained from the runtime's clock.
    //
    // We don't provide `Storing::{to,from}_raw_parts` nor `Loading::from_raw_parts`
    // because you can (sort of) do all of constructors with a suitable `SleepProvider`,
    // and we don't want to give too much detail about the implementation and innards.
    pub fn start(runtime: &impl SleepProvider) -> Self {
        Storing(Now::new(runtime))
    }

    /// Prepare a reference time for storage
    pub fn store_ref(&self) -> Reference {
        Reference {
            time_t: self.0.time_t,
        }
    }

    /// Convert an `Instant` in the future into a form suitable for saving on disk
    ///
    /// If `val` *isn't* in the future, the current time will be stored instead.
    pub fn store_future(&self, val: Instant) -> FutureTimestamp {
        let offset = val
            .checked_duration_since(self.0.inst)
            .unwrap_or_default()
            .as_secs();
        FutureTimestamp { offset }
    }
}

impl Loading {
    /// Obtain a [`Loading`] from a stored [`Reference`], for deserialising `Instant`s
    ///
    /// Uses the runtime's clock as a basis for understanding the supplied `Reference`
    /// and relating it to the current monotonic time (`Instant`) on this host.
    pub fn start(runtime: &impl SleepProvider, stored: Reference) -> Loading {
        let now = Now::new(runtime);
        let elapsed = now.time_t.saturating_sub(stored.time_t);
        // If time went backwards, pretend it stood still
        let elapsed = elapsed.try_into().unwrap_or(0);
        Loading {
            inst: now.inst,
            elapsed,
        }
    }

    /// Convert a future `Instant` from a value saved on disk
    ///
    /// If the `Instant` that was saved has since passed,
    /// the returned value is the current time.
    ///
    /// If the system clock is inaccurate (or was inaccurate when the timestamp was saved),
    /// the value may be wrong:
    /// but, regardless, the returned value will be no further in the future,
    /// than how far it was in the future when it was saved.
    ///
    /// In other words, even in the presence of clock skew, the effect is, at worst,
    /// as if the local system's clock has stood still, or has run very fast.
    pub fn load_future(&self, stored: FutureTimestamp) -> Instant {
        let offset = stored.offset.saturating_sub(self.elapsed);
        self.inst
            .checked_add(Duration::from_secs(offset))
            .unwrap_or_else(|| {
                warn!("time overflow loading time_t now+{offset}!");
                // `Instant` is overflowing, which can only happen if something is
                // very wrong with the system, or `stored.offset` was stupidly large.
                // Using "now" is clearly wrong but there is no Instant::MAX,
                // and this seems better than making this method fallible and bailing.
                self.inst
            })
    }

    //----- accessors for Loading -----

    /// Returns how long has elapsed since the timestamps were stored
    ///
    /// This depends on the system wall clock being right both when we stored, and now.
    /// In the presence of clock skew, may return a value which is far too large,
    /// or too small.
    ///
    /// But, if the system wall clock seems to have gone backwards, returns zero.
    ///
    /// The time is measured from when [`start`](Loading::start) was called.
    /// If you need to know that time as an `Instant`,
    /// use [`as_raw_parts`](Loading::as_raw_parts).
    //
    // We provide this (and `as_raw_parts`) because some callers may
    // actually have a good use for it.
    pub fn elapsed(&self) -> Duration {
        Duration::from_secs(self.elapsed)
    }

    /// Returns how long has elapsed, in seconds, and the `Instant` at which that was true
    ///
    /// Returns number of seconds elapsed,
    /// between when the timestamps were stored,
    /// and the returned `Instant`.
    ///
    /// See [`elapsed`](Loading::elapsed) for details of clock skew handling.
    pub fn as_raw_parts(&self) -> (u64, Instant) {
        (self.elapsed, self.inst)
    }
}

//---------- formatting ----------

/// Displays as `T+Duration`, where [`Duration`] is in seconds, formatted using [`humantime`]
//
// This format is a balance between human-readability and the desire to avoid
// allowing the possibility of invalid (corrupted) files whose `FutureTimestamp`
// is actually before the stored `Reference`.
impl Display for FutureTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let d = humantime::format_duration(Duration::from_secs(self.offset));
        write!(f, "T+{}", d)
    }
}

/// Error parsing a timestamp or reference
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[non_exhaustive]
#[derive(Error)]
#[error("invalid timestamp or reference time format")]
pub struct ParseError {
    // We probably don't need to say precisely what's wrong
}

impl FromStr for FutureTimestamp {
    type Err = ParseError;
    // Bespoke parser so we have control over our error/overflow cases
    // (and also since ideally we don't want to deal with a complex HMS time API).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.strip_prefix("T+").ok_or(ParseError {})?;
        let offset = humantime::parse_duration(s)
            .map_err(|_: humantime::DurationError| ParseError {})?
            .as_secs();
        Ok(FutureTimestamp { offset })
    }
}

impl FromStr for Reference {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let st = humantime::parse_rfc3339(s).map_err(|_| ParseError {})?;
        let time_t = system_time_to_time_t(st);
        Ok(Reference { time_t })
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
    use humantime::parse_rfc3339;
    use itertools::{chain, Itertools};
    use tor_rtmock::{simple_time::SimpleMockTimeProvider, MockRuntime};

    fn secs(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    #[test]
    fn hms_fmt() {
        let ft = FutureTimestamp {
            offset: 2 * 86400 + 22 * 3600 + 4 * 60 + 5,
        };

        assert_eq!(ft.to_string(), "T+2days 22h 4m 5s");

        assert_eq!(Ok(ft), FutureTimestamp::from_str("T+2days 22h 4m 5s"));
        assert_eq!(Ok(ft), FutureTimestamp::from_str("T+70h 4m 5s"));
        // we inherit rounding behaviour from humantime; we don't mind tolerating that
        assert_eq!(Ok(ft), FutureTimestamp::from_str("T+2days 22h 4m 5s 100ms"));
        assert_eq!(Ok(ft), FutureTimestamp::from_str("T+2days 22h 4m 5s 900ms"));
        let e = Err(ParseError {});
        assert_eq!(e, FutureTimestamp::from_str("2days"));
        assert_eq!(e, FutureTimestamp::from_str("T+"));
        assert_eq!(e, FutureTimestamp::from_str("T+ "));
        assert_eq!(e, FutureTimestamp::from_str("T+X"));
        assert_eq!(e, FutureTimestamp::from_str("T+23kg"));
    }

    #[test]
    #[allow(clippy::unusual_byte_groupings)] // we want them to line up, dammit!
    fn system_time_conversions() {
        assert!(system_time_min() <= SystemTime::UNIX_EPOCH);
        assert!(system_time_max() > SystemTime::UNIX_EPOCH);

        let p = |s| parse_rfc3339(s).expect(s);
        let time_t_2st = time_t_to_system_time;
        assert_eq!(p("1970-01-01T00:00:00Z"), time_t_2st(0));
        assert_eq!(p("2038-01-19T03:14:07Z"), time_t_2st(0x___7fff_ffff));
        assert_eq!(p("2038-01-19T03:14:08Z"), time_t_2st(0x___8000_0000));
        assert_eq!(p("2106-02-07T06:28:16Z"), time_t_2st(0x_1_0000_0000));
        assert_eq!(p("4147-08-20T07:32:16Z"), time_t_2st(0x10_0000_0000));
    }

    #[test]
    fn ref_fmt() {
        let time_t = 1217635200;
        let rf = Reference { time_t };
        let s = "2008-08-02T00:00:00Z";
        assert_eq!(rf.to_string(), s);

        let p = Reference::from_str;
        assert_eq!(Ok(rf), p(s));
        // we inherit rounding behaviour from humantime; we don't mind tolerating that
        assert_eq!(Ok(rf), p("2008-08-02T00:00:00.00Z"));
        assert_eq!(Ok(rf), p("2008-08-02T00:00:00.999Z"));
        let e = Err(ParseError {});
        assert_eq!(e, p("2008-08-02T00:00Z"));
        assert_eq!(e, p("2008-08-02T00:00:00"));
        assert_eq!(e, p("2008-08-02T00:00:00B"));
        assert_eq!(e, p("2008-08-02T00:00:00+00:00"));
    }

    #[test]
    fn basic() {
        #[derive(Serialize, Deserialize, Debug)]
        struct Stored {
            stored: Reference,
            s0: FutureTimestamp,
            s1: FutureTimestamp,
            s2: FutureTimestamp,
        }

        let real_instant = Instant::now();
        let test_systime = parse_rfc3339("2008-08-02T00:00:00Z").unwrap();

        let mk_runtime = |instant, systime| {
            let times = SimpleMockTimeProvider::new(instant, systime);
            MockRuntime::builder().sleep_provider(times).build()
        };

        let stored = {
            let runtime = mk_runtime(real_instant + secs(100_000), test_systime);
            let now = Storing::start(&runtime);

            let t0 = runtime.now() - secs(1000);
            let t1 = runtime.now() + secs(10);
            let t2 = runtime.now() + secs(3000);

            Stored {
                stored: now.store_ref(),
                s0: now.store_future(t0),
                s1: now.store_future(t1),
                s2: now.store_future(t2),
            }
        };

        let json = serde_json::to_string(&stored).unwrap();
        println!("{json}");
        assert_eq!(
            json,
            format!(concat!(
                r#"{{"stored":"2008-08-02T00:00:00Z","#,
                r#""s0":"T+0s","s1":"T+10s","s2":"T+50m"}}"#
            ))
        );

        let mpack = rmp_serde::to_vec_named(&stored).unwrap();
        println!("{}", hex::encode(&mpack));
        assert_eq!(
            mpack,
            chain!(
                &[132, 166],
                b"stored",
                &[206],
                &[0x48, 0x93, 0xa3, 0x80], // 0x4893a380 1217635200 = 2008-08-02T00:00:00Z
                &[162],
                b"s0",
                &[0],
                &[162],
                b"s1",
                &[10],
                &[162],
                b"s2",
                &[205],
                &[0x0b, 0xb8], // 0xbb8 == 3000
            )
            .cloned()
            .collect_vec(),
        );

        // Simulate a restart with an Instant which is *smaller* (maybe the host rebooted),
        // but with a wall clock time 200s later.
        {
            let runtime = mk_runtime(real_instant, test_systime + secs(200));
            let now = Loading::start(&runtime, stored.stored);

            let t0 = now.load_future(stored.s0);
            let t1 = now.load_future(stored.s1);
            let t2 = now.load_future(stored.s2);

            assert_eq!(t0, runtime.now()); // was already in the past when stored
            assert_eq!(t1, runtime.now()); // is now in the past
            assert_eq!(t2, runtime.now() + secs(2800));
        }

        // Simulate a restart with a later Instant
        // and with a wall clock time 1200s *earlier* due to clock skew.
        {
            let runtime = mk_runtime(real_instant + secs(200_000), test_systime - secs(1200));
            let now = Loading::start(&runtime, stored.stored);

            let t0 = now.load_future(stored.s0);
            let t1 = now.load_future(stored.s1);
            let t2 = now.load_future(stored.s2);

            assert_eq!(t0, runtime.now()); // was already in the past when stored
            assert_eq!(t1, runtime.now() + secs(10)); // well, it was only 10 even then
            assert_eq!(t2, runtime.now() + secs(3000)); // can't be increased
        }
    }
}
