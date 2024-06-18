//! Utilities to track and compare times and timeouts
//!
//! Contains [`TrackingNow`], and variants.
//!
//! Each one records the current time,
//! and can be used to see if prospective timeouts have expired yet,
//! via the [`PartialOrd`] implementations.
//!
//! Each can be compared with a prospective wakeup time via a `.cmp()` method,
//! and via implementations of [`PartialOrd`] (including via `<` operators etc.)
//!
//! Each tracks every such comparison,
//! and can yield the earliest *unexpired* timeout that was asked about.
//!
//! I.e., the timeout tracker tells you when (in the future)
//! any of the comparisons you have made, might produce different answers.
//! So, that can be used to know how long to sleep for when waiting for timeout(s).
//!
//! This approach means you must be sure to actually perform the timeout action
//! whenever a comparison tells you the relevant period has elapsed.
//! If you fail to do so, the timeout tracker will still disregard the event
//! for the purposes of calculating how to wait, since it is in the past.
//! So if you use the timeout tracker to decide how long to sleep,
//! you won't be woken up until *something else* occurs.
//! (When the timeout has *exactly* elapsed, you should eagerly perform the action.
//! Otherwise the timeout tracker will calculate a zero timeout and you'll spin.)
//!
//! Each tracker has interior mutability,
//! which is necessary because `PartialOrd` (`<=` etc.) only passes immutable references.
//! Most are `Send`, none are `Sync`,
//! so use in thread-safe async code is somewhat restricted.
//! (Recommended use is to do all work influencing timeout calculations synchronously;
//! otherwise, in any case, you risk the time advancing mid-calculations.)
//!
//! `Clone` gives you a *copy*, not a handle onto the same tracker.
//! Comparisons done with the clone do not update the original.
//! (Exception: `TrackingInstantOffsetNow::clone`.)
//!
//! The types are:
//!
//!  * [`TrackingNow`]: tracks timeouts based on both [`SystemTime`] and [`Instant`],
//!  * [`TrackingSystemTimeNow`]: tracks timeouts based on [`SystemTime`]
//!  * [`TrackingInstantNow`]: tracks timeouts based on [`Instant`]
//!  * [`TrackingInstantOffsetNow`]: `InstantTrackingNow` but with an offset applied
//!
//! # Advantages, disadvantages, and alternatives
//!
//! Using `TrackingNow` allows time-dependent code to be written
//! in a natural, imperative, style,
//! even if the timeout calculations are complex.
//! Simply test whether it is time yet to do each thing, and if so do it.
//!
//! This can conveniently be combined with an idempotent imperative style
//! for handling non-time-based inputs:
//! for each possible action, you can decide in one place whether it needs doing.
//! (Use a `select_biased!`, with [`wait_for_earliest`](TrackingNow::wait_for_earliest)
//! as one of the branches.)
//!
//! This approach makes it harder to write bugs where
//! some of the consequences of events are forgotten.
//! Each timeout calculation is always done afresh from all its inputs.
//! There is only ever one place where each action is considered,
//! and the consideration is always redone from first principles.
//!
//! However, this is not necessarily the most performant approach.
//! Each iteration of the event loop doesn't know *why* it has woken up,
//! so must simply re-test all of the things that might need to be done.
//!
//! When higher performance is needed, consider maintaining timeouts as state:
//! either as wakeup times or durations, or as actual `Future`s,
//! depending on how frequently they are going to occur,
//! and how much they need to be modified.
//! With this approach you must remember to update or recalculate the timeout,
//! on every change to any of the inputs to each timeout calculation.
//! You must write code to check (or perform) each action,
//! in the handler for each event that might trigger it.
//! Omitting a call is easy,
//! can result in mysterious ordering-dependent "stuckess" bugs,
//! and is often detectable only by very comprehensive testing.
//!
//! # Example
//!
//! ```
//! use std::sync::{Arc, Mutex};
//! use std::time::Duration;
//! use futures::task::SpawnExt as _;
//! use tor_rtcompat::{BlockOn as _, SleepProvider as _};
//!
//! # use tor_hsservice::timeout_track_for_doctests_unstable_no_semver_guarantees as timeout_track;
//! # #[cfg(all)] // works like #[cfg(FALSE)].  Instead, we have this workaround ^.
//! use crate::timeout_track;
//! use timeout_track::TrackingInstantNow;
//!
//! // Test harness
//! let runtime = tor_rtmock::MockRuntime::new();
//! let actions = Arc::new(Mutex::new("".to_string())); // initial letters of performed actions
//! let perform_action = {
//!     let actions = actions.clone();
//!     move |s: &str| actions.lock().unwrap().extend(s.chars().take(1))
//! };
//!
//! runtime.spawn({
//!     let runtime = runtime.clone();
//!
//!     // Example program which models cooking a stir-fry
//!     async move {
//!         perform_action("add ingredients");
//!         let started = runtime.now();
//!         let mut last_stirred = started;
//!         loop {
//!             let now_track = TrackingInstantNow::now(&runtime);
//!
//!             const STIR_EVERY: Duration = Duration::from_secs(25);
//!             // In production, we might avoid panics:  .. >= last_stirred.checked_add(..)
//!             if now_track >= last_stirred + STIR_EVERY {
//!                 perform_action("stir");
//!                 last_stirred = now_track.get_now_untracked();
//!                 continue;
//!             }
//!
//!             const COOK_FOR: Duration = Duration::from_secs(3 * 60);
//!             if now_track >= started + COOK_FOR {
//!                 break;
//!             }
//!
//!             now_track.wait_for_earliest(&runtime).await;
//!         }
//!         perform_action("dish up");
//!     }
//! }).unwrap();
//!
//! // Do a test run
//! runtime.block_on(async {
//!     runtime.advance_by(Duration::from_secs(1 * 60)).await;
//!     assert_eq!(*actions.lock().unwrap(), "ass");
//!     runtime.advance_by(Duration::from_secs(2 * 60)).await;
//!     assert_eq!(*actions.lock().unwrap(), "asssssssd");
//! });
//! ```

// TODO - eventually we hope this will become pub, in another crate

// Rustdoc complains that we link to these private docs from these docs which are
// themselves only formatted with --document-private-items.
// TODO - Remove when this is actually public
#![allow(rustdoc::private_intra_doc_links)]

use std::cell::Cell;
use std::cmp::Ordering;
use std::time::{Duration, Instant, SystemTime};

use derive_deftly::{define_derive_deftly, Deftly};
use futures::{future, select_biased, FutureExt as _};
use itertools::chain;

use tor_rtcompat::{SleepProvider, SleepProviderExt as _};

//========== derive-deftly macros, which must come first ==========

define_derive_deftly! {
    /// Defines methods and types which are common to trackers for `Instant` and `SystemTime`
    SingleTimeoutTracker for struct, expect items:

    // type of the `now` field, ie the absolute time type
    ${define NOW $(
        ${when approx_equal($fname, now)}
        $ftype
    ) }

    // type that we track, ie the inner contents of the `Cell<Option<...>>`
    ${define TRACK ${tmeta(track) as ty}}

    // TODO maybe some of this should be a trait?  But that would probably include
    // wait_for_earliest, which would be an async trait method and quite annoying.
    impl $ttype {
        /// Creates a new timeout tracker, given a value for the current time
        pub fn new(now: $NOW) -> Self {
            Self {
                now,
                earliest: None.into(),
            }
        }

        /// Creates a new timeout tracker from the current time as seen by a runtime
        pub fn now(r: &impl SleepProvider) -> Self {
            let now = r.${tmeta(from_runtime) as ident}();
            Self::new(now)
        }

        /// Return the "current time" value in use
        ///
        /// If you do comparisons with this, they won't be tracked, obviously.
        pub fn get_now_untracked(&self) -> $NOW {
            self.now
        }

        /// Core of a tracked update: updates `earliest` with `maybe_earlier`
        fn update_unconditional(earliest: &Cell<Option<$TRACK>>, maybe_earlier: $TRACK) {
            earliest.set(chain!(
                earliest.take(),
                [maybe_earlier],
            ).min())
        }

        /// Core of a tracked update: updates `earliest` with `maybe_earlier`, if necessary
        ///
        /// `o` is what we are about to return:
        /// `Less` if the current time hasn't reached `maybe_earlier` yet.
        fn update_conditional(
            o: Ordering,
            earliest: &Cell<Option<$TRACK>>,
            maybe_earlier: $TRACK,
        ) {
            match o {
                Ordering::Greater | Ordering::Equal => {},
                Ordering::Less => Self::update_unconditional(earliest, maybe_earlier),
            }
        }
    }

    impl Sealed for $ttype {}
}

define_derive_deftly! {
    /// Impls for `TrackingNow`, the combined tracker
    ///
    /// Defines just the methods which want to abstract over fields
    CombinedTimeoutTracker for struct, expect items:

    ${define NOW ${fmeta(now) as ty}}

    impl $ttype {
        /// Creates a new combined timeout tracker, given values for the current time
        pub fn new( $(
            $fname: $NOW,
        ) ) -> $ttype {
            $ttype { $( $fname: $ftype::new($fname), ) }
        }

        /// Creates a new timeout tracker from the current times as seen by a runtime
        pub fn now(r: &impl SleepProvider) -> Self {
            $ttype { $(
                $fname: $ftype::now(r),
            ) }
        }

      $(
        #[doc = concat!("Access the specific timeout tracker for [`", stringify!($NOW), "`]")]
        pub fn $fname(&self) -> &$ftype {
            &self.$fname
        }
      )

        /// Return the shortest `Duration` until any future time with which this has been compared
        pub fn shortest(self) -> Option<Duration> {
            chain!( $(
                self.$fname.shortest(),
            ) ).min()
        }
    }

  $(
    impl Update<$NOW> for TrackingNow {
        fn update(&self, t: $NOW) {
            self.$fname.update(t);
        }
    }

    define_PartialOrd_via_cmp! { $ttype, $NOW, .$fname }
  )
}

define_derive_deftly! {
    /// Defines `wait_for_earliest`
    ///
    /// Combined into this macro mostly so we only have to write the docs once
    WaitForEarliest for struct, expect items:

    impl $ttype {
        /// Wait for the earliest timeout implied by any of the comparisons
        ///
        /// Waits until the earliest future time at which any of the comparisons performed
        /// might change their answer.
        ///
        /// If there were no comparisons there are no timeouts, so we wait forever.
        pub async fn wait_for_earliest(self, runtime: &impl SleepProvider) {
            ${if tmeta(runtime_sleep) {
                // tracker for a single kind of time
                match self.earliest.into_inner() {
                    None => future::pending().await,
                    Some(earliest) => runtime.${tmeta(runtime_sleep) as ident}(earliest).await,
                }
            } else {
                // combined tracker, wait for earliest of any kind of timeout
                select_biased! { $(
                    () = self.$fname.wait_for_earliest(runtime).fuse() => {},
                ) }
            }}
        }
    }
}

/// `impl PartialOrd<$NOW> for $ttype` in terms of `...$field.cmp()`
macro_rules! define_PartialOrd_via_cmp { {
    $ttype:ty, $NOW:ty, $( $field:tt )*
} => {
    /// Check if time `t` has been reached yet (and if not, remember that we want to wake up then)
    ///
    /// Always returns `Some`.
    impl PartialEq<$NOW> for $ttype {
        fn eq(&self, t: &$NOW) -> bool {
            self $($field)* .cmp(*t) == Ordering::Equal
        }
    }

    /// Check if time `t` has been reached yet (and if not, remember that we want to wake up then)
    ///
    /// Always returns `Some`.
    impl PartialOrd<$NOW> for $ttype {
        fn partial_cmp(&self, t: &$NOW) -> Option<std::cmp::Ordering> {
            Some(self $($field)* .cmp(*t))
        }
    }

    /// Check if we have reached time `t` yet (and if not, remember that we want to wake up then)
    ///
    /// Always returns `Some`.
    impl PartialEq<$ttype> for $NOW {
        fn eq(&self, t: &$ttype) -> bool {
            t.eq(self)
        }
    }

    /// Check if we have reached time `t` yet (and if not, remember that we want to wake up then)
    ///
    /// Always returns `Some`.
    impl PartialOrd<$ttype> for $NOW {
        fn partial_cmp(&self, t: &$ttype) -> Option<std::cmp::Ordering> {
            t.partial_cmp(self).map(|o| o.reverse())
        }
    }
} }

//========== data structures ==========

/// Utility to track timeouts based on [`SystemTime`] (wall clock time)
///
/// Represents the current `SystemTime` (from when it was created).
/// See the [module-level documentation](self) for the general overview.
///
/// To operate a timeout,
/// you should calculate the `SystemTime` at which you should time out,
/// and compare that future planned wakeup time with this `TrackingSystemTimeNow`
/// (via [`.cmp()`](Self::cmp) or inequality operators and [`PartialOrd`]).
#[derive(Clone, Debug, Deftly)]
#[derive_deftly(SingleTimeoutTracker, WaitForEarliest)]
#[deftly(track = "SystemTime")]
#[deftly(from_runtime = "wallclock", runtime_sleep = "sleep_until_wallclock")]
pub struct TrackingSystemTimeNow {
    /// Current time
    now: SystemTime,
    /// Earliest time at which we should wake up
    earliest: Cell<Option<SystemTime>>,
}

/// Earliest timeout at which an [`Instant`] based timeout should occur, as duration from now
///
/// The actual tracker, found via `TrackingInstantNow` or `TrackingInstantOffsetNow`
type InstantEarliest = Cell<Option<Duration>>;

/// Utility to track timeouts based on [`Instant`] (monotonic time)
///
/// Represents the current `Instant` (from when it was created).
/// See the [module-level documentation](self) for the general overview.
///
/// To calculate and check a timeout,
/// you can
/// calculate the future `Instant` at which you wish to wake up,
/// and compare it with a `TrackingInstantNow`,
/// via [`.cmp()`](Self::cmp) or inequality operators and [`PartialOrd`].
///
/// Or you can
/// use
/// [`.checked_sub()`](TrackingInstantNow::checked_sub)
/// to obtain a [`TrackingInstantOffsetNow`].
#[derive(Clone, Debug, Deftly)]
#[derive_deftly(SingleTimeoutTracker, WaitForEarliest)]
#[deftly(track = "Duration")]
#[deftly(from_runtime = "now", runtime_sleep = "sleep")]
pub struct TrackingInstantNow {
    /// Current time
    now: Instant,
    /// Duration until earliest time we should wake up
    earliest: InstantEarliest,
}

/// Current minus an offset, for [`Instant`]-based timeout checks
///
/// Returned by
/// [`TrackingNow::checked_sub()`]
/// and
/// [`TrackingInstantNow::checked_sub()`].
///
/// You can compare this with an interesting fixed `Instant`,
/// via [`.cmp()`](Self::cmp) or inequality operators and [`PartialOrd`].
///
/// Borrows from its parent `TrackingInstantNow`;
/// multiple different `TrackingInstantOffsetNow`'s can exist
/// for the same parent tracker,
/// and they'll all update it.
///
/// (There is no corresponding call for `SystemTime`;
/// see the [docs for `TrackingNow::checked_sub()`](TrackingNow::checked_sub)
/// for why.)
#[derive(Debug)]
pub struct TrackingInstantOffsetNow<'i> {
    /// Value to compare with
    threshold: Instant,
    /// Comparison tracker
    earliest: &'i InstantEarliest,
}

/// Timeout tracker that can handle both `Instant`s and `SystemTime`s
///
/// Internally, the two kinds of timeouts are tracked separately:
/// this contains a [`TrackingInstantNow`] and a [`TrackingSystemTimeNow`].
#[derive(Clone, Debug, Deftly)]
#[derive_deftly(CombinedTimeoutTracker, WaitForEarliest)]
pub struct TrackingNow {
    /// For `Instant`s
    #[deftly(now = "Instant")]
    instant: TrackingInstantNow,
    /// For `SystemTime`s
    #[deftly(now = "SystemTime")]
    system_time: TrackingSystemTimeNow,
}

//========== trait for providing `update` method ==========

/// Trait providing the `update` method on timeout trackers
pub trait Update<T>: Sealed {
    /// Update the "earliest timeout" notion, to ensure it's at least as early as `t`
    ///
    /// This is an *unconditional* update.
    /// Usually, `t` should be (strictly) in the future.
    ///
    /// Implemented for [`TrackingNow`], [`TrackingInstantNow`],
    /// and [`TrackingSystemTimeNow`].
    /// `t` can be a `SystemTime`, `Instant`, or `Duration`,
    /// (depending on the type of `self`).
    ///
    /// `Update<Duration>` is not implemented for [`TrackingSystemTimeNow`]
    /// because tracking of relative times should be done via `Instant`,
    /// as the use of the monotonic clock is more reliable.
    fn update(&self, t: T);
}

/// Sealed
mod sealed {
    /// Sealed
    pub trait Sealed {}
}
use sealed::*;

//========== implementations, organised by theme ==========

//----- earliest accessor ----

impl TrackingSystemTimeNow {
    /// Return the earliest future `SystemTime` with which this has been compared
    pub fn earliest(self) -> Option<SystemTime> {
        self.earliest.into_inner()
    }

    /// Return the shortest `Duration` until any future `SystemTime` with which this has been compared
    pub fn shortest(self) -> Option<Duration> {
        self.earliest
            .into_inner()
            .map(|earliest| earliest.duration_since(self.now).unwrap_or(Duration::ZERO))
    }
}

impl TrackingInstantNow {
    /// Return the shortest `Duration` until any future `Instant` with which this has been compared
    pub fn shortest(self) -> Option<Duration> {
        self.earliest.into_inner()
    }
}

//----- manual update functions ----

impl Update<SystemTime> for TrackingSystemTimeNow {
    fn update(&self, t: SystemTime) {
        Self::update_unconditional(&self.earliest, t);
    }
}

impl Update<Instant> for TrackingInstantNow {
    fn update(&self, t: Instant) {
        self.update(t.checked_duration_since(self.now).unwrap_or_default());
    }
}

impl Update<Duration> for TrackingInstantNow {
    fn update(&self, d: Duration) {
        Self::update_unconditional(&self.earliest, d);
    }
}

impl Sealed for TrackingNow {}

impl Update<Duration> for TrackingNow {
    fn update(&self, d: Duration) {
        self.instant().update(d);
    }
}

//----- cmp and PartialOrd implementation ----

impl TrackingSystemTimeNow {
    /// Check if time `t` has been reached yet (and remember that we want to wake up then)
    ///
    /// Also available via [`PartialOrd`]
    fn cmp(&self, t: SystemTime) -> std::cmp::Ordering {
        let o = self.now.cmp(&t);
        Self::update_conditional(o, &self.earliest, t);
        o
    }
}
define_PartialOrd_via_cmp! { TrackingSystemTimeNow, SystemTime, }

/// Check `t` against a now-based `threshold` (and remember for wakeup)
///
/// Common code for `TrackingInstantNow` and `TrackingInstantOffsetNow`'s
/// `cmp`.
fn instant_cmp(earliest: &InstantEarliest, threshold: Instant, t: Instant) -> Ordering {
    let Some(d) = t.checked_duration_since(threshold) else {
        return Ordering::Greater;
    };

    let o = Duration::ZERO.cmp(&d);
    TrackingInstantNow::update_conditional(o, earliest, d);
    o
}

impl TrackingInstantNow {
    /// Check if time `t` has been reached yet (and remember that we want to wake up then)
    ///
    /// Also available via [`PartialOrd`]
    fn cmp(&self, t: Instant) -> std::cmp::Ordering {
        instant_cmp(&self.earliest, self.now, t)
    }
}
define_PartialOrd_via_cmp! { TrackingInstantNow, Instant, }

impl<'i> TrackingInstantOffsetNow<'i> {
    /// Check if the offset current time has advanced to `t` yet (and remember for wakeup)
    ///
    /// Also available via [`PartialOrd`]
    ///
    /// ### Alternative description
    ///
    /// Checks if the current time has advanced to `offset` *after* `t`,
    /// where `offset` was passed to `TrackingInstantNow::checked_sub`.
    fn cmp(&self, t: Instant) -> std::cmp::Ordering {
        instant_cmp(self.earliest, self.threshold, t)
    }
}
define_PartialOrd_via_cmp! { TrackingInstantOffsetNow<'_>, Instant, }

// Combined TrackingNow cmp and PartialOrd impls done via derive-deftly

//----- checked_sub (constructor for Instant offset tracker) -----

impl TrackingInstantNow {
    /// Return a tracker representing a specific offset before the current time
    ///
    /// You can use this to pre-calculate an offset from the current time,
    /// to compare other `Instant`s with.
    ///
    /// This can be convenient to avoid repetition;
    /// also,
    /// when working with checked time arithmetic,
    /// this can helpfully centralise the out-of-bounds error handling site.
    pub fn checked_sub(&self, offset: Duration) -> Option<TrackingInstantOffsetNow> {
        let threshold = self.now.checked_sub(offset)?;
        Some(TrackingInstantOffsetNow {
            threshold,
            earliest: &self.earliest,
        })
    }
}

impl TrackingNow {
    /// Return a tracker representing an `Instant` a specific offset before the current time
    ///
    /// See [`TrackingInstantNow::checked_sub()`] for more details.
    ///
    /// ### `Instant`-only
    ///
    /// The returned tracker handles only `Instant`s,
    /// for reasons relating to clock warps:
    /// broadly, waiting for a particular `SystemTime` must always be done
    /// by working with the future `SystemTime` at which to wake up;
    /// whereas, waiting for a particular `Instant` can be done by calculating `Durations`s.
    ///
    /// For the same reason there is no
    /// `.checked_sub()` method on [`TrackingSystemTimeNow`].
    pub fn checked_sub(&self, offset: Duration) -> Option<TrackingInstantOffsetNow> {
        self.instant.checked_sub(offset)
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

    #![allow(clippy::needless_pass_by_value)] // TODO hoist into standard lint block

    use super::*;
    use futures::poll;
    use std::future::Future;
    use std::task::Poll;
    use tor_async_utils::oneshot;
    use tor_rtcompat::BlockOn;
    use tor_rtmock::MockRuntime;

    fn parse_rfc3339(s: &str) -> SystemTime {
        humantime::parse_rfc3339(s).unwrap()
    }

    fn earliest_systemtime() -> SystemTime {
        parse_rfc3339("1993-11-01T00:00:00Z")
    }

    fn check_orderings<TT, T>(tt: &TT, earliest: T, middle: T, later: T)
    where
        TT: PartialOrd<T>,
        T: PartialOrd<TT>,
    {
        assert!(*tt > earliest);
        assert!(*tt >= earliest);
        assert!(earliest < *tt);
        assert!(earliest <= *tt);
        assert!(*tt == middle);
        assert!(middle == *tt);
        assert!(*tt < later);
        assert!(*tt <= later);
        assert!(later > *tt);
        assert!(later >= *tt);
    }

    fn test_systemtimes() -> (SystemTime, SystemTime, SystemTime) {
        (
            earliest_systemtime(),
            parse_rfc3339("1994-11-01T00:00:00Z"),
            parse_rfc3339("1995-11-01T00:00:00Z"),
        )
    }

    fn secs(s: u64) -> Duration {
        Duration::from_secs(s)
    }
    fn days(d: u64) -> Duration {
        Duration::from_secs(86400 * d)
    }

    #[test]
    fn arith_systemtime() {
        let (earliest, middle, later) = test_systemtimes();

        {
            let tt = TrackingSystemTimeNow::new(middle);
            assert_eq!(tt.earliest(), None);
        }
        {
            let tt = TrackingSystemTimeNow::new(middle);
            assert_eq!(tt.cmp(earliest), Ordering::Greater);
            assert_eq!(tt.clone().shortest(), None);
            assert_eq!(tt.earliest(), None);
        }
        {
            let tt = TrackingSystemTimeNow::new(middle);
            assert_eq!(tt.cmp(later), Ordering::Less);
            assert_eq!(tt.clone().shortest(), Some(days(365)));
            assert_eq!(tt.earliest(), Some(later));
        }
        {
            let tt = TrackingSystemTimeNow::new(middle);
            check_orderings(&tt, earliest, middle, later);
            assert_eq!(tt.clone().shortest(), Some(days(365)));
            assert_eq!(tt.earliest(), Some(later));
        }
        {
            let tt = TrackingSystemTimeNow::new(middle);
            // Use this notation so we can see that all the Update impls are tested
            <TrackingSystemTimeNow as Update<SystemTime>>::update(&tt, later);
            assert_eq!(tt.clone().shortest(), Some(days(365)));
            // Test the underflow edge case (albeit that this would probably be a caller bug)
            <TrackingSystemTimeNow as Update<SystemTime>>::update(&tt, earliest);
            assert_eq!(tt.shortest(), Some(days(0)));
        }
    }

    #[test]
    fn arith_instant_combined() {
        // Adding 1Ms gives us some headroom, since we don't want to underflow
        let earliest = Instant::now() + secs(1000000);
        let middle_d = secs(200);
        let middle = earliest + middle_d;
        let later_d = secs(300);
        let later = middle + later_d;

        {
            let tt = TrackingInstantNow::new(middle);
            assert_eq!(tt.shortest(), None);
        }
        {
            let tt = TrackingInstantNow::new(middle);
            assert_eq!(tt.cmp(earliest), Ordering::Greater);
            assert_eq!(tt.shortest(), None);
        }
        {
            let tt = TrackingInstantNow::new(middle);
            check_orderings(&tt, earliest, middle, later);
            assert_eq!(tt.shortest(), Some(secs(300)));
        }
        {
            let tt = TrackingInstantNow::new(middle);
            let off = tt.checked_sub(secs(700)).expect("underflow");
            assert!(off < earliest); // (200-700) vs 0
            assert_eq!(tt.shortest(), Some(secs(500)));
        }
        {
            let tt = TrackingInstantNow::new(middle);
            let off = tt.checked_sub(Duration::ZERO).unwrap();
            check_orderings(&off, earliest, middle, later);
            assert_eq!(tt.shortest(), Some(secs(300)));
        }
        {
            let tt = TrackingInstantNow::new(middle);
            <TrackingInstantNow as Update<Instant>>::update(&tt, later);
            assert_eq!(tt.clone().shortest(), Some(secs(300)));
            <TrackingInstantNow as Update<Duration>>::update(&tt, secs(100));
            assert_eq!(tt.clone().shortest(), Some(secs(100)));
            // Test the underflow edge case (albeit that this would probably be a caller bug)
            <TrackingInstantNow as Update<Instant>>::update(&tt, earliest);
            assert_eq!(tt.shortest(), Some(secs(0)));
        }

        let (earliest_st, middle_st, later_st) = test_systemtimes();
        {
            let tt = TrackingNow::new(middle, middle_st);
            let off = tt.checked_sub(Duration::ZERO).unwrap();
            check_orderings(&tt, earliest, middle, later);
            check_orderings(&off, earliest, middle, later);
            check_orderings(&tt, earliest_st, middle_st, later_st);
            assert_eq!(tt.clone().shortest(), Some(secs(300)));
            assert_eq!(tt.instant().clone().shortest(), Some(secs(300)));
            assert_eq!(tt.system_time().clone().shortest(), Some(days(365)));
            assert_eq!(tt.system_time().clone().earliest(), Some(later_st));
        }
        let (_earliest_st, middle_st, later_st) = test_systemtimes();
        {
            let tt = TrackingNow::new(middle, middle_st);
            <TrackingNow as Update<SystemTime>>::update(&tt, later_st);
            assert_eq!(tt.clone().shortest(), Some(days(365)));
            <TrackingNow as Update<Duration>>::update(&tt, days(10));
            assert_eq!(tt.clone().shortest(), Some(days(10)));
            <TrackingNow as Update<Instant>>::update(&tt, middle + days(5));
            assert_eq!(tt.shortest(), Some(days(5)));
            // No need to test edge cases, as our Update impls are just delegations
        }
    }

    fn test_sleeper<WF>(
        expected_wait: Option<Duration>,
        wait_for_timeout: impl FnOnce(MockRuntime) -> WF + Send + 'static,
    ) where
        WF: Future<Output = ()> + Send + 'static,
    {
        let runtime = MockRuntime::new();
        runtime.clone().block_on(async move {
            // prevent underflow of Instant in case we started very recently
            // (just jump the clock)
            runtime.advance_by(secs(1000000)).await;
            // set SystemTime to a known value
            runtime.jump_wallclock(earliest_systemtime());

            let (tx, rx) = oneshot::channel();

            runtime.mock_task().spawn_identified("timeout task", {
                let runtime = runtime.clone();
                async move {
                    wait_for_timeout(runtime.clone()).await;
                    tx.send(()).unwrap();
                }
            });

            runtime.mock_task().progress_until_stalled().await;

            if expected_wait == Some(Duration::ZERO) {
                assert_eq!(poll!(rx), Poll::Ready(Ok(())));
            } else {
                let actual_wait = runtime.time_until_next_timeout();
                assert_eq!(actual_wait, expected_wait);
            }
        });
    }

    fn test_sleeper_combined(
        expected_wait: Option<Duration>,
        update_tt: impl FnOnce(&MockRuntime, &TrackingNow) + Send + 'static,
    ) {
        test_sleeper(expected_wait, |rt| async move {
            let tt = TrackingNow::now(&rt);
            update_tt(&rt, &tt);
            tt.wait_for_earliest(&rt).await;
        });
    }

    #[test]
    fn sleeps() {
        let s = earliest_systemtime();
        let d = secs(42);

        test_sleeper_combined(None, |_rt, _tt| {});
        test_sleeper_combined(None, move |_rt, tt| {
            assert!(*tt > (s - d));
        });
        test_sleeper_combined(Some(d), move |_rt, tt| {
            assert!(*tt < (s + d));
        });

        test_sleeper_combined(None, move |rt, tt| {
            let i = rt.now();
            assert!(*tt > (i - d));
        });
        test_sleeper_combined(Some(d), move |rt, tt| {
            let i = rt.now();
            assert!(*tt < (i + d));
        });
    }
}
