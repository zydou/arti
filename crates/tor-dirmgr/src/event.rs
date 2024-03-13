//! Code for notifying other modules about changes in the directory.

// TODO(nickm): After we have enough experience with this FlagPublisher, we
// might want to make it a public interface. If we do it should probably move
// into another crate.

use std::{
    fmt,
    marker::PhantomData,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    task::Poll,
    time::SystemTime,
};

use educe::Educe;
use futures::{stream::Stream, Future, StreamExt};
use itertools::chain;
use paste::paste;
use time::OffsetDateTime;
use tor_basic_utils::skip_fmt;
use tor_netdir::DirEvent;
use tor_netdoc::doc::netstatus;

#[cfg(feature = "bridge-client")]
use tor_guardmgr::bridge::BridgeDescEvent;

use crate::bootstrap::AttemptId;

/// A trait to indicate something that can be published with [`FlagPublisher`].
///
/// Since the implementation of `FlagPublisher` requires that its events be
/// represented as small integers, this trait is mainly about converting to and
/// from those integers.
pub(crate) trait FlagEvent: Sized {
    /// The maximum allowed integer value that [`FlagEvent::to_index()`] can return
    /// for this type.
    ///
    /// This is limited to u16 because the [`FlagPublisher`] uses a vector of all
    /// known flags, and sometimes iterates over the whole vector.
    const MAXIMUM: u16;
    /// Convert this event into an index.
    ///
    /// For efficiency, indices should be small and densely packed.
    fn to_index(self) -> u16;
    /// Try to reconstruct an event from its index.  Return None if the index is
    /// out-of-bounds.
    fn from_index(flag: u16) -> Option<Self>;
}

/// Implements [`FlagEvent`] for a C-like enum
///
/// Requiremets:
///
///  * `$ty` must implement [`strum::EnumCount`] [`strum::IntoEnumIterator`]
///
///  * `$ty` type must implement [`Into<u16>`] and [`TryFrom<u16>`]
///     (for example using the `num_enum` crate).
///
///  * The discriminants must be densely allocated.
///    This will be done automatically by the compiler
///    if explicit discriminants are not specified.
///    (This property is checked in a test.)
///
///  * The variants may not contain any data.
///    This is required for correctness.
///    We think it is checked if you use `num_enum::TryFromPrimitive`.
///
/// # Example
///
// Sadly, it does not appear to be possible to doctest a private macro.
/// ```rust,ignore
/// use num_enum::{IntoPrimitive, TryFromPrimitive};
/// use strum::{EnumCount, EnumIter};
///
/// #[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// #[derive(EnumIter, EnumCount, IntoPrimitive, TryFromPrimitive)]
/// #[non_exhaustive]
/// #[repr(u16)]
/// pub enum DirEvent {
///     NewConsensus,
///     NewDescriptors,
/// }
///
/// impl_FlagEvent!{ DirEvent }
/// ```
macro_rules! impl_FlagEvent { { $ty:ident } => { paste!{
    impl FlagEvent for $ty {
        const MAXIMUM: u16 = {
            let count = <$ty as $crate::strum::EnumCount>::COUNT;
            (count - 1) as u16
        };
        fn to_index(self) -> u16 {
            self.into()
        }
        fn from_index(flag: u16) -> Option<Self> {
            flag.try_into().ok()
        }
    }

    #[test]
    #[allow(non_snake_case)]
    fn [< flagevent_test_variant_numbers_ $ty >]() {
        for variant in <$ty as $crate::strum::IntoEnumIterator>::iter() {
            assert!(<$ty as FlagEvent>::to_index(variant) <=
                    <$ty as FlagEvent>::MAXIMUM,
                    "impl_FlagEvent only allowed if discriminators are dense");
        }
    }
} } }

impl_FlagEvent! { DirEvent }

#[cfg(feature = "bridge-client")]
impl_FlagEvent! { BridgeDescEvent }

/// A publisher that broadcasts flag-level events to multiple subscribers.
///
/// Events with the same flag value may be coalesced: that is, if the same event
/// is published ten times in a row, a subscriber may receive only a single
/// notification of the event.
///
/// FlagPublisher supports an MPMC model: cloning a Publisher creates a new handle
/// that can also broadcast events to everybody listening on the channel.
///  Dropping the last handle closes all streams subscribed to it.
pub(crate) struct FlagPublisher<F> {
    /// Inner data shared by publishers and streams.
    inner: Arc<Inner<F>>,
}

/// Shared structure to implement [`FlagPublisher`] and [`FlagListener`].
struct Inner<F> {
    /// An event that we use to broadcast whenever a new [`FlagEvent`] event has occurred.
    event: event_listener::Event,
    /// How many times has each event occurred, ever.
    ///
    /// (It is safe for this to wrap around.)
    // TODO(nickm): I wish this could be an array, but const generics don't
    // quite support that yet.
    counts: Vec<AtomicUsize>, // I wish this could be an array.
    /// How many publishers remain?
    n_publishers: AtomicUsize,
    /// Phantom member to provide correct covariance.
    ///
    /// The `fn` business is a covariance trick to include `F` without affecting
    /// this object's Send/Sync status.
    _phantom: PhantomData<fn(F) -> F>,
}

/// A [`Stream`] that returns a series of event [`FlagEvent`]s broadcast by a
/// [`FlagPublisher`].
pub(crate) struct FlagListener<F> {
    /// What value of each flag's count have we seen most recently?  
    ///
    /// Note that we count the event as "received" only once for each observed
    /// change in the flag's count, even if that count has changed by more than
    /// 1.
    my_counts: Vec<usize>,
    /// An an `EventListener` that will be notified when events are published,
    /// or when the final publisher is dropped.
    ///
    /// We must always have one of these available _before_ we check any counts
    /// in self.inner.
    listener: event_listener::EventListener,
    /// Reference to shared data.
    inner: Arc<Inner<F>>,
}

impl<F: FlagEvent> Default for FlagPublisher<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: FlagEvent> FlagPublisher<F> {
    /// Construct a new FlagPublisher.
    pub(crate) fn new() -> Self {
        // We can't use vec![AtomicUsize::new(0); F::MAXIMUM+1]: that would
        // require AtomicUsize to be Clone.
        let counts = std::iter::repeat_with(AtomicUsize::default)
            .take(F::MAXIMUM as usize + 1)
            .collect();
        FlagPublisher {
            inner: Arc::new(Inner {
                event: event_listener::Event::new(),
                counts,
                n_publishers: AtomicUsize::new(1),
                _phantom: PhantomData,
            }),
        }
    }

    /// Create a new subscription to this FlagPublisher.
    pub(crate) fn subscribe(&self) -> FlagListener<F> {
        // We need to do this event.listen before we check the counts; otherwise
        // we could have a sequence where: we check the count, then the
        // publisher increments the count, then the publisher calls
        // event.notify(), and we call event.listen(). That would cause us to
        // miss the increment.
        let listener = self.inner.event.listen();

        FlagListener {
            my_counts: self
                .inner
                .counts
                .iter()
                .map(|a| a.load(Ordering::SeqCst))
                .collect(),
            listener,
            inner: Arc::clone(&self.inner),
        }
    }

    /// Tell every listener that the provided flag has been published.
    pub(crate) fn publish(&self, flag: F) {
        self.inner.counts[flag.to_index() as usize].fetch_add(1, Ordering::SeqCst);
        self.inner.event.notify(usize::MAX);
    }
}

impl<F> Clone for FlagPublisher<F> {
    fn clone(&self) -> FlagPublisher<F> {
        self.inner.n_publishers.fetch_add(1, Ordering::SeqCst);
        FlagPublisher {
            inner: Arc::clone(&self.inner),
        }
    }
}

// We must implement Drop to keep count publishers, and so that when the last
// publisher goes away, we can wake up every listener  so that it notices that
// the stream is now ended.
impl<F> Drop for FlagPublisher<F> {
    fn drop(&mut self) {
        if self.inner.n_publishers.fetch_sub(1, Ordering::SeqCst) == 1 {
            // That was the last reference; we must notify the listeners.
            self.inner.event.notify(usize::MAX);
        }
    }
}

impl<F: FlagEvent> Stream for FlagListener<F> {
    type Item = F;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        loop {
            // Notify the caller if any events are ready to fire.
            for idx in 0..F::MAXIMUM as usize + 1 {
                let cur = self.inner.counts[idx].load(Ordering::SeqCst);
                // We don't have to use < here specifically, since any change
                // indicates that the count has been modified. That lets us
                // survive usize wraparound.
                if cur != self.my_counts[idx] {
                    self.my_counts[idx] = cur;
                    return Poll::Ready(Some(F::from_index(idx as u16).expect("Internal error")));
                }
            }

            // At this point, notify the caller if there are no more publishers.
            if self.inner.n_publishers.load(Ordering::SeqCst) == 0 {
                return Poll::Ready(None);
            }

            if let Poll::Ready(()) = Pin::new(&mut self.listener).poll(cx) {
                // Got a new notification; we must create a new event and continue the loop.
                //
                // See discussion in `FlagPublisher::subscribe()` for why we must always create
                // this listener _before_ checking any flags.
                self.listener = self.inner.event.listen();
            } else {
                // Nothing to do yet: put the listener back.
                return Poll::Pending;
            }
        }
    }
}

/// Description of the directory manager's current bootstrapping status.
///
/// This status does not necessarily increase monotonically: it can go backwards
/// if (for example) our directory information expires before we're able to get
/// new information.
//
// TODO(nickm): This type has gotten a bit large for being the type we send over
// a `postage::watch`: perhaps we'd be better off having this information stored
// in the guardmgr, and having only a summary of it sent over the
// `postage::watch`.  But for now, let's not, unless it shows up in profiles.
#[derive(Clone, Debug, Default)]
pub struct DirBootstrapStatus(StatusEnum);

/// The contents of a DirBootstrapStatus.
///
/// This is a separate type since we don't want to make these variables public.
#[derive(Clone, Debug, Default)]
enum StatusEnum {
    /// There is no active attempt to load or fetch a directory.
    #[default]
    NoActivity,
    /// We have only one attempt to fetch a directory.
    Single {
        /// The currently active directory attempt.
        ///
        /// We're either using this directory now, or we plan to use it as soon
        /// as it's complete enough.
        current: StatusEntry,
    },
    /// We have an existing directory attempt, but it's stale, and we're
    /// fetching a new one to replace it.
    ///
    /// Invariant: `current.id < next.id`
    Replacing {
        /// The previous attempt's status.  It may still be trying to fetch
        /// information if it has descriptors left to download.
        current: StatusEntry,
        /// The current attempt's status.  We are not yet using this directory
        /// for our activity, since it does not (yet) have enough information.
        next: StatusEntry,
    },
}

/// The status and identifier of a single attempt to download a full directory.
#[derive(Clone, Debug)]
struct StatusEntry {
    /// The identifier for this attempt.
    id: AttemptId,
    /// The latest status.
    status: DirStatus,
}

/// The status for a single directory.
#[derive(Clone, Debug, Default, derive_more::Display)]
#[display(fmt = "{0}", progress)]
pub(crate) struct DirStatus {
    /// How much of the directory do we currently have?
    progress: DirProgress,
    /// How many resets have been forced while fetching this directory?
    n_resets: usize,
    /// How many errors have we encountered since last we advanced the
    /// 'progress' on this directory?
    n_errors: usize,
    /// How many times has an `update_progress` call not actually moved us
    /// forward since we last advanced the 'progress' on this directory?
    n_stalls: usize,
}

/// How much progress have we made in downloading a given directory?
///
/// This is a separate type so that we don't make the variants public.
#[derive(Clone, Debug, Educe)]
#[educe(Default)]
pub(crate) enum DirProgress {
    /// We don't have any information yet.
    #[educe(Default)]
    NoConsensus {
        /// If present, we are fetching a consensus whose valid-after time
        /// postdates this time.
        #[allow(dead_code)]
        after: Option<SystemTime>,
    },
    /// We've downloaded a consensus, but we haven't validated it yet.
    FetchingCerts {
        /// The actual declared lifetime of the consensus.
        lifetime: netstatus::Lifetime,
        /// The lifetime for which we are willing to use this consensus.  (This
        /// may be broader than `lifetime`.)
        usable_lifetime: netstatus::Lifetime,
        /// A fraction (in (numerator,denominator) format) of the certificates
        /// we have for this consensus.
        n_certs: (u16, u16),
    },
    /// We've validated a consensus and we're fetching (or have fetched) its
    /// microdescriptors.
    Validated {
        /// The actual declared lifetime of the consensus.
        lifetime: netstatus::Lifetime,
        /// The lifetime for which we are willing to use this consensus.  (This
        /// may be broader than `lifetime`.)
        usable_lifetime: netstatus::Lifetime,
        /// A fraction (in (numerator,denominator) form) of the microdescriptors
        /// that we have for this consensus.
        n_mds: (u32, u32),
        /// True iff we've decided that the consensus is usable.
        usable: bool,
        // TODO(nickm) Someday we could add a field about whether any primary
        // guards are missing microdescriptors, to give a better explanation for
        // the case where we won't switch our consensus because of that.
    },
}

/// A reported diagnostic for what kind of trouble we've seen while trying to
/// bootstrap a directory.
///
/// These blockages types are not yet terribly specific: if you encounter one,
/// it's probably a good idea to check the logs to see what's really going on.
///
/// If you encounter connection blockage _and_ directory blockage at the same
/// time, the connection blockage is almost certainly the real problem.
//
// TODO(nickm): At present these diagnostics aren't very helpful; they say too
// much about _how we know_ that the process has gone wrong, but not so much
// about _what the problem is_.  In the future, we may wish to look more closely
// at what _kind_ of errors or resets we've seen, so we can report better
// information. Probably, however, we should only do that after we get some
// experience with which problems people encounter in practice, and what
// diagnostics would be useful for them.
#[derive(Clone, Debug, derive_more::Display)]
#[non_exhaustive]
pub enum DirBlockage {
    /// We've been downloading information without error, but we haven't
    /// actually been getting anything that we want.
    ///
    /// This might indicate that there's a problem with information propagating
    /// through the Tor network, or it might indicate that a bogus consensus or
    /// a bad clock has tricked us into asking for something that nobody has.
    #[display(fmt = "Can't make progress.")]
    Stalled,
    /// We've gotten a lot of errors without making forward progress on our
    /// bootstrap attempt.
    ///
    /// This might indicate that something's wrong with the Tor network, or that
    /// there's something buggy with our ability to handle directory responses.
    /// It might also indicate a malfunction on our directory guards, or a bug
    /// on our retry logic.
    #[display(fmt = "Too many errors without making progress.")]
    TooManyErrors,
    /// We've reset our bootstrap attempt a lot of times.
    ///
    /// This either indicates that we have been failing a lot for one of the
    /// other reasons above, or that we keep getting served a consensus which
    /// turns out, upon trying to fetch certificates, not to be usable.  It can
    /// also indicate a bug in our retry logic.
    #[display(fmt = "Had to reset bootstrapping too many times.")]
    TooManyResets,
}

impl fmt::Display for DirProgress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        /// Format this time in a format useful for displaying
        /// lifetime boundaries.
        fn fmt_time(t: SystemTime) -> String {
            use once_cell::sync::Lazy;
            /// Formatter object for lifetime boundaries.
            ///
            /// We use "YYYY-MM-DD HH:MM:SS UTC" here, since we never have
            /// sub-second times here, and using non-UTC offsets is confusing
            /// in this context.
            static FORMAT: Lazy<Vec<time::format_description::FormatItem>> = Lazy::new(|| {
                time::format_description::parse("[year]-[month]-[day] [hour]:[minute]:[second] UTC")
                    .expect("Invalid time format")
            });
            OffsetDateTime::from(t)
                .format(&FORMAT)
                .unwrap_or_else(|_| "(could not format)".into())
        }

        match &self {
            DirProgress::NoConsensus { .. } => write!(f, "fetching a consensus"),
            DirProgress::FetchingCerts { n_certs, .. } => write!(
                f,
                "fetching authority certificates ({}/{})",
                n_certs.0, n_certs.1
            ),
            DirProgress::Validated {
                usable: false,
                n_mds,
                ..
            } => write!(f, "fetching microdescriptors ({}/{})", n_mds.0, n_mds.1),
            DirProgress::Validated {
                usable: true,
                lifetime,
                ..
            } => write!(
                f,
                "usable, fresh until {}, and valid until {}",
                fmt_time(lifetime.fresh_until()),
                fmt_time(lifetime.valid_until())
            ),
        }
    }
}

impl fmt::Display for DirBootstrapStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            StatusEnum::NoActivity => write!(f, "not downloading")?,
            StatusEnum::Single { current } => write!(f, "directory is {}", current.status)?,
            StatusEnum::Replacing { current, next } => write!(
                f,
                "directory is {}; next directory is {}",
                current.status, next.status
            )?,
        }
        Ok(())
    }
}

impl DirBootstrapStatus {
    /// Return the current DirStatus.
    ///
    /// This is the _most complete_ status.  If we have any usable status, it is
    /// this one.
    fn current(&self) -> Option<&DirStatus> {
        match &self.0 {
            StatusEnum::NoActivity => None,
            StatusEnum::Single { current } => Some(&current.status),
            StatusEnum::Replacing { current, .. } => Some(&current.status),
        }
    }

    /// Return the next DirStatus, if there is one.
    fn next(&self) -> Option<&DirStatus> {
        match &self.0 {
            StatusEnum::Replacing { next, .. } => Some(&next.status),
            _ => None,
        }
    }

    /// Return the contained `DirStatus`es, in order: `current`, then `next`
    #[allow(clippy::implied_bounds_in_impls)]
    fn statuses(&self) -> impl Iterator<Item = &DirStatus> + DoubleEndedIterator {
        chain!(self.current(), self.next(),)
    }

    /// Return the contained `StatusEntry`s mutably, in order: `current`, then `next`
    #[allow(clippy::implied_bounds_in_impls)]
    fn entries_mut(&mut self) -> impl Iterator<Item = &mut StatusEntry> + DoubleEndedIterator {
        let (current, next) = match &mut self.0 {
            StatusEnum::NoActivity => (None, None),
            StatusEnum::Single { current } => (Some(current), None),
            StatusEnum::Replacing { current, next } => (Some(current), Some(next)),
        };
        chain!(current, next,)
    }

    /// Return the fraction of completion for directory download, in a form
    /// suitable for a progress bar at some particular time.
    ///
    /// This value is not monotonic, and can go down as one directory is
    /// replaced with another.
    ///
    /// Callers _should not_ depend on the specific meaning of any particular
    /// fraction; we may change these fractions in the future.
    pub fn frac_at(&self, when: SystemTime) -> f32 {
        self.statuses()
            .filter_map(|st| st.frac_at(when))
            .next()
            .unwrap_or(0.0)
    }

    /// Return true if this status indicates that we have a current usable
    /// directory.
    pub fn usable_at(&self, now: SystemTime) -> bool {
        if let Some(current) = self.current() {
            current.progress.usable() && current.okay_to_use_at(now)
        } else {
            false
        }
    }

    /// If there is a problem with our attempts to bootstrap, return a
    /// corresponding DirBlockage.  
    pub fn blockage(&self, now: SystemTime) -> Option<DirBlockage> {
        if let Some(current) = self.current() {
            if current.progress.usable() && current.declared_live_at(now) {
                // The current directory is sufficient, and not even a little bit
                // expired. There is no problem.
                return None;
            }
        }

        // Any blockage in "current" is more serious, so return that if there is one
        self.statuses().filter_map(|st| st.blockage()).next()
    }

    /// Return the appropriate DirStatus for `AttemptId`, constructing it if
    /// necessary.
    ///
    /// Return None if all relevant attempts are more recent than this Id.
    #[allow(clippy::search_is_some)] // tpo/core/arti/-/merge_requests/599#note_2816368
    fn mut_status_for(&mut self, attempt_id: AttemptId) -> Option<&mut DirStatus> {
        // First, ensure that we have a *recent enough* attempt
        // Look for the latest attempt, and see if it's new enough; if not, start a new one.
        if self
            .entries_mut()
            .rev()
            .take(1)
            .find(|entry| entry.id >= attempt_id)
            .is_none()
        {
            let current = match std::mem::take(&mut self.0) {
                StatusEnum::NoActivity => None,
                StatusEnum::Single { current } => Some(current),
                StatusEnum::Replacing { current, .. } => Some(current),
            };
            // If we have a `current` already, we keep it, and restart `next`.
            let next = StatusEntry::new(attempt_id);
            self.0 = match current {
                None => StatusEnum::Single { current: next },
                Some(current) => StatusEnum::Replacing { current, next },
            };
        }

        // Find the entry with `attempt_id` and return it.
        // (Despite the above, there might not be one: maybe `attempt_id` is old.)
        self.entries_mut()
            .find(|entry| entry.id == attempt_id)
            .map(|entry| &mut entry.status)
    }

    /// If the "next" status is usable, replace the current status with it.
    fn advance_status(&mut self) {
        // TODO: should make sure that the compiler is smart enough to optimize
        // this mem::take() and replacement away, and turn it into a conditional
        // replacement?
        self.0 = match std::mem::take(&mut self.0) {
            StatusEnum::Replacing { next, .. } if next.status.progress.usable() => {
                StatusEnum::Single { current: next }
            }
            other => other,
        };
    }

    /// Update this status by replacing the `DirProgress` in its current status
    /// (or its next status) with `new_status`, as appropriate.
    pub(crate) fn update_progress(&mut self, attempt_id: AttemptId, new_progress: DirProgress) {
        if let Some(status) = self.mut_status_for(attempt_id) {
            let old_frac = status.frac();
            status.progress = new_progress;
            let new_frac = status.frac();
            if new_frac > old_frac {
                // This download has made progress: clear our count of errors
                // and stalls.
                status.n_errors = 0;
                status.n_stalls = 0;
            } else {
                // This download didn't make progress; increment the stall
                // count.
                status.n_stalls += 1;
            }
            self.advance_status();
        }
    }

    /// Update this status by noting that some errors have occurred in a given
    /// download attempt.
    pub(crate) fn note_errors(&mut self, attempt_id: AttemptId, n_errors: usize) {
        if let Some(status) = self.mut_status_for(attempt_id) {
            status.n_errors += n_errors;
        }
    }

    /// Update this status by noting that we had to reset a given download attempt;
    pub(crate) fn note_reset(&mut self, attempt_id: AttemptId) {
        if let Some(status) = self.mut_status_for(attempt_id) {
            status.n_resets += 1;
        }
    }
}

impl StatusEntry {
    /// Construct a new StatusEntry with a given attempt id, and no progress
    /// reported.
    fn new(id: AttemptId) -> Self {
        Self {
            id,
            status: DirStatus::default(),
        }
    }
}

impl DirStatus {
    /// Return the declared consensus lifetime for this directory, if we have one.
    fn declared_lifetime(&self) -> Option<&netstatus::Lifetime> {
        match &self.progress {
            DirProgress::NoConsensus { .. } => None,
            DirProgress::FetchingCerts { lifetime, .. } => Some(lifetime),
            DirProgress::Validated { lifetime, .. } => Some(lifetime),
        }
    }

    /// Return the consensus lifetime for this directory, if we have one, as
    /// modified by our skew-tolerance settings.
    fn usable_lifetime(&self) -> Option<&netstatus::Lifetime> {
        match &self.progress {
            DirProgress::NoConsensus { .. } => None,
            DirProgress::FetchingCerts {
                usable_lifetime, ..
            } => Some(usable_lifetime),
            DirProgress::Validated {
                usable_lifetime, ..
            } => Some(usable_lifetime),
        }
    }

    /// Return true if the directory is valid at the given time, as modified by
    /// our clock skew settings.
    fn okay_to_use_at(&self, when: SystemTime) -> bool {
        self.usable_lifetime()
            .map(|lt| lt.valid_at(when))
            .unwrap_or(false)
    }

    /// Return true if the directory is valid at the given time, _unmodified_ by our
    /// clock skew settings.
    fn declared_live_at(&self, when: SystemTime) -> bool {
        self.declared_lifetime()
            .map(|lt| lt.valid_at(when))
            .unwrap_or(false)
    }

    /// As `frac`, but return None if this consensus is not valid at the given time,
    /// and down-rate expired consensuses that we're still willing to use.
    fn frac_at(&self, when: SystemTime) -> Option<f32> {
        if self
            .declared_lifetime()
            .map(|lt| lt.valid_at(when))
            .unwrap_or(false)
        {
            // We're officially okay to use this directory.
            Some(self.frac())
        } else if self.okay_to_use_at(when) {
            // This directory is a little expired, but only a little.
            Some(self.frac() * 0.9)
        } else {
            None
        }
    }

    /// Return the fraction of completion for directory download, in a form
    /// suitable for a progress bar.
    ///
    /// This is monotonically increasing for a single directory, but can go down
    /// as one directory is replaced with another.
    ///
    /// Callers _should not_ depend on the specific meaning of any particular
    /// fraction; we may change these fractions in the future.
    fn frac(&self) -> f32 {
        // We arbitrarily decide that 25% is downloading the consensus, 10% is
        // downloading the certificates, and the remaining 65% is downloading
        // the microdescriptors until we become usable.  We may want to re-tune that in the future, but
        // the documentation of this function should allow us to do so.
        match &self.progress {
            DirProgress::NoConsensus { .. } => 0.0,
            DirProgress::FetchingCerts { n_certs, .. } => {
                0.25 + f32::from(n_certs.0) / f32::from(n_certs.1) * 0.10
            }
            DirProgress::Validated {
                usable: false,
                n_mds,
                ..
            } => 0.35 + (n_mds.0 as f32) / (n_mds.1 as f32) * 0.65,
            DirProgress::Validated { usable: true, .. } => 1.0,
        }
    }

    /// If we think there is a problem with our bootstrapping process, return a
    /// [`DirBlockage`] to describe it.
    ///
    /// The caller may want to also check `usable_at` to avoid reporting trouble
    /// if the directory is currently usable.
    fn blockage(&self) -> Option<DirBlockage> {
        /// How many resets are sufficient for us to report a blockage?
        const RESET_THRESHOLD: usize = 2;
        /// How many errors are sufficient for us to report a blockage?
        const ERROR_THRESHOLD: usize = 6;
        /// How many no-progress download attempts are sufficient for us to
        /// report a blockage?
        const STALL_THRESHOLD: usize = 8;

        if self.n_resets >= RESET_THRESHOLD {
            Some(DirBlockage::TooManyResets)
        } else if self.n_errors >= ERROR_THRESHOLD {
            Some(DirBlockage::TooManyErrors)
        } else if self.n_stalls >= STALL_THRESHOLD {
            Some(DirBlockage::Stalled)
        } else {
            None
        }
    }
}

impl DirProgress {
    /// Return true if this progress indicates a usable directory.
    fn usable(&self) -> bool {
        matches!(self, DirProgress::Validated { usable: true, .. })
    }
}

/// A stream of [`DirBootstrapStatus`] events.
#[derive(Clone, Educe)]
#[educe(Debug)]
pub struct DirBootstrapEvents {
    /// The `postage::watch::Receiver` that we're wrapping.
    ///
    /// We wrap this type so that we don't expose its entire API, and so that we
    /// can migrate to some other implementation in the future if we want.
    #[educe(Debug(method = "skip_fmt"))]
    pub(crate) inner: postage::watch::Receiver<DirBootstrapStatus>,
}

impl Stream for DirBootstrapEvents {
    type Item = DirBootstrapStatus;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        self.inner.poll_next_unpin(cx)
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
    use std::time::Duration;

    use super::*;
    use float_eq::assert_float_eq;
    use futures::stream::StreamExt;
    use tor_rtcompat::test_with_all_runtimes;

    #[test]
    fn subscribe_and_publish() {
        test_with_all_runtimes!(|_rt| async {
            let publish: FlagPublisher<DirEvent> = FlagPublisher::new();
            let mut sub1 = publish.subscribe();
            publish.publish(DirEvent::NewConsensus);
            let mut sub2 = publish.subscribe();
            let ev = event_listener::Event::new();
            let lis = ev.listen();

            futures::join!(
                async {
                    // sub1 was created in time to see this event...
                    let val1 = sub1.next().await;
                    assert_eq!(val1, Some(DirEvent::NewConsensus));
                    ev.notify(1); // Tell the third task below to drop the publisher.
                    let val2 = sub1.next().await;
                    assert_eq!(val2, None);
                },
                async {
                    let val = sub2.next().await;
                    assert_eq!(val, None);
                },
                async {
                    lis.await;
                    drop(publish);
                }
            );
        });
    }

    #[test]
    fn receive_two() {
        test_with_all_runtimes!(|_rt| async {
            let publish: FlagPublisher<DirEvent> = FlagPublisher::new();

            let mut sub = publish.subscribe();
            let ev = event_listener::Event::new();
            let ev_lis = ev.listen();
            futures::join!(
                async {
                    let val1 = sub.next().await;
                    assert_eq!(val1, Some(DirEvent::NewDescriptors));
                    ev.notify(1);
                    let val2 = sub.next().await;
                    assert_eq!(val2, Some(DirEvent::NewConsensus));
                },
                async {
                    publish.publish(DirEvent::NewDescriptors);
                    ev_lis.await;
                    publish.publish(DirEvent::NewConsensus);
                }
            );
        });
    }

    #[test]
    fn two_publishers() {
        test_with_all_runtimes!(|_rt| async {
            let publish1: FlagPublisher<DirEvent> = FlagPublisher::new();
            let publish2 = publish1.clone();

            let mut sub = publish1.subscribe();
            let ev1 = event_listener::Event::new();
            let ev2 = event_listener::Event::new();
            let ev1_lis = ev1.listen();
            let ev2_lis = ev2.listen();
            futures::join!(
                async {
                    let mut count = [0_usize; 2];
                    // These awaits guarantee that we will see at least one event flag of each
                    // type, before the stream is dropped.
                    ev1_lis.await;
                    ev2_lis.await;
                    while let Some(e) = sub.next().await {
                        count[e.to_index() as usize] += 1;
                    }
                    assert!(count[0] > 0);
                    assert!(count[1] > 0);
                    assert!(count[0] <= 100);
                    assert!(count[1] <= 100);
                },
                async {
                    for _ in 0..100 {
                        publish1.publish(DirEvent::NewDescriptors);
                        ev1.notify(1);
                        tor_rtcompat::task::yield_now().await;
                    }
                    drop(publish1);
                },
                async {
                    for _ in 0..100 {
                        publish2.publish(DirEvent::NewConsensus);
                        ev2.notify(1);
                        tor_rtcompat::task::yield_now().await;
                    }
                    drop(publish2);
                }
            );
        });
    }

    #[test]
    fn receive_after_publishers_are_gone() {
        test_with_all_runtimes!(|_rt| async {
            let publish: FlagPublisher<DirEvent> = FlagPublisher::new();

            let mut sub = publish.subscribe();

            publish.publish(DirEvent::NewConsensus);
            drop(publish);
            let v = sub.next().await;
            assert_eq!(v, Some(DirEvent::NewConsensus));
            let v = sub.next().await;
            assert!(v.is_none());
        });
    }

    #[test]
    fn failed_conversion() {
        assert_eq!(DirEvent::from_index(999), None);
    }

    #[test]
    fn dir_status_basics() {
        let now = SystemTime::now();
        let hour = Duration::new(3600, 0);

        let nothing = DirStatus {
            progress: DirProgress::NoConsensus { after: None },
            ..Default::default()
        };
        let lifetime = netstatus::Lifetime::new(now, now + hour, now + hour * 2).unwrap();
        let unval = DirStatus {
            progress: DirProgress::FetchingCerts {
                lifetime: lifetime.clone(),
                usable_lifetime: lifetime,
                n_certs: (3, 5),
            },
            ..Default::default()
        };
        let lifetime =
            netstatus::Lifetime::new(now + hour, now + hour * 2, now + hour * 3).unwrap();
        let with_c = DirStatus {
            progress: DirProgress::Validated {
                lifetime: lifetime.clone(),
                usable_lifetime: lifetime,
                n_mds: (30, 40),
                usable: false,
            },
            ..Default::default()
        };

        // lifetime()
        assert!(nothing.usable_lifetime().is_none());
        assert_eq!(unval.usable_lifetime().unwrap().valid_after(), now);
        assert_eq!(
            with_c.usable_lifetime().unwrap().valid_until(),
            now + hour * 3
        );

        // frac() (It's okay if we change the actual numbers here later; the
        // current ones are more or less arbitrary.)
        const TOL: f32 = 0.00001;
        assert_float_eq!(nothing.frac(), 0.0, abs <= TOL);
        assert_float_eq!(unval.frac(), 0.25 + 0.06, abs <= TOL);
        assert_float_eq!(with_c.frac(), 0.35 + 0.65 * 0.75, abs <= TOL);

        // frac_at()
        let t1 = now + hour / 2;
        let t2 = t1 + hour * 2;
        assert!(nothing.frac_at(t1).is_none());
        assert_float_eq!(unval.frac_at(t1).unwrap(), 0.25 + 0.06, abs <= TOL);
        assert!(with_c.frac_at(t1).is_none());
        assert!(nothing.frac_at(t2).is_none());
        assert!(unval.frac_at(t2).is_none());
        assert_float_eq!(with_c.frac_at(t2).unwrap(), 0.35 + 0.65 * 0.75, abs <= TOL);
    }

    #[test]
    fn dir_status_display() {
        use time::macros::datetime;
        let t1: SystemTime = datetime!(2022-01-17 11:00:00 UTC).into();
        let hour = Duration::new(3600, 0);
        let lifetime = netstatus::Lifetime::new(t1, t1 + hour, t1 + hour * 3).unwrap();

        let ds = DirStatus {
            progress: DirProgress::NoConsensus { after: None },
            ..Default::default()
        };
        assert_eq!(ds.to_string(), "fetching a consensus");

        let ds = DirStatus {
            progress: DirProgress::FetchingCerts {
                lifetime: lifetime.clone(),
                usable_lifetime: lifetime.clone(),
                n_certs: (3, 5),
            },
            ..Default::default()
        };
        assert_eq!(ds.to_string(), "fetching authority certificates (3/5)");

        let ds = DirStatus {
            progress: DirProgress::Validated {
                lifetime: lifetime.clone(),
                usable_lifetime: lifetime.clone(),
                n_mds: (30, 40),
                usable: false,
            },
            ..Default::default()
        };
        assert_eq!(ds.to_string(), "fetching microdescriptors (30/40)");

        let ds = DirStatus {
            progress: DirProgress::Validated {
                lifetime: lifetime.clone(),
                usable_lifetime: lifetime,
                n_mds: (30, 40),
                usable: true,
            },
            ..Default::default()
        };
        assert_eq!(
            ds.to_string(),
            "usable, fresh until 2022-01-17 12:00:00 UTC, and valid until 2022-01-17 14:00:00 UTC"
        );
    }

    #[test]
    fn bootstrap_status() {
        use time::macros::datetime;
        let t1: SystemTime = datetime!(2022-01-17 11:00:00 UTC).into();
        let hour = Duration::new(3600, 0);
        let lifetime = netstatus::Lifetime::new(t1, t1 + hour, t1 + hour * 3).unwrap();
        let lifetime2 = netstatus::Lifetime::new(t1 + hour, t1 + hour * 2, t1 + hour * 4).unwrap();

        let dp1 = DirProgress::Validated {
            lifetime: lifetime.clone(),
            usable_lifetime: lifetime.clone(),
            n_mds: (3, 40),
            usable: true,
        };
        let dp2 = DirProgress::Validated {
            lifetime: lifetime2.clone(),
            usable_lifetime: lifetime2.clone(),
            n_mds: (5, 40),
            usable: false,
        };
        let attempt1 = AttemptId::next();
        let attempt2 = AttemptId::next();

        let bs = DirBootstrapStatus(StatusEnum::Replacing {
            current: StatusEntry {
                id: attempt1,
                status: DirStatus {
                    progress: dp1.clone(),
                    ..Default::default()
                },
            },
            next: StatusEntry {
                id: attempt2,
                status: DirStatus {
                    progress: dp2.clone(),
                    ..Default::default()
                },
            },
        });

        assert_eq!(bs.to_string(),
            "directory is usable, fresh until 2022-01-17 12:00:00 UTC, and valid until 2022-01-17 14:00:00 UTC; next directory is fetching microdescriptors (5/40)"
        );

        const TOL: f32 = 0.00001;
        assert_float_eq!(bs.frac_at(t1 + hour / 2), 1.0, abs <= TOL);
        assert_float_eq!(
            bs.frac_at(t1 + hour * 3 + hour / 2),
            0.35 + 0.65 * 0.125,
            abs <= TOL
        );

        // Now try updating.

        // Case 1: we have a usable directory and the updated status isn't usable.
        let mut bs = bs;
        let dp3 = DirProgress::Validated {
            lifetime: lifetime2.clone(),
            usable_lifetime: lifetime2.clone(),
            n_mds: (10, 40),
            usable: false,
        };

        bs.update_progress(attempt2, dp3);
        assert!(matches!(
            bs.next().unwrap(),
            DirStatus {
                progress: DirProgress::Validated {
                    n_mds: (10, 40),
                    ..
                },
                ..
            }
        ));

        // Case 2: The new directory _is_ usable and newer.  It will replace the old one.
        let ds4 = DirStatus {
            progress: DirProgress::Validated {
                lifetime: lifetime2.clone(),
                usable_lifetime: lifetime2.clone(),
                n_mds: (20, 40),
                usable: true,
            },
            ..Default::default()
        };
        bs.update_progress(attempt2, ds4.progress);
        assert!(bs.next().is_none());
        assert_eq!(
            bs.current()
                .unwrap()
                .usable_lifetime()
                .unwrap()
                .valid_after(),
            lifetime2.valid_after()
        );

        // Case 3: The new directory is usable but older. Nothing will happen.
        bs.update_progress(attempt1, dp1);
        assert!(bs.next().as_ref().is_none());
        assert_ne!(
            bs.current()
                .unwrap()
                .usable_lifetime()
                .unwrap()
                .valid_after(),
            lifetime.valid_after()
        );

        // Case 4: starting with an unusable directory, we always replace.
        let mut bs = DirBootstrapStatus::default();
        assert!(!dp2.usable());
        assert!(bs.current().is_none());
        bs.update_progress(attempt2, dp2);
        assert!(bs.current().unwrap().usable_lifetime().is_some());
    }
}
