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
use time::OffsetDateTime;
use tor_basic_utils::skip_fmt;
use tor_netdir::DirEvent;
use tor_netdoc::doc::netstatus;

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

impl FlagEvent for DirEvent {
    const MAXIMUM: u16 = 1;
    fn to_index(self) -> u16 {
        match self {
            DirEvent::NewConsensus => 0,
            DirEvent::NewDescriptors => 1,
            // HACK(eta): This is an unfortunate consequence of marking DirEvent #[non_exhaustive].
            _ => panic!("DirEvent updated without updating its FlagEvent impl"),
        }
    }
    fn from_index(flag: u16) -> Option<Self> {
        match flag {
            0 => Some(DirEvent::NewConsensus),
            1 => Some(DirEvent::NewDescriptors),
            _ => None,
        }
    }
}

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
#[derive(Clone, Debug, Default)]
pub struct DirBootstrapStatus {
    /// Identifier for the current attempt (if any).
    current_id: Option<AttemptId>,
    /// The status for the current directory that we're using right now.
    pub(crate) current: DirStatus,

    /// Identifier for the next attempt (if any).
    next_id: Option<AttemptId>,
    /// The status for a directory that we're downloading to replace the current
    /// directory.
    ///
    /// This is "None" if we haven't started fetching the next consensus yet.
    pub(crate) next: Option<DirStatus>,
}

/// The status for a single directory.
#[derive(Clone, Debug, Default, derive_more::Display)]
#[display(fmt = "{progress}")]
pub struct DirStatus {
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
        write!(f, "directory is {}", self.current)?;
        if let Some(ref next) = self.next {
            write!(f, "; next directory is {}", next)?;
        }
        Ok(())
    }
}

impl DirBootstrapStatus {
    /// Return the fraction of completion for directory download, in a form
    /// suitable for a progress bar at some particular time.
    ///
    /// This value is not monotonic, and can go down as one directory is
    /// replaced with another.
    ///
    /// Callers _should not_ depend on the specific meaning of any particular
    /// fraction; we may change these fractions in the future.
    pub fn frac_at(&self, when: SystemTime) -> f32 {
        self.current
            .frac_at(when)
            .or_else(|| self.next.as_ref().and_then(|next| next.frac_at(when)))
            .unwrap_or(0.0)
    }

    /// Return true if this status indicates that we have a current usable
    /// directory.
    pub fn usable_at(&self, now: SystemTime) -> bool {
        self.current.progress.usable() && self.current.okay_to_use_at(now)
    }

    /// Return the appropriate DirStatus for `AttemptId`, constructing it if
    /// necessary.
    ///
    /// Return None if all relevant attempts are more recent than this Id.
    fn mut_status_for(&mut self, attempt_id: AttemptId) -> Option<&mut DirStatus> {
        match (self.current_id, self.next_id, attempt_id) {
            (None, _, _) => {
                self.current_id = Some(attempt_id);
                self.current = DirStatus::default();
                Some(&mut self.current)
            }
            (Some(cur), _, a) if a < cur => None,
            (Some(cur), _, a) if a == cur => Some(&mut self.current),
            (_, Some(next), a) if a < next => None,
            (_, Some(next), a) if a == next => self.next.as_mut(),
            (_, _, _) => {
                self.next_id = Some(attempt_id);
                self.next = Some(DirStatus::default());
                self.next.as_mut()
            }
        }
    }

    /// If the "next" status is usable, replace the current status with it.
    fn advance_status(&mut self) {
        if self.next.as_ref().map(|st| st.progress.usable()) == Some(true) {
            self.current_id = self.next_id;
            self.current = self
                .next
                .take()
                .expect("The next status was there a moment ago.");
            self.next_id = None;
            self.next = None;
        }
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

#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod test {
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

        let bs = DirBootstrapStatus {
            current_id: Some(attempt1),
            current: DirStatus {
                progress: dp1.clone(),
                ..Default::default()
            },
            next_id: Some(attempt2),
            next: Some(DirStatus {
                progress: dp2.clone(),
                ..Default::default()
            }),
        };

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
            bs.next.as_ref().unwrap().progress,
            DirProgress::Validated {
                n_mds: (10, 40),
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
        assert!(bs.next.as_ref().is_none());
        assert_eq!(
            bs.current.usable_lifetime().unwrap().valid_after(),
            lifetime2.valid_after()
        );

        // Case 3: The new directory is usable but older. Nothing will happen.
        bs.update_progress(attempt1, dp1);
        assert!(bs.next.as_ref().is_none());
        assert_ne!(
            bs.current.usable_lifetime().unwrap().valid_after(),
            lifetime.valid_after()
        );

        // Case 4: starting with an unusable directory, we always replace.
        let mut bs = DirBootstrapStatus::default();
        assert!(!dp2.usable());
        assert!(bs.current.usable_lifetime().is_none());
        bs.update_progress(attempt2, dp2);
        assert!(bs.current.usable_lifetime().is_some());
    }
}
