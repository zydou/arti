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
    /// The status for the current directory that we're using right now.
    pub(crate) current: DirStatus,
    /// The status for a directory that we're downloading to replace the current
    /// directory.
    ///
    /// This is "None" if we haven't started fetching the next consensus yet.
    pub(crate) next: Option<DirStatus>,
}

/// The status for a single directory.
#[derive(Clone, Debug, Default)]
pub struct DirStatus(DirStatusInner);

/// The contents of a single DirStatus.
///
/// This is a separate type so that we don't make the variants public.
#[derive(Clone, Debug, Educe)]
#[educe(Default)]
pub(crate) enum DirStatusInner {
    /// We don't have any information yet.
    #[educe(Default)]
    NoConsensus {
        /// If present, we are fetching a consensus whose valid-after time
        /// postdates this time.
        after: Option<SystemTime>,
    },
    /// We've downloaded a consensus, but we haven't validated it yet.
    FetchingCerts {
        /// The lifetime of the consensus.
        lifetime: netstatus::Lifetime,
        /// A fraction (in (numerator,denominator) format) of the certificates
        /// we have for this consensus.
        n_certs: (u16, u16),
    },
    /// We've validated a consensus and we're fetching (or have fetched) its
    /// microdescriptors.
    Validated {
        /// The lifetime of the consensus.
        lifetime: netstatus::Lifetime,
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

impl From<DirStatusInner> for DirStatus {
    fn from(inner: DirStatusInner) -> DirStatus {
        DirStatus(inner)
    }
}

impl fmt::Display for DirStatus {
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

        match &self.0 {
            DirStatusInner::NoConsensus { .. } => write!(f, "fetching a consensus"),
            DirStatusInner::FetchingCerts { n_certs, .. } => write!(
                f,
                "fetching authority certificates ({}/{})",
                n_certs.0, n_certs.1
            ),
            DirStatusInner::Validated {
                usable: false,
                n_mds,
                ..
            } => write!(f, "fetching microdescriptors ({}/{})", n_mds.0, n_mds.1),
            DirStatusInner::Validated {
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
        self.current.usable() && self.current.valid_at(now)
    }

    /// Update this status by replacing its current status (or its next status)
    /// with `new_status`, as appropriate.
    pub(crate) fn update(&mut self, new_status: DirStatus) {
        if new_status.usable() {
            // This is a usable directory, but it might be a stale one still
            // getting updated.  Make sure that it is at least as new as the one
            // in `current` before we set `current`.
            if new_status.at_least_as_new_as(&self.current) {
                // This one will be `current`. Should we clear `next`? Only if
                // this one is at least as recent as `next` too.
                if let Some(ref next) = self.next {
                    if new_status.at_least_as_new_as(next) {
                        self.next = None;
                    }
                }
                self.current = new_status;
            }
        } else if !self.current.usable() {
            // Not a usable directory, but we don't _have_ a usable directory. This is therefore current.
            self.current = new_status;
        } else {
            // This is _not_ a usable directory, so it can only be `next`.
            self.next = Some(new_status);
        }
    }
}

impl DirStatus {
    /// Return the consensus lifetime for this directory, if we have one.
    fn lifetime(&self) -> Option<&netstatus::Lifetime> {
        match &self.0 {
            DirStatusInner::NoConsensus { .. } => None,
            DirStatusInner::FetchingCerts { lifetime, .. } => Some(lifetime),
            DirStatusInner::Validated { lifetime, .. } => Some(lifetime),
        }
    }

    /// Return true if the directory is valid at the given time.
    fn valid_at(&self, when: SystemTime) -> bool {
        if let Some(lifetime) = self.lifetime() {
            lifetime.valid_after() <= when && when < lifetime.valid_until()
        } else {
            false
        }
    }

    /// As frac_at, but return None if this consensus is not valid at the given time.
    fn frac_at(&self, when: SystemTime) -> Option<f32> {
        if self.valid_at(when) {
            Some(self.frac())
        } else {
            None
        }
    }

    /// Return true if this status indicates a usable directory.
    fn usable(&self) -> bool {
        matches!(self.0, DirStatusInner::Validated { usable: true, .. })
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
        match &self.0 {
            DirStatusInner::NoConsensus { .. } => 0.0,
            DirStatusInner::FetchingCerts { n_certs, .. } => {
                0.25 + f32::from(n_certs.0) / f32::from(n_certs.1) * 0.10
            }
            DirStatusInner::Validated {
                usable: false,
                n_mds,
                ..
            } => 0.35 + (n_mds.0 as f32) / (n_mds.1 as f32) * 0.65,
            DirStatusInner::Validated { usable: true, .. } => 1.0,
        }
    }

    /// Return true if the consensus in this DirStatus (if any) is at least as
    /// new as the one in `other`.
    fn at_least_as_new_as(&self, other: &DirStatus) -> bool {
        /// return a candidate "valid after" time for a DirStatus, for comparison purposes.
        fn start_time(st: &DirStatus) -> Option<SystemTime> {
            match &st.0 {
                DirStatusInner::NoConsensus { after: Some(t) } => {
                    Some(*t + std::time::Duration::new(1, 0)) // Make sure this sorts _after_ t.
                }
                DirStatusInner::FetchingCerts { lifetime, .. } => Some(lifetime.valid_after()),
                DirStatusInner::Validated { lifetime, .. } => Some(lifetime.valid_after()),
                _ => None,
            }
        }

        match (start_time(self), start_time(other)) {
            // If both have a lifetime, compare their valid_after times.
            (Some(l1), Some(l2)) => l1 >= l2,
            // Any consensus is newer than none.
            (Some(_), None) => true,
            // No consensus is never newer than anything.
            (None, _) => false,
        }
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
        #[allow(clippy::disallowed_methods)]
        let now = SystemTime::now();
        let hour = Duration::new(3600, 0);

        let nothing = DirStatus(DirStatusInner::NoConsensus { after: None });
        let unval = DirStatus(DirStatusInner::FetchingCerts {
            lifetime: netstatus::Lifetime::new(now, now + hour, now + hour * 2).unwrap(),
            n_certs: (3, 5),
        });
        let with_c = DirStatus(DirStatusInner::Validated {
            lifetime: netstatus::Lifetime::new(now + hour, now + hour * 2, now + hour * 3).unwrap(),
            n_mds: (30, 40),
            usable: false,
        });

        // lifetime()
        assert!(nothing.lifetime().is_none());
        assert_eq!(unval.lifetime().unwrap().valid_after(), now);
        assert_eq!(with_c.lifetime().unwrap().valid_until(), now + hour * 3);

        // at_least_as_new_as()
        assert!(!nothing.at_least_as_new_as(&nothing));
        assert!(unval.at_least_as_new_as(&nothing));
        assert!(unval.at_least_as_new_as(&unval));
        assert!(!unval.at_least_as_new_as(&with_c));
        assert!(with_c.at_least_as_new_as(&unval));
        assert!(with_c.at_least_as_new_as(&with_c));

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

        let ds = DirStatus(DirStatusInner::NoConsensus { after: None });
        assert_eq!(ds.to_string(), "fetching a consensus");

        let ds = DirStatus(DirStatusInner::FetchingCerts {
            lifetime: lifetime.clone(),
            n_certs: (3, 5),
        });
        assert_eq!(ds.to_string(), "fetching authority certificates (3/5)");

        let ds = DirStatus(DirStatusInner::Validated {
            lifetime: lifetime.clone(),
            n_mds: (30, 40),
            usable: false,
        });
        assert_eq!(ds.to_string(), "fetching microdescriptors (30/40)");

        let ds = DirStatus(DirStatusInner::Validated {
            lifetime,
            n_mds: (30, 40),
            usable: true,
        });
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

        let ds1: DirStatus = DirStatusInner::Validated {
            lifetime: lifetime.clone(),
            n_mds: (3, 40),
            usable: true,
        }
        .into();
        let ds2: DirStatus = DirStatusInner::Validated {
            lifetime: lifetime2.clone(),
            n_mds: (5, 40),
            usable: false,
        }
        .into();

        let bs = DirBootstrapStatus {
            current: ds1.clone(),
            next: Some(ds2.clone()),
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
        let ds3 = DirStatus(DirStatusInner::Validated {
            lifetime: lifetime2.clone(),
            n_mds: (10, 40),
            usable: false,
        });
        bs.update(ds3);
        assert!(matches!(
            bs.next.as_ref().unwrap().0,
            DirStatusInner::Validated {
                n_mds: (10, 40),
                ..
            }
        ));

        // Case 2: The new directory _is_ usable and newer.  It will replace the old one.
        let ds4 = DirStatus(DirStatusInner::Validated {
            lifetime: lifetime2.clone(),
            n_mds: (20, 40),
            usable: true,
        });
        bs.update(ds4);
        assert!(bs.next.as_ref().is_none());
        assert_eq!(
            bs.current.lifetime().unwrap().valid_after(),
            lifetime2.valid_after()
        );

        // Case 3: The new directory is usable but older. Nothing will happen.
        bs.update(ds1);
        assert!(bs.next.as_ref().is_none());
        assert_ne!(
            bs.current.lifetime().unwrap().valid_after(),
            lifetime.valid_after()
        );

        // Case 4: starting with an unusable directory, we always replace.
        let mut bs = DirBootstrapStatus::default();
        assert!(!ds2.usable());
        assert!(bs.current.lifetime().is_none());
        bs.update(ds2);
        assert!(bs.current.lifetime().is_some());
    }
}
