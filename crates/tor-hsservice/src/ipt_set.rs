//! IPT set - the principal API between the IPT manager and publisher

use std::ops::DerefMut;
use std::sync::Arc;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use futures::channel::mpsc;
use futures::StreamExt as _;

use derive_more::{Deref, DerefMut};

use crate::FatalError;
use crate::IptLocalId;

use tor_error::internal;

/// Set of introduction points to be advertised in a descriptor (if we are to publish)
///
/// If `Some`, the publisher will try to maintain a published descriptor,
/// of lifetime `lifetime`, listing `ipts`.
///
/// If `None`, the publisher will not try to publish.
/// (Already-published descriptors will not be deleted.)
///
/// These instructions ultimately come from
/// [`IptManager::compute_iptsetstatus_publish`](crate::ipt_mgr::IptManager::compute_iptsetstatus_publish).
pub(crate) type PublishIptSet = Option<IptSet>;

/// A set of introduction points for publication
///
/// This is shared between the manager and the publisher.
/// Each leaf field says who sets it.
#[derive(Debug)]
pub(crate) struct IptSet {
    /// The actual introduction points
    pub(crate) ipts: Vec<IptInSet>,

    /// When to make the descriptor expire
    ///
    /// Set by the manager and read by the publisher.
    pub(crate) lifetime: Duration,
}

/// Introduction point as specified to publisher by manager
///
/// Convenience type alias.
#[derive(Debug)]
pub(crate) struct IptInSet {
    /// Details of the introduction point
    ///
    /// Set by the manager and read by the publisher.
    pub(crate) ipt: Ipt,

    /// Local identifier for this introduction point
    ///
    /// Set and used by the manager, to correlate this data structure with the manager's.
    /// May also be read by the publisher.
    pub(crate) lid: IptLocalId,

    /// Time until which the manager ought we to try to maintain this ipt,
    /// even after we stop publishing it.
    ///
    /// This is a ceiling on:
    ///
    ///   * The last time we *finished* publishing the descriptor
    ///     (we can estimate this by taking the time we *started* to publish
    ///     plus our timeout on the publication attempt).
    ///
    ///   * Plus the `lifetime` that was used for publication.
    ///
    ///   * Plus the length of time between a client obtaining the descriptor
    ///     and its introduction request reaching us through the intro point
    ///     ([`IPT_PUBLISH_EXPIRY_SLOP`])
    ///
    /// If the descriptor has never been published, is `None`.
    ///
    /// This field is updated by the publisher, using
    /// [`note_publication_attempt`](IptSet::note_publication_attempt)
    /// and read by the manager.
    ///
    /// A separate copy of the information is stored by the manager,
    /// in `ipt_mgr::Ipt::last_descriptor_expiry_including_slop`.
    pub(crate) last_descriptor_expiry_including_slop: Option<Instant>,
}

/// Actual introduction point details as specified to publisher by manager
///
/// Convenience type alias.
pub(crate) type Ipt = tor_netdoc::doc::hsdesc::IntroPointDesc;

/// Descriptor expiry time slop
///
/// How long after our descriptor expired should we continue to maintain an old IPT?
/// This is an allowance for:
///
///   - Various RTTs and delays in clients setting up circuits
///     (we can't really measure this ourselves properly,
///     since what matters is the client's latency)
///
///   - Clock skew
//
// TODO HSS IPT_PUBLISH_EXPIRY_SLOP configure?
pub(crate) const IPT_PUBLISH_EXPIRY_SLOP: Duration = Duration::from_secs(300); // 5 minutes

/// Shared view of introduction points - IPT manager's view
///
/// This is the manager's end of a bidirectional "channel",
/// containing a shared `PublishIptSet`, i.e. an `Option<IptSet>`.
#[derive(Debug)]
pub(crate) struct IptsManagerView {
    /// Actual shared data
    shared: Shared,

    /// Notification sender
    ///
    /// We don't wrap the state in a postage::watch,
    /// because the publisher needs to be able to mutably borrow the data
    /// without re-notifying itself when it drops the guard.
    notify: mpsc::Sender<()>,
}

/// Shared view of introduction points - IPT publisher's view
///
/// This is the publishers's end of a bidirectional "channel",
/// containing a shared `PublishIptSet`, i.e. an `Option<IptSet>`.
pub(crate) struct IptsPublisherView {
    /// Actual shared data
    shared: Shared,

    /// Notification receiver
    notify: mpsc::Receiver<()>,
}

/// Core shared state
type Shared = Arc<Mutex<PublishIptSet>>;

/// Mutex guard that will notify when dropped
///
/// Returned by [`IptsManagerView::borrow_for_update`]
#[derive(Deref, DerefMut)]
struct NotifyingBorrow<'v> {
    /// Lock guard
    #[deref(forward)]
    #[deref_mut(forward)]
    guard: MutexGuard<'v, PublishIptSet>,

    /// To be notified on drop
    notify: &'v mut mpsc::Sender<()>,
}

/// Create a new shared state channel for the publication instructions
pub(crate) fn ipts_channel(initial_state: PublishIptSet) -> (IptsManagerView, IptsPublisherView) {
    let shared = Arc::new(Mutex::new(initial_state));
    // Zero buffer is right.  Docs for `mpsc::channel` say:
    //   each sender gets a guaranteed slot in the channel capacity,
    //   and on top of that there are buffer “first come, first serve” slots
    // We only have one sender and only ever want one outstanding,
    // since we can (and would like to) coalesce notifications.
    let (tx, rx) = mpsc::channel(0);
    (
        IptsManagerView {
            shared: shared.clone(),
            notify: tx,
        },
        IptsPublisherView { shared, notify: rx },
    )
}

/// Lock the shared state and obtain a lock guard
///
/// Does not do any notification.
fn lock_shared(shared: &Shared) -> MutexGuard<PublishIptSet> {
    // Propagating panics is fine since if either the manager or the publisher crashes,
    // the other one cannot survive.
    shared.lock().expect("IPT set shared state poisoned")
}

impl IptsManagerView {
    /// Arrange to be able to update the list of introduction points
    ///
    /// The manager may add new ipts, or delete old ones.
    ///
    /// The returned value is a lock guard.
    /// (It is not `Send` so cannot be held across await points.)
    /// The publisher will be notified when it is dropped.
    pub(crate) fn borrow_for_update(&mut self) -> impl DerefMut<Target = PublishIptSet> + '_ {
        let guard = lock_shared(&self.shared);
        NotifyingBorrow {
            guard,
            notify: &mut self.notify,
        }
    }
}

impl Drop for NotifyingBorrow<'_> {
    fn drop(&mut self) {
        // Channel full?  Well, then the receiver is indeed going to wake up, so fine
        // Channel disconnected?  The publisher has crashed or terminated,
        // but we are not in a position to fail and shut down the establisher.
        // If our HS is shutting down, the manager will be shut down by other means.
        let _: Result<(), mpsc::TrySendError<_>> = self.notify.try_send(());

        // Now the fields will be dropped, includeing `guard`.
        // I.e. the mutex gets unlocked.  This means we notify the publisher
        // (which might make it wake up on another thread) just *before*
        // we release the lock, rather than just after.
        // This is slightly suboptimal but doesn't matter here.
        // To do better, we'd need to make the guard into an Option.
    }
}

impl IptsPublisherView {
    /// Wait until the IPT set has changed (or may have)
    ///
    /// After this returns, to find out what the new IPT set is,
    /// the publisher calls `borrow_for_publish`.
    ///
    /// Will complete immediately if the IPT set has
    /// changed since the last call to `await_update`.
    ///
    /// Returns:
    ///  * `Some(Ok(())` if the IPT set was (or may have been) updated
    ///  * `None` if the manager is shutting down and the publisher should shut down too
    ///  * `Some(Err(..))` if a fatal error occurred
    pub(crate) async fn await_update(&mut self) -> Option<Result<(), crate::FatalError>> {
        // Cancellation safety:
        //
        // We're using mpsc::Receiver's implementation of Stream, via StreamExt.
        // Stream::next() must be cancellation safe or it would be lossy everywhere.
        // So it is OK to create the future from next, here, and possibly discard it
        // before it becomes Ready.
        let () = self.notify.next().await?;
        Some(Ok(()))
    }

    /// Look at the list of introduction points to publish
    ///
    /// Whenever a a publication attempt is started,
    /// [`note_publication_attempt`](IptSet::note_publication_attempt)
    /// must be called.
    ///
    /// The returned value is a lock guard.
    /// (It is not `Send` so cannot be held across await points.)
    pub(crate) fn borrow_for_publish(&self) -> impl DerefMut<Target = PublishIptSet> + '_ {
        lock_shared(&self.shared)
    }
}

impl IptSet {
    /// Update all the `last_descriptor_expiry_including_slop` for a publication attempt
    ///
    /// Called by the publisher when it starts a publication attempt.
    ///
    /// When calling this, the publisher promises that the publication attempt
    /// will either complete, or be abandoned, before `worst_case_end`.
    pub(crate) fn note_publication_attempt(
        &mut self,
        worst_case_end: Instant,
    ) -> Result<(), FatalError> {
        let new_value = (|| {
            worst_case_end
                .checked_add(self.lifetime)?
                .checked_add(IPT_PUBLISH_EXPIRY_SLOP)
        })()
        .ok_or_else(
            // Clock overflow on the monotonic clock.  Everything is terrible.
            // We will have no idea when we can stop publishing the descriptor!
            // I guess we'll return an error and cause the publisher to bail out?
            // An ErrorKind of ClockSkew is wrong, since this is a purely local problem,
            // and should be impossible if we properly checked our parameters.
            || internal!("monotonic clock overflow"),
        )?;
        for ipt in &mut self.ipts {
            ipt.last_descriptor_expiry_including_slop = chain!(
                //
                ipt.last_descriptor_expiry_including_slop,
                [new_value],
            )
            .max();
        }
        Ok(())
    }
}
