//! IPT set - the principal API between the IPT manager and publisher

use std::ops::DerefMut;
use std::time::{Duration, Instant};

use void::Void;

use crate::IptLocalId;

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
    /// [`note_publication_attempt_start`](IptSet::note_publication_attempt_start)
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
    /// TODO HSS
    todo: Void,
}

/// Shared view of introduction points - IPT publisher's view
///
/// This is the publishers's end of a bidirectional "channel",
/// containing a shared `PublishIptSet`, i.e. an `Option<IptSet>`.
pub(crate) struct IptsPublisherView {
    /// TODO HSS
    todo: Void,
}

/// Create a new shared state channel for the publication instructions
pub(crate) fn ipts_channel(initial_state: PublishIptSet) -> (IptsManagerView, IptsPublisherView) {
    drop(initial_state); // clippy::needless_pass_by_value
    todo!()
}

impl IptsManagerView {
    /// Arrange to be able to update the list of introduction points
    ///
    /// The manager may add new ipts, or delete old ones.
    ///
    /// The returned value is a lock guard.
    /// (It is not `Send` so cannot be held across await points.)
    /// The publisher will be notified when it is dropped.
    #[allow(unreachable_code)] // TODO HSS remove
    pub(crate) fn borrow_for_update(&mut self) -> impl DerefMut<Target = PublishIptSet> + '_ {
        // assist type inference with bogus type
        std::convert::identity::<Box<PublishIptSet>>(void::unreachable(self.todo))
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
        void::unreachable(self.todo)
    }

    /// Look at the list of introduction points to publish
    ///
    /// Whenever a a publication attempt is started,
    /// [`note_publication_attempt_start`](IptSet::note_publication_attempt_start)
    /// must be called.
    ///
    /// The returned value is a lock guard.
    /// (It is not `Send` so cannot be held across await points.)
    #[allow(unreachable_code)] // TODO HSS remove
    pub(crate) fn borrow_for_publish(&self) -> impl DerefMut<Target = PublishIptSet> + '_ {
        // assist type inference with bogus type
        std::convert::identity::<Box<PublishIptSet>>(void::unreachable(self.todo))
    }
}

impl IptSet {
    /// Update all the `last_descriptor_expiry_including_slop` for a publication attempt
    ///
    /// Called by the publisher when it starts a publication attempt.
    ///
    /// When calling this, the publisher promises that the publication attempt
    /// will either complete, or be abandoned, before `worst_case_end`.
    pub(crate) fn note_publication_attempt_start(&mut self, worst_case_end: Instant) {
        todo!()
    }
}
