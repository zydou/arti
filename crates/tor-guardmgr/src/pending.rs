//! Help the guard manager (and other crates) deal with "pending
//! information".
//!
//! There are two kinds of pending information to deal with.  First,
//! every guard that we hand out needs to be marked as succeeded or
//! failed. Second, if a guard is given out on an exploratory basis,
//! then the circuit manager can't know whether to use a circuit built
//! through that guard until the guard manager tells it.  This is
//! handled via [`GuardUsable`].
use crate::{daemon, FirstHopId};

use educe::Educe;
use futures::{channel::mpsc::UnboundedSender, Future};
use oneshot_fused_workaround as oneshot;
use pin_project::pin_project;
use std::fmt::Debug;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Instant;
use tor_proto::ClockSkew;

use tor_basic_utils::skip_fmt;

/// A future used to see if we have "permission" to use a guard.
///
/// For efficiency, the [`GuardMgr`](crate::GuardMgr) implementation sometimes gives
/// out lower-priority guards when it is not certain whether
/// higher-priority guards are running.  After having built a circuit
/// with such a guard, the caller must wait on this future to see whether
/// the circuit is usable or not.
///
/// The circuit may be usable immediately (as happens if the guard was
/// of sufficient priority, or if all higher-priority guards are
/// _known_ to be down).  It may eventually _become_ usable (if all of
/// the higher-priority guards are _discovered_ to be down).  Or it may
/// eventually become unusable (if we find a higher-priority guard
/// that works).
///
/// Any [`GuardRestriction`](crate::GuardRestriction)s that were used to select this guard
/// may influence whether it is usable: if higher priority guards were
/// ignored because of a restriction, then we might use a guard that we
/// otherwise wouldn't.
#[pin_project]
pub struct GuardUsable {
    /// If present, then this is a future to wait on to see whether the
    /// guard is usable.
    ///
    /// If absent, then the guard is ready immediately and no waiting
    /// is needed.
    //
    // TODO: use a type that makes the case here more distinguishable.
    #[pin]
    u: Option<oneshot::Receiver<bool>>,
}

impl Future for GuardUsable {
    type Output = Result<bool, oneshot::Canceled>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project().u.as_pin_mut() {
            None => Poll::Ready(Ok(true)),
            Some(u) => u.poll(cx),
        }
    }
}

impl GuardUsable {
    /// Create a new GuardUsable for a primary guard or a fallback directory.
    ///
    /// (Circuits built through these are usable immediately, independently of
    /// whether other guards succeed or fail, so we don't need a way to report
    /// whether such guards/fallbacks are usable.)
    pub(crate) fn new_usable_immediately() -> Self {
        GuardUsable { u: None }
    }

    /// Create a new GuardUsable for a guard with undecided usability status.
    ///
    /// (We use this constructor when a circuit is built through a non-primary
    /// guard, and there are other guards _we would prefer to use, if they turn
    /// out to work_.  If such a circuit succeeds, the caller must still use
    /// this `GuardUsable` to wait until the `GuardMgr` sees whether the
    /// more-preferred guards have succeeded or failed.)
    pub(crate) fn new_uncertain() -> (Self, oneshot::Sender<bool>) {
        let (snd, rcv) = oneshot::channel();
        (GuardUsable { u: Some(rcv) }, snd)
    }
}

/// A message that we can get back from the circuit manager who asked
/// for a guard.
#[derive(Copy, Clone, Debug)]
#[non_exhaustive]
pub enum GuardStatus {
    /// The guard was used successfully.
    Success,
    /// The guard was used unsuccessfully.
    Failure,
    /// The circuit failed in a way that we cannot prove is the guard's
    /// fault, but which _might_ be the guard's fault.
    Indeterminate,
    /// Our attempt to use the guard didn't get far enough to be sure
    /// whether the guard is usable or not.
    AttemptAbandoned,
}

/// An object used to tell the [`GuardMgr`](crate::GuardMgr) about the result of
/// trying to build a circuit through a guard.
///
/// The `GuardMgr` needs to know about these statuses, so that it can tell
/// whether the guard is running or not.
#[must_use = "You need to report the status of any guard that you asked for"]
#[derive(Educe)]
#[educe(Debug)]
pub struct GuardMonitor {
    /// The Id that we're going to report about.
    id: RequestId,
    /// The status that we will report if this monitor is dropped now.
    pending_status: GuardStatus,
    /// If set, we change `Indeterminate` to `AttemptAbandoned` before
    /// reporting it to the guard manager.
    ///
    /// We do this when a failure to finish the circuit doesn't reflect
    /// badly against the guard at all: typically, because the circuit's
    /// path is not random.
    ignore_indeterminate: bool,
    /// If set, we will report the given clock skew as having been observed and
    /// authenticated from this guard or fallback.
    pending_skew: Option<ClockSkew>,
    /// A sender that needs to get told when the attempt to use the guard is
    /// finished or abandoned.
    ///
    /// TODO: This doesn't really need to be an Option, but we use None
    /// here to indicate that we've already used the sender, and it can't
    /// be used again.
    #[educe(Debug(method = "skip_fmt"))]
    snd: Option<UnboundedSender<daemon::Msg>>,
}

impl GuardMonitor {
    /// Create a new GuardMonitor object.
    pub(crate) fn new(id: RequestId, snd: UnboundedSender<daemon::Msg>) -> Self {
        GuardMonitor {
            id,
            pending_status: GuardStatus::AttemptAbandoned,
            ignore_indeterminate: false,
            pending_skew: None,
            snd: Some(snd),
        }
    }

    /// Report that a circuit was successfully built in a way that
    /// indicates that the guard is working.
    ///
    /// Note that this doesn't necessarily mean that the circuit
    /// succeeded. For example, we might decide that extending to a
    /// second hop means that a guard is usable, even if the circuit
    /// stalled at the third hop.
    pub fn succeeded(self) {
        self.report(GuardStatus::Success);
    }

    /// Report that the circuit could not be built successfully, in
    /// a way that indicates that the guard isn't working.
    ///
    /// (This either be because of a network failure, a timeout, or
    /// something else.)
    pub fn failed(self) {
        self.report(GuardStatus::Failure);
    }

    /// Report that we did not try to build a circuit using the guard,
    /// or that we can't tell whether the guard is working.
    ///
    /// Dropping a `GuardMonitor` is without calling `succeeded` or
    /// `failed` or `pending_status` is equivalent to calling this
    /// function.
    pub fn attempt_abandoned(self) {
        self.report(GuardStatus::AttemptAbandoned);
    }

    /// Configure this monitor so that, if it is dropped before use,
    /// it sends the status `status`.
    pub fn pending_status(&mut self, status: GuardStatus) {
        self.pending_status = status;
    }

    /// Set the given clock skew value to be reported to the guard manager.
    ///
    /// Clock skew can be reported on success or failure, but it should only be
    /// reported if the first hop is actually authenticated.
    pub fn skew(&mut self, skew: ClockSkew) {
        self.pending_skew = Some(skew);
    }

    /// Return the current pending status and "ignore indeterminate"
    /// status for this guard monitor.
    #[cfg(feature = "testing")]
    pub fn inspect_pending_status(&self) -> (GuardStatus, bool) {
        (self.pending_status, self.ignore_indeterminate)
    }

    /// Configure this monitor to ignore any indeterminate status
    /// values, and treat them as abandoned attempts.
    ///
    /// We should use this whenever the path being built with this guard
    /// is not randomly generated.
    pub fn ignore_indeterminate_status(&mut self) {
        self.ignore_indeterminate = true;
    }

    /// Report a message for this guard.
    pub fn report(mut self, msg: GuardStatus) {
        self.report_impl(msg);
    }

    /// As [`GuardMonitor::report`], but take a &mut reference.
    fn report_impl(&mut self, msg: GuardStatus) {
        let msg = match (msg, self.ignore_indeterminate) {
            (GuardStatus::Indeterminate, true) => GuardStatus::AttemptAbandoned,
            (m, _) => m,
        };
        let _ignore = self
            .snd
            .take()
            .expect("GuardMonitor initialized with no sender")
            .unbounded_send(daemon::Msg::Status(self.id, msg, self.pending_skew));
    }

    /// Report the pending message for his guard, whatever it is.
    pub fn commit(self) {
        let status = self.pending_status;
        self.report(status);
    }
}

impl Drop for GuardMonitor {
    fn drop(&mut self) {
        if self.snd.is_some() {
            self.report_impl(self.pending_status);
        }
    }
}

/// Internal unique identifier used to tell PendingRequest objects apart.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub(crate) struct RequestId {
    /// The value of the identifier.
    id: u64,
}

impl RequestId {
    /// Create a new, never-before-used RequestId.
    ///
    /// # Panics
    ///
    /// Panics if we have somehow exhausted a 64-bit space of request IDs.
    pub(crate) fn next() -> RequestId {
        /// The next identifier in sequence we'll give out.
        static NEXT_VAL: AtomicU64 = AtomicU64::new(1);
        let id = NEXT_VAL.fetch_add(1, Ordering::Relaxed);
        assert!(id != 0, "Exhausted guard request Id space.");
        RequestId { id }
    }
}

/// Pending information about a guard that we handed out in response to
/// some request, but where we have not yet reported whether the guard
/// is usable.
///
/// We create one of these whenever we give out a guard with an
/// uncertain usability status via [`GuardUsable::new_uncertain`].
#[derive(Debug)]
pub(crate) struct PendingRequest {
    /// Identity of the guard that we gave out.
    guard_id: FirstHopId,
    /// The usage for which this guard was requested.
    ///
    /// We need this information because, if we find that a better guard
    /// than this one might be usable, we should only give it precedence
    /// if that guard is also allowable _for this usage_.
    usage: crate::GuardUsage,
    /// A oneshot channel used to tell the circuit manager that a circuit
    /// built through this guard can be used.
    ///
    /// (This is an option so that we can safely make reply() once-only.
    /// Otherwise we run into lifetime issues elsewhere.)
    usable: Option<oneshot::Sender<bool>>,
    /// The time at which the circuit manager told us that this guard was
    /// successful.
    waiting_since: Option<Instant>,
    /// If true, then the network has been down for a long time when we
    /// launched this request.
    ///
    /// If this request succeeds, it probably means that the net has
    /// come back up.
    net_has_been_down: bool,
}

impl PendingRequest {
    /// Create a new PendingRequest.
    pub(crate) fn new(
        guard_id: FirstHopId,
        usage: crate::GuardUsage,
        usable: Option<oneshot::Sender<bool>>,
        net_has_been_down: bool,
    ) -> Self {
        PendingRequest {
            guard_id,
            usage,
            usable,
            waiting_since: None,
            net_has_been_down,
        }
    }

    /// Return the Id of the guard we gave out.
    pub(crate) fn guard_id(&self) -> &FirstHopId {
        &self.guard_id
    }

    /// Return the usage for which we gave out the guard.
    pub(crate) fn usage(&self) -> &crate::GuardUsage {
        &self.usage
    }

    /// Return the time (if any) when we were told that the guard
    /// was successful.
    pub(crate) fn waiting_since(&self) -> Option<Instant> {
        self.waiting_since
    }

    /// Return true if the network had been down for a long time when
    /// this guard was handed out.
    pub(crate) fn net_has_been_down(&self) -> bool {
        self.net_has_been_down
    }

    /// Tell the circuit manager that the guard is usable (or unusable),
    /// depending on the argument.
    ///
    /// Does nothing if reply() has already been called.
    pub(crate) fn reply(&mut self, usable: bool) {
        if let Some(sender) = self.usable.take() {
            // If this gives us an error, then the circuit manager doesn't
            // care about this circuit any more.
            let _ignore = sender.send(usable);
        }
    }

    /// Mark this request as "waiting" since the time `now`.
    ///
    /// This function should only be called once per request.
    pub(crate) fn mark_waiting(&mut self, now: Instant) {
        debug_assert!(self.waiting_since.is_none());
        self.waiting_since = Some(now);
    }
}
