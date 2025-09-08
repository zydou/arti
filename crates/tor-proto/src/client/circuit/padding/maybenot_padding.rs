//! A `maybenot`-specific backend for padding.

mod backend;

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use bitvec::BitArr;
use maybenot::MachineId;
use smallvec::SmallVec;
use tor_memquota::memory_cost_structural_copy;
use tor_rtcompat::{DynTimeProvider, SleepProvider};

use crate::HopNum;
use backend::PaddingBackend;

/// The type of Instant that we'll use for our padding machines.
///
/// We use a separate type alias here in case we want to move to coarsetime.
type Instant = std::time::Instant;

/// The type of Duration that we'll use for our padding machines.
///
/// We use a separate type alias here in case we want to move to coarsetime.
type Duration = std::time::Duration;

/// A type we use to generate a set of [`PaddingEvent`].
///
/// This is a separate type so we can tune it and make it into a smallvec if needed.
type PaddingEventVec = Vec<PaddingEvent>;

/// A type we use to generate a set of [`PaddingEvent`].
///
/// This is a separate type so we can tune it and make it into a smallvec if needed.
type PerHopPaddingEventVec = Vec<PerHopPaddingEvent>;

/// An instruction from the padding machine to the circuit.
///
/// These are returned from the [`PaddingEventStream`].
///
/// When the `circ-padding` feature is disabled, these won't actually be constructed.
#[derive(Clone, Copy, Debug)]
pub(crate) enum PaddingEvent {
    /// An instruction to send padding.
    SendPadding(SendPadding),
    /// An instruction to start blocking outbound traffic,
    /// or change the hop at which traffic is blocked.
    StartBlocking(StartBlocking),
    /// An instruction to stop all blocking.
    StopBlocking,
}

/// An instruction from a single padding hop.
///
/// This will be turned into a [`PaddingEvent`] before it's given
/// to the circuit reactor.
#[derive(Clone, Copy, Debug)]
enum PerHopPaddingEvent {
    /// An instruction to send padding.
    SendPadding {
        /// The machine that told us to send the padding.
        ///
        /// (We need to use this when we report that we sent the padding.)
        machine: MachineId,
        /// Whether the padding can be replaced with regular data.
        replace: Replace,
        /// Whether the padding can bypass a bypassable block.
        bypass: Bypass,
    },
    /// An instruction to start blocking traffic..
    StartBlocking {
        /// Whether this blocking instance may be bypassed by padding with
        /// [`Bypass::BypassBlocking`].
        ///
        /// (Note that this is _not_ a `Bypass`, since that enum notes whether
        /// or not a _padding_ cell can bypass blocking)
        is_bypassable: bool,
    },
    /// An instruction to stop blocking.
    StopBlocking,
}

/// Whether a given piece of padding can be replaced with queued data.
///
/// This is an enum to avoid confusing it with `Bypass`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Replace {
    /// The padding can be replaced
    /// either by packaging data in a regular data cell,
    /// or with data currently queued but not yet sent.
    Replaceable,
    /// The padding must be queued; it can't be replaced with data.
    NotReplaceable,
}

impl Replace {
    /// Construct a [`Replace`] from a bool.
    fn from_bool(replace: bool) -> Self {
        match replace {
            true => Replace::Replaceable,
            false => Replace::NotReplaceable,
        }
    }
}

/// Whether a piece of padding can bypass a bypassable case of blocking.
///
/// This is an enum to avoid confusing it with `Release`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Bypass {
    /// This padding may bypass the block, if the block is bypassable.
    ///
    /// Note that this case has complicated interactions with `Replace`; see the
    /// `maybenot` documentation.
    BypassBlocking,
    /// The padding may not bypass the block.
    DoNotBypass,
}

/// Information about a queued cell that we need to feed back into the padding
/// subsystem.
#[derive(Clone, Copy, Debug)]
pub(crate) struct QueuedCellPaddingInfo {
    /// The hop that will receive this cell.
    target_hop: HopNum,
}
memory_cost_structural_copy!(QueuedCellPaddingInfo);

impl Bypass {
    /// Construct a [`Bypass`] from a bool.
    fn from_bool(replace: bool) -> Self {
        match replace {
            true => Bypass::BypassBlocking,
            false => Bypass::DoNotBypass,
        }
    }
}

/// An indication that we should send a padding cell.
///
/// Don't drop this: instead, once the cell is queued,
/// pass this `SendPadding` object to the relevant [`PaddingController`]
/// to report that the particular piece of padding has been queued.
#[derive(Clone, Debug, Copy)]
pub(crate) struct SendPadding {
    /// The machine within a framework that told us to send the padding.
    ///
    /// We store this so we can tell the framework which machine's padding we sent.
    machine: maybenot::MachineId,

    /// The hop to which we need to send the padding.
    pub(crate) hop: HopNum,

    /// Whether this padding can be replaced by regular data.
    pub(crate) replace: Replace,

    /// Whether this padding cell should bypass any current blocking.
    pub(crate) bypass: Bypass,
}

impl SendPadding {
    /// Create a new SendPadding based on instructions from Maybenot.
    fn new(machine: maybenot::MachineId, hop: HopNum, replace: Replace, bypass: Bypass) -> Self {
        Self {
            machine,
            hop,
            replace,
            bypass,
        }
    }

    /// Convert this SendPadding into a TriggerEvent for Maybenot,
    /// to indicate that the padding was sent.
    fn into_sent_event(self) -> maybenot::TriggerEvent {
        maybenot::TriggerEvent::PaddingSent {
            machine: self.machine,
        }
    }

    /// If true, we are allowed to replace this padding cell
    /// with a normal non-padding cell.
    ///
    /// (If we do, we should call [`PaddingController::queued_data_as_padding`])
    pub(crate) fn may_replace_with_data(&self) -> Replace {
        self.replace
    }

    /// Return whether this padding cell is allowed to bypass any current blocking.
    pub(crate) fn may_bypass_block(&self) -> Bypass {
        self.bypass
    }
}

/// An instruction to start blocking traffic to a given hop,
/// or to change the rules for blocking traffic.
#[derive(Clone, Copy, Debug)]
pub(crate) struct StartBlocking {
    /// The first hop to which normal data should no longer be sent.
    pub(crate) hop: HopNum,
    /// If true, then padding traffic _to the blocking hop_
    /// can bypass this block, if it has [`Bypass::BypassBlocking`].
    ///
    /// (All traffic can be sent to earlier hops as normal.
    /// No traffic may be sent to later hops.)
    pub(crate) is_bypassable: bool,
}

/// Estimated upper bound for the likely number of hops.
const HOPS: usize = 6;

/// Absolute upper bound for number of hops.
const MAX_HOPS: usize = 64;

/// A handle to the padding state of a single circuit.
///
/// Used to tell the padders about events that they need to react to.
#[derive(Clone, derive_more::Debug)]
pub(crate) struct PaddingController<S = DynTimeProvider>
where
    S: SleepProvider,
{
    /// The underlying shared state.
    #[debug(skip)]
    shared: Arc<Mutex<PaddingShared<S>>>,
}

/// The shared state for a single circuit's padding.
///
/// Used by both PaddingController and PaddingEventStream.
struct PaddingShared<S: SleepProvider> {
    /// A sleep provider for telling the time and creating sleep futures.
    runtime: S,
    /// Per-hop state for each hop that we have enabled padding with.
    ///
    /// INVARIANT: the length of this vector is no greater than `MAX_HOPS`.
    hops: SmallVec<[Option<Box<dyn PaddingBackend>>; HOPS]>,
    /// Which hops are currently blocking, and whether that blocking is bypassable.
    blocking: BlockingState,
    /// When will the currently pending sleep future next expire?
    ///
    /// We keep track of this so that we know when we need to reset the sleep future.
    /// It gets updated by `PaddingStream::schedule_next_wakeup`,
    /// which we call in `<PaddingStream as Stream>::poll_next` immediately
    /// before we create a timer.
    next_scheduled_wakeup: Option<Instant>,
}

/// Current padding-related blocking status for a circuit.
#[derive(Default)]
struct BlockingState {
    /// Whether each hop is currently blocked.
    hop_blocked: BitArr![for MAX_HOPS],
    /// Whether each hop's blocking is currently bypassable.
    blocking_bypassable: BitArr![for MAX_HOPS],
}

impl BlockingState {
    /// Set the hop at position `idx` to blocked.
    fn set_blocked(&mut self, idx: usize, is_bypassable: bool) {
        self.hop_blocked.set(idx, true);
        self.blocking_bypassable.set(idx, is_bypassable);
    }
    /// Set the hop at position `idx` to unblocked.
    fn set_unblocked(&mut self, idx: usize) {
        self.hop_blocked.set(idx, false);
    }
    /// Return a [`PaddingEvent`]
    fn blocking_update_paddingevent(&self) -> PaddingEvent {
        match self.hop_blocked.first_one() {
            Some(hop_idx) => {
                let hop = hopnum_from_hop_idx(hop_idx);
                PaddingEvent::StartBlocking(StartBlocking {
                    hop,
                    is_bypassable: self.blocking_bypassable[hop_idx],
                })
            }
            None => PaddingEvent::StopBlocking,
        }
    }
}

#[allow(clippy::unnecessary_wraps)]
impl<S: SleepProvider> PaddingController<S> {
    /// Report that we've enqueued a non-padding cell for a given hop.
    ///
    /// Return a QueuedCellPaddingInfo if we need to alert the padding subsystem
    /// when this cell is flushed.
    pub(crate) fn queued_data(&self, hop: HopNum) -> Option<QueuedCellPaddingInfo> {
        // Every hop up to and including the target hop will see this as normal data.
        self.trigger_events(hop, &[maybenot::TriggerEvent::NormalSent]);
        self.info_for_hop(hop)
    }

    /// Report that we have enqueued a non-padding cell
    /// in place of a replaceable padding cell
    /// for a given hop.
    ///
    /// Return a QueuedCellPaddingInfo if we need to alert the padding subsystem
    /// when this cell is flushed.
    pub(crate) fn queued_data_as_padding(
        &self,
        hop: HopNum,
        sendpadding: SendPadding,
    ) -> Option<QueuedCellPaddingInfo> {
        assert_eq!(hop, sendpadding.hop);
        assert_eq!(Replace::Replaceable, sendpadding.replace);

        self.trigger_events_mixed(
            hop,
            // Each intermediate hop sees this as normal data.
            &[maybenot::TriggerEvent::NormalSent],
            // For the target hop, we treat this both as normal, _and_ as padding.
            &[
                maybenot::TriggerEvent::NormalSent,
                sendpadding.into_sent_event(),
            ],
        );
        self.info_for_hop(hop)
    }

    /// Report that we have enqueued a padding cell to a given hop.
    ///
    /// Return a QueuedCellPaddingInfo if we need to alert the padding subsystem
    /// when this cell is flushed.
    pub(crate) fn queued_padding(
        &self,
        hop: HopNum,
        sendpadding: SendPadding,
    ) -> Option<QueuedCellPaddingInfo> {
        assert_eq!(hop, sendpadding.hop);
        self.trigger_events_mixed(
            hop,
            // Each intermediate hop sees this as normal data.
            &[maybenot::TriggerEvent::NormalSent],
            // The target hop sees this as padding.
            &[sendpadding.into_sent_event()],
        );
        self.info_for_hop(hop)
    }

    /// Report that we've flushed a cell from the queue for the given hop.
    pub(crate) fn flushed_relay_cell(&self, info: QueuedCellPaddingInfo) {
        // Every hop up to the last
        self.trigger_events(info.target_hop, &[maybenot::TriggerEvent::TunnelSent]);
    }

    /// Report that we have decrypted a non-padding cell from our queue
    /// from a given hop.
    ///
    // Note that in theory, it would be better to trigger TunnelRecv as soon as
    // possible after we receive and enqueue the data cell, and NormalRecv only
    // once we've decrypted it and found it to be data.  But we can't do that,
    // since we won't know which hop actually originated the cell until we
    // decrypt it.
    pub(crate) fn decrypted_data(&self, hop: HopNum) {
        self.trigger_events(
            hop,
            // We treat this as normal data from every hop.
            &[
                maybenot::TriggerEvent::TunnelRecv,
                maybenot::TriggerEvent::NormalRecv,
            ],
        );
    }
    /// Report that we have decrypted a non-padding cell from our queue.
    //
    // See note above.
    pub(crate) fn decrypted_padding(&self, hop: HopNum) {
        self.trigger_events_mixed(
            hop,
            // We treat this as normal data from the intermediate hops.
            &[
                maybenot::TriggerEvent::TunnelRecv,
                maybenot::TriggerEvent::NormalRecv,
            ],
            // But from the target hop, it counts as padding.
            &[
                maybenot::TriggerEvent::TunnelRecv,
                maybenot::TriggerEvent::PaddingRecv,
            ],
        );
    }

    /// Return the `QueuedCellPaddingInfo` to use when sending messages to `target_hop`
    fn info_for_hop(&self, target_hop: HopNum) -> Option<QueuedCellPaddingInfo> {
        // TODO circpad optimization: This is always Some for now, but we
        // could someday avoid creating this object
        // when padding is not enabled on the circuit,
        // or if padding is not enabled on any hop of the circuit <= target_hop.
        Some(QueuedCellPaddingInfo { target_hop })
    }

    /// Trigger a list of maybenot events on every hop up to and including `hop`.
    fn trigger_events(&self, hop: HopNum, events: &[maybenot::TriggerEvent]) {
        let final_idx = usize::from(hop);
        let shared = &mut self.shared.lock().expect("poisoned lock");
        let now = shared.runtime.now();
        let next_scheduled_wakeup = shared.next_scheduled_wakeup;
        for hop_controller in shared.hops.iter_mut().take(final_idx + 1) {
            let Some(hop_controller) = hop_controller else {
                continue;
            };
            hop_controller.report_events_at(events, now, next_scheduled_wakeup);
        }
    }

    /// Trigger `intermediate_hop_events` on every hop up to but _not_ including `hop`.
    ///
    /// Trigger `final_hop_events` on `hop`.
    ///
    /// (Don't trigger anything on any hops _after_ `hop`.)
    fn trigger_events_mixed(
        &self,
        hop: HopNum,
        intermediate_hop_events: &[maybenot::TriggerEvent],
        final_hop_events: &[maybenot::TriggerEvent],
    ) {
        use itertools::Itertools as _;
        use itertools::Position as P;
        let final_idx = usize::from(hop);
        let shared = &mut self.shared.lock().expect("poisoned lock");
        let now = shared.runtime.now();
        let next_scheduled_wakeup = shared.next_scheduled_wakeup;
        for (position, hop_controller) in shared.hops.iter_mut().take(final_idx + 1).with_position()
        {
            let Some(hop_controller) = hop_controller else {
                continue;
            };
            let events = match position {
                P::First | P::Middle => intermediate_hop_events,
                P::Last | P::Only => final_hop_events,
            };
            hop_controller.report_events_at(events, now, next_scheduled_wakeup);
        }
    }
}

impl<S: SleepProvider> PaddingShared<S> {
    /// Install a PaddingBackend for a single hop.
    ///
    // TODO circpad: define a wrapper for this function; right now it's unreachable.
    fn set_hop_backend(&mut self, hop: HopNum, backend: Option<Box<dyn PaddingBackend>>) {
        let hop_idx: usize = hop.into();
        assert!(hop_idx < MAX_HOPS);
        let n_needed = hop_idx + 1;
        // Make sure there are enough spaces in self.hops.
        // We can't use "resize" or "extend", since Box<dyn<PaddingBackend>>
        // doesn't implement Clone, which SmallVec requires.
        while self.hops.len() < n_needed {
            self.hops.push(None);
        }
        self.hops[hop_idx] = backend;
        // TODO circpad: we probably need to wake up the stream in this case.

        // TODO circpad: this won't behave correctly if there was previously a backend for this hop,
        // and it had set blocking.  We need to make sure that an appropriate blocking-related
        // PaddingEvent gets generated.
        self.blocking.set_unblocked(hop_idx);
    }

    /// Transform a [`PerHopPaddingEvent`] for a single hop with index `idx` into a [`PaddingEvent`],
    /// updating our state as appropriate.
    fn process_per_hop_event(
        blocking: &mut BlockingState,
        hop_idx: usize,
        event: PerHopPaddingEvent,
    ) -> PaddingEvent {
        use PaddingEvent as PE;
        use PerHopPaddingEvent as PHPE;

        match event {
            PHPE::SendPadding {
                machine,
                replace,
                bypass,
            } => PE::SendPadding(SendPadding {
                machine,
                hop: hopnum_from_hop_idx(hop_idx),
                replace,
                bypass,
            }),
            PHPE::StartBlocking { is_bypassable } => {
                blocking.set_blocked(hop_idx, is_bypassable);
                // TODO circpad-trafficblock: by design, "is_bypassable" only works for the first hop
                // that is blocking; Is this as intended?
                blocking.blocking_update_paddingevent()
            }
            PHPE::StopBlocking => {
                blocking.set_unblocked(hop_idx);
                blocking.blocking_update_paddingevent()
            }
        }
    }

    /// Extract every PaddingEvent that is ready to be reported to the circuit at time `now`.
    ///
    /// May trigger other events, or wake up the stream, in the course of running.
    fn take_padding_events_at(&mut self, now: Instant) -> PaddingEventVec {
        let mut output = PaddingEventVec::default();
        for (hop_idx, backend) in self.hops.iter_mut().enumerate() {
            let Some(backend) = backend else {
                continue;
            };

            let hop_events = backend.take_padding_events_at(now, self.next_scheduled_wakeup);

            output.extend(
                hop_events
                    .into_iter()
                    .map(|ev| Self::process_per_hop_event(&mut self.blocking, hop_idx, ev)),
            );
        }
        output
    }

    /// Find the next time at which we should wake up the stream, and register it as our
    /// "next scheduled wakeup".
    fn schedule_next_wakeup(&mut self, waker: &Waker) -> Option<Instant> {
        // Find the earliest time at which any hop has a scheduled event.
        let next_expiration = self
            .hops
            .iter_mut()
            .flatten()
            .filter_map(|hop| hop.next_wakeup(waker))
            .min();
        self.next_scheduled_wakeup = next_expiration;
        next_expiration
    }
}

/// A stream of [`PaddingEvent`] to tell a circuit when (if at all) it should send
/// padding and block traffic.
//
// TODO circpad: Optimize this even more for the no-padding case?
// We could make it smaller or faster.
pub(crate) struct PaddingEventStream<S = DynTimeProvider>
where
    S: SleepProvider,
{
    /// An underlying list of PaddingBackend.
    shared: Arc<Mutex<PaddingShared<S>>>,
    /// A future defining a time at which we must next call `padder.padding_events_at`.
    ///
    /// (We also arrange for the backend to wake us up if we need to change this time,
    /// or call `padder.padding_events_at`.)
    ///
    /// Note that this timer is allowed to be _earlier_ than our true wakeup time,
    /// but not later.
    sleep_future: S::SleepFuture,

    /// A list of `PaddingEvent` that we want to yield.
    ///
    /// We store this list in reverse order from that returned by `padding_events_at`,
    /// so that we can pop them one by one.
    pending_events: PaddingEventVec,
}

impl futures::Stream for PaddingEventStream {
    type Item = PaddingEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            let (now, next_wakeup, runtime) = {
                // We destructure like this to avoid simultaneous mutable/immutable borrows.
                let Self {
                    shared,
                    pending_events,
                    ..
                } = &mut *self;

                // Do we have any events that are waiting to be yielded?
                if let Some(val) = pending_events.pop() {
                    return Poll::Ready(Some(val));
                }

                let mut shared = shared.lock().expect("Poisoned lock");

                // Does the padder have any events that have become ready to be yielded?
                let now = shared.runtime.now();
                *pending_events = shared.take_padding_events_at(now);
                // (we reverse them, so that we can pop them one by one.)
                pending_events.reverse();
                if let Some(val) = pending_events.pop() {
                    return Poll::Ready(Some(val));
                }

                // If we reach this point, there are no events to trigger right now.
                //
                // We'll ask all the padders for the time at which they next might need to take
                // action, and register our Waker with them, to be alerted if we need to take any action
                // before that.
                (
                    now,
                    shared.schedule_next_wakeup(cx.waker()),
                    shared.runtime.clone(),
                )
                // Here we drop the lock on the shared state.
            };

            match next_wakeup {
                None => {
                    return Poll::Pending;
                }
                Some(t) => {
                    // TODO circpad: Avoid rebuilding sleep future needlessly.  May require new APIs in
                    // tor-rtcompat.
                    self.sleep_future = runtime.sleep(t.saturating_duration_since(now));
                    match self.sleep_future.as_mut().poll(cx) {
                        Poll::Ready(()) => {
                            // Okay, The timer expired already. Continue through the loop.
                            continue;
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
        }
    }
}

impl futures::stream::FusedStream for PaddingEventStream {
    fn is_terminated(&self) -> bool {
        // This stream is _never_ terminated: even if it has no padding machines now,
        // we might add some in the future.
        false
    }
}

/// Construct a HopNum from an index into the `hops` field of a [`PaddingShared`].
///
/// # Panics
///
/// Panics if `hop_idx` is greater than u8::MAX, which should be impossible.
fn hopnum_from_hop_idx(hop_idx: usize) -> HopNum {
    // (Static assertion: makes sure we can represent every index of hops as a HopNum.)
    const _: () = assert!(MAX_HOPS < u8::MAX as usize);
    HopNum::from(u8::try_from(hop_idx).expect("hop_idx out of range!"))
}

/// Create a new, empty padding instance for a new circuit.
pub(crate) fn new_padding<S>(runtime: S) -> (PaddingController<S>, PaddingEventStream<S>)
where
    S: SleepProvider,
{
    // Start with an arbitrary sleep future.  We won't actually use this until
    // the first time that we have an event to schedule, so the timeout doesn't matter.
    let sleep_future = runtime.sleep(Duration::new(86400, 0));

    let shared = PaddingShared {
        runtime,
        hops: Default::default(),
        blocking: Default::default(),
        next_scheduled_wakeup: None,
    };
    let shared = Arc::new(Mutex::new(shared));
    let controller = PaddingController {
        shared: shared.clone(),
    };
    let stream = PaddingEventStream {
        shared,
        sleep_future,
        pending_events: PaddingEventVec::default(),
    };

    (controller, stream)
}
