//! A `maybenot`-specific backend for padding.

// Some of the circuit padding implementation isn't reachable unless
// the extra-experimental circ-padding-manual feature is also present.
//
// TODO circpad: Remove this once we have circ-padding negotiation implemented.
#![cfg_attr(
    all(feature = "circ-padding", not(feature = "circ-padding-manual")),
    expect(dead_code)
)]

mod backend;

use std::collections::VecDeque;
use std::num::NonZeroU16;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use bitvec::BitArr;
use maybenot::MachineId;
use smallvec::SmallVec;
use tor_memquota::memory_cost_structural_copy;
use tor_rtcompat::{DynTimeProvider, SleepProvider};

use crate::HopNum;
use crate::util::err::ExcessPadding;
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
type PaddingEventQueue = VecDeque<PaddingEvent>;

/// A type we use to generate a set of [`PaddingEvent`].
///
/// This is a separate type so we can tune it and make it into a smallvec if needed.
type PerHopPaddingEventVec = Vec<PerHopPaddingEvent>;

/// Specifications for a set of maybenot padding machines as used in Arti: used to construct a `maybenot::Framework`.
#[derive(Clone, Debug, derive_builder::Builder)]
#[builder(build_fn(
    validate = "Self::validate",
    private,
    error = "CircuitPadderConfigError"
))]
#[builder(name = "CircuitPadderConfig")]
#[cfg_attr(not(feature = "circ-padding-manual"), builder(private))]
#[cfg_attr(feature = "circ-padding-manual", builder(public))]
pub(crate) struct PaddingRules {
    /// List of padding machines to use for shaping traffic.
    ///
    /// Note that this list may be empty, if we only want to receive padding,
    /// and never send it.
    machines: Arc<[maybenot::Machine]>,
    /// Maximum allowable outbound padding fraction.
    ///
    /// Passed directly to maybenot; not enforced in Arti.
    /// See [`maybenot::Framework::new`] for details.
    ///
    /// Must be between 0.0 and 1.0
    #[builder(default = "1.0")]
    max_outbound_blocking_frac: f64,
    /// Maximum allowable outbound blocking fraction.
    ///
    /// Passed directly to maybenot; not enforced in Arti.
    /// See [`maybenot::Framework::new`] for details.
    ///
    /// Must be between 0.0 and 1.0.
    #[builder(default = "1.0")]
    max_outbound_padding_frac: f64,
    /// Maximum allowable fraction of inbound padding
    #[builder(default = "1.0")]
    max_inbound_padding_frac: f64,
    /// Number of cells before which we should not enforce max_inbound_padding_frac.
    #[builder(default = "1")]
    enforce_inbound_padding_after_cells: u16,
}

/// An error returned from validating a [`CircuitPadderConfig`].
#[derive(Clone, Debug, thiserror::Error)]
#[cfg_attr(feature = "circ-padding-manual", visibility::make(pub))]
#[non_exhaustive]
pub(crate) enum CircuitPadderConfigError {
    /// A field needed to be given, but wasn't.
    #[error("No value was given for {0}")]
    UninitializedField(&'static str),
    /// A field needed to be a proper fraction, but wasn't.
    #[error("Value was out of range for {0}. (Must be between 0 and 1)")]
    FractionOutOfRange(&'static str),
    /// Maybenot gave us an error when initializing the framework.
    #[error("Maybenot could not initialize framework for rules")]
    MaybenotError(#[from] maybenot::Error),
}

impl From<derive_builder::UninitializedFieldError> for CircuitPadderConfigError {
    fn from(value: derive_builder::UninitializedFieldError) -> Self {
        Self::UninitializedField(value.field_name())
    }
}

impl CircuitPadderConfig {
    /// Helper: Return an error if this is not a valid Builder.
    fn validate(&self) -> Result<(), CircuitPadderConfigError> {
        macro_rules! enforce_frac {
            { $field:ident } =>
            {
                if self.$field.is_some_and(|v| ! (0.0 .. 1.0).contains(&v)) {
                    return Err(CircuitPadderConfigError::FractionOutOfRange(stringify!($field)));
                }
            }
        }
        enforce_frac!(max_outbound_blocking_frac);
        enforce_frac!(max_outbound_padding_frac);
        enforce_frac!(max_inbound_padding_frac);

        Ok(())
    }

    /// Construct a [`CircuitPadder`] based on this [`CircuitPadderConfig`].
    ///
    /// A [`CircuitPadderConfig`] is created its accessors, and used with this method to build a [`CircuitPadder`].
    ///
    /// That [`CircuitPadder`] can then be installed on a circuit using [`ClientCirc::start_padding_at_hop`](crate::client::circuit::ClientCirc::start_padding_at_hop).
    #[cfg_attr(feature = "circ-padding-manual", visibility::make(pub))]
    pub(crate) fn create_padder(&self) -> Result<CircuitPadder, CircuitPadderConfigError> {
        let rules = self.build()?;
        let backend = rules.create_padding_backend()?;
        let initial_stats = rules.initialize_stats();
        Ok(CircuitPadder {
            initial_stats,
            backend,
        })
    }
}

impl PaddingRules {
    /// Create a [`PaddingBackend`] for this [`PaddingRules`], so we can install it in a
    /// [`PaddingShared`].
    fn create_padding_backend(&self) -> Result<Box<dyn PaddingBackend>, maybenot::Error> {
        // TODO circpad: specialize this for particular values of n_machines,
        // when we finally go to implement padding.
        const OPTIMIZE_FOR_N_MACHINES: usize = 4;

        let backend =
            backend::MaybenotPadder::<OPTIMIZE_FOR_N_MACHINES>::from_framework_rules(self)?;
        Ok(Box::new(backend))
    }

    /// Create a new `PaddingStats` to reflect the rules for inbound padding of this  PaddingRules
    fn initialize_stats(&self) -> PaddingStats {
        PaddingStats {
            n_padding: 0,
            n_normal: 0,
            max_padding_frac: self.max_inbound_padding_frac as f32,
            // We just convert 0 to 1, since that's necessarily what was meant.
            enforce_max_after: self
                .enforce_inbound_padding_after_cells
                .try_into()
                .unwrap_or(1.try_into().expect("1 was not nonzero!?")),
        }
    }
}

/// A opaque handle to a padding implementation for a single hop.
///
/// This type is constructed with [`CircuitPadderConfig::create_padder`].
#[derive(derive_more::Debug)]
#[cfg_attr(feature = "circ-padding-manual", visibility::make(pub))]
pub(crate) struct CircuitPadder {
    /// The initial padding stats and restrictions for inbound padding.
    initial_stats: PaddingStats,
    /// The underlying backend to use.
    #[debug(skip)]
    backend: Box<dyn PaddingBackend>,
}

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
    pub(crate) target_hop: HopNum,
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

/// An instruction to start blocking traffic
/// or to change the rules for blocking traffic.
#[derive(Clone, Copy, Debug)]
pub(crate) struct StartBlocking {
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
    /// Records about how much padding and normal traffic we have received from each hop,
    /// and how much padding is allowed.
    stats: SmallVec<[Option<PaddingStats>; HOPS]>,
    /// Which hops are currently blocking, and whether that blocking is bypassable.
    blocking: BlockingState,
    /// When will the currently pending sleep future next expire?
    ///
    /// We keep track of this so that we know when we need to reset the sleep future.
    /// It gets updated by `PaddingStream::schedule_next_wakeup`,
    /// which we call in `<PaddingStream as Stream>::poll_next` immediately
    /// before we create a timer.
    next_scheduled_wakeup: Option<Instant>,

    /// A deque of `PaddingEvent` that we want to yield from our [`PaddingEventStream`].
    ///
    /// NOTE: If you put new items in this list from anywhere other than inside
    /// `PaddingEventStream::poll_next`, you need to alert the `waker`.
    pending_events: PaddingEventQueue,

    /// A waker to alert if we've added any events to padding_events,
    /// or if we need the stream to re-poll.
    //
    // TODO circpad: This waker is redundant with the one stored in every backend's `Timer`.
    // When we revisit this code we may want to consider combining them somehow.
    waker: Waker,
}

/// The number of padding and non-padding cells we have received from each hop,
/// and the rules for how many are allowed.
#[derive(Clone, Debug)]
struct PaddingStats {
    /// The number of padding cells we've received from this hop.
    n_padding: u64,
    /// The number of non-padding cells we've received from this hop.
    n_normal: u64,
    /// The maximum allowable fraction of padding cells.
    max_padding_frac: f32,
    /// A lower limit, below which we will not enforce `max_padding_frac`.
    //
    // This is a NonZero for several reasons:
    // - It doesn't make sense to enforce a ratio when no cells have been received.
    // - If we only check when the total is at above zero, we can avoid a division-by-zero check.
    // - Having an impossible value here ensures that the niche optimization
    //   will work on PaddingStats.
    enforce_max_after: NonZeroU16,
}

impl PaddingStats {
    /// Return an error if this PaddingStats has exceeded its maximum.
    fn validate(&self) -> Result<(), ExcessPadding> {
        // Total number of cells.
        // (It is impossible to get so many cells that this addition will overflow a u64.)
        let total = self.n_padding + self.n_normal;

        if total >= u16::from(self.enforce_max_after).into() {
            // TODO: is there a way we can avoid a floating-point op here?
            // Or can we limit the number of times that we need to check?
            // (Tobias suggests randomization; I'm worried.)
            //
            // On the one hand, this may never appear on our profiles.
            // But on the other hand, if it _does_ matter for performance,
            // it is likely to be on some marginal platform with bad FP performance,
            // where we are unlikely to be doing much testing.
            //
            // One promising possibility is to calculate a minimum amount of padding
            // that we _know_ will be valid, given the current total,
            // and then not check again until we at all until we reach that amount.
            if self.n_padding as f32 > (total as f32 * self.max_padding_frac) {
                return Err(ExcessPadding::PaddingExceedsLimit);
            }
        }
        Ok(())
    }
}

/// Current padding-related blocking status for a circuit.
///
/// We have to keep track of whether each hop is blocked or not,
/// and whether its blocking is bypassable.
/// But all we actually need to tell the reactor code
/// is whether to block the _entire_ circuit or not.
//
// TODO circpad: It might beneficial
// to block only the first blocking hop and its successors,
// but that creates tricky starvation problems
// in the case where we have queued traffic for a later, blocking, hop
// that prevents us from flushing any messages to earlier hops.
// We could solve this with tricky out-of-order designs,
// but for now we're just treating "blocked" as a boolean.
#[derive(Default)]
struct BlockingState {
    /// Whether each hop is currently blocked.
    hop_blocked: BitArr![for MAX_HOPS],
    /// Whether each hop's blocking is currently **not** bypassable.
    blocking_non_bypassable: BitArr![for MAX_HOPS],
}

impl BlockingState {
    /// Set the hop at position `idx` to blocked.
    fn set_blocked(&mut self, idx: usize, is_bypassable: bool) {
        self.hop_blocked.set(idx, true);
        self.blocking_non_bypassable.set(idx, !is_bypassable);
    }
    /// Set the hop at position `idx` to unblocked.
    fn set_unblocked(&mut self, idx: usize) {
        self.hop_blocked.set(idx, false);
        self.blocking_non_bypassable.set(idx, false);
    }
    /// Return a [`PaddingEvent`]
    fn blocking_update_paddingevent(&self) -> PaddingEvent {
        if self.blocking_non_bypassable.any() {
            // At least one hop has non-bypassable blocking, so our blocking is non-bypassable.
            PaddingEvent::StartBlocking(StartBlocking {
                is_bypassable: false,
            })
        } else if self.hop_blocked.any() {
            // At least one hop is blocking, but no hop has non-bypassable padding, so this padding
            // is bypassable.
            PaddingEvent::StartBlocking(StartBlocking {
                is_bypassable: true,
            })
        } else {
            // Nobody is blocking right now; it's time to unblock.
            PaddingEvent::StopBlocking
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
        let mut shared = self.shared.lock().expect("Lock poisoned");
        // Every hop up to and including the target hop will see this as normal data.
        shared.trigger_events(hop, &[maybenot::TriggerEvent::NormalSent]);
        shared.info_for_hop(hop)
    }

    /// Install the given [`CircuitPadder`] to start padding traffic to the listed `hop`.
    ///
    /// Stops padding if the provided padder is `None`.
    ///
    /// Replaces any previous [`CircuitPadder`].
    pub(crate) fn install_padder_padding_at_hop(&self, hop: HopNum, padder: Option<CircuitPadder>) {
        self.shared
            .lock()
            .expect("lock poisoned")
            .set_hop_backend(hop, padder);
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
        let mut shared = self.shared.lock().expect("Lock poisoned");
        shared.trigger_events_mixed(
            hop,
            // Each intermediate hop sees this as normal data.
            &[maybenot::TriggerEvent::NormalSent],
            // For the target hop, we treat this both as normal, _and_ as padding.
            &[
                maybenot::TriggerEvent::NormalSent,
                sendpadding.into_sent_event(),
            ],
        );
        shared.info_for_hop(hop)
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
        let mut shared = self.shared.lock().expect("Lock poisoned");
        shared.trigger_events_mixed(
            hop,
            // Each intermediate hop sees this as normal data.
            &[maybenot::TriggerEvent::NormalSent],
            // The target hop sees this as padding.
            &[sendpadding.into_sent_event()],
        );
        shared.info_for_hop(hop)
    }

    /// Report that we are using an already-queued cell
    /// as a substitute for sending padding to a given hop.
    pub(crate) fn replaceable_padding_already_queued(&self, hop: HopNum, sendpadding: SendPadding) {
        assert_eq!(hop, sendpadding.hop);
        let mut shared = self.shared.lock().expect("Lock poisoned");
        shared.trigger_events_mixed(
            hop,
            // No additional data will be seen for any intermediate hops.
            &[],
            // The target hop's machine sees this as padding.
            &[sendpadding.into_sent_event()],
        );
    }

    /// Report that we've flushed a cell from the queue for the given hop.
    pub(crate) fn flushed_relay_cell(&self, info: QueuedCellPaddingInfo) {
        // Every hop up to the last
        let mut shared = self.shared.lock().expect("Lock poisoned");
        shared.trigger_events(info.target_hop, &[maybenot::TriggerEvent::TunnelSent]);
    }

    /// Report that we've flushed a cell from the per-channel queue.
    pub(crate) fn flushed_channel_cell(&self) {
        let mut shared = self.shared.lock().expect("Lock poisoned");
        shared.trigger_events(HopNum::from(0), &[maybenot::TriggerEvent::TunnelSent]);
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
        let mut shared = self.shared.lock().expect("Lock poisoned");
        shared.inc_normal_received(hop);
        shared.trigger_events(
            hop,
            // We treat this as normal data from every hop.
            &[
                maybenot::TriggerEvent::TunnelRecv,
                maybenot::TriggerEvent::NormalRecv,
            ],
        );
    }
    /// Report that we have decrypted a padding cell from our queue.
    ///
    /// Return an error if this padding cell is not acceptable
    /// (because we have received too much padding from this hop,
    /// or because we have not enabled padding with this hop.)
    //
    // See note above.
    pub(crate) fn decrypted_padding(&self, hop: HopNum) -> Result<(), crate::Error> {
        let mut shared = self.shared.lock().expect("Lock poisoned");
        shared
            .inc_padding_received(hop)
            .map_err(|e| crate::Error::ExcessPadding(e, hop))?;
        shared.trigger_events_mixed(
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
        Ok(())
    }
}

impl<S: SleepProvider> PaddingShared<S> {
    /// Trigger a list of maybenot events on every hop up to and including `hop`.
    fn trigger_events(&mut self, hop: HopNum, events: &[maybenot::TriggerEvent]) {
        let final_idx = usize::from(hop);
        let now = self.runtime.now();
        let next_scheduled_wakeup = self.next_scheduled_wakeup;
        for hop_controller in self.hops.iter_mut().take(final_idx + 1) {
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
        &mut self,
        hop: HopNum,
        intermediate_hop_events: &[maybenot::TriggerEvent],
        final_hop_events: &[maybenot::TriggerEvent],
    ) {
        use itertools::Itertools as _;
        use itertools::Position as P;
        let final_idx = usize::from(hop);
        let now = self.runtime.now();
        let next_scheduled_wakeup = self.next_scheduled_wakeup;
        for (position, hop_controller) in self.hops.iter_mut().take(final_idx + 1).with_position() {
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

    /// Increment the normal cell count from every hop up to and including `hop`.
    fn inc_normal_received(&mut self, hop: HopNum) {
        let final_idx = usize::from(hop);
        for stats in self.stats.iter_mut().take(final_idx + 1).flatten() {
            stats.n_normal += 1;
        }
    }

    /// Increment the padding count from `hop`, and the normal cell count from all earlier hops.
    ///
    /// Return an error if a padding cell from `hop` would not be acceptable.
    fn inc_padding_received(&mut self, hop: HopNum) -> Result<(), ExcessPadding> {
        use itertools::Itertools as _;
        use itertools::Position as P;
        let final_idx = usize::from(hop);
        for (position, stats) in self.stats.iter_mut().take(final_idx + 1).with_position() {
            match (position, stats) {
                (P::First | P::Middle, Some(stats)) => stats.n_normal += 1,
                (P::First | P::Middle, None) => {}
                (P::Last | P::Only, Some(stats)) => {
                    stats.n_padding += 1;
                    stats.validate()?;
                }
                (P::Last | P::Only, None) => {
                    return Err(ExcessPadding::NoPaddingNegotiated);
                }
            }
        }
        Ok(())
    }

    /// Return the `QueuedCellPaddingInfo` to use when sending messages to `target_hop`
    #[allow(clippy::unnecessary_wraps)]
    fn info_for_hop(&self, target_hop: HopNum) -> Option<QueuedCellPaddingInfo> {
        // TODO circpad optimization: This is always Some for now, but we
        // could someday avoid creating this object
        // when padding is not enabled on the circuit,
        // or if padding is not enabled on any hop of the circuit <= target_hop.
        Some(QueuedCellPaddingInfo { target_hop })
    }
}

impl<S: SleepProvider> PaddingShared<S> {
    /// Install or remove a [`CircuitPadder`] for a single hop.
    fn set_hop_backend(&mut self, hop: HopNum, backend: Option<CircuitPadder>) {
        let hop_idx: usize = hop.into();
        assert!(hop_idx < MAX_HOPS);
        let n_needed = hop_idx + 1;
        // Make sure there are enough spaces in self.hops.
        // We can't use "resize" or "extend", since Box<dyn<PaddingBackend>>
        // doesn't implement Clone, which SmallVec requires.
        while self.hops.len() < n_needed {
            self.hops.push(None);
        }
        while self.stats.len() < n_needed {
            self.stats.push(None);
        }
        // project through option...
        let (hop_backend, stats) = if let Some(padder) = backend {
            (Some(padder.backend), Some(padder.initial_stats))
        } else {
            (None, None)
        };
        self.hops[hop_idx] = hop_backend;
        self.stats[hop_idx] = stats;

        let was_blocked = self.blocking.hop_blocked[hop_idx];
        self.blocking.set_unblocked(hop_idx);
        if was_blocked {
            self.pending_events
                .push_back(self.blocking.blocking_update_paddingevent());
        }

        // We need to alert the stream, in case we added an event above, and so that it will poll
        // the new padder at least once.
        self.waker.wake_by_ref();
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
                // NOTE that we remember is_bypassable for every hop, but the blocking is only
                // bypassable if _every_ hop is unblocked, or has bypassable blocking.
                blocking.set_blocked(hop_idx, is_bypassable);
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
    fn take_padding_events_at(&mut self, now: Instant) -> PaddingEventQueue {
        let mut output = PaddingEventQueue::default();
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
        self.waker = waker.clone();
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
}

impl futures::Stream for PaddingEventStream {
    type Item = PaddingEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            let (now, next_wakeup, runtime) = {
                // We destructure like this to avoid simultaneous mutable/immutable borrows.
                let Self { shared, .. } = &mut *self;

                let mut shared = shared.lock().expect("Poisoned lock");

                // Do we have any events that are waiting to be yielded?
                if let Some(val) = shared.pending_events.pop_front() {
                    return Poll::Ready(Some(val));
                }

                // Does the padder have any events that have become ready to be yielded?
                let now = shared.runtime.now();
                shared.pending_events = shared.take_padding_events_at(now);

                if let Some(val) = shared.pending_events.pop_front() {
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
        stats: Default::default(),
        blocking: Default::default(),
        next_scheduled_wakeup: None,
        pending_events: PaddingEventQueue::default(),
        waker: Waker::noop().clone(),
    };
    let shared = Arc::new(Mutex::new(shared));
    let controller = PaddingController {
        shared: shared.clone(),
    };
    let stream = PaddingEventStream {
        shared,
        sleep_future,
    };

    (controller, stream)
}
