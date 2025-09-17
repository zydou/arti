//! Padding backend based on [`maybenot`].
//!
//! # Operation
//!
//! For each each circuit hop, we have an optional [`maybenot::Framework`].
//! This framework wraps multiple "padding machines",
//! each of which is a randomized state machine.
//! (Arti is built with a list of pre-configured of padding machines.
//! The set of padding machines to use with any given circuit hop
//! are negotiated via `PADDING_NEGOTIATE` messages.)
//! We interact with the framework via
//! [`Framework::trigger_events`](maybenot::Framework::trigger_events),
//! which consumes [`TriggerEvent`]s and gives us [`TriggerAction`]s.
//! Those `TriggerAction`s tell us to schedule or reschedule different timers,
//! to block traffic, or to send padding.
//!
//! We wrap the `Framework` in [`MaybenotPadder`],
//! which keeps track of the expiration time for each timer.
//! From `MaybenotPadder`, we expose a single timer
//! describing when the next action from the padding machine may be necessary.
//! This timer is likely to update frequently.

use std::{sync::Arc, task::Waker};

use maybenot::{MachineId, TriggerEvent};
use smallvec::SmallVec;

use super::{Bypass, Duration, Instant, PerHopPaddingEvent, PerHopPaddingEventVec, Replace};

/// The Rng that we construct for our padding machines.
///
/// We use a separate type alias here in case we want to move to a per-Framework
/// ChaCha8Rng or something.
type Rng = ThisThreadRng;

/// The particular instantiated padding framework type that we use.
type Framework = maybenot::Framework<Arc<[maybenot::Machine]>, Rng, Instant>;

/// A [`maybenot::TriggerAction`] as we construct it for use with our [`Framework`]s.
type TriggerAction = maybenot::TriggerAction<Instant>;

/// A type we use to report events that we must trigger on the basis of triggering other events.
///
/// We've optimized here for the assumption that we _usually_ won't need to trigger more than one
/// event.
type TriggerEventsOutVec = SmallVec<[TriggerEvent; 1]>;

/// An action that we should take on a machine's behalf,
/// after a certain interval has elapsed.
#[derive(Clone, Debug)]
enum ScheduledAction {
    /// We should send padding if and when the machine's action timer expires.
    SendPadding {
        /// Send padding even if bypassable blocking is in place.
        /// (Blocking can be bypassable or non-bypassable.)
        bypass: bool,
        /// If an existing non-padding cell is queued,
        /// it can replace this padding.
        //
        /// If `bypass` is true, such a cell can also bypass bypassable blocking.
        replace: bool,
    },
    /// We should block outbound traffic if and when the machine's action timer expires.
    Block {
        /// If true, then the blocking is bypassable.
        bypass: bool,
        /// If true, then we should change the duration of the current blocking unconditionally.
        /// If false, we should use whichever duration is longer.
        replace: bool,
        /// The interval of the blocking that we should apply.
        duration: Duration,
    },
}

/// The state for a _single_ padding Machine within a Framework.
#[derive(Default, Clone, Debug)]
struct MachineState {
    /// The current state for the machine's "internal timer".
    ///
    /// Each machine has a single internal timer,
    /// and manages the timer itself via the `UpdateTimer` and `Cancel`
    /// [`TriggerAction`] variants.
    internal_timer_expires: Option<Instant>,

    /// The current state for the machine's "action timer".
    ///
    /// Each machine has a single action timer, after which some [`ScheduledAction`]
    /// should be taken.
    ///
    /// (Note that only one action can be scheduled per machine,
    /// so if we're told to schedule blocking, we should cancel padding;
    /// and if we're told to schedule padding, we should cancel blocking.)
    action_timer_expires: Option<(Instant, ScheduledAction)>,
}

impl MachineState {
    /// Return the earliest time that either of this machine's timers will expire.
    fn next_expiration(&self) -> Option<Instant> {
        match (&self.internal_timer_expires, &self.action_timer_expires) {
            (None, None) => None,
            (None, Some((t, _))) => Some(*t),
            (Some(t), None) => Some(*t),
            (Some(t1), Some((t2, _))) => Some(*t1.min(t2)),
        }
    }
}

/// Represents the state for all padding machines within a framework.
///
/// N should be around the number of padding machines that the framework should support.
struct PadderState<const N: usize> {
    /// A list of all the padding machine states for a single framework.
    ///
    /// This list is indexed by `MachineId`.
    //
    // TODO: Optimize this size even more if appropriate
    state: SmallVec<[MachineState; N]>,
}

impl<const N: usize> PadderState<N> {
    /// Return a mutable reference to the state corresponding to a given [`MachineId`]
    ///
    /// # Panics
    ///
    /// Panics if `id` is out of range, which can only happen if a MachineId from
    /// one Framework is given to another Framework.
    fn state_mut(&mut self, id: MachineId) -> &mut MachineState {
        &mut self.state[id.into_raw()]
    }

    /// Execute a single [`TriggerAction`] on this state.
    ///
    /// `TriggerActions` are created by `maybenot::Framework` instances
    /// in response to [`TriggerEvent`]s.
    ///
    /// Executing a `TriggerAction` can adjust timers,
    /// and can schedule a new [`ScheduledAction`] to be taken in the future;
    /// it does not, however, send any padding or adjust any blocking on its own.
    ///
    /// The current time should be provided in `now`.
    ///
    /// Executing a `TriggerAction` can cause more events to occur.
    /// If this happens, they are added to `events_out`.
    ///
    /// If this method returns false, no timer has changed.
    /// If this method returns true, then a timer may have changed.
    /// (False positives are possible, but not false negatives.)
    fn trigger_action(
        &mut self,
        action: &TriggerAction,
        now: Instant,
        events_out: &mut TriggerEventsOutVec,
    ) -> bool {
        use maybenot::Timer as T;
        use maybenot::TriggerAction as A;

        let mut timer_changed = false;

        match action {
            A::Cancel { machine, timer } => {
                // "Cancel" means to stop one or both of the timers from this machine.
                let st = self.state_mut(*machine);
                match timer {
                    T::Action => st.action_timer_expires = None,
                    T::Internal => st.internal_timer_expires = None,
                    T::All => {
                        st.action_timer_expires = None;
                        st.internal_timer_expires = None;
                    }
                };
                timer_changed = true;
            }
            A::SendPadding {
                timeout,
                bypass,
                replace,
                machine,
            } => {
                // "SendPadding" means to schedule padding to be sent after a given timeout,
                // and to replace any previous timed action.
                let st = self.state_mut(*machine);
                st.action_timer_expires = Some((
                    now + *timeout,
                    ScheduledAction::SendPadding {
                        bypass: *bypass,
                        replace: *replace,
                    },
                ));
                timer_changed = true;
            }
            A::BlockOutgoing {
                timeout,
                duration,
                bypass,
                replace,
                machine,
            } => {
                // "BlockOutgoing" means to begin blocking traffic for a given duration,
                // after a given timeout,
                // and to replace any previous timed action.
                let st = self.state_mut(*machine);
                st.action_timer_expires = Some((
                    now + *timeout,
                    ScheduledAction::Block {
                        bypass: *bypass,
                        replace: *replace,
                        duration: *duration,
                    },
                ));
                timer_changed = true;
            }
            A::UpdateTimer {
                duration,
                replace,
                machine,
            } => {
                // "UpdateTimer" means to set or re-set the internal timer for this machine.
                let st = self.state_mut(*machine);

                let new_expiry = now + *duration;
                // The "replace" flag means "update the internal timer unconditionally".
                // If it is false, and the timer is already set, then we should only update
                // the internal timer to be _longer_.
                let update_timer = match (replace, st.internal_timer_expires) {
                    (_, None) => true,
                    (true, Some(_)) => true,
                    (false, Some(cur)) if new_expiry > cur => true,
                    (false, Some(_)) => false,
                };
                if update_timer {
                    st.internal_timer_expires = Some(new_expiry);
                    timer_changed = true;
                }
                // Note: We are supposed to trigger TimerBegin unconditionally
                // if the timer changes at all.
                events_out.push(TriggerEvent::TimerBegin { machine: *machine });
            }
        }

        timer_changed
    }

    /// Return the next instant (if any) at which any of the padding machines' timers will expire.
    fn next_expiration(&self) -> Option<Instant> {
        self.state
            .iter()
            .filter_map(MachineState::next_expiration)
            .min()
    }
}

/// Possible state of a Framework's aggregate timer.
///
/// (Since there are two possible timers for each Machine,
/// we just keep track of the one that will expire next.)
#[derive(Clone, Debug)]
struct Timer {
    /// The next time at which any of this padding machines' timer will expire.
    ///
    /// (None means "no timers are set.")
    next_expiration: Option<Instant>,

    /// A [`Waker`] that we must wake whenever `self.next_expiration` becomes sooner than
    /// our next scheduled wakeup (as passed as an argument to `set_expiration`).
    waker: Waker,
}

impl Timer {
    /// Construct a new Timer.
    fn new() -> Self {
        Self {
            next_expiration: None,
            waker: Waker::noop().clone(),
        }
    }

    /// Return the next expiration time, and schedule `waker` to be alerted whenever
    /// the expiration time becomes earlier than the time at which we've actually decided to sleep
    /// (passed as an argument to `set_expiration()`).
    ///
    /// (There are two separate expiration times at work here because, in higher-level code,
    /// we combine _all_ the timer expirations for all padding machines on a circuit
    /// into a single expiration, and track only that expiration.)
    fn get_expiration(&mut self, waker: &Waker) -> Option<Instant> {
        // TODO: Perhaps this should instead return and/or manipulate a sleep future.
        // TODO: Perhaps there should be a shared AtomicWaker?
        self.waker = waker.clone();
        self.next_expiration
    }

    /// Change the expiration time to `new_expiration`, alerting the [`Waker`] if that time
    /// is earlier than `next_scheduled_wakeup`.
    fn set_expiration(
        &mut self,
        new_expiration: Option<Instant>,
        next_scheduled_wakeup: Option<Instant>,
    ) {
        // we need to invoke the waker if the new expiration is earlier than the one the waker has.
        let wake = match (next_scheduled_wakeup, new_expiration) {
            (_, None) => false,
            (None, Some(_)) => true,
            (Some(w_exp), Some(new_exp)) => new_exp < w_exp,
        };
        self.next_expiration = new_expiration;
        if wake {
            self.waker.wake_by_ref();
        }
    }
}

/// State of a MaybenotPadder that is blocking.
///
/// Here we only need to remember when the blocking expires;
/// we record the bypassable status of the padding in [`super::PaddingShared`].
#[derive(Debug)]
struct BlockingState {
    /// The time at which this blocking expires.
    expiration: Instant,
}

/// An implementation of circuit padding using [`maybenot`].
///
/// Supports up to `N` padding machines without spilling over onto the heap.
pub(super) struct MaybenotPadder<const N: usize> {
    /// Our underlying [`maybenot::Framework`].
    framework: Framework,
    /// The state of our padding machines.
    state: PadderState<N>,
    /// Our current timer information.
    timer: Timer,
    /// If we are blocking, information about the blocking.
    blocking: Option<BlockingState>,
}

impl<const N: usize> MaybenotPadder<N> {
    /// Construct a new MaybyenotPadder from a provided `FrameworkRules`.
    pub(super) fn from_framework_rules(
        rules: &super::PaddingRules,
    ) -> Result<Self, maybenot::Error> {
        let framework = maybenot::Framework::new(
            rules.machines.clone(),
            rules.max_outbound_padding_frac,
            rules.max_outbound_blocking_frac,
            Instant::now(),
            ThisThreadRng,
        )?;
        Ok(Self::from_framework(framework))
    }

    /// Construct a new MaybenotPadder from a given Framework.
    pub(super) fn from_framework(framework: Framework) -> Self {
        let n = framework.num_machines();
        let state = PadderState {
            state: smallvec::smallvec![MachineState::default(); n],
        };
        Self {
            framework,
            state,
            timer: Timer::new(),
            blocking: None,
        }
    }

    /// Return the next expiration time, and schedule `waker` to be alerted whenever
    /// the expiration time becomes earlier than that.
    pub(super) fn get_expiration(&mut self, waker: &Waker) -> Option<Instant> {
        self.timer.get_expiration(waker)
    }

    /// Tell the padding machines about all of the given `events`,
    /// report them happening at `now`, and adjust internal state.
    ///
    /// If doing this would cause any timer to become earlier than `next_scheduled_wakeup`,
    /// wake up the registered [`Waker`].
    pub(super) fn trigger_events_at(
        &mut self,
        events: &[TriggerEvent],
        now: Instant,
        next_scheduled_wakeup: Option<Instant>,
    ) {
        let mut timer_changed = false;

        // A pair of buffers that we'll use to handle events that arise while triggering other
        // events.  (The BeginTimer event can be triggered by the UpdateTimer action.)
        let (mut e1, mut e2) = (TriggerEventsOutVec::new(), TriggerEventsOutVec::new());
        let (mut processing, mut pending) = (&mut e1, &mut e2);

        let mut events = events;

        /// If we go through our loop more than this many times, we stop:
        /// An infinite loop is in theory possible, but we don't want to allow one.
        const MAX_LOOPS: usize = 4;

        let finished_normally = 'finished: {
            for _ in 0..MAX_LOOPS {
                pending.clear();
                for action in self.framework.trigger_events(events, now) {
                    timer_changed |= self.state.trigger_action(action, now, pending);
                }

                if pending.is_empty() {
                    // We don't have any additional events to trigger.
                    break 'finished true;
                } else {
                    std::mem::swap(&mut processing, &mut pending);
                    events = &processing[..];
                }
            }
            // We got to the last iteration of the loop and still had events to trigger.
            break 'finished false;
        };

        if !finished_normally {
            // TODO: Log in this case, but not too many times.
        }

        if timer_changed {
            self.timer
                .set_expiration(self.state.next_expiration(), next_scheduled_wakeup);
        }
    }

    /// Take any actions that need to occur at time `now`.
    ///
    /// We should call this function as soon as possible after our timer has expired.
    ///
    /// Returns zero or more [`PerHopPaddingEvent`]s reflecting the padding that we should send,
    /// and what we should do with blocking.
    fn take_actions_at(
        &mut self,
        now: Instant,
        next_scheduled_wakeup: Option<Instant>,
    ) -> PerHopPaddingEventVec {
        // Events that we need to trigger based on expired timers.
        // TODO: We might want a smaller N here.
        let mut e: SmallVec<[TriggerEvent; N]> = SmallVec::default();

        // A list of events that we can't handle internally, and which we need to report
        // to a circuit/tunnel reactor.
        let mut return_events = PerHopPaddingEventVec::default();

        let mut timer_changed = false;

        if let Some(blocking) = &self.blocking {
            if blocking.expiration <= now {
                timer_changed = true;
                self.blocking = None;
                e.push(TriggerEvent::BlockingEnd);
                return_events.push(PerHopPaddingEvent::StopBlocking);
            }
        }

        for (idx, st) in self.state.state.iter_mut().enumerate() {
            match st.internal_timer_expires {
                Some(t) if t <= now => {
                    // This machine's internal timer has expired; we tell it so.
                    st.internal_timer_expires = None;
                    timer_changed = true;
                    e.push(TriggerEvent::TimerEnd {
                        machine: MachineId::from_raw(idx),
                    });
                }
                None | Some(_) => {}
            }
            match &st.action_timer_expires {
                Some((t, _)) if *t <= now => {
                    // This machine's action timer has expired; we now take that action.
                    use ScheduledAction as SA;
                    let action = st
                        .action_timer_expires
                        .take()
                        .expect("It was Some a minute ago!")
                        .1;
                    timer_changed = true;
                    match action {
                        SA::SendPadding { bypass, replace } => {
                            return_events.push(PerHopPaddingEvent::SendPadding {
                                machine: MachineId::from_raw(idx),
                                replace: Replace::from_bool(replace),
                                bypass: Bypass::from_bool(bypass),
                            });
                        }
                        SA::Block {
                            bypass,
                            replace,
                            duration,
                        } => {
                            let new_expiry = now + duration;
                            if self.blocking.is_none() {
                                return_events.push(PerHopPaddingEvent::StartBlocking {
                                    is_bypassable: bypass,
                                });
                            }
                            let replace = match &self.blocking {
                                None => true,
                                Some(b) if replace || b.expiration < new_expiry => true,
                                Some(_) => false,
                            };
                            if replace {
                                self.blocking = Some(BlockingState {
                                    expiration: new_expiry,
                                });
                            }

                            // We trigger this event unconditionally, even if we were already
                            // blocking.
                            e.push(TriggerEvent::BlockingBegin {
                                machine: MachineId::from_raw(idx),
                            });
                        }
                    }
                }
                None | Some(_) => {}
            }
        }

        if timer_changed {
            self.timer
                .set_expiration(self.state.next_expiration(), next_scheduled_wakeup);
        }

        // Inform the framework of any expired timeouts.
        self.trigger_events_at(&e[..], now, next_scheduled_wakeup);

        return_events
    }
}

/// Helper: An Rng object that calls `rand::rng()` to get the thread Rng.
///
/// (We use this since we want our maybenot Framework to use the thread Rng,
/// but we can't have it _own_ the thread Rng. )
#[derive(Clone, Debug)]
pub(super) struct ThisThreadRng;
impl rand::RngCore for ThisThreadRng {
    fn next_u32(&mut self) -> u32 {
        rand::rng().next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        rand::rng().next_u64()
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        rand::rng().fill_bytes(dst);
    }
}

/// Helper trait: Used to wrap a single [`MaybenotPadder`].
///
/// (We don't use `MaybenotPadder` directly because we want to keep the freedom
/// to parameterize it differently, or maybe even to replace it with something else.)
//
// TODO circpad: Decide whether this optimization/flexibility makes any sense.
pub(super) trait PaddingBackend: Send + Sync {
    /// Report one or more TriggerEvents to the padder.
    ///
    /// Alert any registered `Waker` if these events cause us to need to take action
    /// earlier than `next_scheduled_wakeup`.
    fn report_events_at(
        &mut self,
        events: &[maybenot::TriggerEvent],
        now: Instant,
        next_scheduled_wakeup: Option<Instant>,
    );

    /// Trigger any padding actions that should be taken `now`.
    ///
    /// If _we_ should perform any actions (blocking, unblocking, or sending padding),
    /// return them in a [`PerHopPaddingEventVec`].
    ///
    /// Alert any registered `Waker` if these events cause us to need to take action
    /// earlier than `next_scheduled_wakeup`.
    fn take_padding_events_at(
        &mut self,
        now: Instant,
        next_scheduled_wakeup: Option<Instant>,
    ) -> PerHopPaddingEventVec;

    /// This method should be called when we have no actions to perform,
    /// with a [`Waker`] that will activate the corresponding [`PaddingEventStream`](super::PaddingEventStream).
    ///
    /// It will return a time at which pending_events_at() should next be called,
    /// and will wake up the Waker if it turns out that we need to call `pending_events_at()`
    /// any earlier than that.
    fn next_wakeup(&mut self, waker: &Waker) -> Option<Instant>;
}

impl<const N: usize> PaddingBackend for MaybenotPadder<N> {
    fn report_events_at(
        &mut self,
        events: &[maybenot::TriggerEvent],
        now: Instant,
        next_scheduled_wakeup: Option<Instant>,
    ) {
        self.trigger_events_at(events, now, next_scheduled_wakeup);
    }

    fn take_padding_events_at(
        &mut self,
        now: Instant,
        next_scheduled_wakeup: Option<Instant>,
    ) -> PerHopPaddingEventVec {
        self.take_actions_at(now, next_scheduled_wakeup)
    }

    fn next_wakeup(&mut self, waker: &Waker) -> Option<Instant> {
        self.get_expiration(waker)
    }
}
