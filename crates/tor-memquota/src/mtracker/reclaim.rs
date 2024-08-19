//! Reclamation algorithm
//!
//! Implementation the of long-running [`task`] function,
//! (which is the only export from here, the wider `mtracker` module).

use super::*;

mod deferred_drop;

use deferred_drop::{DeferredDrop, GuardWithDeferredDrop};

/// Total number of participants
///
/// Used in reporting and in calculations of various edge cases.
/// On 64-bit systems, bigger than the refcounts, which are all `u32`
type NumParticips = usize;

//========== candiate victim analysis ==========

/// The nominal data age of a participant
#[derive(Ord, PartialOrd, Eq, PartialEq)]
enum Age {
    /// Treat this participant as having very old data
    TreatAsVeryOld,
    /// Data age value from the [`IsParticipant`]
    Actual(CoarseInstant),
}

/// Participant status, as a candidate victim
enum PStatus {
    /// Treat participant as having data of age OldestData
    Candidate(Age),
    /// Tear this participant down right away
    TearDown,
    /// Treat participant as not having any data; don't reclaim from it
    NoData,
}

/// Outcome of a completed reclamation run
///
/// This is used only within `choose_victim`, and only for logging
#[derive(Debug, derive_more::Display)]
enum Outcome {
    /// We reached the low water mark
    #[display(fmt = "complete")]
    TargetReached,

    /// We didn't, but we have so many participants that that's possibly expected
    ///
    /// (Can only happen on 32-bit platforms.)
    #[display(fmt = "{} participants, good enough - stopping", n_particips)]
    GoodEnough {
        /// The number of participants
        n_particips: NumParticips,
    },
}

/// Figure out whether a participant is a candidate victim, and obtain its data age
fn analyse_particip(precord: &PRecord, defer_drop: &mut DeferredDrop) -> PStatus {
    let Some(particip) = precord.particip.upgrade() else {
        // Oh!  This participant has vanished!
        // We can't reclaim from it.  It may already be reclaiming.
        // Delete it from our data structure.
        return PStatus::TearDown;
    };

    let got_oldest = catch_unwind(AssertUnwindSafe(|| particip.get_oldest()));
    defer_drop.push(particip);

    match got_oldest {
        Ok(Some(age)) => return PStatus::Candidate(Age::Actual(age)),
        Ok(None) => {}
        Err(_panicked) => {
            // _panicked is of a useless type
            error!("memory tracker: call to get_oldest panicked!");
            return PStatus::TearDown;
        }
    }

    // The participant claims not to have any memory
    // There might be some cached, let's check

    let Some(max_cached) = precord
        .refcount
        .as_usize()
        .checked_mul(MAX_CACHE.as_usize())
    else {
        // WTF!  So many Participation clones that the max usage has
        // overflowed.  (This can only happen on 32-bit platforms
        // since refcount is a u32.)  Probably we should reclaim
        // from this participant.
        log_ratelim!(
            "memtrack: participant with many clones claims to have no data";
            Err::<Void, _>(internal!("{} Participation clones", *precord.refcount));
        );
        return PStatus::Candidate(Age::TreatAsVeryOld);
    };

    if precord.used.as_raw() > Qty(max_cached) {
        // This participant is lying to us somehow.
        log_ratelim!(
            "memtrack: participant claims to have no data, but our accounting disagrees";
            Err::<Void, _>(internal!("{} used (by {} clones)", precord.used, *precord.refcount));
        );
        return PStatus::Candidate(Age::TreatAsVeryOld);
    }

    // Participant plausibly does have no data
    PStatus::NoData
}

//========== reclamation algorith, the main pieces ==========

/// State while reclamation is active
struct Reclaiming {
    /// The heap of candidates, oldest at top of heap
    heap: BinaryHeap<Reverse<(Age, AId)>>,
}

/// A victim we have selected for reclamation
///
/// This designates a specific Participant.
///
/// But, note that we always reclaim from an Account, so if we are reclaiming
/// from one `Victim`, we may be reclaiming from other `Victim`s with the same
/// `AId` and different `IsParticipant`s.  And because of inheritance, we might
/// be reclaiming from other Accounts too.
type Victim = (AId, drop_reentrancy::ProtectedArc<dyn IsParticipant>);

/// Marker indicating that the victim's reclaim function panicked
struct VictimPanicked;

/// Set of responses from the victims, after they have all finished reclaiming.
type VictimResponses = Vec<(AId, Result<Reclaimed, VictimPanicked>)>;

impl Reclaiming {
    /// Check to see if we should start reclaiming, and if so return a `Reclaiming`
    ///
    ///  1. Checks to see if usage is above `max`; if not, returns `None`
    ///  2. Logs that we're starting reclamation
    ///  3. Calculates the heap of data ages
    fn maybe_start(state: &mut GuardWithDeferredDrop) -> Option<Self> {
        let (state, deferred_drop) = state.deref_mut_both();

        if *state.total_used <= state.global.config.max {
            return None;
        }

        info!(
            "memory tracking: {} > {}, reclamation started (target {})",
            *state.total_used, state.config.max, state.config.low_water,
        );

        // `BinaryHeap` is a max heap, so use Rev
        let mut heap = BinaryHeap::new();

        // Build heap of participants we might want to reclaim from
        // (and, while we're at it, tear down broken participants)
        for (aid, arecord) in &mut state.accounts {
            arecord.ps.retain(|_pid, precord| {
                match analyse_particip(precord, deferred_drop) {
                    PStatus::Candidate(age) => {
                        heap.push(Reverse((age, aid)));
                        true // retain
                    }
                    PStatus::NoData => {
                        true // retain
                    }
                    PStatus::TearDown => {
                        precord.auto_release(&mut state.global);
                        false // remove
                    }
                }
            });
        }

        Some(Reclaiming {
            heap,
        })
    }

    /// If we're reclaiming, choose the next victim(s) to reclaim
    ///
    /// This is the account whose participant has the oldest data age,
    /// and all of that account's children.
    ///
    /// We might discover that we didn't want to continue reclamation after all:
    /// this function is responsible for checking our progress
    /// against the low water mark.
    ///
    /// If reclamation should stop, this function logs, and returns `None`.
    fn choose_victims(&mut self, state: &mut State) -> Result<Option<Vec<Victim>>, ReclaimCrashed> {
        let stop = |state: &mut State, outcome| {
            info!(
                "memory tracking reclamation reached: {} (target {}): {}",
                *state.total_used, state.config.low_water, outcome,
            );
            Ok(None)
        };

        if *state.total_used <= state.config.low_water {
            return stop(state, Outcome::TargetReached);
        }
        let Some(Reverse((_, oldest_aid))) = self.heap.pop() else {
            // All our remaining participants are NoData.
            let n_particips: usize = state
                .accounts
                .values()
                .map(|ar| {
                    ar.ps
                        .values()
                        .map(
                            |pr| *pr.refcount as NumParticips, // refcount is u32, so this is fine
                        )
                        .sum::<NumParticips>()
                })
                .sum::<NumParticips>();

            if state.total_used.as_raw().as_usize() / n_particips < usize::from(MAX_CACHE) {
                // On 32-bit, this could happen due to the cache, if we have
                // 2^32 / MAX_CACHE participants.
                return stop(state, Outcome::GoodEnough { n_particips });
            }

            // Oh dear.
            return Err(internal!(
                "memory accounting state corrupted: used={} n_particips={} all NoData",
                *state.total_used,
                n_particips,
            )
            .into());
        };

        // When we do partial reclamation, rather than just Collapsing:
        //
        // fudge next_oldest by something to do with number of loop iterations,
        // to avoid one-allocation-each-time ping pong between multiple caches
        //
        // (this match statement will fail to compile when we add a non-Collapsing variant)
        //
        // let next_oldest = heap.peek_lowest();
        match None {
            None | Some(Reclaimed::Collapsing) => {}
        }

        let victim_aids = state.get_aid_and_children_recursively(oldest_aid);

        let victims: Vec<Victim> = {
            let mut particips = vec![];
            for aid in victim_aids {
                let Some(arecord) = state.accounts.get_mut(aid) else {
                    // shouldn't happen but no need to panic
                    continue;
                };
                arecord.ps.retain(|_pid, precord| {
                    let Some(particip) = precord.particip.upgrade() else {
                        // tear this down!
                        precord.auto_release(&mut state.global);
                        return false;
                    };
                    particips.push((aid, particip));
                    true
                });
            }
            particips
        };

        Ok(Some(victims))
    }

    /// Notify the chosen victims and obtain their responses
    ///
    /// This is the async part, and is done with the state unlocked.
    // Doesn't actually need `self`, only `victims`, but we take it for form's sake
    async fn notify_victims(&mut self, victims: Vec<Victim>) -> VictimResponses {
        futures::future::join_all(
            //
            victims.into_iter().map(|(aid, particip)| async move {
                let particip = particip.promise_dropping_is_ok();
                // We run the `.reclaim()` calls within the same task (since that's what
                // `join_all` does).  So they all run on whatever executor thread is polling
                // the reclamation task.
                let reclaimed = AssertUnwindSafe(particip.reclaim())
                    .catch_unwind()
                    .await
                    .map_err(|_panicked| VictimPanicked);
                // We drop the `ProtectedArc<dyn IsParticipant>` here, which is OK
                // because we don't hold the lock.  Since drop isn't async, and
                // `join_all` doesn't spawn tasks, we drop them sequentially.
                (aid, reclaimed)
            }),
        )
        .await
    }

    /// Process the victim's responses and update `state` accordingly
    // Doesn't actually need `self`, only `state`, but we take it for form's sake
    fn handle_victim_responses(&mut self, state: &mut State, responses: VictimResponses) {
        for (aid, reclaimed) in responses {
            match reclaimed {
                Ok(Reclaimed::Collapsing) | Err(VictimPanicked) => {
                    let Some(mut arecord) = state.accounts.remove(aid) else {
                        // Account is gone, fair enough
                        continue;
                    };
                    arecord.auto_release(&mut state.global);
                    // Account is definitely gone now
                }
            }
        }
    }
}

//========== the reclamation task, in terms of the pieces ==========-

/// Return value from the task, when it finishes due to the tracker being shut down
struct TaskFinished;

/// Reclaim memory until we reach low water, if necessary
///
/// Looks to see if we're above `config.max`.
/// If so, constructs a list of victims, and starts reclaiming from them,
/// until we reach low water.
async fn inner_loop(
    tracker: &Arc<MemoryQuotaTracker>,
) -> Result<(), ReclaimCrashed> {
    let mut reclaiming;
    let mut victims;
    {
        let mut state_guard = GuardWithDeferredDrop::new(tracker.lock()?);

        let Some(r) = Reclaiming::maybe_start(&mut state_guard) else {
            return Ok(());
        };
        reclaiming = r;

        // Duplicating this call to reclaiming.choose_victims means we don't
        // release the lock between `maybe_start` and `choose_victims` (here)
        // and between `handle_victim_responses` and `choose_victims` (bellw).
        // (Releasing the lock would not be a bug, but it's not desirable.)
        let Some(v) = reclaiming.choose_victims(&mut state_guard)? else {
            return Ok(());
        };
        victims = v;
    }

    loop {
        let responses = reclaiming.notify_victims(mem::take(&mut victims)).await;
        let mut state_guard = tracker.lock()?;
        reclaiming.handle_victim_responses(&mut state_guard, responses);
        let Some(v) = reclaiming.choose_victims(&mut state_guard)? else {
            return Ok(());
        };
        victims = v;
    }
}

/// Internal long-running task, handling reclamation - main loop
///
/// Handles routine logging, but not termination
async fn task_loop(
    tracker: &Weak<MemoryQuotaTracker>,
    mut wakeup: mpsc::Receiver<()>,
) -> Result<TaskFinished, ReclaimCrashed> {
    loop {
        // We don't hold a strong reference while we loop around, so we detect
        // last drop of an actual client handle.
        {
            let Some(tracker) = tracker.upgrade() else {
                return Ok(TaskFinished);
            };

            inner_loop(&tracker).await?;
        }

        let Some(()) = wakeup.next().await else {
            // Sender dropped
            return Ok(TaskFinished);
        };
    }
}

/// Internal long-running task, handling reclamation
///
/// This is the entrypoint used by the rest of the `tracker`.
/// It handles logging of crashes.
pub(super) async fn task(
    tracker: Weak<MemoryQuotaTracker>,
    wakeup: mpsc::Receiver<()>,
) {
    match task_loop(&tracker, wakeup).await {
        Ok(TaskFinished) => {}
        Err(bug) => {
            let _: Option<()> = (|| {
                let tracker = tracker.upgrade()?;
                let mut state = tracker.state.lock().ok()?;
                state.total_used.set_poisoned();
                Some(())
            })();
            error_report!(bug, "memory tracker task failed");
        }
    }
}
