//! Code implementing version 1 proof-of-work for onion service hosts.
//!
//! Spec links:
//! * <https://spec.torproject.org/hspow-spec/common-protocol.html>
//! * <https://spec.torproject.org/hspow-spec/v1-equix.html>

use std::{
    collections::{BinaryHeap, HashMap},
    sync::{Arc, Mutex, RwLock},
    task::Waker,
    time::{Duration, SystemTime},
};

use arrayvec::ArrayVec;
use futures::task::SpawnExt;
use futures::{channel::mpsc, Stream};
use futures::{SinkExt, StreamExt};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use tor_basic_utils::RngExt as _;
use tor_cell::relaycell::hs::pow::{v1::ProofOfWorkV1, ProofOfWork};
use tor_checkable::timed::TimerangeBound;
use tor_hscrypto::{
    pk::HsBlindIdKey,
    pow::v1::{Effort, Instance, Seed, SeedHead, Solution, SolutionErrorV1, Verifier},
    time::TimePeriod,
};
use tor_keymgr::KeyMgr;
use tor_netdoc::doc::hsdesc::pow::{v1::PowParamsV1, PowParams};
use tor_persist::{
    hsnickname::HsNickname,
    state_dir::{InstanceRawSubdir, StorageHandle},
};
use tor_rtcompat::Runtime;

use crate::{
    rend_handshake, replay::PowNonceReplayLog, BlindIdPublicKeySpecifier, CreateIptError,
    RendRequest, ReplayError, StartupError,
};

use super::NewPowManager;

/// This is responsible for rotating Proof-of-Work seeds and doing verification of PoW solves.
pub(crate) struct PowManager<R>(RwLock<State<R>>);

/// Internal state for [`PowManager`].
struct State<R> {
    /// The [`Seed`]s for a given [`TimePeriod`]
    ///
    /// The [`ArrayVec`] contains the current and previous seed, and the [`SystemTime`] is when the
    /// current seed will expire.
    seeds: HashMap<TimePeriod, SeedsForTimePeriod>,

    /// Verifiers for all the seeds that exist in `seeds`.
    verifiers: HashMap<SeedHead, (Verifier, Mutex<PowNonceReplayLog>)>,

    /// The nickname for this hidden service.
    ///
    /// We need this so we can get the blinded keys from the [`KeyMgr`].
    nickname: HsNickname,

    /// Directory used to store nonce replay log.
    instance_dir: InstanceRawSubdir,

    /// Key manager.
    keymgr: Arc<KeyMgr>,

    /// Current suggested effort that we publish in the pow-params line.
    suggested_effort: Effort,

    /// Runtime
    runtime: R,

    /// Handle for storing state we need to persist to disk.
    storage_handle: StorageHandle<PowManagerStateRecord>,

    /// Queue to tell the publisher to re-upload a descriptor for a given TP, since we've rotated
    /// that seed.
    publisher_update_tx: mpsc::Sender<TimePeriod>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// Information about the current and previous [`Seed`] for a given [`TimePeriod`].
struct SeedsForTimePeriod {
    /// The previous and current [`Seed`].
    ///
    /// The last element in this array is the current seed.
    seeds: ArrayVec<Seed, 2>,

    /// When the current seed will expire.
    next_expiration_time: SystemTime,
}

#[derive(Debug)]
#[allow(unused)]
/// A PoW solve was invalid.
///
/// While this contains the reason for the failure, we probably just want to use that for
/// debugging, we shouldn't make any logical decisions based on what the particular error was.
pub(crate) enum PowSolveError {
    /// Seed head was not recognized, it may be expired.
    InvalidSeedHead,
    /// We have already seen a solve with this nonce
    NonceReplay(ReplayError),
    /// The bytes given as a solution do not form a valid Equi-X puzzle
    InvalidEquixSolution(SolutionErrorV1),
    /// The solution given was invalid.
    InvalidSolve(tor_hscrypto::pow::Error),
}

/// On-disk record of [`PowManager`] state.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PowManagerStateRecord {
    /// Seeds for each time period.
    ///
    /// Conceptually, this is a map between TimePeriod and SeedsForTimePeriod, but since TimePeriod
    /// can't be serialized to a string, it's not very simple to use serde to serialize it like
    /// that, so we instead store it as a list of tuples, and convert it to/from the map when
    /// saving/loading.
    seeds: Vec<(TimePeriod, SeedsForTimePeriod)>,
    // TODO POW: suggested_effort / etc should be serialized
}

impl<R: Runtime> State<R> {
    /// Make a [`PowManagerStateRecord`] for this state.
    pub(crate) fn to_record(&self) -> PowManagerStateRecord {
        PowManagerStateRecord {
            seeds: self.seeds.clone().into_iter().collect(),
        }
    }
}

/// How soon before a seed's expiration time we should rotate it and publish a new seed.
const SEED_EARLY_ROTATION_TIME: Duration = Duration::from_secs(60 * 5);

/// Minimum seed expiration time in minutes. See:
/// <https://spec.torproject.org/hspow-spec/v1-equix.html#parameter-descriptor>
const EXPIRATION_TIME_MINS_MIN: u64 = 105;

/// Maximum seed expiration time in minutes. See:
/// <https://spec.torproject.org/hspow-spec/v1-equix.html#parameter-descriptor>
const EXPIRATION_TIME_MINS_MAX: u64 = 120;

/// Enforce that early rotation time is less than or equal to min expiration time.
const _: () = assert!(
    SEED_EARLY_ROTATION_TIME.as_secs() <= EXPIRATION_TIME_MINS_MIN * 60,
    "Early rotation time must be less than minimum expiration time"
);

/// Enforce that min expiration time is less than or equal to max.
const _: () = assert!(
    EXPIRATION_TIME_MINS_MIN <= EXPIRATION_TIME_MINS_MAX,
    "Minimum expiration time must be less than or equal to max"
);

/// Depth of the queue used to signal the publisher that it needs to update a given time period.
///
/// 32 is likely way larger than we need but the messages are tiny so we might as well.
const PUBLISHER_UPDATE_QUEUE_DEPTH: usize = 32;

#[derive(Debug)]
#[allow(dead_code)] // We want to show fields in Debug even if we don't use them.
/// Internal error within the PoW subsystem.
pub(crate) enum InternalPowError {
    /// We don't have a key that is needed.
    MissingKey,
    /// Error in the underlying storage layer.
    StorageError,
    /// Error from the ReplayLog.
    CreateIptError(CreateIptError),
}

impl<R: Runtime> PowManager<R> {
    /// Create a new [`PowManager`].
    #[allow(clippy::new_ret_no_self)]
    pub(crate) fn new(
        runtime: R,
        nickname: HsNickname,
        instance_dir: InstanceRawSubdir,
        keymgr: Arc<KeyMgr>,
        storage_handle: StorageHandle<PowManagerStateRecord>,
    ) -> Result<NewPowManager<R>, StartupError> {
        let on_disk_state = storage_handle.load().map_err(StartupError::LoadState)?;
        let seeds = on_disk_state.map_or(vec![], |on_disk_state| on_disk_state.seeds);
        let seeds = seeds.into_iter().collect();

        // This queue is extremely small, and we only make one of it per onion service, so it's
        // fine to not use memquota tracking.
        let (publisher_update_tx, publisher_update_rx) =
            crate::mpsc_channel_no_memquota(PUBLISHER_UPDATE_QUEUE_DEPTH);

        let state = State {
            seeds,
            nickname,
            instance_dir,
            keymgr,
            publisher_update_tx,
            verifiers: HashMap::new(),
            suggested_effort: Effort::zero(),
            runtime: runtime.clone(),
            storage_handle,
        };
        let pow_manager = Arc::new(PowManager(RwLock::new(state)));

        let (rend_req_tx, rend_req_rx) = super::make_rend_queue();
        let rend_req_rx = RendRequestReceiver::new(runtime, pow_manager.clone(), rend_req_rx);

        Ok(NewPowManager {
            pow_manager,
            rend_req_tx,
            rend_req_rx: Box::pin(rend_req_rx),
            publisher_update_rx,
        })
    }

    /// Launch background task to rotate seeds.
    pub(crate) fn launch(self: &Arc<Self>) -> Result<(), StartupError> {
        let pow_manager = self.clone();
        let runtime = pow_manager.0.read().expect("Lock poisoned").runtime.clone();

        runtime
            .spawn(pow_manager.main_loop_task())
            .map_err(|cause| StartupError::Spawn {
                spawning: "pow manager",
                cause: cause.into(),
            })?;
        Ok(())
    }

    /// Main loop for rotating seeds.
    async fn main_loop_task(self: Arc<Self>) {
        let runtime = self.0.write().expect("Lock poisoned").runtime.clone();

        loop {
            let next_update_time = self.rotate_seeds_if_expiring().await;

            // A new TimePeriod that we don't know about (and thus that isn't in next_update_time)
            // might get added at any point. Making sure that our maximum delay is the minimum
            // amount of time that it might take for a seed to expire means that we can be sure
            // that we will rotate newly-added seeds properly.
            let max_delay =
                Duration::from_secs(EXPIRATION_TIME_MINS_MIN * 60) - SEED_EARLY_ROTATION_TIME;
            let delay = next_update_time
                .map(|x| x.duration_since(SystemTime::now()).unwrap_or(max_delay))
                .unwrap_or(max_delay)
                .min(max_delay);

            tracing::debug!(next_wakeup = ?delay, "Recalculated PoW seeds.");

            runtime.sleep(delay).await;
        }
    }

    /// Make a randomized seed expiration time.
    fn make_next_expiration_time<Rng: RngCore + CryptoRng>(rng: &mut Rng) -> SystemTime {
        SystemTime::now()
            + Duration::from_secs(
                60 * rng
                    .gen_range_checked(EXPIRATION_TIME_MINS_MIN..=EXPIRATION_TIME_MINS_MAX)
                    .expect("Can't generate expiration_time"),
            )
    }

    /// Make a ner [`Verifier`] for a given [`TimePeriod`] and [`Seed`].
    ///
    /// If a key is not available for this TP, returns None.
    ///
    /// This takes individual agruments instead of `&self` to avoid getting into any trouble with
    /// locking.
    fn make_verifier(
        keymgr: &Arc<KeyMgr>,
        nickname: HsNickname,
        time_period: TimePeriod,
        seed: Seed,
    ) -> Option<Verifier> {
        let blind_id_spec = BlindIdPublicKeySpecifier::new(nickname, time_period);
        let blind_id_key = match keymgr.get::<HsBlindIdKey>(&blind_id_spec) {
            Ok(blind_id_key) => blind_id_key,
            Err(err) => {
                tracing::warn!(?err, "KeyMgr error when getting blinded ID key for PoW");
                None
            }
        };
        let instance = Instance::new(blind_id_key?.id(), seed);
        Some(Verifier::new(instance))
    }

    /// Calculate a time when we want to rotate a seed, slightly before it expires, in order to
    /// ensure that clients don't ever download a seed that is already out of date.
    fn calculate_early_rotation_time(expiration_time: SystemTime) -> SystemTime {
        // Underflow cannot happen because:
        //
        // * We set the expiration time to the current time plus at least the minimum
        //   expiration time
        // * We know (backed up by a compile-time assertion) that SEED_EARLY_ROTATION_TIME is
        //   less than the minimum expiration time.
        //
        // Thus, the only way this subtraction can underflow is if the system time at the
        // moment we set the expiration time was before the epoch, which is not possible on
        // reasonable platforms.
        expiration_time
            .checked_sub(SEED_EARLY_ROTATION_TIME)
            .expect("PoW seed expiration underflow")
    }

    /// Rotate any seeds that will expire soon.
    ///
    /// This also pokes the publisher when needed to cause rotated seeds to be published.
    ///
    /// Returns the next time this function should be called again.
    async fn rotate_seeds_if_expiring(&self) -> Option<SystemTime> {
        let mut expired_verifiers = vec![];
        let mut new_verifiers = vec![];

        let mut update_times = vec![];
        let mut updated_tps = vec![];
        let mut expired_tps = vec![];

        let mut publisher_update_tx = {
            // TODO POW: get rng from the right place...
            let mut rng = rand::rng();

            let mut state = self.0.write().expect("Lock poisoned");

            let keymgr = state.keymgr.clone();
            let nickname = state.nickname.clone();

            for (time_period, info) in state.seeds.iter_mut() {
                let rotation_time = Self::calculate_early_rotation_time(info.next_expiration_time);
                update_times.push(rotation_time);

                if rotation_time <= SystemTime::now() {
                    let seed = Seed::new(&mut rng, None);
                    let verifier = match Self::make_verifier(
                        &keymgr,
                        nickname.clone(),
                        *time_period,
                        seed.clone(),
                    ) {
                        Some(verifier) => verifier,
                        None => {
                            // We use not having a key for a given TP as the signal that we should
                            // stop keeping track of seeds for that TP.
                            expired_tps.push(*time_period);
                            continue;
                        }
                    };

                    let expired_seed = if info.seeds.is_full() {
                        info.seeds.pop_at(0)
                    } else {
                        None
                    };
                    // .push() is safe, since we just made space above.
                    info.seeds.push(seed.clone());
                    info.next_expiration_time = Self::make_next_expiration_time(&mut rng);
                    update_times.push(info.next_expiration_time);

                    // Make a note to add the new verifier and remove the old one.
                    new_verifiers.push((seed, verifier));
                    if let Some(expired_seed) = expired_seed {
                        expired_verifiers.push(expired_seed.head());
                    }

                    // Tell the publisher to update this TP
                    updated_tps.push(*time_period);

                    tracing::debug!(time_period = ?time_period, "Rotated PoW seed");
                }
            }

            for time_period in expired_tps {
                if let Some(seeds) = state.seeds.remove(&time_period) {
                    for seed in seeds.seeds {
                        state.verifiers.remove(&seed.head());
                    }
                }
            }

            for (seed, verifier) in new_verifiers {
                let replay_log = Mutex::new(
                    PowNonceReplayLog::new_logged(&state.instance_dir, &seed)
                        .expect("Couldn't make ReplayLog."),
                );
                state.verifiers.insert(seed.head(), (verifier, replay_log));
            }

            for seed_head in expired_verifiers {
                state.verifiers.remove(&seed_head);
            }

            let record = state.to_record();
            if let Err(err) = state.storage_handle.store(&record) {
                tracing::warn!(?err, "Error saving PoW state");
            }

            state.publisher_update_tx.clone()
        };

        for time_period in updated_tps {
            if let Err(err) = publisher_update_tx.send(time_period).await {
                tracing::warn!(?err, "Couldn't send update message to publisher");
            }
        }

        update_times.iter().min().cloned()
    }

    /// Get [`PowParams`] for a given [`TimePeriod`].
    ///
    /// If we don't have any [`Seed`]s for the requested period, generate them. This is the only
    /// way that [`PowManager`] learns about new [`TimePeriod`]s.
    pub(crate) fn get_pow_params(
        self: &Arc<Self>,
        time_period: TimePeriod,
    ) -> Result<PowParams, InternalPowError> {
        let (seed_and_expiration, suggested_effort) = {
            let state = self.0.read().expect("Lock poisoned");
            let seed = state
                .seeds
                .get(&time_period)
                .and_then(|x| Some((x.seeds.last()?.clone(), x.next_expiration_time)));
            (seed, state.suggested_effort)
        };

        let (seed, expiration) = match seed_and_expiration {
            Some(seed) => seed,
            None => {
                // We don't have a seed for this time period, so we need to generate one.

                // TODO POW: get rng from the right place...
                let mut rng = rand::rng();

                let seed = Seed::new(&mut rng, None);
                let next_expiration_time = Self::make_next_expiration_time(&mut rng);

                let mut seeds = ArrayVec::new();
                seeds.push(seed.clone());

                let mut state = self.0.write().expect("Lock poisoned");

                state.seeds.insert(
                    time_period,
                    SeedsForTimePeriod {
                        seeds,
                        next_expiration_time,
                    },
                );

                let verifier = Self::make_verifier(
                    &state.keymgr,
                    state.nickname.clone(),
                    time_period,
                    seed.clone(),
                )
                .ok_or(InternalPowError::MissingKey)?;

                let replay_log = Mutex::new(
                    PowNonceReplayLog::new_logged(&state.instance_dir, &seed)
                        .map_err(InternalPowError::CreateIptError)?,
                );
                state.verifiers.insert(seed.head(), (verifier, replay_log));

                let record = state.to_record();
                state
                    .storage_handle
                    .store(&record)
                    .map_err(|_| InternalPowError::StorageError)?;

                (seed, next_expiration_time)
            }
        };

        Ok(PowParams::V1(PowParamsV1::new(
            TimerangeBound::new(seed, ..expiration),
            suggested_effort,
        )))
    }

    /// Verify a PoW solve.
    fn check_solve(self: &Arc<Self>, solve: &ProofOfWorkV1) -> Result<(), PowSolveError> {
        // TODO POW: This puts the nonce in the replay structure before we check if the solve is
        // valid, which could be a problem — a potential attack would be to send a large number of
        // invalid solves with the hope of causing collisions with valid requests. This is probably
        // highly impractical, but we should think through it before stabilizing PoW.
        {
            let state = self.0.write().expect("Lock poisoned");
            let mut replay_log = match state.verifiers.get(&solve.seed_head()) {
                Some((_, replay_log)) => replay_log.lock().expect("Lock poisoned"),
                None => return Err(PowSolveError::InvalidSeedHead),
            };
            replay_log
                .check_for_replay(solve.nonce())
                .map_err(PowSolveError::NonceReplay)?;
        }

        // TODO: Once RwLock::downgrade is stabilized, it would make sense to use it here...

        let state = self.0.read().expect("Lock poisoned");
        let verifier = match state.verifiers.get(&solve.seed_head()) {
            Some((verifier, _)) => verifier,
            None => return Err(PowSolveError::InvalidSeedHead),
        };

        let solution = match Solution::try_from_bytes(
            solve.nonce().clone(),
            solve.effort(),
            solve.seed_head(),
            solve.solution(),
        ) {
            Ok(solution) => solution,
            Err(err) => return Err(PowSolveError::InvalidEquixSolution(err)),
        };

        match verifier.check(&solution) {
            Ok(()) => Ok(()),
            Err(err) => Err(PowSolveError::InvalidSolve(err)),
        }
    }
}

/// Wrapper around [`RendRequest`] that implements [`std::cmp::Ord`] to sort by [`Effort`].
#[derive(Debug)]
struct RendRequestOrdByEffort {
    /// The underlying request.
    request: RendRequest,
    /// The proof-of-work options, if given.
    pow: Option<ProofOfWorkV1>,
}

impl RendRequestOrdByEffort {
    /// Create a new [`RendRequestOrdByEffort`].
    fn new(request: RendRequest) -> Result<Self, rend_handshake::IntroRequestError> {
        let pow = match request
            .intro_request()?
            .intro_payload()
            .proof_of_work_extension()
            .cloned()
        {
            Some(ProofOfWork::V1(pow)) => Some(pow),
            None | Some(_) => None,
        };

        Ok(Self { request, pow })
    }
}

impl Ord for RendRequestOrdByEffort {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let self_effort = self.pow.as_ref().map_or(Effort::zero(), |pow| pow.effort());
        let other_effort = other
            .pow
            .as_ref()
            .map_or(Effort::zero(), |pow| pow.effort());
        self_effort.cmp(&other_effort)
    }
}

impl PartialOrd for RendRequestOrdByEffort {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for RendRequestOrdByEffort {
    fn eq(&self, other: &Self) -> bool {
        let self_effort = self.pow.as_ref().map_or(Effort::zero(), |pow| pow.effort());
        let other_effort = other
            .pow
            .as_ref()
            .map_or(Effort::zero(), |pow| pow.effort());
        self_effort == other_effort
    }
}

impl Eq for RendRequestOrdByEffort {}

/// Implements [`Stream`] for incoming [`RendRequest`]s, using a priority queue system to dequeue
/// high-[`Effort`] requests first.
///
/// This is implemented on top of a [`mpsc::Receiver`]. There is a thread that dequeues from the
/// [`mpsc::Receiver`], checks the PoW solve, and if it is correct, adds it to a [`BinaryHeap`],
/// which the [`Stream`] implementation reads from.
///
/// This is not particularly optimized — queueing and dequeuing use a [`Mutex`], so there may be
/// some contention there. It's possible there may be some fancy lockless (or more optimized)
/// priorty queue that we could use, but we should properly benchmark things before trying to make
/// a optimization like that.
#[derive(Clone)]
pub(crate) struct RendRequestReceiver(Arc<Mutex<RendRequestReceiverInner>>);

/// Inner implementation for [`RendRequestReceiver`].
struct RendRequestReceiverInner {
    /// Internal priority queue of requests.
    queue: BinaryHeap<RendRequestOrdByEffort>,

    /// Waker to inform async readers when there is a new message on the queue.
    waker: Option<Waker>,
}

impl RendRequestReceiver {
    /// Create a new [`RendRequestReceiver`].
    fn new<R: Runtime>(
        runtime: R,
        pow_manager: Arc<PowManager<R>>,
        inner_receiver: mpsc::Receiver<RendRequest>,
    ) -> Self {
        let receiver = RendRequestReceiver(Arc::new(Mutex::new(RendRequestReceiverInner {
            queue: BinaryHeap::new(),
            waker: None,
        })));
        let receiver_clone = receiver.clone();
        let accept_thread = runtime.clone().spawn_blocking(move || {
            receiver_clone.accept_loop(&runtime, &pow_manager, inner_receiver);
        });
        drop(accept_thread);
        receiver
    }

    /// Loop to accept message from the wrapped [`mpsc::Receiver`], validate PoW sovles, and
    /// enqueue onto the priority queue.
    fn accept_loop<R: Runtime>(
        self,
        runtime: &R,
        pow_manager: &Arc<PowManager<R>>,
        mut receiver: mpsc::Receiver<RendRequest>,
    ) {
        loop {
            let rend_request = runtime
                .reenter_block_on(receiver.next())
                .expect("Other side of RendRequest queue hung up");
            let rend_request = match RendRequestOrdByEffort::new(rend_request) {
                Ok(rend_request) => rend_request,
                Err(err) => {
                    tracing::trace!(?err, "Error processing RendRequest");
                    continue;
                }
            };

            if let Some(ref pow) = rend_request.pow {
                if let Err(err) = pow_manager.check_solve(pow) {
                    tracing::debug!(?err, "PoW verification failed");
                    continue;
                }
            }

            let mut inner = self.0.lock().expect("Lock poisened");
            inner.queue.push(rend_request);
            if let Some(waker) = &inner.waker {
                waker.wake_by_ref();
            }
        }
    }
}

impl Stream for RendRequestReceiver {
    type Item = RendRequest;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let mut inner = self.get_mut().0.lock().expect("Lock poisened");
        match inner.queue.pop() {
            Some(item) => std::task::Poll::Ready(Some(item.request)),
            None => {
                inner.waker = Some(cx.waker().clone());
                std::task::Poll::Pending
            }
        }
    }
}
