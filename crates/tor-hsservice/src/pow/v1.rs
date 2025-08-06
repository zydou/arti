//! Code implementing version 1 proof-of-work for onion service hosts.
//!
//! Spec links:
//! * <https://spec.torproject.org/hspow-spec/common-protocol.html>
//! * <https://spec.torproject.org/hspow-spec/v1-equix.html>

use std::{
    collections::{BTreeSet, HashMap},
    sync::{Arc, Mutex, RwLock},
    task::Waker,
    time::{Duration, Instant, SystemTime},
};

use arrayvec::ArrayVec;
use futures::task::SpawnExt;
use futures::{channel::mpsc, Stream};
use futures::{SinkExt, StreamExt};
use num_traits::FromPrimitive;
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
use tor_netdir::{params::NetParameters, NetDirProvider, NetdirProviderShutdown};
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

/// Proof-of-Work manager type alias for production, using concrete [`RendRequest`].
pub(crate) type PowManager<R> = PowManagerGeneric<R, RendRequest>;

/// This is responsible for rotating Proof-of-Work seeds and doing verification of PoW solves.
pub(crate) struct PowManagerGeneric<R, Q>(RwLock<State<R, Q>>);

/// Internal state for [`PowManagerGeneric`].
struct State<R, Q> {
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
    ///
    /// This is only read by the PowManagerGeneric, and is written to by the [`RendRequestReceiver`].
    suggested_effort: Arc<Mutex<Effort>>,

    /// Runtime
    runtime: R,

    /// Handle for storing state we need to persist to disk.
    storage_handle: StorageHandle<PowManagerStateRecord>,

    /// Queue to tell the publisher to re-upload a descriptor for a given TP, since we've rotated
    /// that seed.
    publisher_update_tx: mpsc::Sender<TimePeriod>,

    /// The [`RendRequestReceiver`], which contains the queue of [`RendRequest`]s.
    ///
    /// We need a reference to this in order to tell it when to update the suggested_effort value.
    rend_request_rx: RendRequestReceiver<R, Q>,

    /// [`NetDirProvider`], used for getting consensus parameters for configuration values.
    netdir_provider: Arc<dyn NetDirProvider>,
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

/// On-disk record of [`PowManagerGeneric`] state.
#[derive(Serialize, Deserialize, Debug, Default)]
pub(crate) struct PowManagerStateRecord {
    /// Seeds for each time period.
    ///
    /// Conceptually, this is a map between TimePeriod and SeedsForTimePeriod, but since TimePeriod
    /// can't be serialized to a string, it's not very simple to use serde to serialize it like
    /// that, so we instead store it as a list of tuples, and convert it to/from the map when
    /// saving/loading.
    seeds: Vec<(TimePeriod, SeedsForTimePeriod)>,

    /// Most recently published suggested_effort value.
    #[serde(default)]
    suggested_effort: Effort,
    // TODO POW: Consider whether we should persist other values from RendRequestReceiver.
}

impl<R: Runtime, Q> State<R, Q> {
    /// Make a [`PowManagerStateRecord`] for this state.
    pub(crate) fn to_record(&self) -> PowManagerStateRecord {
        PowManagerStateRecord {
            seeds: self.seeds.clone().into_iter().collect(),
            suggested_effort: *self.suggested_effort.lock().expect("Lock poisoned"),
        }
    }
}

/// Maximum depth of the queue of [`RendRequest`]s.
// TODO POW: Allow this to be changed in onion service config.
// Each request should take a few KB, so a queue of this depth should only take up ~32MB in the
// worst case.
//
// The "a few KB" measurement was done by using the get_size crate to
// measure the size of the RendRequest object, but due to limitations in
// that crate (and in my willingness to go implement ways of checking the
// size of external types), it might be somewhat off. The ~32MB value is
// based on the idea that each RendRequest is 4KB.
const REND_REQUEST_QUEUE_MAX_DEPTH: usize = 8192;

/// How frequently the suggested effort should be recalculated.
const HS_UPDATE_PERIOD: Duration = Duration::from_secs(300);

/// When the suggested effort has changed by less than this much, we don't republish it.
///
/// Specified as "15 percent" in <https://spec.torproject.org/hspow-spec/common-protocol.html>
///
/// However, we may want to make this configurable in the future.
const SUGGESTED_EFFORT_DEADZONE: f64 = 0.15;

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
    /// NetDirProvider has shut down
    NetdirProviderShutdown(NetdirProviderShutdown),
}

impl<R: Runtime, Q: MockableRendRequest + Send + 'static> PowManagerGeneric<R, Q> {
    /// Create a new [`PowManagerGeneric`].
    #[allow(clippy::new_ret_no_self)]
    pub(crate) fn new(
        runtime: R,
        nickname: HsNickname,
        instance_dir: InstanceRawSubdir,
        keymgr: Arc<KeyMgr>,
        storage_handle: StorageHandle<PowManagerStateRecord>,
        netdir_provider: Arc<dyn NetDirProvider>,
    ) -> Result<NewPowManager<R>, StartupError> {
        let on_disk_state = storage_handle
            .load()
            .map_err(StartupError::LoadState)?
            .unwrap_or(PowManagerStateRecord::default());

        let seeds = on_disk_state.seeds.into_iter().collect();
        let suggested_effort = Arc::new(Mutex::new(on_disk_state.suggested_effort));

        // This queue is extremely small, and we only make one of it per onion service, so it's
        // fine to not use memquota tracking.
        let (publisher_update_tx, publisher_update_rx) =
            crate::mpsc_channel_no_memquota(PUBLISHER_UPDATE_QUEUE_DEPTH);

        let (rend_req_tx, rend_req_rx_channel) = super::make_rend_queue();
        let rend_req_rx = RendRequestReceiver::new(
            runtime.clone(),
            suggested_effort.clone(),
            netdir_provider.clone(),
        );

        let state = State {
            seeds,
            nickname,
            instance_dir,
            keymgr,
            publisher_update_tx,
            verifiers: HashMap::new(),
            suggested_effort: suggested_effort.clone(),
            runtime: runtime.clone(),
            storage_handle,
            rend_request_rx: rend_req_rx.clone(),
            netdir_provider,
        };
        let pow_manager = Arc::new(PowManagerGeneric(RwLock::new(state)));

        rend_req_rx.start_accept_thread(runtime, pow_manager.clone(), rend_req_rx_channel);

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
            .spawn(pow_manager.main_loop_error_wrapper())
            .map_err(|cause| StartupError::Spawn {
                spawning: "pow manager",
                cause: cause.into(),
            })?;
        Ok(())
    }

    /// Run [`Self::main_loop_task`], reporting any errors.
    async fn main_loop_error_wrapper(self: Arc<Self>) {
        if let Err(err) = self.clone().main_loop_task().await {
            tracing::warn!(?err, "PoW main loop error!");
        }
    }

    /// Main loop for rotating seeds.
    async fn main_loop_task(self: Arc<Self>) -> Result<(), InternalPowError> {
        let runtime = self.0.write().expect("Lock poisoned").runtime.clone();

        let mut last_suggested_effort_update = runtime.now();
        let mut last_published_suggested_effort: u32 = (*self
            .0
            .read()
            .expect("Lock poisoned")
            .suggested_effort
            .lock()
            .expect("Lock poisoned"))
        .into();

        let netdir_provider = self
            .0
            .read()
            .expect("Lock poisoned")
            .netdir_provider
            .clone();
        let net_params = netdir_provider
            .wait_for_netdir(tor_netdir::Timeliness::Timely)
            .await
            .map_err(InternalPowError::NetdirProviderShutdown)?
            .params()
            .clone();

        loop {
            let next_update_time = self.rotate_seeds_if_expiring().await;

            // Update the suggested effort, if needed
            if runtime.now() - last_suggested_effort_update >= HS_UPDATE_PERIOD {
                let (tps_to_update, mut publisher_update_tx) = {
                    let mut tps_to_update = vec![];

                    let inner = self.0.read().expect("Lock poisoned");

                    inner.rend_request_rx.update_suggested_effort(&net_params);
                    last_suggested_effort_update = runtime.now();
                    let new_suggested_effort: u32 =
                        (*inner.suggested_effort.lock().expect("Lock poisoned")).into();

                    let percent_change =
                        f64::from(new_suggested_effort - last_published_suggested_effort)
                            / f64::from(last_published_suggested_effort);
                    if percent_change.abs() >= SUGGESTED_EFFORT_DEADZONE {
                        last_published_suggested_effort = new_suggested_effort;

                        tps_to_update = inner.seeds.iter().map(|x| *x.0).collect();
                    }

                    let publisher_update_tx = inner.publisher_update_tx.clone();
                    (tps_to_update, publisher_update_tx)
                };

                for time_period in tps_to_update {
                    let _ = publisher_update_tx.send(time_period).await;
                }
            }

            let suggested_effort_update_delay =
                HS_UPDATE_PERIOD - (runtime.now() - last_suggested_effort_update);

            // A new TimePeriod that we don't know about (and thus that isn't in next_update_time)
            // might get added at any point. Making sure that our maximum delay is the minimum
            // amount of time that it might take for a seed to expire means that we can be sure
            // that we will rotate newly-added seeds properly.
            let max_delay =
                Duration::from_secs(EXPIRATION_TIME_MINS_MIN * 60) - SEED_EARLY_ROTATION_TIME;
            let delay = next_update_time
                .map(|x| x.duration_since(SystemTime::now()).unwrap_or(max_delay))
                .unwrap_or(max_delay)
                .min(max_delay)
                .min(suggested_effort_update_delay);

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
    /// This takes individual arguments instead of `&self` to avoid getting into any trouble with
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
    #[allow(clippy::cognitive_complexity)]
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
    /// way that [`PowManagerGeneric`] learns about new [`TimePeriod`]s.
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
            let suggested_effort = *state.suggested_effort.lock().expect("Lock poisoned");
            (seed, suggested_effort)
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

/// Trait to allow mocking PowManagerGeneric in tests.
trait MockablePowManager {
    /// Verify a PoW solve.
    fn check_solve(self: &Arc<Self>, solve: &ProofOfWorkV1) -> Result<(), PowSolveError>;
}

impl<R: Runtime> MockablePowManager for PowManager<R> {
    fn check_solve(self: &Arc<Self>, solve: &ProofOfWorkV1) -> Result<(), PowSolveError> {
        PowManager::check_solve(self, solve)
    }
}

/// Trait to allow mocking RendRequest in tests.
pub(crate) trait MockableRendRequest {
    /// Get the proof-of-work extension associated with this request.
    fn proof_of_work(&self) -> Result<Option<&ProofOfWork>, rend_handshake::IntroRequestError>;
}

impl MockableRendRequest for RendRequest {
    fn proof_of_work(&self) -> Result<Option<&ProofOfWork>, rend_handshake::IntroRequestError> {
        Ok(self
            .intro_request()?
            .intro_payload()
            .proof_of_work_extension())
    }
}

/// Wrapper around [`RendRequest`] that implements [`std::cmp::Ord`] to sort by [`Effort`] and time.
#[derive(Debug)]
struct RendRequestOrdByEffort<Q> {
    /// The underlying request.
    request: Q,
    /// The proof-of-work options, if given.
    pow: Option<ProofOfWorkV1>,
    /// When this request was received, used for ordreing if the effort values are the same.
    recv_time: Instant,
    /// Unique number for this request, which is used for ordering among requests with the same
    /// timestamp.
    ///
    /// This is intended to be monotonically increasing, although it may overflow. Overflows are
    /// not handled in any special way, given that they are a edge case of an edge case, and
    /// ordering among requests that came in at the same instant is not important.
    request_num: u64,
}

impl<Q: MockableRendRequest> RendRequestOrdByEffort<Q> {
    /// Create a new [`RendRequestOrdByEffort`].
    fn new(
        request: Q,
        max_effort: Effort,
        request_num: u64,
    ) -> Result<Self, rend_handshake::IntroRequestError> {
        let pow = match request.proof_of_work()?.cloned() {
            Some(ProofOfWork::V1(pow)) => Some(pow.cap_effort(max_effort)),
            None | Some(_) => None,
        };

        Ok(Self {
            request,
            pow,
            recv_time: Instant::now(),
            request_num,
        })
    }
}

impl<Q: MockableRendRequest> Ord for RendRequestOrdByEffort<Q> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let self_effort = self.pow.as_ref().map_or(Effort::zero(), |pow| pow.effort());
        let other_effort = other
            .pow
            .as_ref()
            .map_or(Effort::zero(), |pow| pow.effort());
        match self_effort.cmp(&other_effort) {
            std::cmp::Ordering::Equal => {
                // Flip ordering, since we want the oldest ones to be handled first.
                match other.recv_time.cmp(&self.recv_time) {
                    // Use request_num as a final tiebreaker, also flipping ordering (since
                    // lower-numbered requests should be older and thus come first)
                    std::cmp::Ordering::Equal => other.request_num.cmp(&self.request_num),
                    not_equal => not_equal,
                }
            }
            not_equal => not_equal,
        }
    }
}

impl<Q: MockableRendRequest> PartialOrd for RendRequestOrdByEffort<Q> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<Q: MockableRendRequest> PartialEq for RendRequestOrdByEffort<Q> {
    fn eq(&self, other: &Self) -> bool {
        let self_effort = self.pow.as_ref().map_or(Effort::zero(), |pow| pow.effort());
        let other_effort = other
            .pow
            .as_ref()
            .map_or(Effort::zero(), |pow| pow.effort());
        self_effort == other_effort && self.recv_time == other.recv_time
    }
}

impl<Q: MockableRendRequest> Eq for RendRequestOrdByEffort<Q> {}

/// Implements [`Stream`] for incoming [`RendRequest`]s, using a priority queue system to dequeue
/// high-[`Effort`] requests first.
///
/// This is implemented on top of a [`mpsc::Receiver`]. There is a thread that dequeues from the
/// [`mpsc::Receiver`], checks the PoW solve, and if it is correct, adds it to a [`BTreeSet`],
/// which the [`Stream`] implementation reads from.
///
/// This is not particularly optimized — queueing and dequeuing use a [`Mutex`], so there may be
/// some contention there. It's possible there may be some fancy lockless (or more optimized)
/// priority queue that we could use, but we should properly benchmark things before trying to make
/// a optimization like that.
pub(crate) struct RendRequestReceiver<R, Q>(Arc<Mutex<RendRequestReceiverInner<R, Q>>>);

impl<R, Q> Clone for RendRequestReceiver<R, Q> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

/// Inner implementation for [`RendRequestReceiver`].
struct RendRequestReceiverInner<R, Q> {
    /// Internal priority queue of requests.
    queue: BTreeSet<RendRequestOrdByEffort<Q>>,

    /// Waker to inform async readers when there is a new message on the queue.
    waker: Option<Waker>,

    /// Runtime, used to get current time in a testable way.
    runtime: R,

    /// [`NetDirProvider`], for getting configuration values in consensus parameters.
    netdir_provider: Arc<dyn NetDirProvider>,

    /// When the current update period started.
    update_period_start: Instant,
    /// Number of requests that were enqueued during the current update period, and had an effort
    /// greater than or equal to the suggested effort.
    num_enqueued_gte_suggested: usize,
    /// Number of requests that were dequeued during the current update period.
    num_dequeued: u32,
    /// Amount of time during the current update period that we spent with no requests in the
    /// queue.
    idle_time: Duration,
    /// Time that the queue last went from having items in it to not having items in it, or vice
    /// versa. This is used to update idle_time.
    last_transition: Instant,
    /// Sum of all effort values that were validated and enqueued during the current update period.
    total_effort: u64,

    /// Most recent published suggested effort value.
    ///
    /// We write to this, which is then published in the pow-params line by [`PowManagerGeneric`].
    suggested_effort: Arc<Mutex<Effort>>,
}

impl<R: Runtime, Q: MockableRendRequest + Send + 'static> RendRequestReceiver<R, Q> {
    /// Create a new [`RendRequestReceiver`].
    fn new(
        runtime: R,
        suggested_effort: Arc<Mutex<Effort>>,
        netdir_provider: Arc<dyn NetDirProvider>,
    ) -> Self {
        let now = runtime.now();
        RendRequestReceiver(Arc::new(Mutex::new(RendRequestReceiverInner {
            queue: BTreeSet::new(),
            waker: None,
            runtime,
            netdir_provider,
            update_period_start: now,
            num_enqueued_gte_suggested: 0,
            num_dequeued: 0,
            idle_time: Duration::new(0, 0),
            last_transition: now,
            total_effort: 0,
            suggested_effort,
        })))
    }

    // spawn_blocking executes immediately, but some of our abstractions make clippy not
    // realize this.
    #[allow(clippy::let_underscore_future)]
    /// Start helper thread to accept and validate [`RendRequest`]s.
    fn start_accept_thread<P: MockablePowManager + Send + Sync + 'static>(
        &self,
        runtime: R,
        pow_manager: Arc<P>,
        inner_receiver: mpsc::Receiver<Q>,
    ) {
        let receiver_clone = self.clone();
        let runtime_clone = runtime.clone();
        let _ = runtime.clone().spawn_blocking(move || {
            if let Err(err) =
                receiver_clone.accept_loop(&runtime_clone, &pow_manager, inner_receiver)
            {
                tracing::warn!(?err, "PoW accept loop error!");
            }
        });

        let receiver_clone = self.clone();
        let _ = runtime.clone().spawn_blocking(move || {
            if let Err(err) = receiver_clone.expire_old_requests_loop(&runtime) {
                tracing::warn!(?err, "PoW request expiration loop error!");
            }
        });
    }

    /// Update the suggested effort value, as per the algorithm in prop362
    fn update_suggested_effort(&self, net_params: &NetParameters) {
        let mut inner = self.0.lock().expect("Lock poisoned");

        let decay_adjustment_fraction = net_params.hs_pow_v1_default_decay_adjustment.as_fraction();

        if inner.num_dequeued != 0 {
            let update_period_duration = inner.runtime.now() - inner.update_period_start;
            let avg_request_duration = update_period_duration / inner.num_dequeued;
            if inner.queue.is_empty() {
                let now = inner.runtime.now();
                let last_transition = inner.last_transition;
                inner.idle_time += now - last_transition;
            }
            let adjusted_idle_time = Duration::saturating_sub(
                inner.idle_time,
                avg_request_duration * inner.queue.len().try_into().expect("Queue too large."),
            );
            // TODO: use as_millis_f64 when stable
            let idle_fraction = f64::from_u128(adjusted_idle_time.as_millis())
                .expect("Conversion error")
                / f64::from_u128(update_period_duration.as_millis()).expect("Conversion error");
            let busy_fraction = 1.0 - idle_fraction;

            let mut suggested_effort = inner.suggested_effort.lock().expect("Lock poisoned");
            let suggested_effort_inner: u32 = (*suggested_effort).into();

            if busy_fraction == 0.0 {
                let new_suggested_effort =
                    u32::from_f64(f64::from(suggested_effort_inner) * decay_adjustment_fraction)
                        .expect("Conversion error");
                *suggested_effort = Effort::from(new_suggested_effort);
            } else {
                let theoretical_num_dequeued =
                    f64::from(inner.num_dequeued) * (1.0 / busy_fraction);
                let num_enqueued_gte_suggested_f64 =
                    f64::from_usize(inner.num_enqueued_gte_suggested).expect("Conversion error");

                if num_enqueued_gte_suggested_f64 >= theoretical_num_dequeued {
                    let effort_per_dequeued = u32::from_f64(
                        f64::from_u64(inner.total_effort).expect("Conversion error")
                            / f64::from(inner.num_dequeued),
                    )
                    .expect("Conversion error");
                    *suggested_effort = Effort::from(std::cmp::max(
                        effort_per_dequeued,
                        suggested_effort_inner + 1,
                    ));
                } else {
                    let decay = num_enqueued_gte_suggested_f64 / theoretical_num_dequeued;
                    let adjusted_decay = decay + ((1.0 - decay) * decay_adjustment_fraction);
                    let new_suggested_effort =
                        u32::from_f64(f64::from(suggested_effort_inner) * adjusted_decay)
                            .expect("Conversion error");
                    *suggested_effort = Effort::from(new_suggested_effort);
                }
            }

            drop(suggested_effort);
        }

        let now = inner.runtime.now();

        inner.update_period_start = now;
        inner.num_enqueued_gte_suggested = 0;
        inner.num_dequeued = 0;
        inner.idle_time = Duration::new(0, 0);
        inner.last_transition = now;
        inner.total_effort = 0;
    }

    /// Loop to accept message from the wrapped [`mpsc::Receiver`], validate PoW sovles, and
    /// enqueue onto the priority queue.
    #[allow(clippy::cognitive_complexity)]
    fn accept_loop<P: MockablePowManager>(
        self,
        runtime: &R,
        pow_manager: &Arc<P>,
        mut receiver: mpsc::Receiver<Q>,
    ) -> Result<(), InternalPowError> {
        let mut request_num = 0;

        let netdir_provider = self
            .0
            .lock()
            .expect("Lock poisoned")
            .netdir_provider
            .clone();
        let net_params = runtime
            .reenter_block_on(netdir_provider.wait_for_netdir(tor_netdir::Timeliness::Timely))
            .map_err(InternalPowError::NetdirProviderShutdown)?
            .params()
            .clone();

        let max_effort: u32 = net_params
            .hs_pow_v1_max_effort
            .get()
            .try_into()
            .expect("Bounded i32 not in range of u32?!");
        let max_effort = Effort::from(max_effort);

        loop {
            let rend_request = runtime
                .reenter_block_on(receiver.next())
                .expect("Other side of RendRequest queue hung up");
            let rend_request =
                match RendRequestOrdByEffort::new(rend_request, max_effort, request_num) {
                    Ok(rend_request) => rend_request,
                    Err(err) => {
                        tracing::trace!(?err, "Error processing RendRequest");
                        continue;
                    }
                };

            request_num = request_num.wrapping_add(1);

            if let Some(ref pow) = rend_request.pow {
                if let Err(err) = pow_manager.check_solve(pow) {
                    tracing::debug!(?err, "PoW verification failed");
                    continue;
                }
            }

            let mut inner = self.0.lock().expect("Lock poisoned");
            if inner.queue.is_empty() {
                let now = runtime.now();
                let last_transition = inner.last_transition;
                inner.idle_time += now - last_transition;
                inner.last_transition = now;
            }
            if let Some(ref request_pow) = rend_request.pow {
                if request_pow.effort() >= *inner.suggested_effort.lock().expect("Lock poisoned") {
                    inner.num_enqueued_gte_suggested += 1;
                    let effort: u32 = request_pow.effort().into();
                    if let Some(total_effort) = inner.total_effort.checked_add(effort.into()) {
                        inner.total_effort = total_effort;
                    } else {
                        tracing::warn!("PoW total_effort would overflow");
                        inner.total_effort = u64::MAX;
                    }
                }
            }
            if inner.queue.len() >= REND_REQUEST_QUEUE_MAX_DEPTH {
                let dropped_request = inner.queue.pop_first();
                tracing::debug!(
                    dropped_effort = ?dropped_request.map(|x| x.pow.map(|x| x.effort())),
                    "RendRequest queue full, dropping request."
                );
            }
            inner.queue.insert(rend_request);
            if let Some(waker) = &inner.waker {
                waker.wake_by_ref();
            }
        }
    }

    /// Loop to check for messages that are older than our timeout and remove them from the queue.
    fn expire_old_requests_loop(self, runtime: &R) -> Result<(), InternalPowError> {
        let netdir_provider = self
            .0
            .lock()
            .expect("Lock poisoned")
            .netdir_provider
            .clone();
        let net_params = runtime
            .reenter_block_on(netdir_provider.wait_for_netdir(tor_netdir::Timeliness::Timely))
            .map_err(InternalPowError::NetdirProviderShutdown)?
            .params()
            .clone();

        let max_age: Duration = net_params
            .hs_pow_v1_service_intro_timeout
            .try_into()
            .expect(
                "Couldn't convert HiddenServiceProofOfWorkV1ServiceIntroTimeoutSeconds to Duration",
            );

        loop {
            let inner = self.0.lock().expect("Lock poisoned");
            // Wake up when the oldest request will reach the expiration age, or, if there are no
            // items currently in the queue, wait for the maximum age.
            let wait_time = inner
                .queue
                .first()
                .map(|r| {
                    max_age.saturating_sub(runtime.now().saturating_duration_since(r.recv_time))
                })
                .unwrap_or(max_age);
            drop(inner);

            runtime.reenter_block_on(runtime.sleep(wait_time));

            tracing::trace!("Expiring timed out RendRequests");
            let mut inner = self.0.lock().expect("Lock poisoned");
            let now = runtime.now();
            inner.queue.retain(|r| now - r.recv_time < max_age);
        }
    }
}

impl<R: Runtime, Q: MockableRendRequest> Stream for RendRequestReceiver<R, Q> {
    type Item = Q;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let mut inner = self.get_mut().0.lock().expect("Lock poisoned");
        match inner.queue.pop_last() {
            Some(item) => {
                inner.num_dequeued += 1;
                if inner.queue.is_empty() {
                    inner.last_transition = inner.runtime.now();
                }
                std::task::Poll::Ready(Some(item.request))
            }
            None => {
                inner.waker = Some(cx.waker().clone());
                std::task::Poll::Pending
            }
        }
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use futures::FutureExt;
    use tor_hscrypto::pow::v1::{Nonce, SolutionByteArray};
    use tor_netdir::{testnet, testprovider::TestNetDirProvider};
    use tor_rtmock::MockRuntime;

    struct MockPowManager;

    #[derive(Debug)]
    struct MockRendRequest {
        id: usize,
        pow: Option<ProofOfWork>,
    }

    impl MockablePowManager for MockPowManager {
        fn check_solve(self: &Arc<Self>, solve: &ProofOfWorkV1) -> Result<(), PowSolveError> {
            // For testing, treat all zeros as the only valid solve. Error is chosen arbitrarily.
            if solve.solution() == &[0; 16] {
                Ok(())
            } else {
                Err(PowSolveError::InvalidSeedHead)
            }
        }
    }

    impl MockableRendRequest for MockRendRequest {
        fn proof_of_work(&self) -> Result<Option<&ProofOfWork>, rend_handshake::IntroRequestError> {
            Ok(self.pow.as_ref())
        }
    }

    fn make_req(id: usize, effort: Option<u32>) -> MockRendRequest {
        MockRendRequest {
            id,
            pow: effort.map(|e| {
                ProofOfWork::V1(ProofOfWorkV1::new(
                    Nonce::from([0; 16]),
                    Effort::from(e),
                    SeedHead::from([0; 4]),
                    SolutionByteArray::from([0; 16]),
                ))
            }),
        }
    }

    fn make_req_invalid(id: usize, effort: u32) -> MockRendRequest {
        MockRendRequest {
            id,
            pow: Some(ProofOfWork::V1(ProofOfWorkV1::new(
                Nonce::from([0; 16]),
                Effort::from(effort),
                SeedHead::from([0; 4]),
                SolutionByteArray::from([1; 16]),
            ))),
        }
    }

    fn make_test_receiver(
        runtime: &MockRuntime,
        netdir_params: Vec<(String, i32)>,
    ) -> (
        RendRequestReceiver<MockRuntime, MockRendRequest>,
        mpsc::Sender<MockRendRequest>,
        Arc<Mutex<Effort>>,
        NetParameters,
    ) {
        let pow_manager = Arc::new(MockPowManager);
        let suggested_effort = Arc::new(Mutex::new(Effort::zero()));
        let netdir = testnet::construct_custom_netdir_with_params(
            testnet::simple_net_func,
            netdir_params,
            None,
        )
        .unwrap()
        .unwrap_if_sufficient()
        .unwrap();
        let net_params = netdir.params().clone();
        let netdir_provider: Arc<TestNetDirProvider> = Arc::new(netdir.into());
        let receiver: RendRequestReceiver<_, MockRendRequest> =
            RendRequestReceiver::new(runtime.clone(), suggested_effort.clone(), netdir_provider);
        let (tx, rx) = mpsc::channel(32);
        receiver.start_accept_thread(runtime.clone(), pow_manager, rx);

        (receiver, tx, suggested_effort, net_params)
    }

    #[test]
    fn test_basic_pow_ordering() {
        MockRuntime::test_with_various(|runtime| async move {
            let (mut receiver, mut tx, _suggested_effort, _net_params) =
                make_test_receiver(&runtime, vec![]);

            // Request with no PoW
            tx.send(make_req(0, None)).await.unwrap();
            assert_eq!(receiver.next().await.unwrap().id, 0);

            // Request with PoW
            tx.send(make_req(1, Some(0))).await.unwrap();
            assert_eq!(receiver.next().await.unwrap().id, 1);

            // Request with effort is before request with zero effort
            tx.send(make_req(2, Some(0))).await.unwrap();
            tx.send(make_req(3, Some(16))).await.unwrap();
            runtime.progress_until_stalled().await;
            assert_eq!(receiver.next().await.unwrap().id, 3);
            assert_eq!(receiver.next().await.unwrap().id, 2);

            // Invalid solves are dropped
            tx.send(make_req_invalid(4, 32)).await.unwrap();
            tx.send(make_req(5, Some(16))).await.unwrap();
            runtime.progress_until_stalled().await;
            assert_eq!(receiver.next().await.unwrap().id, 5);
            assert_eq!(receiver.0.lock().unwrap().queue.len(), 0);
        });
    }

    #[test]
    fn test_suggested_effort_increase() {
        MockRuntime::test_with_various(|runtime| async move {
            let (mut receiver, mut tx, suggested_effort, net_params) = make_test_receiver(
                &runtime,
                vec![(
                    "HiddenServiceProofOfWorkV1ServiceIntroTimeoutSeconds".to_string(),
                    60000,
                )],
            );

            // Get through all the requests in plenty of time, no increase

            for n in 0..128 {
                tx.send(make_req(n, Some(0))).await.unwrap();
            }

            runtime.advance_by(HS_UPDATE_PERIOD / 2).await;

            for _ in 0..128 {
                receiver.next().await.unwrap();
            }

            runtime.advance_by(HS_UPDATE_PERIOD / 2).await;
            receiver.update_suggested_effort(&net_params);

            assert_eq!(suggested_effort.lock().unwrap().clone(), Effort::zero());

            // Requests left in the queue with zero suggested effort, suggested effort should
            // increase

            for n in 0..128 {
                tx.send(make_req(n, Some(0))).await.unwrap();
            }

            runtime.advance_by(HS_UPDATE_PERIOD / 2).await;

            for _ in 0..64 {
                receiver.next().await.unwrap();
            }

            runtime.advance_by(HS_UPDATE_PERIOD / 2).await;
            receiver.update_suggested_effort(&net_params);

            let mut new_suggested_effort = *suggested_effort.lock().unwrap();
            assert!(new_suggested_effort > Effort::zero());

            // We keep on being behind, effort should increase again.

            for n in 0..64 {
                tx.send(make_req(n, Some(new_suggested_effort.into())))
                    .await
                    .unwrap();
            }

            receiver.next().await.unwrap();
            runtime.advance_by(HS_UPDATE_PERIOD).await;
            receiver.update_suggested_effort(&net_params);

            let mut old_suggested_effort = new_suggested_effort;
            new_suggested_effort = *suggested_effort.lock().unwrap();
            assert!(new_suggested_effort > old_suggested_effort);

            // We catch up now, effort should start dropping, but not be zero immediately.

            for n in 0..32 {
                tx.send(make_req(n, Some(new_suggested_effort.into())))
                    .await
                    .unwrap();
            }

            runtime.advance_by(HS_UPDATE_PERIOD / 16 * 15).await;

            while receiver.next().now_or_never().is_some() {
                // Keep going...
            }

            runtime.advance_by(HS_UPDATE_PERIOD / 16).await;
            receiver.update_suggested_effort(&net_params);

            old_suggested_effort = new_suggested_effort;
            new_suggested_effort = *suggested_effort.lock().unwrap();
            assert!(new_suggested_effort < old_suggested_effort);
            assert!(new_suggested_effort > Effort::zero());

            // Effort will drop to zero eventually

            let mut num_loops = 0;
            loop {
                tx.send(make_req(0, Some(new_suggested_effort.into())))
                    .await
                    .unwrap();
                runtime.advance_by(HS_UPDATE_PERIOD / 2).await;

                while receiver.next().now_or_never().is_some() {
                    // Keep going...
                }

                runtime.advance_by(HS_UPDATE_PERIOD / 2).await;
                receiver.update_suggested_effort(&net_params);

                old_suggested_effort = new_suggested_effort;
                new_suggested_effort = *suggested_effort.lock().unwrap();

                assert!(new_suggested_effort < old_suggested_effort);

                if new_suggested_effort == Effort::zero() {
                    break;
                }

                num_loops += 1;

                if num_loops > 5 {
                    panic!("Took too long for suggested effort to fall!");
                }
            }
        });
    }

    #[test]
    fn test_rendrequest_timeout() {
        MockRuntime::test_with_various(|runtime| async move {
            let (receiver, mut tx, _suggested_effort, net_params) =
                make_test_receiver(&runtime, vec![]);

            let r0 = MockRendRequest { id: 0, pow: None };
            tx.send(r0).await.unwrap();

            let max_age: Duration = net_params
                .hs_pow_v1_service_intro_timeout
                .try_into()
                .unwrap();
            runtime.advance_by(max_age * 2).await;

            // Waited too long, request has been dropped
            assert_eq!(receiver.0.lock().unwrap().queue.len(), 0);
        });
    }
}
