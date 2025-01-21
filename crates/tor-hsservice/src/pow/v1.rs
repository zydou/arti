//! Code implementing version 1 proof-of-work for onion service hosts.
//!
//! Spec links:
//! * <https://spec.torproject.org/hspow-spec/common-protocol.html>
//! * <https://spec.torproject.org/hspow-spec/v1-equix.html>

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::{Duration, SystemTime},
};

use arrayvec::ArrayVec;
use futures::channel::mpsc;
use futures::task::SpawnExt;
use futures::SinkExt;
use rand::{CryptoRng, RngCore};
use tor_basic_utils::RngExt as _;
use tor_checkable::timed::TimerangeBound;
use tor_hscrypto::{
    pk::HsBlindIdKey,
    pow::v1::{Effort, Instance, Seed, SeedHead, Verifier},
    time::TimePeriod,
};
use tor_keymgr::KeyMgr;
use tor_netdoc::doc::hsdesc::pow::{v1::PowParamsV1, PowParams};
use tor_persist::hsnickname::HsNickname;
use tor_rtcompat::Runtime;

use crate::{BlindIdPublicKeySpecifier, StartupError};

use super::NewPowManager;

/// This is responsible for rotating Proof-of-Work seeds and doing verification of PoW solves.
pub(crate) struct PowManager<R>(RwLock<State<R>>);

/// Internal state for [`PowManager`].
struct State<R> {
    /// The [`Seed`]s for a given [`TimePeriod`]
    ///
    /// The [`ArrayVec`] contains the current and previous seed, and the [`SystemTime`] is when the
    /// current seed will expire.
    // TODO POW: where do we get rid of old TPs?
    seeds: HashMap<TimePeriod, SeedsForTimePeriod>,

    /// Verifiers for all the seeds that exist in `seeds`.
    verifiers: HashMap<SeedHead, Verifier>,

    /// The nickname for this hidden service.
    ///
    /// We need this so we can get the blinded keys from the [`KeyMgr`].
    nickname: HsNickname,

    /// Key manager.
    keymgr: Arc<KeyMgr>,

    /// Current suggested effort that we publish in the pow-params line.
    suggested_effort: Effort,

    /// Runtime
    runtime: R,

    /// Queue to tell the publisher to re-upload a descriptor for a given TP, since we've rotated
    /// that seed.
    publisher_update_tx: mpsc::Sender<TimePeriod>,
}

#[derive(Debug, Clone)]
/// Information about the current and previous [`Seed`] for a given [`TimePeriod`].
struct SeedsForTimePeriod {
    /// The previous and current [`Seed`].
    ///
    /// The last element in this array is the current seed.
    seeds: ArrayVec<Seed, 2>,

    /// When the current seed will expire.
    next_expiration_time: SystemTime,
    // TODO POW: Maybe we should keep the HsBlindId for this TP here?
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
const PUBLISHER_UPDATE_QUEUE_DEPTH: usize = 32;

impl<R: Runtime> PowManager<R> {
    /// Create a new [`PowManager`].
    #[allow(clippy::new_ret_no_self)]
    pub(crate) fn new(runtime: R, nickname: HsNickname, keymgr: Arc<KeyMgr>) -> NewPowManager<R> {
        let (rend_req_tx, rend_req_rx) = super::make_rend_queue();
        let (publisher_update_tx, publisher_update_rx) =
            mpsc::channel(PUBLISHER_UPDATE_QUEUE_DEPTH);

        let state = State {
            seeds: HashMap::new(),
            nickname,
            keymgr,
            publisher_update_tx,
            verifiers: HashMap::new(),
            suggested_effort: Effort::zero(),
            runtime,
        };
        let pow_manager = Arc::new(PowManager(RwLock::new(state)));

        NewPowManager {
            pow_manager,
            rend_req_tx,
            rend_req_rx: Box::pin(rend_req_rx),
            publisher_update_rx,
        }
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
    /// This takes individual agruments instead of `&self` to avoid getting into any trouble with
    /// locking.
    ///
    /// # Panics
    ///
    /// Panics if the [HsBlindIdKey``] for the requested [`TimePeriod`] is not in the [`KeyMgr`].
    fn make_verifier(
        keymgr: &Arc<KeyMgr>,
        nickname: HsNickname,
        time_period: TimePeriod,
        seed: Seed,
    ) -> Verifier {
        let blind_id_spec = BlindIdPublicKeySpecifier::new(nickname, time_period);
        let blind_id_key = keymgr
            .get::<HsBlindIdKey>(&blind_id_spec)
            .expect("KeyMgr error!")
            .expect("Don't have HS blind ID!");
        let instance = Instance::new(blind_id_key.id(), seed);
        Verifier::new(instance)
    }

    /// Calculate a time when we want to rotate a seed, slightly before it expires, in order to
    /// ensure that clients don't ever download a seed that is already out of date.
    fn calculate_early_rotation_time(expiration_time: SystemTime) -> SystemTime {
        // Underflow cannot happen cannot happen because:
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
                    let verifier =
                        Self::make_verifier(&keymgr, nickname.clone(), *time_period, seed.clone());

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
                    new_verifiers.push((seed.head(), verifier));
                    if let Some(expired_seed) = expired_seed {
                        expired_verifiers.push(expired_seed.head());
                    }

                    // Tell the publisher to update this TP
                    updated_tps.push(*time_period);

                    tracing::debug!(time_period = ?time_period, "Rotated PoW seed");
                }
            }

            for (seed_head, verifier) in new_verifiers {
                state.verifiers.insert(seed_head, verifier);
            }

            for seed_head in expired_verifiers {
                state.verifiers.remove(&seed_head);
            }

            state.publisher_update_tx.clone()
        };

        for time_period in updated_tps {
            publisher_update_tx
                .send(time_period)
                .await
                .expect("Couldn't send update message to publisher");
        }

        update_times.iter().min().cloned()
    }

    /// Get [`PowParams`] for a given [`TimePeriod`].
    ///
    /// If we don't have any [`Seed`]s for the requested period, generate them. This is the only
    /// way that [`PowManager`] learns about new [`TimePeriod`]s.
    ///
    /// # Panics
    ///
    /// Panics if the [HsBlindIdKey``] for the requested [`TimePeriod`] is not in the [`KeyMgr`].
    pub(crate) fn get_pow_params(self: &Arc<Self>, time_period: TimePeriod) -> PowParams {
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
                );
                state.verifiers.insert(seed.head(), verifier);

                (seed, next_expiration_time)
            }
        };

        PowParams::V1(PowParamsV1::new(
            TimerangeBound::new(seed, ..expiration),
            suggested_effort,
        ))
    }
}
