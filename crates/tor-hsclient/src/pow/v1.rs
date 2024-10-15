//! Client support for the `v1` onion service proof of work scheme

use crate::err::ProofOfWorkError;
use rand::thread_rng;
use std::time::Instant;
use tor_async_utils::oneshot;
use tor_async_utils::oneshot::Canceled;
use tor_cell::relaycell::hs::pow::v1::ProofOfWorkV1;
use tor_checkable::{timed::TimerangeBound, Timebound};
use tor_hscrypto::pk::HsBlindId;
use tor_hscrypto::pow::v1::{Effort, Instance, SolverInput};
use tor_netdoc::doc::hsdesc::pow::v1::PowParamsV1;
use tracing::debug;

/// Double effort at retry until this threshold.
///
/// This could be made configurable, but currently it's hardcoded in c-tor and documented in the
/// spec as a recommended value.
const CLIENT_POW_EFFORT_DOUBLE_UNTIL: Effort = Effort::new(1000);

/// Effort multiplier to use above the doubling threshold.
///
/// This could be made configurable, but currently it's hardcoded in c-tor and documented in the
/// spec as a recommended value.
const CLIENT_POW_RETRY_MULTIPLIER: f32 = 1.5;

/// Minimum effort for retries.
///
/// This could be made configurable, but currently it's hardcoded in c-tor and documented in the
/// spec as a recommended value.
const CLIENT_MIN_RETRY_POW_EFFORT: Effort = Effort::new(8);

/// Client maximum effort.
///
/// This could be made configurable, but currently it's hardcoded in c-tor and documented in the
/// spec as a recommended value.
const CLIENT_MAX_POW_EFFORT: Effort = Effort::new(10000);

/// Client-side state for the 'v1' scheme in particular
///
#[derive(Debug)]
pub(super) struct HsPowClientV1 {
    /// Time limited puzzle instance
    instance: TimerangeBound<Instance>,
    /// Next effort to use
    effort: Effort,
}

impl HsPowClientV1 {
    /// Initialize client state for the `v1` scheme
    ///
    pub(super) fn new(hs_blind_id: &HsBlindId, params: &PowParamsV1) -> Self {
        Self {
            // Create a puzzle Instance for this Seed. It doesn't matter whether
            // the seed is valid at this moment. The time bound is preserved, and
            // it's checked before we use the seed at each retry.
            instance: params
                .seed()
                .to_owned()
                .dangerously_map(|seed| Instance::new(hs_blind_id.to_owned(), seed)),
            // Enforce maximum effort right away
            effort: params
                .suggested_effort()
                .clamp(Effort::zero(), CLIENT_MAX_POW_EFFORT),
        }
    }

    /// Increase effort in response to a failed connection attempt.
    ///
    /// If no proof of work scheme is in use or the effort cannot be increased, this has no effect.
    ///
    /// Specified in <https://spec.torproject.org/hspow-spec/common-protocol.html#client-timeout>
    ///
    pub(super) fn increase_effort(&mut self) {
        let effort = if self.effort < CLIENT_POW_EFFORT_DOUBLE_UNTIL {
            self.effort.saturating_mul_u32(2)
        } else {
            self.effort.saturating_mul_f32(CLIENT_POW_RETRY_MULTIPLIER)
        };
        self.effort = effort.clamp(CLIENT_MIN_RETRY_POW_EFFORT, CLIENT_MAX_POW_EFFORT);
    }

    /// Run the `v1` solver on a thread, if the effort is nonzero
    ///
    /// Returns None if the effort was zero.
    /// Returns an Err() if the solver experienced a runtime error,
    /// or if the seed is expired.
    pub(super) async fn solve(&self) -> Result<Option<ProofOfWorkV1>, ProofOfWorkError> {
        if self.effort == Effort::zero() {
            return Ok(None);
        }
        let instance = self.instance.as_ref().check_valid_now()?.clone();
        let mut input = SolverInput::new(instance, self.effort);
        // TODO: config option
        input.runtime(Default::default());

        let start_time = Instant::now();
        debug!("beginning solve, {:?}", self.effort);

        let (result_sender, result_receiver) = oneshot::channel();
        std::thread::spawn(move || {
            let mut solver = input.solve(&mut thread_rng());
            let result = loop {
                match solver.run_step() {
                    Err(e) => break Err(e),
                    Ok(Some(result)) => break Ok(result),
                    Ok(None) => (),
                }
                if result_sender.is_canceled() {
                    return;
                }
            };
            let _ = result_sender.send(result);
        });

        let result = match result_receiver.await {
            Ok(Ok(solution)) => Ok(Some(ProofOfWorkV1::new(
                solution.nonce().to_owned(),
                solution.effort(),
                solution.seed_head(),
                solution.proof_to_bytes(),
            ))),
            Ok(Err(e)) => Err(ProofOfWorkError::Runtime(e.into())),
            Err(Canceled) => Err(ProofOfWorkError::SolverDisconnected),
        };

        let elapsed_time = start_time.elapsed();
        debug!(
            "solve complete, {:?} {:?} duration={}ms (ratio: {} ms)",
            result.as_ref().map(|_| ()),
            self.effort,
            elapsed_time.as_millis(),
            (elapsed_time.as_millis() as f32) / (*self.effort.as_ref() as f32),
        );
        result
    }
}
