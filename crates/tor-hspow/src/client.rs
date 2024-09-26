//! Common support for proof of work denial of service mitigation on the client side

use crate::err::RuntimeError;
use crate::v1;
use rand::thread_rng;
use std::time::Instant;
use tor_async_utils::oneshot;
use tor_async_utils::oneshot::Canceled;
use tor_cell::relaycell::hs::pow::ProofOfWork;
use tor_cell::relaycell::hs::pow::ProofOfWorkV1;
use tor_hscrypto::pk::HsBlindId;
use tor_netdoc::doc::hsdesc::pow::HsPowParams;
use tor_netdoc::doc::hsdesc::HsDesc;
use tracing::debug;

/// Double effort at retry until this threshold.
///
/// This could be made configurable, but currently it's hardcoded in c-tor and documented in the
/// spec as a recommended value.
const CLIENT_POW_EFFORT_DOUBLE_UNTIL: u32 = 1000;

/// Effort multiplier to use above the doubling threshold.
///
/// This could be made configurable, but currently it's hardcoded in c-tor and documented in the
/// spec as a recommended value.
const CLIENT_POW_RETRY_MULTIPLIER: f32 = 1.5;

/// Minimum effort for retries.
///
/// This could be made configurable, but currently it's hardcoded in c-tor and documented in the
/// spec as a recommended value.
const CLIENT_MIN_RETRY_POW_EFFORT: u32 = 8;

/// Client maximum effort.
///
/// This could be made configurable, but currently it's hardcoded in c-tor and documented in the
/// spec as a recommended value.
const CLIENT_MAX_POW_EFFORT: u32 = 10000;

/// Client-side state for a connection which may use proof-of-work over multiple attempts.
///
/// The `HsPowClient` initialized from the `HsDesc`, at which point we choose a proof of work
/// algorithm and its initial parameters.
///
/// When an attempt fails, we can increase the effort in an algorithm-specific way.
#[derive(Default)]
pub struct HsPowClient {
    /// Puzzle instance for the `v1` algorithm
    v1_instance: Option<v1::Instance>,
    /// Next effort to use with the `v1` algorithm
    v1_effort: v1::Effort,
}

impl HsPowClient {
    /// Initialize a new group of connection attempts, given the required context
    pub fn new(hs_blind_id: &HsBlindId, desc: &HsDesc) -> Self {
        let mut client: HsPowClient = Default::default();
        for params in desc.pow_params() {
            if let HsPowParams::V1(v1) = params {
                client.v1_instance = Some(v1::Instance::new(
                    hs_blind_id.to_owned(),
                    v1.seed().to_owned().into(),
                ));
                client.v1_effort =
                    std::cmp::min(CLIENT_MAX_POW_EFFORT, v1.suggested_effort()).into();
            }
        }
        client
    }

    /// Increase effort in response to a failed connection attempt.
    ///
    /// If no proof of work scheme is in use or the effort cannot be increased, this has no effect.
    ///
    /// Specified in <https://spec.torproject.org/hspow-spec/common-protocol.html#client-timeout>
    ///
    pub fn increase_effort(&mut self) {
        if self.v1_instance.is_some() {
            let effort: u32 = *self.v1_effort.as_ref();
            let effort = if effort < CLIENT_POW_EFFORT_DOUBLE_UNTIL {
                effort * 2
            } else {
                ((effort as f32) * CLIENT_POW_RETRY_MULTIPLIER) as u32
            };
            let effort = std::cmp::max(CLIENT_MIN_RETRY_POW_EFFORT, effort);
            let effort = std::cmp::min(CLIENT_MAX_POW_EFFORT, effort);
            self.v1_effort = effort.into();
        }
    }

    /// Wait for a complete solution if necessary, and return a proof-of-work suitable for attaching to an `Introduce1`
    pub async fn solve(&self) -> Result<Option<ProofOfWork>, RuntimeError> {
        if self.v1_effort.as_ref() > &0 {
            if let Some(v1) = &self.v1_instance {
                let start_time = Instant::now();
                debug!("beginning v1 solve {:?}", self.v1_effort);
                let result =
                    Self::solve_v1(v1::SolverInput::new(v1.to_owned(), self.v1_effort)).await;
                let elapsed_time = start_time.elapsed();
                debug!(
                    "v1 solve complete, {:?} {:?} duration={}ms (ratio: {} ms)",
                    result.as_ref().map(|_| ()),
                    self.v1_effort,
                    elapsed_time.as_millis(),
                    (elapsed_time.as_millis() as f32) / (*self.v1_effort.as_ref() as f32),
                );
                return result;
            }
        }
        Ok(None)
    }

    /// Run the `v1` solver on a thread
    async fn solve_v1(mut input: v1::SolverInput) -> Result<Option<ProofOfWork>, RuntimeError> {
        // TODO: config option
        input.runtime(Default::default());

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
        match result_receiver.await {
            Ok(Ok(solution)) => Ok(Some(ProofOfWork::V1(ProofOfWorkV1::new(
                *solution.nonce().as_ref(),
                *solution.effort().as_ref(),
                *solution.seed_head().as_ref(),
                solution.proof_to_bytes(),
            )))),
            Ok(Err(e)) => Err(e.into()),
            Err(Canceled) => Ok(None),
        }
    }
}
