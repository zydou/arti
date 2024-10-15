//! Common support for proof of work denial of service mitigation on the client side

#[cfg_attr(not(feature = "pow-v1"), path = "pow/v1_stub.rs")]
mod v1;

use crate::err::ProofOfWorkError;
use tor_cell::relaycell::hs::pow::ProofOfWork;
use tor_hscrypto::pk::HsBlindId;
use tor_netdoc::doc::hsdesc::pow::PowParams;
use tor_netdoc::doc::hsdesc::HsDesc;
use v1::HsPowClientV1;

/// Client-side state for a series of connection attempts that might use proof-of-work.
///
/// The `HsPowClient` can be initialized using a recent `HsDesc`, at which point
/// we choose a proof of work scheme and its initial parameters.
///
/// When an attempt fails, we can increase the effort in an algorithm-specific way.
///
/// For now we have only scheme, `v1`. We try to make only minimal assumptions
/// about how future schemes may interact with each other.
#[derive(Default)]
pub(crate) struct HsPowClient {
    /// Client state specifically for the `v1` scheme
    v1: Option<HsPowClientV1>,
}

impl HsPowClient {
    /// Initialize a new group of connection attempts, given the required context
    pub(crate) fn new(hs_blind_id: &HsBlindId, desc: &HsDesc) -> Self {
        let mut client: HsPowClient = Default::default();
        for params in desc.pow_params() {
            if let PowParams::V1(v1) = params {
                client.v1 = Some(HsPowClientV1::new(hs_blind_id, v1));
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
    pub(crate) fn increase_effort(&mut self) {
        if let Some(v1) = &mut self.v1 {
            v1.increase_effort();
        }
    }

    /// If we have an applicable proof of work scheme, do the work and return a proof
    pub(crate) async fn solve(&self) -> Result<Option<ProofOfWork>, ProofOfWorkError> {
        if let Some(v1) = &self.v1 {
            Ok(v1.solve().await?.map(ProofOfWork::V1))
        } else {
            Ok(None)
        }
    }
}
