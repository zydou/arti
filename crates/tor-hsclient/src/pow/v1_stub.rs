//! Stub; `v1` proof of work scheme has been disabled at compile time

use crate::err::ProofOfWorkError;
use tor_cell::relaycell::hs::pow::v1::ProofOfWorkV1;
use tor_hscrypto::pk::HsBlindId;
use tor_netdoc::doc::hsdesc::pow::v1::PowParamsV1;

/// Stub client for the `v1` scheme which never offers a solution
#[derive(Debug)]
pub(super) struct HsPowClientV1;

impl HsPowClientV1 {
    /// Stub constructor
    pub(super) fn new(_hs_blind_id: &HsBlindId, _params: &PowParamsV1) -> Self {
        Self
    }

    /// Stub; has no effect
    pub(super) fn increase_effort(&mut self) {}

    /// Stub; always returns None
    pub(super) async fn solve(&self) -> Result<Option<ProofOfWorkV1>, ProofOfWorkError> {
        Ok(None)
    }
}
