//! Shared random (consensus calculation)

use super::*;
use crate::shared_random::*;
use netstatus::{SharedRandStatus, SharedRandStatuses, SharedRandStatusesConstructor};

/// Number of authorities needed at 00:00 to make SRV
///
/// <https://spec.torproject.org/srv-spec/overview.html#inserting>
const NEW_SRV_MIN_VOTERS_PARAM: &str = "AuthDirNumSRVAgreements";

/// Inputs needed for calculating SRV field in a consensus
///
/// These are just the corresponding fields from the preamble
pub(super) struct SrvAC<'r> {
    /// lifetime fields
    pub(crate) lifetime: &'r netstatus::Lifetime,
    /// netparams, `params`
    pub(crate) params: &'r netstatus::NetParams,
}

impl Aggregate<SrvAC<'_>> for SharedRandStatuses {
    type Output = Self;

    fn aggregate<'i>(
        context: ConsensusContextRefs<SrvAC>,
        inputs: impl ComponentInVotes<&'i Self>,
    ) -> Result<Self::Output, ConsensusError>
    where
        Self: 'i,
    {
        calc! { out.shared_rand_previous_value }
        calc! { out.shared_rand_current_value }
        Ok(construct! {
            SharedRandStatuses {
            } {
                out. shared_rand_previous_value;
                out. shared_rand_current_value;
            }
        })
    }
}

impl Aggregate<SrvAC<'_>> for Option<SharedRandStatus> {
    type Output = Self;

    fn aggregate<'i>(
        context: ConsensusContextRefs<SrvAC>,
        inputs: impl ComponentInVotes<&'i Self>,
    ) -> Result<Self::Output, ConsensusError>
    where
        Self: 'i,
    {
        // https://spec.torproject.org/srv-spec/overview.html#inserting

        let ac = context.computed;

        let phase = shared_random::Phase::for_voting_period(
            *ac.lifetime.valid_after,
            ac.lifetime
                .fresh_until
                .duration_since(*ac.lifetime.valid_after)
                .map_err(|_: std::time::SystemTimeError| {
                    ConsensusError::Unreasonable("lifetime fresh_until before valid_after".into())
                })?,
        )?;

        // IEFE allows us to use `?` to early exit with `Ok(None)`
        Ok((|| {
            let counts = inputs.votes().filter_map(|srv| srv.as_ref()).counts();
            let (srv, n_in_favour) = counts.into_iter().max_by_key(|(_, n)| *n)?;
            context
                .is_more_than_half_all_auths(n_in_favour)
                .then_some(())?;
            if phase == shared_random::Phase::NEW_SRV {
                if let Some(reqd) = ac.params.without_defaults().get(NEW_SRV_MIN_VOTERS_PARAM) {
                    // reqd is i32, saturatingly convert to usize
                    let reqd = usize::try_from(*reqd).unwrap_or(usize::MAX);
                    (n_in_favour >= reqd).then_some(())?;
                }
            }
            Some(srv.clone())
        })())
    }
}
