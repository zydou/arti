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

#[cfg(test)]
pub(crate) mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    #![allow(clippy::string_slice)] // See arti#2571
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    use crate::consensus::test::compute_test;
    use humantime::parse_rfc3339;
    use netstatus::SharedRandVal;
    use std::cell::RefCell;

    #[test]
    fn srv() {
        fn chk(
            n_votes: usize,
            n_auths: usize,
            votes: &[u8], // if too short, other voters vote None
            hour: u8,
            auth_dir_num_s_r_v_agreements_netparam: Option<i32>,
            exp: Option<u8>,
        ) {
            assert!(votes.len() <= n_votes);

            let mk_srs = |byte: u8| {
                let value = SharedRandVal::from(std::array::repeat(byte));
                netstatus::SharedRandStatusConstructor {
                    n_reveals: 1,
                    value,
                }
                .construct()
            };
            let hours = |h: u8| Duration::from_hours(h.into());

            let prev = RefCell::new(None);

            compute_test(
                n_votes,
                n_auths,
                |vnum, vote| {
                    let ss = &mut vote.authority.authority.shared_rand;
                    ss.shared_rand_current_value = votes.get(vnum).copied().map(mk_srs);

                    *prev.borrow_mut() = ss.shared_rand_previous_value.clone();

                    let valid_after = Iso8601TimeSp::from(
                        parse_rfc3339("2026-10-01T00:00:00Z").unwrap() + hours(hour),
                    );
                    let fresh_until = (*valid_after + hours(1)).into();
                    let valid_until = (*valid_after + hours(100)).into();

                    vote.preamble.lifetime = netstatus::LifetimeConstructor {
                        valid_after,
                        fresh_until,
                        valid_until,
                    }
                    .construct();

                    let params = &mut vote.preamble.params;
                    match auth_dir_num_s_r_v_agreements_netparam {
                        Some(v) => params.set(NEW_SRV_MIN_VOTERS_PARAM.into(), v),
                        None => params.clear(NEW_SRV_MIN_VOTERS_PARAM),
                    }

                    Ok(())
                },
                |(plain, md)| {
                    let chk_out = |ss: &SharedRandStatuses| {
                        assert_eq!(
                            ss.shared_rand_current_value,
                            exp.map(mk_srs),
                            "{n_votes} {n_auths} {votes:?} {hour} {:?}",
                            auth_dir_num_s_r_v_agreements_netparam,
                        );

                        if exp.is_some() {
                            assert_eq!(ss.shared_rand_previous_value, *prev.borrow(),);
                        }
                    };

                    chk_out(&plain.preamble.shared_rand);
                    chk_out(&md.preamble.shared_rand);
                    Ok(())
                },
            );
        }

        chk(3, 7, &[1, 1, 1], 0, None, None);
        chk(4, 7, &[1, 1, 1, 1], 0, None, Some(1));
        chk(6, 6, &[1, 1, 1, 2, 2, 2], 0, None, None);

        chk(6, 7, &[1, 1, 1, 2, 2, 2], 0, None, None);
        chk(6, 7, &[1, 1, 1, 1, 2, 2], 0, None, Some(1));
        chk(6, 7, &[1, 1, 1, 1, 2, 2], 0, Some(2), Some(1));
        chk(6, 7, &[1, 1, 1, 1, 2, 2], 0, Some(5), None);
        chk(6, 7, &[1, 1, 1, 1, 2, 2], 1, Some(5), Some(1));
        chk(6, 7, &[1, 1, 1, 1, 2, 2], 23, Some(5), Some(1));
    }
}
