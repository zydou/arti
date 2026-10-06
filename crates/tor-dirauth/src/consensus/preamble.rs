//! Calculate consensus preamble

use super::*;

// TODO DIRAUTH tests of consensus calculation

impl ConsensusesFromVotes<()> for netstatus::vote::Preamble {
    type PlainOutput = netstatus::plain::Preamble;
    type MdOutput = netstatus::md::Preamble;

    fn consensuses<'i>(
        context: ConsensusContextRefs<()>,
        inputs: impl Iterator<Item = (VoterNum, &'i Self)> + Clone,
    ) -> Result<(Self::PlainOutput, Self::MdOutput), ConsensusError>
    where
        Self: 'i,
    {
        calc! { both.lifetime }
        calc! { both.consensus_method = ((*context.method).into(),) }
        calc! { both.consensus_methods = NotPresent }
        calc! { both.published = NotPresent }
        calc! { md,plain .known_flags <+ doc_relay_flags_union }
        calc! { md,plain .params <+ netparams_preamble_aggregate }

        // TODO DIRAUTH replace dummy values
        calc! { both.proto_statuses = Default::default() }
        calc! { both.voting_delay }
        calc! { both.client_versions }
        calc! { both.server_versions }
        calc! { both.shared_rand = Default::default() }

        Ok(construct_both! {
            netstatus::plain::Preamble, netstatus::md::Preamble {
                both. lifetime, consensus_method, consensus_methods, published;
                both. known_flags, params, proto_statuses, voting_delay;
            } {
                both. client_versions, server_versions, shared_rand;
            }
        })
    }
}

impl<AC> Aggregate<AC> for netstatus::Lifetime {
    type Output = Self;

    fn aggregate<'i>(
        context: ConsensusContextRefs<AC>,
        inputs: impl ComponentInVotes<&'i Self>,
    ) -> Result<Self, ConsensusError>
    where
        Self: 'i,
    {
        calc! { out.valid_after <+ functions::low_median }
        calc! { out.fresh_until <+ functions::low_median }
        calc! { out.valid_until <+ functions::low_median }

        // We want these to be in increasing order, or the resulting consensus is nonsensical.
        // This could only be violated if some of the inputs votes didn't have them in
        // increasing order.   TODO arti#2786

        Ok(construct! {
            netstatus::Lifetime {
                out. valid_after, fresh_until, valid_until;
            } {
            }
        })
    }
}

impl<AC> Aggregate<AC> for netstatus::VotingDelay {
    type Output = Self;

    fn aggregate<'i>(
        context: ConsensusContextRefs<AC>,
        inputs: impl ComponentInVotes<&'i Self>,
    ) -> Result<Self, ConsensusError>
    where
        Self: 'i,
    {
        // Spec just says "median".  Low median will do; it's in seconds.
        calc! { out.vote_seconds <+ functions::low_median }
        calc! { out.dist_seconds <+ functions::low_median  }
        Ok(construct! {
            netstatus::VotingDelay {
                out. vote_seconds, dist_seconds;
            } {
            }
        })
    }
}

/// Calculate the union of two `DocRelayFlags`z
pub(super) fn doc_relay_flags_union<'i>(
    _context: ConsensusContextRefs<()>,
    inputs: impl ComponentInVotes<&'i DocRelayFlags>,
) -> Result<DocRelayFlags, ConsensusError> {
    Ok(inputs
        .map(|(_vnum, flags)| flags.iter_incl_unknown())
        .flatten_ok()
        .process_results(|flag_iters| flag_iters.unique().collect())?)
}

/// Calculate the `params` line in a consensus
//
// Not `impl Aggregate` because NetParams is a very general type used in all sorts of
// places, and we don't want them to get this impl by mistake.
#[allow(clippy::needless_pass_by_value, clippy::unnecessary_wraps)]
pub(super) fn netparams_preamble_aggregate<'i>(
    context: ConsensusContextRefs<()>,
    inputs: impl ComponentInVotes<&'i NetParams<i32>>,
) -> Result<NetParams<i32>, ConsensusError> {
    Ok(inputs
        .clone()
        .flat_map(|(_vnum, i)| i.iter().map(|(k, _v)| k))
        .unique()
        .filter_map(|k| {
            // "every keyword on which a majority of authorities (total
            // authorities, not just those participating in this vote) voted
            // on, or if at least three authorities voted for that parameter.
            const MIN_THRESH: usize = 3;

            let opinions = inputs.clone().filter_map(|(_vnum, i)| i.get(k)).copied();
            let n_opinions = opinions.clone().count();
            let want = context.is_more_than_half_all_auths(n_opinions) || n_opinions >= MIN_THRESH;
            if !want {
                return None;
            }

            const_assert!(MIN_THRESH > 0);
            let out = functions::low_median_raw(opinions)
                .expect("more than half is always >0, and so is MIN_THRESH");
            Some((String::from(k), out))
        })
        .collect())
}

impl<AC> Aggregate<AC> for netstatus::RecommendedTorVersions {
    type Output = Self;

    fn aggregate<'i>(
        _context: ConsensusContextRefs<AC>,
        inputs: impl ComponentInVotes<&'i Self>,
    ) -> Result<Self, ConsensusError>
    where
        Self: 'i,
    {
        let inputs = inputs.map(|(_vnum, i)| i).filter(|i| i.is_known());

        Ok(inputs
            .clone()
            .flat_map(|i| i.iter())
            .unique()
            .try_filter(|k| {
                is_true_for_more_than_half_of(
                    //
                    inputs.clone(),
                    |i| Ok::<_, Bug>(i.contains(&**k)),
                )
            })
            .process_results(|ks| netstatus::RecommendedTorVersions::from_iter(ks))?
            .map_err(into_internal!(
                "passed through software version was invalid"
            ))?)
    }
}
