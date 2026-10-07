//! Calculate consensus preamble

use super::*;

use tor_netdoc::doc::netstatus;

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

        // TODO DIRAUTH replace dummy values
        calc! { both.known_flags = DocRelayFlags::new_empty_unknown_discarded() }
        calc! { both.params = Default::default() }
        calc! { both.proto_statuses = Default::default() }
        calc! { both.voting_delay }

        Ok(construct_both! {
            netstatus::plain::Preamble, netstatus::md::Preamble {
                both. lifetime, consensus_method, consensus_methods, published;
                both. known_flags, params, proto_statuses, voting_delay;
            } {
                // TODO DIRAUTH Preamble fields missing
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
