//! Calculate consensus preamble

use super::*;

impl ConsensusesFromVotes<()> for netstatus::vote::NetworkStatus {
    type PlainOutput = netstatus::plain::NetworkStatus;
    type MdOutput = netstatus::md::NetworkStatus;

    fn consensuses<'i>(
        context: ConsensusContextRefs<()>,
        inputs: impl Iterator<Item = (VoterNum, &'i Self)> + Clone,
    ) -> Result<(Self::PlainOutput, Self::MdOutput), ConsensusError>
    where
        Self: 'i,
    {
        calc! { both.preamble }

        let context = ConsensusContextRefs {
            context: *context,
            computed: &plain_preamble,
        };

        calc! { both.routers }

        calc! { both.authority = todo() }
        calc! { both.footer = todo() }

        Ok(construct_both! {
            netstatus::plain::NetworkStatus, netstatus::md::NetworkStatus {
                both. authority, footer, preamble;
            } {
                both. routers;
                // TODO DIRAUTH NetworkStatus fields missing
            }
        })
    }
}

/// Computes a consensus from the input votes
///
/// ### Security
///
/// It is the caller's responsibility to check that each of the `votes`
/// came from a recognised authority.
pub fn compute_consensus_from_votes<'v>(
    method: SupportedConsensusMethod,
    n_authorities: usize,
    votes: impl Iterator<
        Item = (
            &'v netstatus::vote::NetworkStatus,
            &'v netstatus::DirectorySignaturesHashesAccu,
        ),
    >,
) -> Result<
    (
        netstatus::plain::NetworkStatus,
        netstatus::md::NetworkStatus,
    ),
    ConsensusError,
> {
    let (votes, sig_hashes) = votes.collect();
    let context = ConsensusCommonContext {
        method,
        n_authorities,
        votes,
        sig_hashes,
    };
    let context = ConsensusContextRefs {
        context: &context,
        computed: &(),
    };
    <netstatus::vote::NetworkStatus as ConsensusesFromVotes<()>>::consensuses(
        context,
        context
            .votes
            .iter_enumerated()
            .map(|(vnum, vote)| (vnum, *vote)),
    )
}
