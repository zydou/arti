//! Calculate consensus preamble

use super::*;

use tor_netdoc::doc::netstatus;

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
