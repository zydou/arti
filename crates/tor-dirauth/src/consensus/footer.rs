//! Calculate consensus footer

use super::*;

/// "Already computed" for footer calculoations
///
/// The footer can depend on all the previous consensus, notably the preamble and the routers.
type FooterAC = netstatus::plain::Preamble;

impl ConsensusesFromVotes<FooterAC> for netstatus::vote::Footer {
    type PlainOutput = netstatus::plain::Footer;
    type MdOutput = netstatus::md::Footer;

    fn consensuses<'i>(
        context: ConsensusContextRefs<FooterAC>,
        _inputs: impl ComponentInVotes<&'i Self>,
    ) -> Result<(Self::PlainOutput, Self::MdOutput), ConsensusError>
    where
        Self: 'i,
    {
        calc! { both.consensus = make_footer_fields(context)?; }

        Ok(construct_both! {
            netstatus::plain::Footer, netstatus::md::Footer {
                both. consensus;
            } {
            }
        })
    }
}

/// Calculate the actual footer, as a `ConsensusFooterFields`
///
/// Not `Aggregate` and doesn't take any inputs, because votes don't have footers
/// (so that field in a vote is `NotPresent`.)
#[allow(clippy::unnecessary_wraps)] // for uniformity
fn make_footer_fields(
    _context: ConsensusContextRefs<FooterAC>,
) -> Result<netstatus::ConsensusFooterFields, ConsensusError> {
    let out_bandwidth_weights = NetParams::default(); // TODO DIRAUTH

    Ok(construct! {
        netstatus::ConsensusFooterFields {
        } {
            out. bandwidth_weights;
        }
    })
}
