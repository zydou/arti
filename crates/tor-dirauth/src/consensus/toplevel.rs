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
        calc! { both.authority }

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

impl<AC> Aggregate<AC> for netstatus::VoteAuthoritySection {
    type Output = netstatus::ConsensusAuthoritySection;

    fn aggregate<'i>(
        context: ConsensusContextRefs<AC>,
        inputs: impl ComponentInVotes<&'i Self>,
    ) -> Result<Self::Output, ConsensusError>
    where
        Self: 'i,
    {
        use netstatus::{
            ConsensusAuthorityEntry, ConsensusAuthorityEntryConstructor, ConsensusAuthoritySection,
            ConsensusAuthoritySectionConstructor, DirectorySignaturesHashesAccu,
            SupersededAuthorityKey, VoteAuthorityEntry,
        };

        fn vote2consensus(
            vae: &VoteAuthorityEntry,
            sig_hashes: &DirectorySignaturesHashesAccu,
        ) -> Result<(ConsensusAuthorityEntry, Option<SupersededAuthorityKey>), Bug> {
            macro_rules! copy_field { { $f:ident } => { let $f = vae.$f.clone(); } }
            copy_field! { dir_source }
            copy_field! { contact }

            let vote_digest = chain!(
                sig_hashes.sha256.as_ref().map(|h| &h[..]),
                sig_hashes.sha1.as_ref().map(|h| &h[..]),
            )
            .next()
            .ok_or_else(|| internal!("vote without any digest"))?
            .to_owned()
            .into();

            let superseded_authority_key = vae.legacy_dir_key.map(|fingerprint| {
                SupersededAuthorityKey::from_dir_source_and_key(
                    //
                    vae.dir_source.clone(),
                    fingerprint,
                )
            });

            Ok((
                ConsensusAuthorityEntry {
                    ..ConsensusAuthorityEntryConstructor {
                        dir_source,
                        contact,
                        vote_digest,
                    }
                    .construct()
                },
                superseded_authority_key,
            ))
        }

        let (authorities, superseded_keys) = inputs
            .map(|(vnum, vas)| {
                let (cae, lkey) = vote2consensus(
                    &vas.authority,
                    context
                        .sig_hashes
                        .get(vnum)
                        .ok_or_else(|| internal!("{vnum:?}"))?,
                )?;
                Ok::<_, Bug>((Some(cae), lkey))
            })
            .process_results(|i| i.filter_collect_unzip())?;

        Ok(ConsensusAuthoritySection {
            superseded_keys,
            ..ConsensusAuthoritySectionConstructor { authorities }.construct()
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
