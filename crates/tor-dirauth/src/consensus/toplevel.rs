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

        let context = context.with_computed(&plain_preamble);

        calc! { both.routers }
        calc! { both.authority }

        let computed = (&plain_preamble, &*plain_routers);
        let context = context.with_computed(&computed);

        calc! { both.footer }

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
    use std::collections::BTreeSet;
    use tor_netdoc::parse2::NetdocParseableUnverified;

    /// Ensure that every rs that has an md digest, has one for `method`
    ///
    /// Needed because sometimes the test data (which is from the live network)
    /// will have votes none of which advertise (and thus, contain md hashes for)
    /// our selected consensus method (usually, the maximum *we* support).
    ///
    /// Fudge every rs in the vote, copying the digest(s) from the maximum supported.
    ///
    /// Of course the resulting digests might be lies, since the actual new method might
    /// involve generating *different* mds.  But that doesn't matter here
    /// in the consensus calculation, where we sees only md digests, not actual mds.
    /// And, discrepancies due to different voters voting different methods
    /// and thus different digests, are impossible with for `compute-test`,
    /// since tht bases all the test votes on the same input vote.
    fn populate_md_digests_for_method(
        our_method: SupportedConsensusMethod,
        vote: &mut netstatus::vote::NetworkStatus,
    ) {
        let vote_max_method = vote
            .preamble
            .consensus_methods
            .iter()
            .copied()
            .max()
            .expect("no methods in vote");
        for rs in &mut vote.routers {
            // `IdentifiedDigest`s in this rs for consensus method `needle`
            let for_method = |needle| {
                netstatus::RouterStatusMdDigestsVote::iter_cross_product_digests(&rs.m)
                    .filter(move |(m, _)| *m == needle)
                    .map(|(_, d)| d)
            };

            if for_method(*our_method).next().is_some() {
                continue;
            }
            let add_consensus_methods = [*our_method].into_iter().collect::<BTreeSet<_>>().into();

            let add_digests = for_method(vote_max_method).collect_vec();
            if add_digests.is_empty() {
                continue;
            };

            rs.m.push(construct! {
                netstatus::RouterStatusMdDigestsVote {
                    add. consensus_methods, digests;
                } {
                }
            });
        }
    }

    /// Compute a consensus from votes, allowing mutation of test data and bespoke checks
    ///
    /// Can be used for testing individual consensus elements:
    ///
    ///  * Use `edit_votes` to install test data into vote fields.
    ///  * Use `check_output` to check the output field is as expected.
    ///
    /// `edit_vote` gets the vote index (within `0..n_votes`),
    /// (as a `usize` rather than `VoterNum`, for test cases' convenience.)
    ///
    /// The basis votes are all the same: the vote from `testata-live`.
    pub(crate) fn compute_test(
        n_votes: usize,
        n_authorities: usize,
        mut edit_vote: impl FnMut(usize, &mut netstatus::vote::NetworkStatus) -> anyhow::Result<()>,
        check_output: impl FnOnce(
            (
                netstatus::plain::NetworkStatus,
                netstatus::md::NetworkStatus,
            ),
        ) -> anyhow::Result<()>,
    ) {
        assert!(n_votes <= n_authorities);
        let method = SupportedConsensusMethod::MAX;

        let (vote_base, sigs) =
            tor_netdoc::testdata_live::netstatus_vote_unverified().inspect_unverified();
        let hashes = &sigs.hashes;

        let votes = (0..n_votes)
            .into_iter()
            .map(move |vnum| {
                let mut vote = vote_base.clone();
                populate_md_digests_for_method(method, &mut vote);
                edit_vote(vnum, &mut vote).expect("vote edit failed");
                vote
            })
            .collect_vec();

        let output =
            compute_consensus_from_votes(method, n_authorities, votes.iter().map(|v| (v, hashes)))
                .expect("compute consensus");

        check_output(output).expect("check output");
    }

    #[test]
    #[traced_test]
    fn compute_for_test_vanilla() {
        compute_test(
            3,
            4,
            |_, _| Ok(()),
            |(plain, md)| {
                dbg!(&plain);
                dbg!(&md);
                Ok(())
            },
        );
    }
}
