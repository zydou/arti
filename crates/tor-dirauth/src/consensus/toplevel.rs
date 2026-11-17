//! Calculate consensus preamble

use super::*;

/// One vote input to `compute_consensus_from_votes`
#[allow(clippy::exhaustive_structs)] // this is an aggregation of a function input argument
pub struct VoteInput<'v> {
    /// The vote; signature must have been verified
    pub vote: &'v netstatus::vote::NetworkStatus,

    /// The voter nickname, used only for logging/reporting
    pub nickname: &'v Nickname,

    /// Signature hashes, from document parsing
    pub sig_hashes: &'v netstatus::DirectorySignaturesHashesAccu,
}

/// Outputs from consensus calculation
#[non_exhaustive]
pub struct Consensuses {
    /// plain consensus
    pub plain: netstatus::plain::NetworkStatus,
    /// md consensus
    pub md: netstatus::md::NetworkStatus,
}

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

        let computed = FooterAC {
            preamble: &plain_preamble,
            routers: &plain_routers,
        };
        let context = context.with_computed(&computed);

        calc! { both.footer }

        Ok(construct_both! {
            netstatus::plain::NetworkStatus, netstatus::md::NetworkStatus {
                both. preamble, authority, footer;
            } {
                // `network_status_version` and `vote_status`: unit tokens, Default is fine
                both. routers;
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
                let (cae, lkey) = vote2consensus(&vas.authority, context.sig_hashes.vote(vnum)?)?;
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
/// came from a distinct recognised authority.
/// Normally this will be assured by the APIs in `tor-netdoc`,
/// particularly [`netstatus::vote::NetworkStatusUnverified::verify`].
pub fn compute_consensus_from_votes<'v>(
    n_authorities: usize,
    votes: impl Iterator<Item = VoteInput<'v>> + Clone,
) -> Result<Consensuses, ConsensusError> {
    let method = compute_method(votes.clone().map(|v| &v.vote.preamble.consensus_methods))?;
    compute_consensus_from_votes_method(method, n_authorities, votes)
}

/// Select the consensus method
///
/// <https://spec.torproject.org/dir-spec/computing-consensus.html#consensus-method-list>
fn compute_method<'v>(
    votes: impl Iterator<Item = &'v netstatus::ConsensusMethods> + Clone,
) -> Result<SupportedConsensusMethod, ConsensusError> {
    let all_methods: HashSet<ConsensusMethod> =
        votes.clone().flat_map(|s| s.iter().copied()).collect();

    Ok(all_methods
        .into_iter()
        .try_filter(|m| {
            StrictlyMoreThanTwoThirds::is_true_for_enough_of(votes.clone(), |v| {
                Ok::<_, Bug>(v.contains(m))
            })
        })
        .process_results(|candidates| candidates.max())?
        .unwrap_or_else(|| {
            let m: ConsensusMethod = SupportedConsensusMethod::MAX.into();
            warn!("no consensus method in common amongst >2/3 of authorities, using {m}!");
            m
        })
        .try_into()?)
}

/// Computes a consensus from the input votes, for a specific method
///
/// ### Security
///
/// See [`compute_consensus_from_votes`].
pub fn compute_consensus_from_votes_method<'v>(
    method: SupportedConsensusMethod,
    n_authorities: usize,
    votes: impl Iterator<Item = VoteInput<'v>>,
) -> Result<Consensuses, ConsensusError> {
    let (votes, nicknames, sig_hashes) = votes
        .map(|vi| (vi.vote, vi.nickname, vi.sig_hashes))
        .collect();
    let context = ConsensusCommonContext {
        method,
        n_authorities,
        votes,
        nicknames,
        sig_hashes,
    };
    let context = ConsensusContextRefs {
        context: &context,
        computed: &(),
    };
    let (plain, md) = <netstatus::vote::NetworkStatus as ConsensusesFromVotes<()>>::consensuses(
        context,
        context
            .votes
            .iter_enumerated()
            .map(|(vnum, vote)| (vnum, *vote)),
    )?;
    Ok(Consensuses { plain, md })
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
        check_output: impl FnOnce(Consensuses) -> anyhow::Result<()>,
    ) {
        assert!(n_votes <= n_authorities);
        let method = SupportedConsensusMethod::MAX;

        let (vote_base, sigs) =
            tor_netdoc::testdata_live::netstatus_vote_unverified().inspect_unverified();
        let sig_hashes = &sigs.hashes;

        let votes = (0..n_votes)
            .into_iter()
            .map(move |vnum| {
                let mut vote = vote_base.clone();
                populate_md_digests_for_method(method, &mut vote);
                edit_vote(vnum, &mut vote).expect("vote edit failed");
                let nick: Nickname = format!("A{vnum}").parse().unwrap();
                (vote, nick)
            })
            .collect_vec();

        let output = compute_consensus_from_votes_method(
            method,
            n_authorities,
            votes.iter().map(|(vote, nickname)| VoteInput {
                vote,
                nickname,
                sig_hashes,
            }),
        )
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
            |Consensuses { plain, md }| {
                dbg!(&plain);
                dbg!(&md);
                Ok(())
            },
        );
    }

    #[test]
    #[traced_test]
    fn select_method() {
        const N_VOTES: usize = 4;
        let max: u32 = SupportedConsensusMethod::MAX.0;

        fn check(exp: Result<u32, u32>, methods_and_counts: &[(u32, usize)]) {
            let votes = (0..N_VOTES)
                .map(|vnum| {
                    let methods = methods_and_counts
                        .iter()
                        .filter_map(|&(method, count)| {
                            (vnum < count).then_some(ConsensusMethod(method))
                        })
                        .collect();
                    netstatus::ConsensusMethods { methods }
                })
                .collect_vec();

            println!("votes = {votes:#?}");

            let exp = exp
                .map(|n| SupportedConsensusMethod::try_from(ConsensusMethod(n)).unwrap())
                .map_err(|n| SupportedConsensusMethod::try_from(ConsensusMethod(n)).unwrap_err());

            let got = compute_method(votes.iter()).map_err(|e| match e {
                ConsensusError::UnsupportedMethodChosen(u) => u,
                other => panic!("unexpected error {other:?}"),
            });

            assert_eq!(got, exp);
        }

        check(Err(10), &[(10, 4)]);
        check(Err(20), &[(10, 4), (20, 3), (max, 1)]);
        check(Err(20), &[(10, 4), (20, 3), (max, 2)]);
        check(Ok(max), &[(10, 4), (20, 3), (max, 3)]);
        check(Ok(max), &[(10, 2), (20, 2), (max, 2)]);
    }
}
