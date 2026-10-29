//! Calculate consensus preamble

use super::*;

// TODO DIRAUTH integration tests of consensus calculation

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
        calc! { both.proto_statuses }
        calc! { md,plain .known_flags <+ doc_relay_flags_union }
        calc! { md,plain .params <+ netparams_preamble_aggregate }

        // TODO DIRAUTH replace dummy values
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
#[allow(clippy::needless_pass_by_value)]
pub(super) fn doc_relay_flags_union<'i>(
    _context: ConsensusContextRefs<()>,
    inputs: impl ComponentInVotes<&'i DocRelayFlags>,
) -> Result<DocRelayFlags, ConsensusError> {
    Ok(inputs
        .votes()
        .map(|flags| flags.iter_incl_unknown())
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
        .votes()
        .flat_map(|i| i.iter().map(|(k, _v)| k))
        .unique()
        .filter_map(|k| {
            // "every keyword on which a majority of authorities (total
            // authorities, not just those participating in this vote) voted
            // on, or if at least three authorities voted for that parameter.
            const MIN_THRESH: usize = 3;

            let opinions = inputs.votes().filter_map(|i| i.get(k)).copied();
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

impl Aggregate<()> for Arc<netstatus::ProtoStatuses> {
    type Output = Self;

    fn aggregate<'i>(
        context: ConsensusContextRefs<()>,
        inputs: impl ComponentInVotes<&'i Self>,
    ) -> Result<Self, ConsensusError>
    where
        Self: 'i,
    {
        calc! { out.client <+ protostatus_preamble_aggregate }
        calc! { out.relay <+ protostatus_preamble_aggregate }
        Ok(construct! {
            netstatus::ProtoStatuses {
            } {
                out. client, relay;
            }
        }
        .into())
    }
}

/// Calculate the `{recommended,required}-*-protocols` items in a consensus
//
// Not `impl Aggregate` because `ProtoStatus` wants to be
// handled quite differently in a routerstatus.
#[allow(clippy::needless_pass_by_value, clippy::unnecessary_wraps)]
fn protostatus_preamble_aggregate<'i>(
    context: ConsensusContextRefs<()>,
    inputs: impl ComponentInVotes<&'i netstatus::ProtoStatus>,
) -> Result<netstatus::ProtoStatus, ConsensusError> {
    fn aggregate_by_threshold<'i, 'r>(
        context: ConsensusContextRefs<'r, ()>,
        inputs: impl ComponentInVotes<&'i tor_protover::Protocols>,
        threshold: impl Fn(&ConsensusCommonContext<'r>, usize) -> bool,
    ) -> Result<tor_protover::Protocols, ConsensusError> {
        // Uncompress the inputs into sets of `(Protocol, Value)`.
        //
        // This is kind of flabby, especially in allocations, but it has the virtue
        // of making the output calculation very obvious.
        //
        // Worst case total allocations (and number of cpu operations) is
        //   O( unknown_keyword_length * n_keywords * n_authorities * 64 )
        // or alternatively
        //   O( total_length_of_all_input_doc_items * 64 )
        // and the constant factor is 3 or 4 words.  See the comments for `Preotocols::iter_all`.
        //
        // We could save a factor of up to 64 in the worst case by using a bitmask representation
        // but tor-protover does not currently expose that in a suitable form,
        // and it would make the calculation less obvious.
        //
        let inputs: Vec<HashSet<(tor_protover::Protocol, tor_protover::Value)>> = inputs
            .map(|(_vnum, i)| i.iter_all().collect())
            .collect_vec();

        Ok(inputs
            .iter()
            .flatten()
            .unique()
            .filter(|k| {
                let n_y = inputs.iter().filter(|i| i.contains(k)).count();
                threshold(&context, n_y)
            })
            .cloned()
            .collect())
    }

    calc! {
        out.recommended <+ aggregate_by_threshold;
        , ConsensusCommonContext::is_more_than_half_all_auths
    }
    calc! {
        out.required <+ aggregate_by_threshold;
        , ConsensusCommonContext::is_at_least_two_thirds_all_auths
    }

    Ok(construct! {
        netstatus::ProtoStatus {
        } {
            out. recommended, required;
        }
    })
}

#[cfg(test)]
mod test {
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

    #[test]
    fn protocols() {
        use tor_protover::Protocols;

        let p = |s| Protocols::from_str_c_compatible(s).unwrap();

        let inputs = [
            // 6 voters
            //
            // For capabilities `counting=K-6`, value K is voted for by K voters.
            p("Link=1 counting=1-6"),
            p("Link=1 counting=2-6 req=1 rec=1 neither=1"),
            p("Link=1 counting=3-6 req=1 rec=1 neither=1"),
            p("Link=1 counting=4-6 req=1 rec=1 neither=1"),
            p("Link=1 counting=5-6 req=1 rec=1"),
            p("Link=1 counting=6 req=1"),
        ];

        let (exp_recommended, exp_required) = (
            p("Link=1 counting=4-6 req=1 rec=1"),
            p("Link=1 counting=5-6 req=1"),
        );

        macro_rules! field { { $cs:ident, $field:ident } => { paste! {

            compute_test(
                inputs.len(),
                7,
                |vnum, vote| {
                    let mut ps = (*vote.preamble.proto_statuses).clone();
                    ps.$cs.$field = inputs[vnum].clone();
                    vote.preamble.proto_statuses = ps.into();
                    Ok(())
                },
                |(plain, _md)| {
                    let got = &plain.preamble.proto_statuses.$cs.$field;
                    let exp = &[< exp_ $field >];
                    assert_eq!(
                        got,
                        exp,
                        "{}\n got={}\n exp={}",
                        stringify!($cs $field),
                        got.to_string(),
                        exp.to_string(),
                    );
                    Ok(())
                },
            );

        } } }

        field! { client, recommended }
        field! { client, required }
        field! { relay, recommended }
        field! { relay, required }
    }
}
