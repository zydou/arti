//! Calculate the body of a routerstatus we have decided to include

use super::*;
use rs_common::*;

/// md digest as it appears in the consensus
//
// TODO arguably this should be in tor-netdoc somewhere, but where?
type MdDigest = FixedB64<{ tor_netdoc::doc::microdesc::DOC_DIGEST_LEN }>;

/// AC that indicates a promise that `inputs` is only votes with the same status-tuple
///
/// Used in trait impls etc. to ensure that we use the correct subset of the votes.
///
/// For background, contrast the wording in
///
///  * <https://spec.torproject.org/dir-spec/computing-consensus.html#choosing-relay-ids>
///  * <https://spec.torproject.org/dir-spec/computing-consensus.html#choosing-relay-descs>
#[derive(Debug, Clone, Copy)]
struct SameStatusTupleAC {
    // nothing actually needed here yet
}

impl<'i> ResolvedRouterStatusInputs<'i> {
    /// Calculate the plain and md routerstatuses
    ///
    /// Similar to `ConsensusesFromVotes::consensuses`,
    /// but takes one `ResolvedRouterStatusInputs`, which includes not only
    /// the routerstatuses from each vote, but also the id-tuple and status-tuple
    /// from the resolution part of the algorithm.
    ///
    /// Can return `None` to mean that this router should not be listed after all
    /// (eg, because its listing would lack the Running flag),
    /// or `Some((md, None))` to list in the plain consensus, but not in the md consensus.
    pub(super) fn consensuses(
        &self,
        context: ConsensusContextRefs<RouterStatusAC<'_>>,
    ) -> Result<
        Option<(
            netstatus::plain::RouterStatus,
            Option<netstatus::md::RouterStatus>,
        )>,
        ConsensusError,
    > {
        let inputs = self.per_voter.iter_enumerated().with_opinions();

        /// Copy a field from `self.status_tuple` to the output.
        ///
        /// `from_status_tuple! { OUT . FIELD; SUFFIX }` is equivalent to
        /// `calc! { OUT.FIELD = self.status_tuple.FIELD SUFFIX }``
        ///
        /// The `; SUFFIX` may be omitted.
        macro_rules! from_status_tuple {
            { $out:ident . $field:ident $(; $($suffix:tt)* )? } => {
                calc! { $out.$field = self.status_tuple.$field $( $($suffix)+ )? }
            };
        }

        let mut md_none_defer = NoneDefer::new();

        let (plain_r, md_r) = {
            calc! { both.identity    = self.id.rsa }
            calc! { both.publication = netstatus::IgnoredPublicationTimeSp }
            from_status_tuple! { both.ip }
            from_status_tuple! { both.nickname; .clone() }
            from_status_tuple! { plain.doc_digest; .into() }
            from_status_tuple! { both.or_port }
            from_status_tuple! { both.dir_port }
            calc! { md.doc_digest = NotPresent }

            construct_both! {
                netstatus::plain::RouterStatusIntroItem, netstatus::md::RouterStatusIntroItem {
                    both. nickname, identity, doc_digest, publication, ip;
                } {
                    both. or_port, dir_port;
                }
            }
        };

        calc! { both.ed25519_id = NotPresent }
        calc! { plain.m = NotPresent }
        calc! { plain, md .w }

        calc! { out.flags }
        // "routers that do not have the Running flag are not listed at all."
        if !out_flags.contains(RelayFlag::Running) {
            return Ok(None);
        }
        calc! { both.flags = out_flags.clone() }
        calc! { both.protos }
        calc! { both.version }

        // In principle we could omit writing these, and let Constructor default them,
        // but this way it's clearer that we've thought of every field,
        // and it might catch mistakes.
        calc! { md.port_policy = NotPresent }
        calc! { both.stats = NotPresent }

        let md_m = md_none_defer.handle(
            {
                calc! { md.m }
                Ok::<_, Bug>(md_m)
            },
            || [0; 32].into(),
        )?;

        //---------- inputs are same status-tuple ----------

        let inputs = inputs
            .iter()
            .filter(|(_, rs_v)| StatusTuple::from_rs(rs_v) == self.status_tuple)
            .collect_vec()
            .into_iter();
        let computed = SameStatusTupleAC {};
        let context = context.with_computed(&computed);

        calc! { plain,md .a <+ aggregate_a_items }
        calc! { plain.port_policy }

        //---------- assemble the output ----------

        let (plain, md) = construct_both! {
            netstatus::plain::RouterStatus, netstatus::md::RouterStatus {
                both. r, m, flags, protos, w, ed25519_id;
            } {
                both. a, version, port_policy, stats;
            }
        };
        Ok(Some((plain, md_none_defer.finish(md))))
    }
}

impl Aggregate<RouterStatusAC<'_>> for VoteRelayBandwidthItem {
    type Output = RelayBandwidthItem;

    #[allow(clippy::needless_late_init)] // re median_inputs and unmeasured; clearer this way
    fn aggregate<'i>(
        context: ConsensusContextRefs<RouterStatusAC<'_>>,
        inputs: impl ComponentInVotes<&'i VoteRelayBandwidthItem>,
    ) -> Result<RelayBandwidthItem, ConsensusError>
    where
        Self: 'i,
    {
        // https://spec.torproject.org/dir-spec/computing-consensus.html#router-status-entries
        // under "`w` item".

        const MEASURED: &str = "Measured";
        const BANDWIDTH: &str = "Bandwidth";
        const UNMEASURED: &str = "Unmeasured";
        const MAX_UNMEASURED_BW_PARAM: &str = "maxunmeasuredbw";
        const MEASURED_THRESHOLD: usize = 3;

        let get_inputs = |k| {
            inputs
                .votes()
                .filter_map(move |rwi| rwi.w.as_ref()?.get(k).copied())
        };
        let calc_median = |k| functions::low_median_raw(get_inputs(k));

        let out; // the calculated output value, for Bandwdith
        let unmeasured; // the (keyword, value) for Unmeasured, or None
        if get_inputs(MEASURED).count() >= MEASURED_THRESHOLD {
            out = calc_median(MEASURED).expect(".count() was >= MEASURED_THRESHOLD so >0");
            const_assert!(MEASURED_THRESHOLD > 0);
            unmeasured = None;
        } else if let Some(median) = calc_median(BANDWIDTH) {
            let max_unmeasured = context
                .computed
                .params
                // no default in the spec, see
                // https://spec.torproject.org/param-spec.html#voting
                .without_defaults()
                .get(MAX_UNMEASURED_BW_PARAM)
                .copied()
                // w items are unsigned 32-bit, but it's capped using netparams which are
                // are *signed* 32-bit.  If the netparam is negative, ignore it
                // (rather than treating it as zero).
                .and_then(|mu: i32| u32::try_from(mu).ok());

            out = chain!([median], max_unmeasured,)
                .min()
                .expect("[median] is nonempthy");
            unmeasured = Some((UNMEASURED, 1));
        } else {
            // There were no w lines, or not enough had Measured, or none had Bandwidth
            return Ok(RelayBandwidthItem::default());
        }

        let out = chain!([(BANDWIDTH, out)], unmeasured)
            .collect::<ParamValues<_>>()
            .try_into()
            .map_err(into_internal!("generated bad w item"))?;

        Ok(out)
    }
}

impl Aggregate<RouterStatusAC<'_>> for DocRelayFlags {
    type Output = DocRelayFlags;

    fn aggregate<'i>(
        context: ConsensusContextRefs<RouterStatusAC<'_>>,
        inputs: impl ComponentInVotes<&'i Self>,
    ) -> Result<Self::Output, ConsensusError>
    where
        Self: 'i,
    {
        let mut out: DocRelayFlags = context
            .computed
            .known_flags
            // "A routerstatus has a flag set if that is included by more than half of the
            // authorities who care about that flag."
            .iter_incl_unknown()?
            .try_filter(|flag| {
                // Check the votes' opinions about `flag`
                let mut tally = BoolIndexedArray::<usize>::default();
                for (vnum, vote_rs_flags) in inputs.iter() {
                    let vote_known_flags = &context.votes.vote(vnum)?.preamble.known_flags;
                    if !vote_known_flags.contains_incl_unknown(flag)? {
                        // This authority didn't advertise this flag as one it knows about.
                        // It's possible that it is included in that authority's vote for this
                        // relay anyway; if so we disregard it.
                        continue;
                    }
                    let is_in_favour: bool = vote_rs_flags.contains_incl_unknown(flag)?;
                    let update = &mut tally[is_in_favour];
                    // can't overflow, but let's use saturating add anyway
                    *update = update.saturating_add(1);
                }
                let y = tally.more_yes_than_no();
                Ok::<_, Bug>(y)
            })
            .try_collect()?;

        // https://spec.torproject.org/dir-spec/computing-consensus.html#routerstatuses
        #[allow(clippy::single_element_loop)] // more uniform this way
        {
            // TODO DIRAUTH this needs to be tested somehow
            use RelayFlag as F;
            let out = &mut out.known;
            if out.contains(F::MiddleOnly) {
                for clear in [F::Exit, F::Guard, F::V2Dir, F::HSDir] {
                    out.remove(clear);
                }
                for set in [F::BadExit] {
                    if context.computed.known_flags.contains(set) {
                        out.insert(set);
                    }
                }
            }
        }

        Ok(out)
    }
}

/// Obtain the relevant md digest from a vote rs
///
/// Returns `Ok(None)` if this voter didn't provide a relevant md digest for this method.
///
/// Throws `Err` if the vote was erroneous.  (This should then be logged.)
fn md_digest_from_vote(
    context: ConsensusContextRefs<RouterStatusAC<'_>>,
    vote: &[netstatus::RouterStatusMdDigestsVote],
) -> Result<Option<MdDigest>, String> {
    Ok(vote
        .iter()
        .filter(|e| e.consensus_methods.methods.contains(&context.method))
        .flat_map(|e| &e.digests)
        .filter(|d| matches!(d.alg, DigestName::Sha256))
        .map(|d| &*d.value)
        .at_most_one()
        .map_err(|_: itertools::ExactlyOneError<_>| "multiple md digests for same router")?
        .map(|d| FixedB64::from_byte_slice(d).ok_or("wrong md digest len"))
        .transpose()?)
}

impl Aggregate<RouterStatusAC<'_>> for Vec<netstatus::RouterStatusMdDigestsVote> {
    type Output = Option<MdDigest>;

    fn aggregate<'i>(
        context: ConsensusContextRefs<RouterStatusAC<'_>>,
        inputs: impl ComponentInVotes<&'i Self>,
    ) -> Result<Self::Output, ConsensusError>
    where
        Self: 'i,
    {
        let counts: HashMap<MdDigest, usize> = inputs
            .iter()
            .filter_map(|(vnum, v)| {
                md_digest_from_vote(context, v).unwrap_or_else(|e: String| {
                    bad_vote!(vnum, "{e}");
                    None
                })
            })
            .counts();

        let n_opinions = counts.values().sum();

        let selected = counts
            .into_iter()
            .find(|(_md, count)| is_more_than_half_of(*count, n_opinions))
            .map(|(md, _count)| md);

        Ok(selected)
    }
}

impl Aggregate<RouterStatusAC<'_>> for tor_protover::Protocols {
    type Output = Self;

    fn aggregate<'i>(
        context: ConsensusContextRefs<RouterStatusAC<'_>>,
        inputs: impl ComponentInVotes<&'i Self>,
    ) -> Result<Self::Output, ConsensusError>
    where
        Self: 'i,
    {
        Ok(functions::choose_most_popular_amongst_votes(
            context,
            inputs,
            |pr: &tor_protover::Protocols| pr.to_string(),
        )?
        .unwrap_or_default())
    }
}

impl Aggregate<RouterStatusAC<'_>> for Option<netstatus::SoftwareVersion> {
    type Output = Self;

    fn aggregate<'i>(
        context: ConsensusContextRefs<RouterStatusAC<'_>>,
        inputs: impl ComponentInVotes<&'i Self>,
    ) -> Result<Self::Output, ConsensusError>
    where
        Self: 'i,
    {
        functions::choose_most_popular_amongst_votes(
            context,
            inputs.with_opinions(),
            functions::ord_string_reverse_choose_lexically_latest,
        )
    }
}

/// Calculate the `a` item(s) in the consensus
///
/// Has the signature of [`Aggregate::aggregate`] for `RouterStatus.a`.
/// Not `impl Aggregate for ..SocketAddr..` because the behaviour is quite special.
#[allow(clippy::ref_option_ref)] // clippy complains about the type annotation in the closure
fn aggregate_a_items<'i>(
    _context: ConsensusContextRefs<SameStatusTupleAC>,
    inputs: impl ComponentInVotes<&'i Vec<SocketAddr>>,
) -> Result<Vec<SocketAddr>, ConsensusError> {
    let inputs = inputs.map(|(vnum, v)| (vnum, v.first()));

    let output = functions::choose_most_popular_amongst_votes_raw(
        inputs,
        // fallback ordering is "natural" according to Rust, which matches the spec
        |a: &Option<&SocketAddr>| std::cmp::Reverse(*a),
    )?
    .flatten()
    .cloned();

    Ok(output.into_iter().collect())
}

impl Aggregate<SameStatusTupleAC> for Option<Intern<PortPolicy>> {
    type Output = Self;

    fn aggregate<'i>(
        context: ConsensusContextRefs<SameStatusTupleAC>,
        inputs: impl ComponentInVotes<&'i Self>,
    ) -> Result<Self::Output, ConsensusError>
    where
        Self: 'i,
    {
        functions::choose_most_popular_amongst_votes(
            context,
            inputs.with_opinions(),
            functions::ord_string_reverse_choose_lexically_latest,
        )
    }
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
    fn relay_flags() -> Result<(), ConsensusError> {
        use tor_netdoc::types::relay_flags::DocRelayFlag;

        let n_voters = 5;

        type One = (&'static str, &'static [usize], &'static [usize], Option<()>);
        #[rustfmt::skip]
        let cases: &[One] = &[
            // flag name      known_flags   rs.f        expected
            ("unknown",       &[],          &[],        None),
            ("one-against",   &[0],         &[],        None),
            ("one-in-favour", &[0],         &[0],       Some(())),
            ("equal",         &[0,1,2,3],   &[0,1],     None),
            ("greater",       &[0,1,2,3],   &[0,1,2],   Some(())),
            ("contradict",    &[0,1,2],     &[0,3],     None),
        ];

        // We use `Unknown` always here.  That's OK because we're not trying to test
        // DocRelayFlag etc. (which is pretty straightforward anyway).
        let f_name = |one: &One| DocRelayFlag::Unknown(one.0.into());
        let f_known = |one: &One| one.1;
        let f_vote = |one: &One| one.2;
        let f_outcome = |one: &One| one.3;

        let mut cc = ConsensusCommonContext::new_for_test();
        cc.n_authorities = n_voters;
        let votes = (0..n_voters)
            .into_iter()
            .map(|v| {
                let mut vote = tor_netdoc::testdata_live::netstatus_vote().clone();
                vote.routers.truncate(1);

                let mk_flags = |extractor: fn(&One) -> &'static [usize]| {
                    cases
                        .iter()
                        .filter(|one| extractor(one).contains(&v))
                        .map(f_name)
                        .collect()
                };

                vote.preamble.known_flags = mk_flags(f_known);
                vote.routers[0].flags = mk_flags(f_vote);

                println!("vote");
                println!("    known   {:?}", vote.preamble.known_flags);
                println!("    router  {:?}", vote.routers[0].flags);

                vote
            })
            .collect_vec();
        cc.votes = votes.iter().collect();

        // TODO it seems likely that much of this testdata- and type-wrestling
        // will want to be reused/simplified as we add more test cases.

        let (plain_preamble, _) = netstatus::vote::Preamble::consensuses(
            cc.with_computed(&()),
            cc.votes
                .iter_enumerated()
                .map(|(vnum, vote)| (vnum, &vote.preamble)),
        )?;

        let output = DocRelayFlags::aggregate(
            cc.with_computed(&RouterStatusAC(&plain_preamble)),
            cc.votes
                .iter_enumerated()
                .map(|(vnum, vote)| (vnum, &vote.routers[0].flags)),
        )?;

        println!("output");
        println!("    known   {:?}", plain_preamble.known_flags);
        println!("    router  {:?}", output);

        for one in cases {
            assert_eq!(
                output.contains_incl_unknown(&f_name(one))?.then_some(()),
                f_outcome(one),
                "{:?}",
                one,
            );
        }

        Ok(())
    }

    #[test]
    #[traced_test]
    fn md_selection() -> anyhow::Result<()> {
        #[derive(Deftly)]
        #[derive_deftly(NetdocParseable)]
        struct TestVote {
            #[allow(unused)]
            vote: (),
            m: Vec<netstatus::RouterStatusMdDigestsVote>,
        }

        // A x 3: vtKpzB+Vw6LlETW6txvAH+1G6gJIl6x1D/N3NZdPK24
        // B x 2: PSFWDSIK+sMS6+fkLrc7PSZ6L0Rkscbz2WcmKCDIdOQ
        let votes = r#"vote # A, with irrelevant SHA1 ignored
m 1,2,3,METHOD sha256=vtKpzB+Vw6LlETW6txvAH+1G6gJIl6x1D/N3NZdPK24
m 1,2,3,METHOD sha1=AAAErLudKby6FyVrs1ko3b/Iq6k
vote # A
m METHOD sha256=vtKpzB+Vw6LlETW6txvAH+1G6gJIl6x1D/N3NZdPK24
vote # A
m METHOD sha256=vtKpzB+Vw6LlETW6txvAH+1G6gJIl6x1D/N3NZdPK24
vote # B, with irrelevant other method
m METHOD sha256=PSFWDSIK+sMS6+fkLrc7PSZ6L0Rkscbz2WcmKCDIdOQ
m 1 sha256=PSFWDSIK+sMS6+fkLrc7PSZ6L0Rkscbz2WcmKCDIdOQ
vote # B
m METHOD sha256=PSFWDSIK+sMS6+fkLrc7PSZ6L0Rkscbz2WcmKCDIdOQ
vote # BX but multiple values, so ignored
m METHOD sha256=PSFWDSIK+sMS6+fkLrc7PSZ6L0Rkscbz2WcmKCDIdOQ
m METHOD sha256=PSFWDSIK+sMS6+fkLrc7PSZ6L0Rkscbz2WcmKCDIdOQ
m METHOD sha256=PSFWDSIK+sMS6+fkLrc7PSZ6L0Rkscbz2WcmKCDIdOQ
m METHOD sha256=PSFWDSIK+sMS6+fkLrc7PSZ6L0Rkscbz2WcmKCDIdOQ
m METHOD sha256=PSFWDSIK+sMS6+fkLrc7PSZ6L0Rkscbz2WcmKCDIdOQ
vote # B but only for irrelevant methods
m 1,2,3 sha256=PSFWDSIK+sMS6+fkLrc7PSZ6L0Rkscbz2WcmKCDIdOQ
"#;

        let votes = votes.replace("METHOD", &SupportedConsensusMethod::MAX.to_string());
        println!("----- test votes -----\n{votes}----- ^ test votes -----");

        let votes: Vec<TestVote> = parse_netdoc_multiple(&ParseInput::new(&votes, "<test data>"))?;

        const NICK: &str = "lisdex";

        compute_test(
            votes.len(),
            12,
            |i, vote| {
                vote.routers
                    .iter_mut()
                    .find(|rs| rs.r.nickname.as_str() == NICK)
                    .unwrap()
                    .m = votes[i].m.clone();
                Ok(())
            },
            |(_plain, md)| {
                let m = &md
                    .routers
                    .iter()
                    .find(|rs| rs.r.nickname.as_str() == NICK)
                    .expect("output router missing")
                    .m;
                assert_eq!(
                    m,
                    &"vtKpzB+Vw6LlETW6txvAH+1G6gJIl6x1D/N3NZdPK24".parse::<MdDigest>()?,
                );
                Ok(())
            },
        );

        Ok(())
    }

    #[test]
    fn protocols() {
        use tor_protover::Protocols;

        let p = |s| Protocols::from_str_c_compatible(s).unwrap();

        let inputs = [
            p("Link=1 counting=2-6 req=1 rec=1 neither=1"), // majority, first
            p("Link=1 counting=2-6 req=1 rec=1 neither=1"),
            p("Link=1"),
        ];

        compute_test(
            inputs.len(),
            4,
            |vnum, vote| {
                vote.routers.truncate(1);
                vote.routers[0].protos = inputs[vnum].clone();
                Ok(())
            },
            |(plain, md)| {
                assert_eq!(plain.routers[0].protos, inputs[0].clone());
                assert_eq!(md.routers[0].protos, inputs[0].clone());
                Ok(())
            },
        );
    }
}
