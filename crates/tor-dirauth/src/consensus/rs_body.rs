//! Calculate the body of a routerstatus we have decided to include

use super::*;
use rs_common::*;

impl<'i> ResolvedRouterStatusInputs<'i> {
    /// Calculate the plain and md routerstatuses
    ///
    /// Similar to `ConsensusesFromVotes::consensuses`,
    /// but takes one `ResolvedRouterStatusInputs`, which includes not only
    /// the routerstatuses from each vote, but also the id-tuple and status-tuple
    /// from the resolution part of the algorithm.
    ///
    /// Can return `None` to mean that this router should not be listed after all
    /// (eg, because its listing would lack the Running flag).
    pub(super) fn consensuses(
        &self,
        context: ConsensusContextRefs<PlainPreamble>,
    ) -> Result<
        Option<(
            //
            netstatus::plain::RouterStatus,
            netstatus::md::RouterStatus,
        )>,
        ConsensusError,
    > {
        let inputs = self
            .per_voter
            .iter_enumerated()
            .filter_map(|(vnum, rs_v)| Some((vnum, rs_v.as_ref()?)));

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

        let (plain_r, md_r) = {
            calc! { both.identity    = self.id.rsa }
            calc! { both.publication = netstatus::IgnoredPublicationTimeSp }
            from_status_tuple! { both.ip }
            from_status_tuple! { both.nickname; .clone() }
            from_status_tuple! { plain.doc_digest; .into() }
            from_status_tuple! { both.or_port }
            from_status_tuple! { both.dir_port }

            // TODO DIRAUTH replace dummy value; actually calculate which md digest to include
            calc! { md.doc_digest = Default::default() }

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
        calc! { plain, md .weight }

        // TODO DIRAUTH replace routerstatus dummy values
        calc! { both.flags = DocRelayFlags::new_empty_unknown_discarded() }
        calc! { both.protos = Default::default() }
        calc! { md.m = [0; 32].into() }

        Ok(Some(construct_both! {
            netstatus::plain::RouterStatus, netstatus::md::RouterStatus {
                both. r, m, flags, protos, weight, ed25519_id;
            } {
                // TODO DIRAUTH routerstatus fields missing
            }
        }))
    }
}

impl Aggregate<PlainPreamble> for VoteRelayWeightsItem {
    type Output = RelayWeightsItem;

    #[allow(clippy::needless_late_init)] // re median_inputs and unmeasured; clearer this way
    fn aggregate<'i>(
        context: ConsensusContextRefs<PlainPreamble>,
        inputs: impl ComponentInVotes<&'i VoteRelayWeightsItem>,
    ) -> Result<RelayWeightsItem, ConsensusError>
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
                .clone()
                .filter_map(move |(_vnum, rwi)| rwi.w.as_ref()?.get(k).copied())
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
            return Ok(RelayWeightsItem::default());
        }

        let out = chain!([(BANDWIDTH, out)], unmeasured)
            .collect::<NetParams<_>>()
            .try_into()
            .map_err(into_internal!("generated bad w item"))?;

        Ok(out)
    }
}
