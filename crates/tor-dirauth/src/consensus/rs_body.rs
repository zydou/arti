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
        context: &ConsensusContext,
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

impl Aggregate for VoteRelayWeightsItem {
    type Output = RelayWeightsItem;

    #[allow(clippy::needless_late_init)] // re median_inputs and unmeasured; clearer this way
    fn aggregate<'i>(
        context: &ConsensusContext,
        inputs: impl ComponentInVotes<&'i VoteRelayWeightsItem>,
    ) -> Result<RelayWeightsItem, ConsensusError>
    where
        Self: 'i,
    {
        // https://spec.torproject.org/dir-spec/computing-consensus.html#router-status-entries
        // under "`w` item".
        //
        // TODO DIRAUTH implements torspec!542, as yet unmerged, so may need to change.

        const MEASURED: &str = "Measured";
        const BANDWIDTH: &str = "Bandwidth";
        const UNMEASURED: &str = "Unmeasured";
        const MEASURED_THRESHOLD: usize = 3;

        // Obtains the Measured value from this vote, if its there and we ought to use it
        let get_measured = |(vnum, rwi): (_, &VoteRelayWeightsItem)| -> Option<u32> {
            if context.bandwidth_authorities.contains(&vnum) {
                rwi.w.as_ref()?.get(MEASURED).copied()
            } else {
                None
            }
        };
        // Obtains some bandwidth value from this vote
        let get_bandwidth = |(vnum, rwi): (_, &VoteRelayWeightsItem)| -> Option<u32> {
            get_measured((vnum, rwi)).or_else(|| {
                //
                rwi.w.as_ref()?.get(BANDWIDTH).copied()
            })
        };

        // Iterator of the Measured values.
        let measured_inputs = inputs.clone().filter_map(&get_measured as &dyn Fn(_) -> _);

        let median_inputs; // the inputs for the median
        let unmeasured; // the (keyword, value) for Unmeasured, or None
        if measured_inputs.clone().count() >= MEASURED_THRESHOLD {
            median_inputs = measured_inputs;
            unmeasured = None;
        } else {
            median_inputs = inputs.clone().filter_map(&get_bandwidth as _);
            unmeasured = Some((UNMEASURED, 1));
        };

        let Some(median) = functions::low_median_raw(median_inputs) else {
            // There were no w lines, or none of them had a bandwidth of any kind.
            return Ok(RelayWeightsItem::default());
        };

        let out = chain!([(BANDWIDTH, median)], unmeasured)
            .collect::<NetParams<_>>()
            .try_into()
            .map_err(into_internal!("generated bad w item"))?;

        Ok(out)
    }
}
