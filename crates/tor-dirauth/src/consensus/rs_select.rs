//! Calculate consensus routerstatus entries for one relay - select RS entries

use super::*;
use rs_common::*;

impl ConsensusesFromVotes for Vec<RouterStatusVote> {
    type PlainOutput = Vec<netstatus::plain::RouterStatus>;
    type MdOutput = Vec<netstatus::md::RouterStatus>;

    fn consensuses<'i>(
        context: &ConsensusContext,
        inputs: impl ComponentInVotes<&'i Self>,
    ) -> Result<(Self::PlainOutput, Self::MdOutput), ConsensusError>
    where
        Self: 'i,
    {
        // ---------- Calculate IdTuples to include ----------
        //
        // https://spec.torproject.org/dir-spec/computing-consensus.html#choosing-relay-ids

        let output_ids;
        let voters_per_id; // buffer; TODO want to use super let instead
        {
            let mut per_id = HashMap::<IdTuple, VoterSet>::new();
            for (vnum, voter_rs_list) in inputs.clone() {
                for rs in voter_rs_list {
                    let id = IdTuple::from_rs(rs);
                    per_id.entry(id).or_default().insert(vnum);
                }
            }
            voters_per_id = per_id;

            output_ids = voters_per_id
                .iter()
                .filter(|(_id, voters)| context.is_more_than_half_all_auths(voters.len()))
                .map(|(id, _voters)| id)
                .collect::<HashSet<&IdTuple>>();

            let discrep_report_filter = DiscrepReportFilter::from_outputs(&output_ids);

            for (id, voters) in &voters_per_id {
                if discrep_report_filter.id_is_discrepant(id) {
                    // Spec says to log the loose identities.  We log them in their pairs.
                    info!("discrepant relay identity {id} ({} voters)", voters.len());
                }
            }
        };

        // ---------- Choose StatusTuple for each output identity ----------
        //
        // https://spec.torproject.org/dir-spec/computing-consensus.html#choosing-relay-descs

        let status_tuple_cmp_key = |(status_tuple, voter_set): &'_ (
            StatusTuple,
            Box<RouterStatusPerRelevantVoter<'_>>,
        )| {
            (
                // matches the largest set
                voter_set.iter().filter(|rs| rs.is_some()).count(),
                // breaking ties in favor of the most recently published
                status_tuple.publication,
                // and then in favor of the smaller server descriptor digest
                cmp::Reverse(status_tuple.doc_digest),
            )
        };

        let output_rs_inputs = {
            let mut candidate_status_tuples = HashMap::<
                IdTuple,
                // for each possible output status-tuple, who voted for it:
                HashMap<StatusTuple, Box<RouterStatusPerRelevantVoter>>,
            >::new();
            for (vnum, voter_rs_list) in inputs.clone() {
                for rs in voter_rs_list {
                    let id = IdTuple::from_rs(rs);
                    if !output_ids.contains(&id) {
                        continue;
                    }
                    let status_tuple = StatusTuple::from_rs(rs);
                    *candidate_status_tuples
                        .entry(id)
                        .or_default()
                        .entry(status_tuple)
                        .or_insert_with(|| ti_vec![None; context.votes.len()].into_boxed_slice())
                        // If multiple routerstatuses in the vote for the same id,
                        // we choose arbitrarily
                        .get_mut(vnum)
                        .ok_or_else(|| internal!("{vnum:?} out of range"))?
                        // Store in the slot for this voter
                        = Some(rs);
                }
            }

            candidate_status_tuples
                .into_iter()
                .map(|(id, status_tuples)| {
                    // Determine the inputs to the per-routerstatus calculation.

                    // Select the preferred status-tuple.
                    let (status_tuple, per_voter) = status_tuples
                        .into_iter()
                        .max_by_key(status_tuple_cmp_key)
                        .expect("entry with no content, impossible");

                    ResolvedRouterStatusInputs {
                        id,
                        status_tuple,
                        per_voter,
                    }
                })
        };

        output_rs_inputs
            .map(|resolved_rs_input| resolved_rs_input.consensuses(context))
            .flatten_ok()
            .collect()
    }
}
