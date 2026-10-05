//! routerstatus calculation - interface between rs selection and per-rs calculation

use super::*;
pub(super) use netstatus::vote::RouterStatus as RouterStatusVote;
pub(super) use routerdesc::RdDigest;
pub(super) use tor_netdoc::doc::routerdesc;

/// Router id-tuple as used in consensus calculations
///
/// See
/// <https://spec.torproject.org/dir-spec/computing-consensus.html#choosing-relay-ids>
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Deftly, derive_more::Display)]
#[derive_deftly(DiscrepReportFilter)]
#[display("ed={ed} / rsa={rsa}")]
pub(super) struct IdTuple {
    /// ed25519
    pub ed: Ed25519Public,

    /// RSA
    pub rsa: Base64Fingerprint,
}

/// Router status-tuple: critical info unified as an aggregate, "most voters wins"
///
/// See
/// <https://spec.torproject.org/dir-spec/computing-consensus.html#choosing-relay-descs>
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Deftly)]
#[derive_deftly(StatusTupleFromRouterStatusVote)]
pub(super) struct StatusTuple {
    /// routerdesc digest
    pub doc_digest: RdDigest,
    /// publication field
    pub publication: Iso8601TimeSp,
    /// nickname
    pub nickname: Nickname,
    /// ip
    pub ip: Ipv4Addr,
    /// dir_port
    pub dir_port: u16,
    /// or_port
    pub or_port: u16,
}

/// The `RouterStatusVote` provided by each voter that voted for this id-tuple
///
/// `None` for voters who didn't vote for this id-tuple.
pub(super) type RouterStatusPerRelevantVoter<'i> =
    TiSlice<VoterNum, Option<&'i netstatus::vote::RouterStatus>>;

/// Input to per-routerstatus routerstatus calculation
pub(super) struct ResolvedRouterStatusInputs<'i> {
    /// id-tuple
    pub id: IdTuple,

    /// status-tuple
    pub status_tuple: StatusTuple,

    /// routerstatuses from each vote that voted for this id-tuple
    pub per_voter: Box<RouterStatusPerRelevantVoter<'i>>,
}

impl IdTuple {
    /// Extract the id-tuple from a vote's routerstatus
    pub(super) fn from_rs(rs: &RouterStatusVote) -> Self {
        IdTuple {
            ed: rs.ed25519_id.pk,
            rsa: rs.r.identity,
        }
    }
}

define_derive_deftly! {
    /// Defines `struct DiscrepReportFilter`
    DiscrepReportFilter beta_deftly:

    /// Filter for discrepancy report algorithm
    ///
    /// Embodies the *chosen* relay identities, so that we can report the *other*
    /// relay identities for which we do output a routerdesc mentioning at least one
    /// of the relevant identities.
    ///
    /// Helps implement the logging requirement in
    /// <https://spec.torproject.org/dir-spec/computing-consensus.html#choosing-relay-ids>
    #[derive(Debug)]
    pub(super) struct DiscrepReportFilter<'i> {
        output_ids: &'i HashSet<&'i IdTuple>,
      $(
        $<included_ $fname>: HashSet<&'i $ftype>,
      )
    }

    impl<'i> DiscrepReportFilter<'i> {
        /// Make a new filter from the set of chosen output identities
        pub(super) fn from_outputs(output_ids: &'i HashSet<&'i IdTuple>) -> Self {
            Self {
                output_ids,
              $(
                $<included_ $fname>:
                    output_ids
                        .clone()
                        .into_iter()
                        .map(|id| &id.$fname)
                        .collect(),
              )
            }
        }

        /// Is this id discrepant (ie, should it be logged) ?
        pub(super) fn id_is_discrepant(&self, id: &IdTuple) -> bool {
            if self.output_ids.contains(id) {
                return false;
            }
          $(
            self.$<included_$fname>.contains(&id.$fname) ||
          )
            false
        }
    }
}
use derive_deftly_template_DiscrepReportFilter;

define_derive_deftly! {
    /// Derives `StatusTuple::from_rs` by copying the corresponding fields
    ///
    /// The data comes from the intro item `r`; it so happens that all the fields for use
    /// in the status-tuple are in the intro item.
    StatusTupleFromRouterStatusVote beta_deftly, meta_quoted strip:

    $impl {
        /// Extract the `StatusTuple` from a routerstatus
        pub(super) fn from_rs(rs: &RouterStatusVote) -> Self {
            Self { $(
                $fname: rs.r.$fname.clone().into(),
            ) }
        }
    }
}
use derive_deftly_template_StatusTupleFromRouterStatusVote;
