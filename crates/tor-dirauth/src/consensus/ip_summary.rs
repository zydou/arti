//! IPv4 port policy summarisation - approximate algorithm
//!
//! <https://spec.torproject.org/dir-spec/computing-microdescriptors.html#item:p>
//!
//! Contrast precise summaries, in `tor-netdoc/src/types/policy/summary.rs`.

#![allow(unused)] // TODO DIRAUTH

use super::*;

// These are very specific to this area; let's not have them in the crate prelude.
use tor_netdoc::types::policy::{
    AddrPolicy, AddrPortPattern, IpPattern, PortPolicy, PortRange, RuleKind,
};

/// How many rejected IPv4 addresses are allowed before we consider the port closed
///
/// Has the same value as [`tor_netdoc::types::policy::PortSummaryThresholds::v4`].
/// But we recapitulate it here, because we mustn't change the output of *this* algorithm
/// without a consensus method change.
///
/// I.e., changing this requires a consensus method change.
const MAX_REJECTED: u32 = 1 << 25;

/// Allows us to write the private ranges in CIDR-like format
macro_rules! ipnet_consts { { $( $a:literal $( , $bcd:literal )* / $p:literal; )* } => {
    &[ $(
        Ipv4Net::new_assert(Ipv4Addr::new($a $(, $bcd)*), $p),
    )* ]
} }

/// Private networks, disregarded for counting rejected number of addresses
///
/// Cut and paste from the spec, with light formatting editing:
/// add semicolon separators; change `.` to `,`; use `//` for comments.
// (We can't use `.` because bits of the input IPv4 addresses end up looking like float literals!)
///
/// <https://spec.torproject.org/dir-spec/computing-microdescriptors.html#item:p:public-ipv4>
///
/// Changing this requires a consensus method change.
/// If we ever do that, we may want to mark these entries with consensus method(s)
/// that they're used in, or have multiple lists, or something.
const PRIVATE_NETWORKS: &[Ipv4Net] = ipnet_consts![
    0,0,0,0/8; // This Network, RFC791 3.2
    10,0,0,0/8; 172,16,0,0/12; 192,168,0,0/16; // Private-Use, RFC1918
    100,64,0,0/10; // Shared Address Space, RFC6598
    127,0,0,0/8; // Loopback, RFC1122 3.2.1.3
    169,254,0,0/16; // Link Local, RFC3927
    192,0,0,0/24; // IETF Protocol Assignments, RFC6890
    192,0,2,0/24; 198,51,100,0/24; 203,0,113,0/24; // Documentation (TEST-NET-[123]), RFC5737
    198,18,0,0/15; // Benchmarking, RFC2544
    192,31,196,0/24; // AS112-v4 (reverse lookup for private addrs) RFC7535
    192,175,48,0/24; // Direct Delegation AS112 RFC5734
    255,255,255,255/32; // “Limited Broadcast”, RFC8190, RFC919 s7
];

/// Port resolution algorithm, main state
///
/// We implement the algorithm specified in
/// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:p>.
///
/// As noted there, we perform the algorithm in parallel, and independently, for each port.
/// But, we use a rangemap so that we can deal with ranges rather than individual ports.
///
/// We loop over all the rules, once, in `summarise_policy_v4_approximate`.
/// This is done in *forward* order; we handle the summarisation algorithm's early exit
/// by having an explicit `Stopped` state in the per-port state.
///
/// We interpret each rule, in `ResolutionState::apply_rule`.
/// That decides what effect the rule has on the relevant ports,
/// and calls `ResolutionState::update_for_ports` to make the appropriate state change.
#[derive(Debug)]
struct ResolutionState {
    /// State of the algorithm for each port
    ///
    /// This always contains *some* entry for 1..65535, but nothing for 0.
    port_map: RangeInclusiveMap<u16, PortState>,

    /// How many ports we have resolve (ie, are in state `Stopped`)
    ///
    /// When this reaches 2^16-1, *all* our parallel loops have stopped,
    /// and we can skip processing the rest of the rules.
    total_resolved: u16,
}

/// The state of the algorithm for any one port.
///
/// (Actually, one of these is stored for a *range* of ports.
/// They are split up and joined as necessary by `rangemap_mutate_range`
/// and `RangeInclusiveMap`.)
#[derive(Debug, Clone, Eq, PartialEq)]
enum PortState {
    /// The algorithm for this port has stopped, yielding `RuleKind`
    Stopped(RuleKind),

    /// The algorithm for this port is continuing
    Running(PortStateRunning),
}
use PortState as PS;

/// State of the still-running algorithm for any one port
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct PortStateRunning {
    /// Rejected address count (saturating)
    rejected: u32,
}

/// "Error" thrown by algorithm computations
#[derive(Debug, derive_more::From)]
enum EarlyTermination {
    /// Pseudo-error, thrown to stop the algorithm early when every port has been decided
    EveryPortResolved,

    /// Bug, "crash" - we don't want to panic, ever
    Bug(#[from] Bug),
}

/// Return the number of hosts in this network, clamped to `u32::MAX`
///
/// Very like `Net::host_count_saturating` in tor-netdoc `summary.rs`,
/// but that returns `u128` and isn't public (and maybe doesn't want to be),
/// and takes less care to avoid impossible panics,
/// whereas this is simpler because it can be IPv4-specific.
fn host_count_saturating(net: Ipv4Net) -> u32 {
    let shift = 32_u8.saturating_sub(net.prefix_len());
    1_u32.checked_shl(shift.into()).unwrap_or(u32::MAX)
}

impl ResolutionState {
    /// Update the state, for those of the relevant ports which are still running
    ///
    /// For each port in `ports` that hasn't `Stopped`, calls `update`.
    /// `update` should return the new state, which might be `Running` or `Stopped`.
    ///
    /// Updates `total_resolved`, and throws `EveryPortResolved` if appropriate.
    fn update_for_ports(
        &mut self,
        ports: RangeInclusive<u16>,
        mut update: impl FnMut(PortStateRunning) -> PortState,
    ) -> Result<(), EarlyTermination> {
        // Silently disregard port 0 as per the spec
        //  https://spec.torproject.org/dir-spec/computing-consensus.html#exit-summary:semantics
        let ports = if *ports.start() == 0 {
            1..=*ports.end()
        } else {
            ports
        };

        rangemap_mutate_range(
            &mut self.port_map,
            &ports,
            // important that we shadow `ports` here
            |state, ports| {
                let state = state
                    .as_mut()
                    .ok_or_else(|| internal!("state entry missing for {ports:?}"))?;
                let running = match state {
                    PS::Running(y) => y,
                    PS::Stopped(_) => return Ok(()),
                };
                *state = update(*running);
                if let PS::Stopped(_) = state {
                    // Fine points, that make this correct:
                    //
                    // We were Running before, and now we're Stopped, so all these ports
                    // are indeed *newly* Stopped.
                    //
                    // If we return `Err`, the update we make to *this* port range
                    // will indeed be applied (see docs for rangemap_mutate_range),
                    // so we don't lose *this* port range's store.
                    //
                    // And, in that case ranges overlapping with the outer ports
                    // will not be processed, but that's OK because we only throw Err
                    // if we know they've already been made Stopped.
                    //
                    // Use checked arithmetic to avoid panics, and an IEFE to catch the Nones.
                    self.total_resolved = (|| {
                        self.total_resolved.checked_add(
                            ports
                                .end()
                                .checked_sub(*ports.start())?
                                // start is always >0, so this is at most u16::MAX, OK
                                .checked_add(1)?,
                        )
                    })()
                    .ok_or_else(|| internal!("overflow in resolved port counts"))?;

                    // Compare with 65535, not 65536, since we never add anything for port 0
                    #[allow(clippy::absurd_extreme_comparisons)] // clippy wants ==, urgh
                    if self.total_resolved >= u16::MAX {
                        return Err(EarlyTermination::EveryPortResolved);
                    }
                }
                Ok(())
            },
        )
    }

    /// Perform one step of the resolution/summarisation algorithm: apply one rule
    ///
    /// This applies the rule, in parallel, to all the ports it applies to.
    /// Ports where the algorithm has already stopped are skipped
    /// (this is done by code in `update_for_ports`).
    fn apply_rule(
        &mut self,
        rule_kind: RuleKind,
        pat: &AddrPortPattern,
    ) -> Result<(), EarlyTermination> {
        use IpPattern as IPP;

        let ports = pat.ports.to_range();

        // This code is fairly specific to the fact that we're doing this only for IPv4.
        // To support IPv6 generically, we'd need a whole panoply of v4/v6 generics
        // for IpNet, the private address nets, the max rejected, and so on.
        //
        // I think we probably won't ever want to do exit summarisation in dirauths for v6.
        // Having the relay do its own summary is fine.
        //
        // But, anyway here are some notes for how to support V6:
        //  - Expose the Net trait from tor-netdoc's summariser.
        //    Under some other name, presumably, and maybe it should be implemented
        //    for IpvXAddr rather IpvXNet.
        //  - In each match below, use those trait methods.
        //    To avoid missing one, maybe call a trait function on pat.addrs
        //    and match on the return value instead.
        //    Or maybe reuse the code in tor-netdoc's `Summariser::apply_rule`.
        //  - Make our own subtrait of Net, and
        //    make MAX_REJECTED and PRIVATE_NETWORKS trait constants in it
        //  - Make PortStateRunning.rejected big enough for v6
        //    (this might mean adding generics to PortState)
        //  - `grep -i ipv` this file to see what you missed
        //  - consider calculating v4 and v6 in parallel

        match (rule_kind, pat.addrs) {
            // From the spec:
            //
            // "* Disregard items whose addrspec matches no IPv4 addresses"
            (_, IPP::Net(IpNet::V6(_))) => Ok(()),

            (RuleKind::Reject, IPP::Net(IpNet::V4(net))) => {
                // "* Disregard `reject`s whose addrspec is an IPv4 subnet
                //    completely contained within a private network (see below)."
                //
                // (As per the spec's suggested approximation, we treat partially-private
                // rejects as public, rather than counting the addresses precisely.)
                if PRIVATE_NETWORKS
                    .iter()
                    .any(|private| private.contains(&net))
                {
                    return Ok(());
                }
                // "* For other `reject` lines, add the size of the subnet
                //    to the "rejected address count"."
                self.update_for_ports(ports, |mut state| {
                    // Avoid overflow; if we saturate, we'll treat it as rejected - fine.
                    state.rejected = state.rejected.saturating_add(host_count_saturating(net));
                    if state.rejected > MAX_REJECTED {
                        // * If the "rejected address count" exceeds the 2^25 limit,
                        //   stop and list the port as closed.
                        PS::Stopped(RuleKind::Reject)
                    } else {
                        PS::Running(state)
                    }
                })
            }

            (RuleKind::Reject, IPP::All) => {
                // This is an "other `reject` line" - but we didn't handle it above.
                // It necessarily blows the limit.
                self.update_for_ports(ports, |_: PortStateRunning| {
                    //
                    PS::Stopped(RuleKind::Reject)
                })
            }

            // "* For an `accept` item which matches all IPv4 addresses,
            //    stop and list the port as open."
            (RuleKind::Accept, IPP::All) => {
                // All-addresses patterns
                self.update_for_ports(ports, |_: PortStateRunning| {
                    //
                    PS::Stopped(RuleKind::Accept)
                })
            }
            (RuleKind::Accept, IPP::Net(IpNet::V4(net))) => {
                if net.prefix_len() == 0 {
                    // IPv4-only patterns matching all IPv4 addresses
                    self.update_for_ports(ports, |_: PortStateRunning| {
                        PS::Stopped(RuleKind::Accept)
                    })
                } else {
                    // Ignore IPv4 accepts which don't accept every address.
                    Ok(())
                }
            }
        }
    }
}

/// IPv4 port policy summarisation, for use by dirauths
///
/// <https://spec.torproject.org/dir-spec/computing-microdescriptors.html#item:p>
///
/// This is an approximate algorithm.
///
/// It is for use by directory authorities when processing routerdescs into
/// microdescs.
///
/// Should *not* be used by relays, or other entities processing reasonably-trusted
/// policy data.  Those should use [`AddrPolicy::summarise_precise`].
///
/// Only implemented for IPv4.
pub(crate) fn summarise_policy_v4_approximate(
    policy: &AddrPolicy,
    _method: SupportedConsensusMethod,
) -> Result<PortPolicy, Bug> {
    let mut state = ResolutionState {
        port_map: RangeInclusiveMap::new(),
        total_resolved: 0,
    };

    state.port_map.insert(
        //
        1..=u16::MAX,
        PS::Running(PortStateRunning { rejected: 0 }),
    );

    let r = (|| {
        for (rule_kind, pat) in policy.rules() {
            state.apply_rule(rule_kind, &pat)?;
        }
        // Otherwise, on reaching the end of the exit policy items, list the port as open.
        state.update_for_ports(1..=u16::MAX, |_: PortStateRunning| {
            PS::Stopped(RuleKind::Accept)
        })
    })();

    match r {
        Err(EarlyTermination::EveryPortResolved) => {}
        Err(EarlyTermination::Bug(bug)) => return Err(bug),
        Ok(()) => return Err(internal!("not every port resolved ({state:?})")),
    }

    let allowed = state
        .port_map
        .into_iter()
        .map(|(range, state)| {
            Ok::<_, Bug>(match state {
                PS::Stopped(RuleKind::Reject) => None,
                PS::Stopped(RuleKind::Accept) => Some(
                    PortRange::from_range(range.clone())
                        .ok_or_else(|| internal!("malformed port range {range:?}"))?,
                ),
                PS::Running(wat) => {
                    Err(internal!("some port loop still running {range:?} {wat:?}"))?
                }
            })
        })
        .flatten_ok()
        .process_results(|ranges| PortPolicy::from_ordered_allowed_ranges(ranges))?
        .map_err(into_internal!("ranges from rangemap out of order"))?;

    Ok(allowed)
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
    use derive_deftly::Deftly;
    use itertools::Itertools;
    use tor_netdoc::parse_testcase_from_netdoc;
    use tor_netdoc::types::policy::PortSummaryThresholds;

    /// cut-down (IPv4 only) version of tor-netdoc's summary.rs version
    const REJECT_PRECISELY_ALLOWED_AMOUNT: &str = r"
                accept *:100
                reject 1.0.0.0/8:400-419
                reject 2.0.0.0/8:410-429
                reject 0.0.0.0/0:1-399
                reject 0.0.0.0/0:430-65535
    ";

    #[derive(Deftly)]
    #[derive_deftly(tor_netdoc::NetdocParseableFields)]
    struct IsPreciseTestCase {
        /// Input policy, `accept` and `reject` lines
        #[deftly(netdoc(flatten))]
        full: AddrPolicy,
    }

    /// Run one test case where the approx summary is, in fact, precise
    ///
    /// The expected output is calculated with [`AddrPolicy::summarise_precise`]
    /// (which uses a quite different implementation strategy to the code here.)
    fn chk_is_precise(input_doc: &str) {
        let case: IsPreciseTestCase = parse_testcase_from_netdoc(input_doc);

        let approx = summarise_policy_v4_approximate(
            //
            &case.full,
            SupportedConsensusMethod::MAX,
        )
        .unwrap();

        let precise = case.full.summarise_precise(
            // if the thresholds change in a new consensus method, we'll probably need
            // to explicitly change the value here and maybe test both thresholds
            &PortSummaryThresholds::default(),
            PRIVATE_NETWORKS.iter().copied().map(IpNet::V4),
        );

        assert_eq!(approx, precise.v4);
    }

    #[test]
    fn basics() {
        chk_is_precise(r"p4 accept 1-65535");
        chk_is_precise(r"p4 reject 1-65535");
        chk_is_precise(r"p4 accept *:*");
        chk_is_precise(r"p4 reject *:25");
    }

    #[test]
    fn edge_cases() {
        chk_is_precise(REJECT_PRECISELY_ALLOWED_AMOUNT);

        // reject a private net, proving it is disregarded
        chk_is_precise(&format!(
            r"  {REJECT_PRECISELY_ALLOWED_AMOUNT}
                reject 100.64.1.0/24:* "
        ));

        // Reject one more address
        chk_is_precise(&format!(
            r"  {REJECT_PRECISELY_ALLOWED_AMOUNT}
                reject 4.0.0.0/32:415-425 "
        ));
    }

    #[derive(Deftly)]
    #[derive_deftly(tor_netdoc::NetdocParseableFields)]
    struct ImpreciseTestCase {
        /// Input policy, `accept` and `reject` lines
        #[deftly(netdoc(flatten))]
        full: AddrPolicy,

        /// Expected IPv4 summary
        p4: PortPolicy,
    }

    /// Run one test case where the approx summary is imprecise
    ///
    /// The expected output is `p4` in the test case.
    fn chk_imprecise(input_doc: &str) {
        let case: ImpreciseTestCase = parse_testcase_from_netdoc(input_doc);

        let approx = summarise_policy_v4_approximate(
            //
            &case.full,
            SupportedConsensusMethod::MAX,
        )
        .unwrap();

        assert_eq!(approx, case.p4);

        let precise = case.full.summarise_precise(
            // if the thresholds change in a new consensus method, we'll probably need
            // to explicitly change the value here and maybe test both thresholds
            &PortSummaryThresholds::default(),
            PRIVATE_NETWORKS.iter().copied().map(IpNet::V4),
        );

        assert_ne!(approx, precise.v4);
    }

    #[test]
    fn approximations() {
        chk_imprecise(&format!(
            r"  accept 1.0.0.0/32:417 # ignored non-wildcard accept
                {REJECT_PRECISELY_ALLOWED_AMOUNT}
                reject 4.0.0.0/32:415-425

                p4 accept 100,400-414,420-429 " // 417 missing
        ));

        chk_imprecise(
            r"  reject 10.0.0.0/7:10 # reject 2^25 addresses, but they're half-private
                reject 4.0.0.0/32:10-20 # tip over the edge

                p4 reject 10 ",
        );
    }
}
