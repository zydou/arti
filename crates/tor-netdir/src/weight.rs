//! Functions for applying the correct weights to relays when choosing
//! a relay at random.
//!
//! The weight to use when picking a relay depends on several factors:
//!
//! - The relay's *apparent bandwidth*.  (This is ideally measured by a set of
//!   bandwidth authorities, but if no bandwidth authorities are running (as on
//!   a test network), we might fall back either to relays' self-declared
//!   values, or we might treat all relays as having equal bandwidth.)
//! - The role that we're selecting a relay to play.  (See [`WeightRole`]).
//! - The flags that a relay has in the consensus, and their scarcity.  If a
//!   relay provides particularly scarce functionality, we might choose not to
//!   use it for other roles, or to use it less commonly for them.

use crate::params::NetParameters;
use crate::ConsensusRelays;
use bitflags::bitflags;
use tor_netdoc::doc::netstatus::{self, MdConsensus, MdConsensusRouterStatus, NetParams};

/// Helper: Calculate the function we should use to find initial relay
/// bandwidths.
fn pick_bandwidth_fn<'a, I>(mut weights: I) -> BandwidthFn
where
    I: Clone + Iterator<Item = &'a netstatus::RelayWeight>,
{
    let has_measured = weights.clone().any(|w| w.is_measured());
    let has_nonzero = weights.clone().any(|w| w.is_nonzero());
    let has_nonzero_measured = weights.any(|w| w.is_measured() && w.is_nonzero());

    if !has_nonzero {
        // If every value is zero, we should just pretend everything has
        // bandwidth == 1.
        BandwidthFn::Uniform
    } else if !has_measured {
        // If there are no measured values, then we can look at unmeasured
        // weights.
        BandwidthFn::IncludeUnmeasured
    } else if has_nonzero_measured {
        // Otherwise, there are measured values; we should look at those only, if
        // any of them is nonzero.
        BandwidthFn::MeasuredOnly
    } else {
        // This is a bit of an ugly case: We have measured values, but they're
        // all zero.  If this happens, the bandwidth authorities exist but they
        // very confused: we should fall back to uniform weighting.
        BandwidthFn::Uniform
    }
}

/// Internal: how should we find the base bandwidth of each relay?  This
/// value is global over a whole directory, and depends on the bandwidth
/// weights in the consensus.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum BandwidthFn {
    /// There are no weights at all in the consensus: weight every
    /// relay as 1.
    Uniform,
    /// There are no measured weights in the consensus: count
    /// unmeasured weights as the weights for relays.
    IncludeUnmeasured,
    /// There are measured relays in the consensus; only use those.
    MeasuredOnly,
}

impl BandwidthFn {
    /// Apply this function to the measured or unmeasured bandwidth
    /// of a single relay.
    fn apply(&self, w: &netstatus::RelayWeight) -> u32 {
        use netstatus::RelayWeight::*;
        use BandwidthFn::*;
        match (self, w) {
            (Uniform, _) => 1,
            (IncludeUnmeasured, Unmeasured(u)) => *u,
            (IncludeUnmeasured, Measured(m)) => *m,
            (MeasuredOnly, Unmeasured(_)) => 0,
            (MeasuredOnly, Measured(m)) => *m,
            (_, _) => 0,
        }
    }
}

/// Possible ways to weight relays when selecting them a random.
///
/// Relays are weighted by a function of their bandwidth that
/// depends on how scarce that "kind" of bandwidth is.  For
/// example, if Exit bandwidth is rare, then Exits should be
/// less likely to get chosen for the middle hop of a path.
#[derive(Clone, Debug, Copy)]
#[non_exhaustive]
pub enum WeightRole {
    /// Selecting a relay to use as a guard
    Guard,
    /// Selecting a relay to use as a middle relay in a circuit.
    Middle,
    /// Selecting a relay to use to deliver traffic to the internet.
    Exit,
    /// Selecting a relay for a one-hop BEGIN_DIR directory request.
    BeginDir,
    /// Selecting a relay with no additional weight beyond its bandwidth.
    Unweighted,
    /// Selecting a relay for use as a hidden service introduction point
    HsIntro,
    // Note: There is no `HsRend` role, since in practice when we want to pick a
    // rendezvous point we use a pre-built circuit from our circuit-pool, the
    // last hop of which was selected with the `Middle` weight.  Fortunately,
    // the weighting rules for picking rendezvous points are the same as for
    // picking middle relays.
}

/// Description for how to weight a single kind of relay for each WeightRole.
#[derive(Clone, Debug, Copy)]
struct RelayWeight {
    /// How to weight this kind of relay when picking a guard relay.
    as_guard: u32,
    /// How to weight this kind of relay when picking a middle relay.
    as_middle: u32,
    /// How to weight this kind of relay when picking a exit relay.
    as_exit: u32,
    /// How to weight this kind of relay when picking a one-hop BEGIN_DIR.
    as_dir: u32,
}

impl std::ops::Mul<u32> for RelayWeight {
    type Output = Self;
    fn mul(self, rhs: u32) -> Self {
        RelayWeight {
            as_guard: self.as_guard * rhs,
            as_middle: self.as_middle * rhs,
            as_exit: self.as_exit * rhs,
            as_dir: self.as_dir * rhs,
        }
    }
}
impl std::ops::Div<u32> for RelayWeight {
    type Output = Self;
    fn div(self, rhs: u32) -> Self {
        RelayWeight {
            as_guard: self.as_guard / rhs,
            as_middle: self.as_middle / rhs,
            as_exit: self.as_exit / rhs,
            as_dir: self.as_dir / rhs,
        }
    }
}

impl RelayWeight {
    /// Return the largest weight that we give for this kind of relay.
    // The unwrap() is safe because array is nonempty.
    #[allow(clippy::unwrap_used)]
    fn max_weight(&self) -> u32 {
        [self.as_guard, self.as_middle, self.as_exit, self.as_dir]
            .iter()
            .max()
            .copied()
            .unwrap()
    }
    /// Return the weight we should give this kind of relay's
    /// bandwidth for a given role.
    fn for_role(&self, role: WeightRole) -> u32 {
        match role {
            WeightRole::Guard => self.as_guard,
            WeightRole::Middle => self.as_middle,
            WeightRole::Exit => self.as_exit,
            WeightRole::BeginDir => self.as_dir,
            WeightRole::HsIntro => self.as_middle, // TODO SPEC is this right?
            WeightRole::Unweighted => 1,
        }
    }
}

bitflags! {
    /// A kind of relay, for the purposes of selecting a relay by weight.
    ///
    /// Relays can have or lack the Guard flag, the Exit flag, and the
    /// V2Dir flag. All together, this makes 8 kinds of relays.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct WeightKind: u8 {
        /// Flag in weightkind for Guard relays.
        const GUARD = 1 << 0;
        /// Flag in weightkind for Exit relays.
        const EXIT = 1 << 1;
        /// Flag in weightkind for V2Dir relays.
        const DIR = 1 << 2;
    }
}

impl WeightKind {
    /// Return the appropriate WeightKind for a relay.
    fn for_rs(rs: &MdConsensusRouterStatus) -> Self {
        let mut r = WeightKind::empty();
        if rs.is_flagged_guard() {
            r |= WeightKind::GUARD;
        }
        if rs.is_flagged_exit() {
            r |= WeightKind::EXIT;
        }
        if rs.is_flagged_v2dir() {
            r |= WeightKind::DIR;
        }
        r
    }
    /// Return the index to use for this kind of a relay within a WeightSet.
    fn idx(self) -> usize {
        self.bits() as usize
    }
}

/// Information derived from a consensus to use when picking relays by
/// weighted bandwidth.
#[derive(Debug, Clone)]
pub(crate) struct WeightSet {
    /// How to find the bandwidth to use when picking a relay by weighted
    /// bandwidth.
    ///
    /// (This tells us us whether to count unmeasured relays, whether
    /// to look at bandwidths at all, etc.)
    bandwidth_fn: BandwidthFn,
    /// Number of bits that we need to right-shift our weighted products
    /// so that their sum won't overflow u64::MAX.
    shift: u8,
    /// A set of RelayWeight values, indexed by [`WeightKind::idx`], used
    /// to weight different kinds of relays.
    w: [RelayWeight; 8],
}

impl WeightSet {
    /// Find the actual 64-bit weight to use for a given routerstatus when
    /// considering it for a given role.
    ///
    /// NOTE: This function _does not_ consider whether the relay in question
    /// actually matches the given role.  For example, if `role` is Guard
    /// we don't check whether or not `rs` actually has the Guard flag.
    pub(crate) fn weight_rs_for_role(&self, rs: &MdConsensusRouterStatus, role: WeightRole) -> u64 {
        self.weight_bw_for_role(WeightKind::for_rs(rs), rs.weight(), role)
    }

    /// Find the 64-bit weight to report for a relay of `kind` whose weight in
    /// the consensus is `relay_weight` when using it for `role`.
    fn weight_bw_for_role(
        &self,
        kind: WeightKind,
        relay_weight: &netstatus::RelayWeight,
        role: WeightRole,
    ) -> u64 {
        let ws = &self.w[kind.idx()];

        let router_bw = self.bandwidth_fn.apply(relay_weight);
        // Note a subtlety here: we multiply the two values _before_
        // we shift, to improve accuracy.  We know that this will be
        // safe, since the inputs are both u32, and so cannot overflow
        // a u64.
        let router_weight = u64::from(router_bw) * u64::from(ws.for_role(role));
        router_weight >> self.shift
    }

    /// Compute the correct WeightSet for a provided MdConsensus.
    pub(crate) fn from_consensus(consensus: &MdConsensus, params: &NetParameters) -> Self {
        let bandwidth_fn = pick_bandwidth_fn(consensus.c_relays().iter().map(|rs| rs.weight()));
        let weight_scale = params.bw_weight_scale.into();

        let total_bw = consensus
            .c_relays()
            .iter()
            .map(|rs| u64::from(bandwidth_fn.apply(rs.weight())))
            .sum();
        let p = consensus.bandwidth_weights();

        Self::from_parts(bandwidth_fn, total_bw, weight_scale, p).validate(consensus)
    }

    /// Compute the correct WeightSet given a bandwidth function, a
    /// weight-scaling parameter, a total amount of bandwidth for all
    /// relays in the consensus, and a set of bandwidth parameters.
    fn from_parts(
        bandwidth_fn: BandwidthFn,
        total_bw: u64,
        weight_scale: u32,
        p: &NetParams<i32>,
    ) -> Self {
        /// Find a single RelayWeight, given the names that its bandwidth
        /// parameters have. The `g` parameter is the weight as a guard, the
        /// `m` parameter is the weight as a middle relay, the `e` parameter is
        /// the weight as an exit, and the `d` parameter is the weight as a
        /// directory.
        #[allow(clippy::many_single_char_names)]
        fn single(p: &NetParams<i32>, g: &str, m: &str, e: &str, d: &str) -> RelayWeight {
            RelayWeight {
                as_guard: w_param(p, g),
                as_middle: w_param(p, m),
                as_exit: w_param(p, e),
                as_dir: w_param(p, d),
            }
        }

        // Prevent division by zero in case we're called with a bogus
        // input.  (That shouldn't be possible.)
        let weight_scale = weight_scale.max(1);

        // For non-V2Dir relays, we have names for most of their weights.
        //
        // (There is no Wge, since we only use Guard relays as guards.  By the
        // same logic, Wme has no reason to exist, but according to the spec it
        // does.)
        let w_none = single(p, "Wgm", "Wmm", "Wem", "Wbm");
        let w_guard = single(p, "Wgg", "Wmg", "Weg", "Wbg");
        let w_exit = single(p, "---", "Wme", "Wee", "Wbe");
        let w_both = single(p, "Wgd", "Wmd", "Wed", "Wbd");

        // Note that the positions of the elements in this array need to
        // match the values returned by WeightKind.as_idx().
        let w = [
            w_none,
            w_guard,
            w_exit,
            w_both,
            // The V2Dir values are the same as the non-V2Dir values, except
            // each is multiplied by an additional factor.
            //
            // (We don't need to check for overflow here, since the
            // authorities make sure that the inputs don't get too big.)
            (w_none * w_param(p, "Wmb")) / weight_scale,
            (w_guard * w_param(p, "Wgb")) / weight_scale,
            (w_exit * w_param(p, "Web")) / weight_scale,
            (w_both * w_param(p, "Wdb")) / weight_scale,
        ];

        // This is the largest weight value.
        // The unwrap() is safe because `w` is nonempty.
        #[allow(clippy::unwrap_used)]
        let w_max = w.iter().map(RelayWeight::max_weight).max().unwrap();

        // We want "shift" such that (total * w_max) >> shift <= u64::max
        let shift = calculate_shift(total_bw, u64::from(w_max)) as u8;

        WeightSet {
            bandwidth_fn,
            shift,
            w,
        }
    }

    /// Assert that we have correctly computed our shift values so that
    /// our total weighted bws do not exceed u64::MAX.
    fn validate(self, consensus: &MdConsensus) -> Self {
        use WeightRole::*;
        for role in [Guard, Middle, Exit, BeginDir, Unweighted] {
            let _: u64 = consensus
                .c_relays()
                .iter()
                .map(|rs| self.weight_rs_for_role(rs, role))
                .fold(0_u64, |a, b| {
                    a.checked_add(b)
                        .expect("Incorrect relay weight calculation: total exceeded u64::MAX!")
                });
        }
        self
    }
}

/// The value to return if a weight parameter is absent.
///
/// (If there are no weights at all, then it's correct to set them all to 1,
/// and just use the bandwidths.  If _some_ are present and some are absent,
/// then the spec doesn't say what to do, but this behavior appears
/// reasonable.)
const DFLT_WEIGHT: i32 = 1;

/// Return the weight param named 'kwd' in p.
///
/// Returns DFLT_WEIGHT if there is no such parameter, and 0
/// if `kwd` is "---".
fn w_param(p: &NetParams<i32>, kwd: &str) -> u32 {
    if kwd == "---" {
        0
    } else {
        clamp_to_pos(*p.get(kwd).unwrap_or(&DFLT_WEIGHT))
    }
}

/// If `inp` is less than 0, return 0.  Otherwise return `inp` as a u32.
fn clamp_to_pos(inp: i32) -> u32 {
    // (The spec says that we might encounter negative values here, though
    // we never actually generate them, and don't plan to generate them.)
    if inp < 0 {
        0
    } else {
        inp as u32
    }
}

/// Compute a 'shift' value such that `(a * b) >> shift` will be contained
/// inside 64 bits.
fn calculate_shift(a: u64, b: u64) -> u32 {
    let bits_for_product = log2_upper(a) + log2_upper(b);
    if bits_for_product < 64 {
        0
    } else {
        bits_for_product - 64
    }
}

/// Return an upper bound for the log2 of n.
///
/// This function overestimates whenever n is a power of two, but that doesn't
/// much matter for the uses we're giving it here.
fn log2_upper(n: u64) -> u32 {
    64 - n.leading_zeros()
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
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    use netstatus::RelayWeight as RW;
    use std::net::SocketAddr;
    use std::time::{Duration, SystemTime};
    use tor_basic_utils::test_rng::testing_rng;
    use tor_netdoc::doc::netstatus::{Lifetime, RelayFlags, RouterStatusBuilder};

    #[test]
    fn t_clamp() {
        assert_eq!(clamp_to_pos(32), 32);
        assert_eq!(clamp_to_pos(std::i32::MAX), std::i32::MAX as u32);
        assert_eq!(clamp_to_pos(0), 0);
        assert_eq!(clamp_to_pos(-1), 0);
        assert_eq!(clamp_to_pos(std::i32::MIN), 0);
    }

    #[test]
    fn t_log2() {
        assert_eq!(log2_upper(std::u64::MAX), 64);
        assert_eq!(log2_upper(0), 0);
        assert_eq!(log2_upper(1), 1);
        assert_eq!(log2_upper(63), 6);
        assert_eq!(log2_upper(64), 7); // a little buggy but harmless.
    }

    #[test]
    fn t_calc_shift() {
        assert_eq!(calculate_shift(1 << 20, 1 << 20), 0);
        assert_eq!(calculate_shift(1 << 50, 1 << 10), 0);
        assert_eq!(calculate_shift(1 << 32, 1 << 33), 3);
        assert!(((1_u64 << 32) >> 3).checked_mul(1_u64 << 33).is_some());
        assert_eq!(calculate_shift(432 << 40, 7777 << 40), 38);
        assert!(((432_u64 << 40) >> 38)
            .checked_mul(7777_u64 << 40)
            .is_some());
    }

    #[test]
    fn t_pick_bwfunc() {
        let empty = [];
        assert_eq!(pick_bandwidth_fn(empty.iter()), BandwidthFn::Uniform);

        let all_zero = [RW::Unmeasured(0), RW::Measured(0), RW::Unmeasured(0)];
        assert_eq!(pick_bandwidth_fn(all_zero.iter()), BandwidthFn::Uniform);

        let all_unmeasured = [RW::Unmeasured(9), RW::Unmeasured(2222)];
        assert_eq!(
            pick_bandwidth_fn(all_unmeasured.iter()),
            BandwidthFn::IncludeUnmeasured
        );

        let some_measured = [
            RW::Unmeasured(10),
            RW::Measured(7),
            RW::Measured(4),
            RW::Unmeasured(0),
        ];
        assert_eq!(
            pick_bandwidth_fn(some_measured.iter()),
            BandwidthFn::MeasuredOnly
        );

        // This corresponds to an open question in
        // `pick_bandwidth_fn`, about what to do when the only nonzero
        // weights are unmeasured.
        let measured_all_zero = [RW::Unmeasured(10), RW::Measured(0)];
        assert_eq!(
            pick_bandwidth_fn(measured_all_zero.iter()),
            BandwidthFn::Uniform
        );
    }

    #[test]
    fn t_apply_bwfn() {
        use netstatus::RelayWeight::*;
        use BandwidthFn::*;

        assert_eq!(Uniform.apply(&Measured(7)), 1);
        assert_eq!(Uniform.apply(&Unmeasured(0)), 1);

        assert_eq!(IncludeUnmeasured.apply(&Measured(7)), 7);
        assert_eq!(IncludeUnmeasured.apply(&Unmeasured(8)), 8);

        assert_eq!(MeasuredOnly.apply(&Measured(9)), 9);
        assert_eq!(MeasuredOnly.apply(&Unmeasured(10)), 0);
    }

    // From a fairly recent Tor consensus.
    const TESTVEC_PARAMS: &str =
        "Wbd=0 Wbe=0 Wbg=4096 Wbm=10000 Wdb=10000 Web=10000 Wed=10000 Wee=10000 Weg=10000 Wem=10000 Wgb=10000 Wgd=0 Wgg=5904 Wgm=5904 Wmb=10000 Wmd=0 Wme=0 Wmg=4096 Wmm=10000";

    #[test]
    fn t_weightset_basic() {
        let total_bandwidth = 1_000_000_000;
        let params = TESTVEC_PARAMS.parse().unwrap();
        let ws = WeightSet::from_parts(BandwidthFn::MeasuredOnly, total_bandwidth, 10000, &params);

        assert_eq!(ws.bandwidth_fn, BandwidthFn::MeasuredOnly);
        assert_eq!(ws.shift, 0);

        assert_eq!(ws.w[0].as_guard, 5904);
        assert_eq!(ws.w[(WeightKind::GUARD.bits()) as usize].as_guard, 5904);
        assert_eq!(ws.w[(WeightKind::EXIT.bits()) as usize].as_exit, 10000);
        assert_eq!(
            ws.w[(WeightKind::EXIT | WeightKind::GUARD).bits() as usize].as_dir,
            0
        );
        assert_eq!(
            ws.w[(WeightKind::GUARD | WeightKind::DIR).bits() as usize].as_dir,
            4096
        );
        assert_eq!(
            ws.w[(WeightKind::GUARD | WeightKind::DIR).bits() as usize].as_dir,
            4096
        );

        assert_eq!(
            ws.weight_bw_for_role(
                WeightKind::GUARD | WeightKind::DIR,
                &RW::Unmeasured(7777),
                WeightRole::Guard
            ),
            0
        );

        assert_eq!(
            ws.weight_bw_for_role(
                WeightKind::GUARD | WeightKind::DIR,
                &RW::Measured(7777),
                WeightRole::Guard
            ),
            7777 * 5904
        );

        assert_eq!(
            ws.weight_bw_for_role(
                WeightKind::GUARD | WeightKind::DIR,
                &RW::Measured(7777),
                WeightRole::Middle
            ),
            7777 * 4096
        );

        assert_eq!(
            ws.weight_bw_for_role(
                WeightKind::GUARD | WeightKind::DIR,
                &RW::Measured(7777),
                WeightRole::Exit
            ),
            7777 * 10000
        );

        assert_eq!(
            ws.weight_bw_for_role(
                WeightKind::GUARD | WeightKind::DIR,
                &RW::Measured(7777),
                WeightRole::BeginDir
            ),
            7777 * 4096
        );

        assert_eq!(
            ws.weight_bw_for_role(
                WeightKind::GUARD | WeightKind::DIR,
                &RW::Measured(7777),
                WeightRole::Unweighted
            ),
            7777
        );

        // Now try those last few with routerstatuses.
        let rs = rs_builder()
            .set_flags(RelayFlags::GUARD | RelayFlags::V2DIR)
            .weight(RW::Measured(7777))
            .build()
            .unwrap();
        assert_eq!(ws.weight_rs_for_role(&rs, WeightRole::Exit), 7777 * 10000);
        assert_eq!(
            ws.weight_rs_for_role(&rs, WeightRole::BeginDir),
            7777 * 4096
        );
        assert_eq!(ws.weight_rs_for_role(&rs, WeightRole::Unweighted), 7777);
    }

    /// Return a routerstatus builder set up to deliver a routerstatus
    /// with most features disabled.
    fn rs_builder() -> RouterStatusBuilder<[u8; 32]> {
        MdConsensus::builder()
            .rs()
            .identity([9; 20].into())
            .add_or_port(SocketAddr::from(([127, 0, 0, 1], 9001)))
            .doc_digest([9; 32])
            .protos("".parse().unwrap())
            .clone()
    }

    #[test]
    fn weight_flags() {
        let rs1 = rs_builder().set_flags(RelayFlags::EXIT).build().unwrap();
        assert_eq!(WeightKind::for_rs(&rs1), WeightKind::EXIT);

        let rs1 = rs_builder().set_flags(RelayFlags::GUARD).build().unwrap();
        assert_eq!(WeightKind::for_rs(&rs1), WeightKind::GUARD);

        let rs1 = rs_builder().set_flags(RelayFlags::V2DIR).build().unwrap();
        assert_eq!(WeightKind::for_rs(&rs1), WeightKind::DIR);

        let rs1 = rs_builder().build().unwrap();
        assert_eq!(WeightKind::for_rs(&rs1), WeightKind::empty());

        let rs1 = rs_builder().set_flags(RelayFlags::all()).build().unwrap();
        assert_eq!(
            WeightKind::for_rs(&rs1),
            WeightKind::EXIT | WeightKind::GUARD | WeightKind::DIR
        );
    }

    #[test]
    fn weightset_from_consensus() {
        use rand::Rng;
        let now = SystemTime::now();
        let one_hour = Duration::new(3600, 0);
        let mut rng = testing_rng();
        let mut bld = MdConsensus::builder();
        bld.consensus_method(34)
            .lifetime(Lifetime::new(now, now + one_hour, now + 2 * one_hour).unwrap())
            .weights(TESTVEC_PARAMS.parse().unwrap());

        // We're going to add a huge amount of unmeasured bandwidth,
        // and a reasonable amount of  measured bandwidth.
        for _ in 0..10 {
            rs_builder()
                .identity(rng.gen::<[u8; 20]>().into()) // random id
                .weight(RW::Unmeasured(1_000_000))
                .set_flags(RelayFlags::GUARD | RelayFlags::EXIT)
                .build_into(&mut bld)
                .unwrap();
        }
        for n in 0..30 {
            rs_builder()
                .identity(rng.gen::<[u8; 20]>().into()) // random id
                .weight(RW::Measured(1_000 * n))
                .set_flags(RelayFlags::GUARD | RelayFlags::EXIT)
                .build_into(&mut bld)
                .unwrap();
        }

        let consensus = bld.testing_consensus().unwrap();
        let params = NetParameters::default();
        let ws = WeightSet::from_consensus(&consensus, &params);

        assert_eq!(ws.bandwidth_fn, BandwidthFn::MeasuredOnly);
        assert_eq!(ws.shift, 0);
        assert_eq!(ws.w[0].as_guard, 5904);
        assert_eq!(ws.w[5].as_guard, 5904);
        assert_eq!(ws.w[5].as_middle, 4096);
    }
}
