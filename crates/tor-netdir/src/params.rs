//! Implements a usable view of Tor network parameters.
//!
//! The Tor consensus document contains a number of 'network
//! parameters', which are integer-valued items voted on by the
//! directory authorities.  They are used to tune the behavior of
//! numerous aspects of the network.
//! A set of Tor network parameters
//!
//! The Tor consensus document contains a number of 'network
//! parameters', which are integer-valued items voted on by the
//! directory authorities.  These parameters are used to tune the
//! behavior of numerous aspects of the network.
//!
//! This type differs from
//! [`NetParams`](tor_netdoc::doc::netstatus::NetParams) in that it
//! only exposes a set of parameters recognized by arti.  In return
//! for this restriction, it makes sure that the values it gives are
//! in range, and provides default values for any parameters that are
//! missing.

use tor_units::{
    BoundedInt32, IntegerDays, IntegerMilliseconds, IntegerMinutes, IntegerSeconds, Percentage,
    SendMeVersion,
};

/// Upper limit for channel padding timeouts
///
/// This is just a safety catch which might help prevent integer overflow,
/// and also might prevent a client getting permanently stuck in a state
/// where it ought to send padding but never does.
///
/// The actual value is stolen from C Tor as per
///   <https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/586#note_2813638>
/// pending an update to the specifications
///   <https://gitlab.torproject.org/tpo/core/torspec/-/issues/120>
pub const CHANNEL_PADDING_TIMEOUT_UPPER_BOUND: i32 = 60_000;

/// An object that can be constructed from an i32, with saturating semantics.
pub trait FromInt32Saturating {
    /// Construct an instance of this object from `val`.
    ///
    /// If `val` is too low, treat it as the lowest value that would be
    /// valid.  If `val` is too high, treat it as the highest value that
    /// would be valid.
    fn from_saturating(val: i32) -> Self;

    /// Try to construct an instance of this object from `val`.
    ///
    /// If `val` is out of range, return an error instead.
    fn from_checked(val: i32) -> Result<Self, tor_units::Error>
    where
        Self: Sized;
}

impl FromInt32Saturating for i32 {
    fn from_saturating(val: i32) -> Self {
        val
    }

    fn from_checked(val: i32) -> Result<Self, tor_units::Error>
    where
        Self: Sized,
    {
        Ok(val)
    }
}
impl<const L: i32, const H: i32> FromInt32Saturating for BoundedInt32<L, H> {
    fn from_saturating(val: i32) -> Self {
        Self::saturating_new(val)
    }

    fn from_checked(val: i32) -> Result<Self, tor_units::Error>
    where
        Self: Sized,
    {
        Self::checked_new(val)
    }
}
impl<T: Copy + Into<f64> + FromInt32Saturating> FromInt32Saturating for Percentage<T> {
    fn from_saturating(val: i32) -> Self {
        Self::new(T::from_saturating(val))
    }

    fn from_checked(val: i32) -> Result<Self, tor_units::Error>
    where
        Self: Sized,
    {
        Ok(Self::new(T::from_checked(val)?))
    }
}
impl<T: FromInt32Saturating + TryInto<u64>> FromInt32Saturating for IntegerMilliseconds<T> {
    fn from_saturating(val: i32) -> Self {
        Self::new(T::from_saturating(val))
    }

    fn from_checked(val: i32) -> Result<Self, tor_units::Error>
    where
        Self: Sized,
    {
        Ok(Self::new(T::from_checked(val)?))
    }
}
impl<T: FromInt32Saturating + TryInto<u64>> FromInt32Saturating for IntegerSeconds<T> {
    fn from_saturating(val: i32) -> Self {
        Self::new(T::from_saturating(val))
    }

    fn from_checked(val: i32) -> Result<Self, tor_units::Error>
    where
        Self: Sized,
    {
        Ok(Self::new(T::from_checked(val)?))
    }
}
impl<T: FromInt32Saturating + TryInto<u64>> FromInt32Saturating for IntegerMinutes<T> {
    fn from_saturating(val: i32) -> Self {
        Self::new(T::from_saturating(val))
    }

    fn from_checked(val: i32) -> Result<Self, tor_units::Error>
    where
        Self: Sized,
    {
        Ok(Self::new(T::from_checked(val)?))
    }
}
impl<T: FromInt32Saturating + TryInto<u64>> FromInt32Saturating for IntegerDays<T> {
    fn from_saturating(val: i32) -> Self {
        Self::new(T::from_saturating(val))
    }

    fn from_checked(val: i32) -> Result<Self, tor_units::Error>
    where
        Self: Sized,
    {
        Ok(Self::new(T::from_checked(val)?))
    }
}
impl FromInt32Saturating for SendMeVersion {
    fn from_saturating(val: i32) -> Self {
        Self::new(val.clamp(0, 255) as u8)
    }

    fn from_checked(val: i32) -> Result<Self, tor_units::Error>
    where
        Self: Sized,
    {
        let val = BoundedInt32::<0, 255>::checked_new(val)?;
        Ok(Self::new(val.get() as u8))
    }
}

/// A macro to help us declare the net parameters object.  It lets us
/// put the information about each parameter in just one place, even
/// though it will later get split between the struct declaration, the
/// Default implementation, and the implementation of
/// `saturating_update_override`.
macro_rules! declare_net_parameters {
    {
        $(#[$s_meta:meta])* $s_v:vis struct $s_name:ident {
            $(
                $(#[$p_meta:meta])* $p_v:vis
                    $p_name:ident : $p_type:ty
                    = ($p_dflt:expr) from $p_string:literal
            ),*
            $( , )?
        }
    } =>
    {
        $(#[$s_meta])* $s_v struct $s_name {
            $(
                $(#[$p_meta])* $p_v $p_name : $p_type
            ),*
        }

        impl $s_name {
            /// Try to construct an instance of with its default values.
            ///
            /// (This should always succeed, unless one of the default values
            /// is out-of-bounds for the type.)
            fn default_values() -> Result<Self, tor_units::Error> {
                Ok(Self {
                    $( $p_name : $p_dflt.try_into()? ),*
                })
            }
            /// Replace the current value for the parameter identified in the
            /// consensus with `key` with a new value `val`.
            ///
            /// Uses saturating semantics if the new value is out-of-range.
            ///
            /// Returns true if the key was recognized, and false otherwise.
            fn set_saturating(&mut self, key: &str, val: i32) -> bool {
                match key {
                    $( $p_string => self.$p_name = {
                        type T = $p_type;
                        match T::from_checked(val) {
                            Ok(v) => v,
                            Err(e) => {
                                tracing::warn!("For key {key}, clamping out of range value: {e:?}");
                                T::from_saturating(val)
                            }
                        }
                    }, )*
                    _ => return false,
                }
                true
            }
        }
    }
}

declare_net_parameters! {

/// This structure holds recognized configuration parameters. All values are type-safe,
/// and where applicable clamped to be within range.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct NetParameters {
    /// A weighting factor for bandwidth calculations
    pub bw_weight_scale: BoundedInt32<1, { i32::MAX }> = (10_000)
        from "bwweightscale",
    /// If true, do not attempt to learn circuit-build timeouts at all.
    pub cbt_learning_disabled: BoundedInt32<0, 1> = (0)
        from "cbtdisabled",
    /// Number of histograms bins to consider when estimating Xm for a
    /// Pareto-based circuit timeout estimator.
    pub cbt_num_xm_modes: BoundedInt32<1, 20> = (10)
        from "cbtnummodes",
    /// How many recent circuit success/timeout statuses do we remember
    /// when trying to tell if our circuit timeouts are too low?
    pub cbt_success_count: BoundedInt32<3, 1_000> = (20)
        from "cbtrecentcount",
    /// How many timeouts (in the last `cbt_success_count` observations)
    /// indicates that our circuit timeouts are too low?
    pub cbt_max_timeouts: BoundedInt32<3, 10_000> = (18)
        from "cbtmaxtimeouts",
    /// Smallest number of circuit build times we have to view in order to use
    /// our Pareto-based circuit timeout estimator.
    pub cbt_min_circs_for_estimate: BoundedInt32<1, 10_000> = (100)
        from "cbtmincircs",
    /// Quantile to use when determining the correct circuit timeout value
    /// with our Pareto estimator.
    ///
    /// (We continue building circuits after this timeout, but only
    /// for build-time measurement purposes.)
    pub cbt_timeout_quantile: Percentage<BoundedInt32<10, 99>> = (80)
        from "cbtquantile",
    /// Quantile to use when determining when to abandon circuits completely
    /// with our Pareto estimator.
    pub cbt_abandon_quantile: Percentage<BoundedInt32<10, 99>> = (99)
        from "cbtclosequantile",
    /// Lowest permissible timeout value for Pareto timeout estimator.
    pub cbt_min_timeout: IntegerMilliseconds<BoundedInt32<10, { i32::MAX }>> = (10)
        from "cbtmintimeout",
    /// Timeout value to use for our Pareto timeout estimator when we have
    /// no initial estimate.
    pub cbt_initial_timeout: IntegerMilliseconds<BoundedInt32<10, { i32::MAX }>> = (60_000)
        from "cbtinitialtimeout",
    /// When we don't have a good build-time estimate yet, how long
    /// (in seconds) do we wait between trying to launch build-time
    /// testing circuits through the network?
    pub cbt_testing_delay: IntegerSeconds<BoundedInt32<1, { i32::MAX }>> = (10)
        from "cbttestfreq",
    /// How many circuits can be open before we will no longer
    /// consider launching testing circuits to learn average build
    /// times?
    pub cbt_max_open_circuits_for_testing: BoundedInt32<0, 14> = (10)
        from "cbtmaxopencircs",

    /// Specifies which congestion control algorithm clients should use.
    /// Current values are 0 for the fixed window algorithm and 2 for Vegas.
    pub cc_alg: BoundedInt32<0, 2> = (2)
        from "cc_alg",

    /// Vegas only. This parameter defines the integer number of 'cc_sendme_inc' multiples
    /// of gap allowed between inflight and cwnd, to still declare the cwnd full.
    pub cc_cwnd_full_gap: BoundedInt32<0, { i16::MAX as i32 }> = (4444)
        from "cc_cwnd_full_gap",
    /// Vegas only. This parameter defines a low watermark in percent.
    pub cc_cwnd_full_minpct: Percentage<BoundedInt32<0, 100>> = (25)
        from "cc_cwnd_full_minpct",
    /// Vegas only. This parameter governs how often a cwnd must be full.
    pub cc_cwnd_full_per_cwnd: BoundedInt32<0, 1> = (1)
        from "cc_cwnd_full_per_cwnd",

    /// Initial congestion window for new congestion control Tor clients.
    pub cc_cwnd_init: BoundedInt32<31, 10_000> = (4 * 31)
        from "cc_cwnd_init",
    /// Percentage of the current congestion window to increment by during slow start,
    /// every congestion window.
    pub cc_cwnd_inc_pct_ss: Percentage<BoundedInt32<1, 500>> = (50)
        from "cc_cwnd_inc_pct_ss",
    /// How much to increment the congestion window by during steady state,
    /// every congestion window.
    pub cc_cwnd_inc: BoundedInt32<1, 1000> = (31)
        from "cc_cwnd_inc",
    /// How often we update our congestion window, per cwnd worth of packets.
    /// (For example, if this is 2, we will update the window twice every window.)
    pub cc_cwnd_inc_rate: BoundedInt32<1, 250> = (1)
        from "cc_cwnd_inc_rate",
    /// The minimum allowed congestion window.
    pub cc_cwnd_min: BoundedInt32<31, 1000> = (31)
        from "cc_cwnd_min",
    /// The maximum allowed congestion window.
    pub cc_cwnd_max: BoundedInt32<500, { i32::MAX }> = (i32::MAX)
        from "cc_cwnd_max",

    /// This specifies the N in N-EWMA smoothing of RTT and BDP estimation,
    /// as a percent of the number of SENDME acks in a congestion window.
    ///
    /// A percentage over 100% indicates smoothing with more than one
    /// congestion window's worth of SENDMEs.
    pub cc_ewma_cwnd_pct: Percentage<BoundedInt32<1, 255>> = (50)
        from "cc_ewma_cwnd_pct",
    /// This specifies the max N in N_EWMA smoothing of RTT and BDP estimation.
    pub cc_ewma_max: BoundedInt32<2, { i32::MAX }> = (10)
        from "cc_ewma_max",
    /// This specifies the N in N_EWMA smoothing of RTT during Slow Start.
    pub cc_ewma_ss: BoundedInt32<2, { i32::MAX }> = (2)
        from "cc_ewma_ss",
    /// Describes a percentile average between RTT_min and RTT_current_ewma,
    /// for use to reset RTT_min, when the congestion window hits cwnd_min.
    pub cc_rtt_reset_pct: Percentage<BoundedInt32<0, 100>> = (100)
        from "cc_rtt_reset_pct",
    /// Specifies how many cells a SENDME acks.
    pub cc_sendme_inc: BoundedInt32<1, 254> = (31)
        from "cc_sendme_inc",
    /// This parameter provides a hard-max on the congestion window in Slow Start.
    pub cc_ss_max: BoundedInt32<500, { i32::MAX }> = (5000)
        from "cc_ss_max",

    /// Vegas alpha parameter for an Exit circuit.
    pub cc_vegas_alpha_exit: BoundedInt32<0, 1000> = (3 * 62)
        from "cc_vegas_alpha_exit",
    /// Vegas beta parameter for an Exit circuit.
    pub cc_vegas_beta_exit: BoundedInt32<0, 1000> = (4 * 62)
        from "cc_vegas_beta_exit",
    /// Vegas delta parameter for an Exit circuit.
    pub cc_vegas_delta_exit: BoundedInt32<0, 1000> = (5 * 62)
        from "cc_vegas_delta_exit",
    /// Vegas gamma parameter for an Exit circuit.
    pub cc_vegas_gamma_exit: BoundedInt32<0, 1000> = (3 * 62)
        from "cc_vegas_gamma_exit",

    /// Vegas alpha parameter for an Onion circuit.
    pub cc_vegas_alpha_onion: BoundedInt32<0, 1000> = (3 * 62)
        from "cc_vegas_alpha_onion",
    /// Vegas beta parameter for an Onion circuit.
    pub cc_vegas_beta_onion: BoundedInt32<0, 1000> = (6 * 62)
        from "cc_vegas_beta_onion",
    /// Vegas delta parameter for an Onion circuit.
    pub cc_vegas_delta_onion: BoundedInt32<0, 1000> = (7 * 62)
        from "cc_vegas_delta_onion",
    /// Vegas gamma parameter for an Onion circuit.
    pub cc_vegas_gamma_onion: BoundedInt32<0, 1000> = (4 * 62)
        from "cc_vegas_gamma_onion",

    /// Parameter for Exit circuit that describe the the RFC3742 'cap', after which
    /// congestion window increments are reduced. The MAX disables RFC3742.
    pub cc_vegas_sscap_exit: BoundedInt32<100, { i32::MAX }> = (600)
        from "cc_sscap_exit",
    /// Parameter for Onion circuit that describe the the RFC3742 'cap', after which
    /// congestion window increments are reduced. The MAX disables RFC3742.
    pub cc_vegas_sscap_onion: BoundedInt32<100, { i32::MAX }> = (475)
        from "cc_sscap_onion",

    // Stream flow control parameters.
    // TODO: There is a `circwindow` for circuit flow control, but is there a similar package window
    // parameter for pre-cc stream flow control?

    /// The outbuf length, in relay cell multiples, before we send an XOFF.
    /// Used by clients (including onion services).
    ///
    /// See prop 324.
    pub cc_xoff_client: BoundedInt32<1, 10_000> = (500)
        from "cc_xoff_client",
    /// The outbuf length, in relay cell multiples, before we send an XOFF.
    /// Used by exits.
    ///
    /// See prop 324.
    pub cc_xoff_exit: BoundedInt32<1, 10_000> = (500)
        from "cc_xoff_exit",
    /// Specifies how many full packed cells of bytes must arrive before we can compute a rate,
    /// as well as how often we can send XONs.
    ///
    /// See prop 324.
    pub cc_xon_rate: BoundedInt32<1, 5000> = (500)
        from "cc_xon_rate",
    /// Specifies how much the edge drain rate can change before we send another advisory cell.
    ///
    /// See prop 324.
    pub cc_xon_change_pct: BoundedInt32<1, 99> = (25)
        from "cc_xon_change_pct",
    /// Specifies the `N` in the `N_EWMA` of rates.
    ///
    /// See prop 324.
    pub cc_xon_ewma_cnt: BoundedInt32<2, 100> = (2)
        from "cc_xon_ewma_cnt",

    /// The maximum cell window size?
    pub circuit_window: BoundedInt32<100, 1000> = (1_000)
        from "circwindow",
    /// The decay parameter for circuit priority
    pub circuit_priority_half_life: IntegerMilliseconds<BoundedInt32<1, { i32::MAX }>> = (30_000)
        from "CircuitPriorityHalflifeMsec",
    /// Whether to perform circuit extensions by Ed25519 ID
    pub extend_by_ed25519_id: BoundedInt32<0, 1> = (0)
        from "ExtendByEd25519ID",

    /// If we have excluded so many possible guards that the
    /// available fraction is below this threshold, we should use a different
    /// guard sample.
    pub guard_meaningful_restriction: Percentage<BoundedInt32<1,100>> = (20)
        from "guard-meaningful-restriction-percent",

    /// We should warn the user if they have excluded so many guards
    /// that the available fraction is below this threshold.
    pub guard_extreme_restriction: Percentage<BoundedInt32<1,100>> = (1)
        from "guard-extreme-restriction-percent",

    /// How long should we keep an unconfirmed guard (one we have not
    /// contacted) before removing it from the guard sample?
    pub guard_lifetime_unconfirmed: IntegerDays<BoundedInt32<1, 3650>> = (120)
        from "guard-lifetime-days",

    /// How long should we keep a _confirmed_ guard (one we have contacted)
    /// before removing it from the guard sample?
    pub guard_lifetime_confirmed: IntegerDays<BoundedInt32<1, 3650>> = (60)
        from "guard-confirmed-min-lifetime-days",

    /// If all circuits have failed for this interval, then treat the internet
    /// as "probably down", and treat any guard failures in that interval
    /// as unproven.
    pub guard_internet_likely_down: IntegerSeconds<BoundedInt32<1, {i32::MAX}>> = (600)
        from "guard-internet-likely-down-interval",
    /// Largest number of guards that a client should try to maintain in
    /// a sample of possible guards.
    pub guard_max_sample_size: BoundedInt32<1, {i32::MAX}> = (60)
        from "guard-max-sample-size",
    /// Largest fraction of guard bandwidth on the network that a client
    /// should try to remain in a sample of possible guards.
    pub guard_max_sample_threshold: Percentage<BoundedInt32<1,100>> = (20)
        from "guard-max-sample-threshold",

    /// If the client ever has fewer than this many guards in their sample,
    /// after filtering out unusable guards, they should try to add more guards
    /// to the sample (if allowed).
    pub guard_filtered_min_sample_size: BoundedInt32<1,{i32::MAX}> = (20)
        from "guard-min-filtered-sample-size",

    /// The number of confirmed guards that the client should treat as
    /// "primary guards".
    pub guard_n_primary: BoundedInt32<1,{i32::MAX}> = (3)
        from "guard-n-primary-guards",
    /// The number of primary guards that the client should use in parallel.
    /// Other primary guards won't get used unless earlier ones are down.
    pub guard_use_parallelism: BoundedInt32<1, {i32::MAX}> = (1)
        from "guard-n-primary-guards-to-use",
    /// The number of primary guards that the client should use in
    /// parallel.  Other primary directory guards won't get used
    /// unless earlier ones are down.
    pub guard_dir_use_parallelism: BoundedInt32<1, {i32::MAX}> = (3)
        from "guard-n-primary-dir-guards-to-use",

    /// When trying to confirm nonprimary guards, if a guard doesn't
    /// answer for more than this long in seconds, treat any lower-
    /// priority guards as possibly usable.
    pub guard_nonprimary_connect_timeout: IntegerSeconds<BoundedInt32<1,{i32::MAX}>> = (15)
        from "guard-nonprimary-guard-connect-timeout",
    /// When trying to confirm nonprimary guards, if a guard doesn't
    /// answer for more than _this_ long in seconds, treat it as down.
    pub guard_nonprimary_idle_timeout: IntegerSeconds<BoundedInt32<1,{i32::MAX}>> = (600)
        from "guard-nonprimary-guard-idle-timeout",
    /// If a guard has been unlisted in the consensus for at least this
    /// long, remove it from the consensus.
    pub guard_remove_unlisted_after: IntegerDays<BoundedInt32<1,3650>> = (20)
        from "guard-remove-unlisted-guards-after-days",


    /// The minimum threshold for circuit patch construction
    pub min_circuit_path_threshold: Percentage<BoundedInt32<25, 95>> = (60)
        from "min_paths_for_circs_pct",

    /// Channel padding, low end of random padding interval, milliseconds
    ///
    /// `nf_ito` stands for "netflow inactive timeout".
    pub nf_ito_low: IntegerMilliseconds<BoundedInt32<0, CHANNEL_PADDING_TIMEOUT_UPPER_BOUND>> = (1500)
        from "nf_ito_low",
    /// Channel padding, high end of random padding interval, milliseconds
    pub nf_ito_high: IntegerMilliseconds<BoundedInt32<0, CHANNEL_PADDING_TIMEOUT_UPPER_BOUND>> = (9500)
        from "nf_ito_high",
    /// Channel padding, low end of random padding interval (reduced padding) milliseconds
    pub nf_ito_low_reduced: IntegerMilliseconds<BoundedInt32<0, CHANNEL_PADDING_TIMEOUT_UPPER_BOUND>> = (9000)
        from "nf_ito_low_reduced",
    /// Channel padding, high end of random padding interval (reduced padding) , milliseconds
    pub nf_ito_high_reduced: IntegerMilliseconds<BoundedInt32<0, CHANNEL_PADDING_TIMEOUT_UPPER_BOUND>> = (14000)
        from "nf_ito_high_reduced",

    /// The minimum sendme version to accept.
    pub sendme_accept_min_version: SendMeVersion = (0)
        from "sendme_accept_min_version",
    /// The minimum sendme version to transmit.
    pub sendme_emit_min_version: SendMeVersion = (0)
        from "sendme_emit_min_version",

    /// How long should never-used client circuits stay available,
    /// in the steady state?
    pub unused_client_circ_timeout: IntegerSeconds<BoundedInt32<60, 86_400>> = (30*60)
        from "nf_conntimeout_clients",
    /// When we're learning circuit timeouts, how long should never-used client
    /// circuits stay available?
    pub unused_client_circ_timeout_while_learning_cbt: IntegerSeconds<BoundedInt32<10, 60_000>> = (3*60)
        from "cbtlearntimeout",

    /// Lower bound on the number of INTRODUCE2 cells to allow per introduction
    /// circuit before the service decides to rotate to a new introduction
    /// circuit.
    pub hs_introcirc_requests_min: BoundedInt32<0, {i32::MAX}> = (16384)
        from "hs_intro_min_introduce2",

    /// Upper bound on the number of INTRODUCE2 cells to allow per introduction
    /// circuit before the service decides to rotate to a new introduction
    /// circuit.
    pub hs_introcirc_requests_max: BoundedInt32<0, {i32::MAX}> = (32768)
        from "hs_intro_max_introduce2",

    /// Lower bound on the lifetime of an introduction point.
    pub hs_intro_min_lifetime: IntegerSeconds<BoundedInt32<0, {i32::MAX}>> = (18 * 60 * 60)
        from "hs_intro_min_lifetime",

    /// Upper bound on the lifetime of an introduction point.
    pub hs_intro_max_lifetime: IntegerSeconds<BoundedInt32<0, {i32::MAX}>> = (24 * 60 * 60)
        from "hs_intro_max_lifetime",

    /// Number of "extra" introduction points that an onion service is allowed
    /// to open based on demand.
    pub hs_intro_num_extra_intropoints: BoundedInt32<0, 128> = (2)
        from "hs_intro_num_extra",

    /// Largest number of allowable relay cells received
    /// in reply to an hsdir download attempt.
    pub hsdir_dl_max_reply_cells: BoundedInt32<2, 2304> = (110)
        from "hsdir_dl_max_reply_cells",

    /// Largest number of allowable relay cells received
    /// in reply to an hsdir upload attempt.
    pub hsdir_ul_max_reply_cells: BoundedInt32<2, 1024> = (8)
        from "hsdir_ul_max_reply_cells",

    /// The duration of a time period, as used in the onion service directory
    /// protocol.
    ///
    /// During each "time period", each onion service gets a different blinded
    /// ID, and the hash ring gets a new layout.
    pub hsdir_timeperiod_length: IntegerMinutes<BoundedInt32<5, 14400>> = (1440)
        from "hsdir_interval",

    /// The number of positions at the hash ring where an onion service
    /// descriptor should be stored.
    pub hsdir_n_replicas: BoundedInt32<1, 16> = (2)
        from "hsdir_n_replicas",

    /// The number of HSDir instances, at each position in the hash ring, that
    /// should be considered when downloading an onion service descriptor.
    pub hsdir_spread_fetch: BoundedInt32<1, 128> = (3)
        from "hsdir_spread_fetch",

    /// The number of HSDir instances, at each position in the hash ring, that
    /// should be considered when uploading an onion service descriptor.
    pub hsdir_spread_store: BoundedInt32<1,128> = (4)
        from "hsdir_spread_store",

    /// Largest allowable v3 onion service size (in bytes).
    pub hsdir_max_desc_size: BoundedInt32<1, {i32::MAX}> = (50_000)
        from "HSV3MaxDescriptorSize",

    /// Largest number of failures to rendezvous that an onion service should
    /// allow for a request.
    pub hs_service_rendezvous_failures_max: BoundedInt32<1, 10> = (2)
        from "hs_service_max_rdv_failures",

    /// If set to 1, introduction points use the INTRODUCE1 rate limiting
    /// defense when no `DosParams` are sent.
    ///
    /// See <https://spec.torproject.org/param-spec.html#HiddenServiceEnableIntroDoSDefense>
    pub hs_intro_dos_enabled: BoundedInt32<0, 1> = (0)
        from "HiddenServiceEnableIntroDoSDefense",

    /// Default _rate_ value for an introduction point to use for INTRODUCE1 rate
    /// limiting when no `DosParams` value is sent, in messages per second.
    ///
    /// See
    /// <https://spec.torproject.org/param-spec.html#HiddenServiceEnableIntroDoSBurstPerSec>
    pub hs_intro_dos_max_burst: BoundedInt32<0, {i32::MAX}> = (200)
        from "HiddenServiceEnableIntroDoSBurstPerSec",

    /// Default _burst_ value for an introduction point to use for INTRODUCE1 rate
    /// limiting when no `DosParams` value is sent.
    ///
    /// See
    /// <https://spec.torproject.org/param-spec.html#HiddenServiceEnableIntroDoSRatePerSec>
    pub hs_intro_dos_rate: BoundedInt32<0, {i32::MAX}> = (25)
        from  "HiddenServiceEnableIntroDoSRatePerSec",

    /// Maximum Proof-of-Work V1 effort clients should send. Services will cap higher efforts to
    /// this value.
    ///
    /// See
    /// <https://spec.torproject.org/proposals/362-update-pow-control-loop.html>
    // TODO POW: Make u32, or change spec.
    pub hs_pow_v1_max_effort: BoundedInt32<0, {i32::MAX}> = (10_000)
        from "HiddenServiceProofOfWorkV1MaxEffort",

    /// The maximum age for items in the onion service intro queue, when Proof-of-Work V1 is
    /// enabled.
    ///
    /// See
    /// <https://spec.torproject.org/proposals/362-update-pow-control-loop.html>
    pub hs_pow_v1_service_intro_timeout: IntegerSeconds<BoundedInt32<1, {i32::MAX}>> = (300)
        from "HiddenServiceProofOfWorkV1ServiceIntroTimeoutSeconds",

    /// The default Proof-of-Work V1 decay adjustment value.
    ///
    /// See
    /// <https://spec.torproject.org/proposals/362-update-pow-control-loop.html>
    pub hs_pow_v1_default_decay_adjustment: Percentage<BoundedInt32<0, 99>> = (0)
        from "HiddenServiceProofOfWorkV1ServiceDefaultDecayAdjustment",

    /// The type of vanguards to use by default when building onion service circuits:
    ///
    /// ```text
    ///    0: No vanguards.
    ///    1: Lite vanguards.
    ///    2: Full vanguards.
    /// ```
    ///
    /// See
    /// <https://spec.torproject.org/param-spec.html#vanguards>
    pub vanguards_enabled: BoundedInt32<0, 2> = (1)
        from "vanguards-enabled",

    /// If higher than `vanguards-enabled`,
    /// and we are running an onion service,
    /// we use this level for all our onion service circuits:
    ///
    /// ```text
    ///    0: No vanguards.
    ///    1: Lite vanguards.
    ///    2: Full vanguards.
    /// ```
    ///
    /// See
    /// <https://spec.torproject.org/param-spec.html#vanguards>
    pub vanguards_hs_service: BoundedInt32<0, 2> = (2)
        from "vanguards-hs-service",

    /// The number of vanguards in the L2 vanguard set.
    ///
    /// See
    /// <https://spec.torproject.org/param-spec.html#vanguards>
    pub guard_hs_l2_number: BoundedInt32<1, {i32::MAX}> = (4)
        from  "guard-hs-l2-number",

    /// The minimum lifetime of L2 vanguards.
    ///
    /// See
    /// <https://spec.torproject.org/param-spec.html#vanguards>
    pub guard_hs_l2_lifetime_min: IntegerSeconds<BoundedInt32<1, {i32::MAX}>> = (86400)
        from  "guard-hs-l2-lifetime-min",

    /// The maximum lifetime of L2 vanguards.
    ///
    /// See
    /// <https://spec.torproject.org/param-spec.html#vanguards>
    pub guard_hs_l2_lifetime_max: IntegerSeconds<BoundedInt32<1, {i32::MAX}>> = (1036800)
        from  "guard-hs-l2-lifetime-max",

    /// The number of vanguards in the L3 vanguard set.
    ///
    /// See
    /// <https://spec.torproject.org/param-spec.html#vanguards>
    pub guard_hs_l3_number: BoundedInt32<1, {i32::MAX}> = (8)
        from  "guard-hs-l3-number",

    /// The minimum lifetime of L3 vanguards.
    ///
    /// See
    /// <https://spec.torproject.org/param-spec.html#vanguards>
    pub guard_hs_l3_lifetime_min: IntegerSeconds<BoundedInt32<1, {i32::MAX}>> = (3600)
        from  "guard-hs-l3-lifetime-min",

    /// The maximum lifetime of L3 vanguards.
    ///
    /// See
    /// <https://spec.torproject.org/param-spec.html#vanguards>
    pub guard_hs_l3_lifetime_max: IntegerSeconds<BoundedInt32<1, {i32::MAX}>> = (172800)
        from  "guard-hs-l3-lifetime-max",

    /// The KIST to use by default when building inter-relay channels:
    ///
    /// ```text
    ///    0: No KIST.
    ///    1: KIST using TCP_NOTSENT_LOWAT.
    /// ```
    ///
    // TODO(KIST): add this to param spec
    // TODO(KIST): make this default to 1 (KIST with TCP_NOTSENT_LOWAT)
    // when we're confident it behaves correctly in conjunction with cc
    pub kist_enabled: BoundedInt32<0, 1> = (0)
        from "kist-enabled",

    /// If `kist_enabled` is `1` (KIST using TCP_NOTSENT_LOWAT),
    /// the TCP_NOTSENT_LOWAT value to set for each channel.
    ///
    /// If `kist_enabled` is `0` (disabled),
    /// the TCP_NOTSENT_LOWAT option is set to 0xFFFFFFFF (u32::MAX).
    ///
    // TODO(KIST): technically, this should be a u32, not an i32.
    // However, because we're using it to limit the amount of unsent data in TCP sockets,
    // it's unlikely we're ever going to want to set this to a high value,
    // so an upper bound of i32::MAX is good enough for our purposes.
    pub kist_tcp_notsent_lowat: BoundedInt32<1, {i32::MAX}> = (1)
        from  "kist-tcp-notsent-lowat",

    /// If true, we use lists of family members
    /// when making decisions about which relays belong to the same family.
    pub use_family_lists: BoundedInt32<0,1> = (1)
        from "use-family-lists",

    /// If true, we use lists of family IDs
    /// when making decisions about which relays belong to the same family.
    pub use_family_ids: BoundedInt32<0,1> = (1)
        from "use-family-ids",
}

}

impl Default for NetParameters {
    fn default() -> Self {
        NetParameters::default_values().expect("Default parameters were out-of-bounds")
    }
}

// This impl is a bit silly, but it makes the `params` method on NetDirProvider
// work out.
impl AsRef<NetParameters> for NetParameters {
    fn as_ref(&self) -> &NetParameters {
        self
    }
}

impl NetParameters {
    /// Construct a new NetParameters from a given list of key=value parameters.
    ///
    /// Unrecognized parameters are ignored.
    pub fn from_map(p: &tor_netdoc::doc::netstatus::NetParams<i32>) -> Self {
        let mut params = NetParameters::default();
        let unrecognized = params.saturating_update(p.iter());
        for u in unrecognized {
            tracing::debug!("Ignored unrecognized net param: {u}");
        }
        params
    }

    /// Replace a list of parameters, using the logic of
    /// `set_saturating`.
    ///
    /// Return a vector of the parameter names we didn't recognize.
    pub(crate) fn saturating_update<'a, S>(
        &mut self,
        iter: impl Iterator<Item = (S, &'a i32)>,
    ) -> Vec<S>
    where
        S: AsRef<str>,
    {
        let mut unrecognized = Vec::new();
        for (k, v) in iter {
            if !self.set_saturating(k.as_ref(), *v) {
                unrecognized.push(k);
            }
        }
        unrecognized
    }
}

#[cfg(test)]
#[allow(clippy::many_single_char_names)]
#[allow(clippy::cognitive_complexity)]
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
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    use std::string::String;

    #[test]
    fn empty_list() {
        let mut x = NetParameters::default();
        let y = Vec::<(&String, &i32)>::new();
        let u = x.saturating_update(y.into_iter());
        assert!(u.is_empty());
    }

    #[test]
    fn unknown_parameter() {
        let mut x = NetParameters::default();
        let mut y = Vec::<(&String, &i32)>::new();
        let k = &String::from("This_is_not_a_real_key");
        let v = &456;
        y.push((k, v));
        let u = x.saturating_update(y.into_iter());
        assert_eq!(u, vec![&String::from("This_is_not_a_real_key")]);
    }

    // #[test]
    // fn duplicate_parameter() {}

    #[test]
    fn single_good_parameter() {
        let mut x = NetParameters::default();
        let mut y = Vec::<(&String, &i32)>::new();
        let k = &String::from("min_paths_for_circs_pct");
        let v = &54;
        y.push((k, v));
        let z = x.saturating_update(y.into_iter());
        assert!(z.is_empty());
        assert_eq!(x.min_circuit_path_threshold.as_percent().get(), 54);
    }

    #[test]
    fn multiple_good_parameters() {
        let mut x = NetParameters::default();
        let mut y = Vec::<(&String, &i32)>::new();
        let k = &String::from("min_paths_for_circs_pct");
        let v = &54;
        y.push((k, v));
        let k = &String::from("circwindow");
        let v = &900;
        y.push((k, v));
        let z = x.saturating_update(y.into_iter());
        assert!(z.is_empty());
        assert_eq!(x.min_circuit_path_threshold.as_percent().get(), 54);
        assert_eq!(x.circuit_window.get(), 900);
    }

    #[test]
    fn good_out_of_range() {
        let mut x = NetParameters::default();
        let mut y = Vec::<(&String, &i32)>::new();
        let k = &String::from("sendme_accept_min_version");
        let v = &30;
        y.push((k, v));
        let k = &String::from("min_paths_for_circs_pct");
        let v = &255;
        y.push((k, v));
        let z = x.saturating_update(y.into_iter());
        assert!(z.is_empty());
        assert_eq!(x.sendme_accept_min_version.get(), 30);
        assert_eq!(x.min_circuit_path_threshold.as_percent().get(), 95);
    }

    #[test]
    fn good_invalid_rep() {
        let mut x = NetParameters::default();
        let mut y = Vec::<(&String, &i32)>::new();
        let k = &String::from("sendme_accept_min_version");
        let v = &30;
        y.push((k, v));
        let k = &String::from("min_paths_for_circs_pct");
        let v = &9000;
        y.push((k, v));
        let z = x.saturating_update(y.into_iter());
        assert!(z.is_empty());
        assert_eq!(x.sendme_accept_min_version.get(), 30);
        assert_eq!(x.min_circuit_path_threshold.as_percent().get(), 95);
    }

    // #[test]
    // fn good_duplicate() {}
    #[test]
    fn good_unknown() {
        let mut x = NetParameters::default();
        let mut y = Vec::<(&String, &i32)>::new();
        let k = &String::from("sendme_accept_min_version");
        let v = &30;
        y.push((k, v));
        let k = &String::from("not_a_real_parameter");
        let v = &9000;
        y.push((k, v));
        let z = x.saturating_update(y.into_iter());
        assert_eq!(z, vec![&String::from("not_a_real_parameter")]);
        assert_eq!(x.sendme_accept_min_version.get(), 30);
    }

    #[test]
    fn from_consensus() {
        let mut p = NetParameters::default();
        let mut mp: std::collections::HashMap<String, i32> = std::collections::HashMap::new();
        mp.insert("bwweightscale".to_string(), 70);
        mp.insert("min_paths_for_circs_pct".to_string(), 45);
        mp.insert("im_a_little_teapot".to_string(), 1);
        mp.insert("circwindow".to_string(), 99999);
        mp.insert("ExtendByEd25519ID".to_string(), 1);

        let z = p.saturating_update(mp.iter());
        assert_eq!(z, vec![&String::from("im_a_little_teapot")]);

        assert_eq!(p.bw_weight_scale.get(), 70);
        assert_eq!(p.min_circuit_path_threshold.as_percent().get(), 45);
        let b_val: bool = p.extend_by_ed25519_id.into();
        assert!(b_val);
    }

    #[test]
    fn all_parameters() {
        use std::time::Duration;
        let mut p = NetParameters::default();
        let mp = [
            ("bwweightscale", 10),
            ("cbtdisabled", 1),
            ("cbtnummodes", 11),
            ("cbtrecentcount", 12),
            ("cbtmaxtimeouts", 13),
            ("cbtmincircs", 5),
            ("cbtquantile", 61),
            ("cbtclosequantile", 15),
            ("cbtlearntimeout", 1900),
            ("cbtmintimeout", 2020),
            ("cbtinitialtimeout", 2050),
            ("cbttestfreq", 110),
            ("cbtmaxopencircs", 14),
            ("circwindow", 999),
            ("CircuitPriorityHalflifeMsec", 222),
            ("guard-lifetime-days", 36),
            ("guard-confirmed-min-lifetime-days", 37),
            ("guard-internet-likely-down-interval", 38),
            ("guard-max-sample-size", 39),
            ("guard-max-sample-threshold", 40),
            ("guard-min-filtered-sample-size", 41),
            ("guard-n-primary-guards", 42),
            ("guard-n-primary-guards-to-use", 43),
            ("guard-n-primary-dir-guards-to-use", 44),
            ("guard-nonprimary-guard-connect-timeout", 45),
            ("guard-nonprimary-guard-idle-timeout", 46),
            ("guard-remove-unlisted-guards-after-days", 47),
            ("guard-meaningful-restriction-percent", 12),
            ("guard-extreme-restriction-percent", 3),
            ("ExtendByEd25519ID", 0),
            ("min_paths_for_circs_pct", 51),
            ("nf_conntimeout_clients", 606),
            ("nf_ito_low", 1_000),
            ("nf_ito_high", 20_000),
            ("nf_ito_low_reduced", 3_000),
            ("nf_ito_high_reduced", 40_000),
            ("sendme_accept_min_version", 31),
            ("sendme_emit_min_version", 32),
        ];
        let ignored = p.saturating_update(mp.iter().map(|(a, b)| (a, b)));
        assert!(ignored.is_empty());

        assert_eq!(p.bw_weight_scale.get(), 10);
        assert!(bool::from(p.cbt_learning_disabled));
        assert_eq!(p.cbt_num_xm_modes.get(), 11);
        assert_eq!(p.cbt_success_count.get(), 12);
        assert_eq!(p.cbt_max_timeouts.get(), 13);
        assert_eq!(p.cbt_min_circs_for_estimate.get(), 5);
        assert_eq!(p.cbt_timeout_quantile.as_percent().get(), 61);
        assert_eq!(p.cbt_abandon_quantile.as_percent().get(), 15);
        assert_eq!(p.nf_ito_low.as_millis().get(), 1_000);
        assert_eq!(p.nf_ito_high.as_millis().get(), 20_000);
        assert_eq!(p.nf_ito_low_reduced.as_millis().get(), 3_000);
        assert_eq!(p.nf_ito_high_reduced.as_millis().get(), 40_000);
        assert_eq!(
            Duration::try_from(p.unused_client_circ_timeout_while_learning_cbt).unwrap(),
            Duration::from_secs(1900)
        );
        assert_eq!(
            Duration::try_from(p.cbt_min_timeout).unwrap(),
            Duration::from_millis(2020)
        );
        assert_eq!(
            Duration::try_from(p.cbt_initial_timeout).unwrap(),
            Duration::from_millis(2050)
        );
        assert_eq!(
            Duration::try_from(p.cbt_testing_delay).unwrap(),
            Duration::from_secs(110)
        );
        assert_eq!(p.cbt_max_open_circuits_for_testing.get(), 14);
        assert_eq!(p.circuit_window.get(), 999);
        assert_eq!(
            Duration::try_from(p.circuit_priority_half_life).unwrap(),
            Duration::from_millis(222)
        );
        assert!(!bool::from(p.extend_by_ed25519_id));
        assert_eq!(p.min_circuit_path_threshold.as_percent().get(), 51);
        assert_eq!(
            Duration::try_from(p.unused_client_circ_timeout).unwrap(),
            Duration::from_secs(606)
        );
        assert_eq!(p.sendme_accept_min_version.get(), 31);
        assert_eq!(p.sendme_emit_min_version.get(), 32);

        assert_eq!(
            Duration::try_from(p.guard_lifetime_unconfirmed).unwrap(),
            Duration::from_secs(86400 * 36)
        );
        assert_eq!(
            Duration::try_from(p.guard_lifetime_confirmed).unwrap(),
            Duration::from_secs(86400 * 37)
        );
        assert_eq!(
            Duration::try_from(p.guard_internet_likely_down).unwrap(),
            Duration::from_secs(38)
        );
        assert_eq!(p.guard_max_sample_size.get(), 39);
        assert_eq!(p.guard_max_sample_threshold.as_percent().get(), 40);
        assert_eq!(p.guard_filtered_min_sample_size.get(), 41);
        assert_eq!(p.guard_n_primary.get(), 42);
        assert_eq!(p.guard_use_parallelism.get(), 43);
        assert_eq!(p.guard_dir_use_parallelism.get(), 44);
        assert_eq!(
            Duration::try_from(p.guard_nonprimary_connect_timeout).unwrap(),
            Duration::from_secs(45)
        );
        assert_eq!(
            Duration::try_from(p.guard_nonprimary_idle_timeout).unwrap(),
            Duration::from_secs(46)
        );
        assert_eq!(
            Duration::try_from(p.guard_remove_unlisted_after).unwrap(),
            Duration::from_secs(86400 * 47)
        );
        assert_eq!(p.guard_meaningful_restriction.as_percent().get(), 12);
        assert_eq!(p.guard_extreme_restriction.as_percent().get(), 3);
    }
}
