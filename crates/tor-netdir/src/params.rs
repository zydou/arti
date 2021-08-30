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

use tor_units::{BoundedInt32, IntegerMilliseconds, IntegerSeconds, Percentage, SendMeVersion};

/// This structure holds recognised configuration parameters. All values are type-safe,
/// and where applicable clamped to be within range.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct NetParameters {
    /// A weighting factor for bandwidth calculations
    pub bw_weight_scale: BoundedInt32<0, { i32::MAX }>,

    /// If true, do not attempt to learn circuit-build timeouts at all.
    pub cbt_learning_disabled: BoundedInt32<0, 1>,
    /// Number of histograms bins to consider when estimating Xm for a
    /// Pareto-based circuit timeout estimator.
    pub cbt_num_xm_modes: BoundedInt32<1, 20>,
    /// How many recent circuit success/timeout statuses do we remember
    /// when trying to tell if our circuit timeouts are too low?
    pub cbt_success_count: BoundedInt32<3, 1000>,
    /// How many timeouts (in the last `cbt_success_count` observations)
    /// indicates that our circuit timeouts are too low?
    pub cbt_max_timeouts: BoundedInt32<3, 10000>, // XXXX-SPEC 10000 is greater than 1000 for cbt_success_count.
    /// Smallest number of circuit build times we have to view in order to use
    /// our Pareto-based circuit timeout estimator.
    pub cbt_min_circs_for_estimate: BoundedInt32<1, 10000>, // XXXX-SPEC 10000 disables this.
    /// Quantile to use when determining the correct circuit timeout value
    /// with our Pareto estimator.
    ///
    /// (We continue building circuits after this timeout, but only
    /// for build-tim measurement purposes.)
    pub cbt_timeout_quantile: Percentage<BoundedInt32<10, 99>>,
    /// Quantile to use when determining when to abandon circuits completely
    /// with our Pareto estimator.
    pub cbt_abandon_quantile: Percentage<BoundedInt32<10, 99>>,
    /// Lowest permissible timeout value for Pareto timeout estimator.
    pub cbt_min_timeout: IntegerMilliseconds<BoundedInt32<10, { i32::MAX }>>,
    /// Timeout value to use for our Pareto timeout estimator when we have
    /// no initial estimate.
    pub cbt_initial_timeout: IntegerMilliseconds<BoundedInt32<10, { i32::MAX }>>,
    /// When we don't have a good build-time estimate yet, how long
    /// (in seconds) do we wait between trying to launch build-time
    /// testing circuits through the network?
    pub cbt_testing_delay: IntegerSeconds<BoundedInt32<1, { i32::MAX }>>,
    /// How many circuits can be open before we will no longer
    /// consider launching testing circuits to learn average build
    /// times?
    pub cbt_max_open_circuits_for_testing: BoundedInt32<0, 14>,

    /// The maximum cell window size?
    pub circuit_window: BoundedInt32<100, 1000>,
    /// The decay parameter for circuit priority
    pub circuit_priority_half_life: IntegerMilliseconds<BoundedInt32<1, { i32::MAX }>>,
    /// Whether to perform circuit extensions by Ed25519 ID
    pub extend_by_ed25519_id: BoundedInt32<0, 1>,
    /// The minimum threshold for circuit patch construction
    pub min_circuit_path_threshold: Percentage<BoundedInt32<25, 95>>,

    /// The minimum sendme version to accept.
    pub sendme_accept_min_version: SendMeVersion,
    /// The minimum sendme version to transmit.
    pub sendme_emit_min_version: SendMeVersion,

    /// How long should never-used client circuits stay available,
    /// in the steady state?
    pub unused_client_circ_timeout: IntegerSeconds<BoundedInt32<60, 86_400>>,
    /// When we're learning circuit timeouts, how long should never-used client
    /// circuits stay available?
    pub unused_client_circ_timeout_while_learning_cbt: IntegerSeconds<BoundedInt32<10, 60_000>>,
}

impl Default for NetParameters {
    fn default() -> Self {
        netparam_defaults().expect("Default parameters were out-of-bounds")
    }
}

/// Try to return a set of default parameters for the network parameters.
///
/// (An error is only possible here if one of our default parameters is somehow
/// out-of-bounds, which would indicate a programming error.)
fn netparam_defaults() -> Result<NetParameters, tor_units::Error> {
    Ok(NetParameters {
        bw_weight_scale: BoundedInt32::checked_new(10000)?,
        cbt_abandon_quantile: Percentage::new(BoundedInt32::checked_new(99)?),
        cbt_initial_timeout: IntegerMilliseconds::new(BoundedInt32::checked_new(60_000)?),
        cbt_learning_disabled: BoundedInt32::checked_new(0)?,
        cbt_max_timeouts: BoundedInt32::checked_new(18)?,
        cbt_min_circs_for_estimate: BoundedInt32::checked_new(100)?,
        cbt_min_timeout: IntegerMilliseconds::new(BoundedInt32::checked_new(10)?),
        cbt_num_xm_modes: BoundedInt32::checked_new(10)?,
        cbt_success_count: BoundedInt32::checked_new(20)?,
        cbt_timeout_quantile: Percentage::new(BoundedInt32::checked_new(80)?),
        cbt_testing_delay: IntegerSeconds::new(BoundedInt32::checked_new(10)?),
        cbt_max_open_circuits_for_testing: BoundedInt32::checked_new(10)?,
        circuit_window: BoundedInt32::checked_new(1000)?,
        circuit_priority_half_life: IntegerMilliseconds::new(BoundedInt32::checked_new(30000)?),
        extend_by_ed25519_id: BoundedInt32::checked_new(0)?,
        min_circuit_path_threshold: Percentage::new(BoundedInt32::checked_new(60)?),
        sendme_accept_min_version: SendMeVersion::new(0),
        sendme_emit_min_version: SendMeVersion::new(0),
        unused_client_circ_timeout: IntegerSeconds::new(BoundedInt32::checked_new(30 * 60)?),
        unused_client_circ_timeout_while_learning_cbt: IntegerSeconds::new(
            BoundedInt32::checked_new(3 * 60)?,
        ),
    })
}

impl NetParameters {
    /// Replace the parameter whose name is `name` with the `value`,
    /// clamping the value to be within allowable bounds.
    ///
    /// Return true if the parameter was recognized; false otherwise.
    fn saturating_update_override(&mut self, name: &str, value: i32) -> bool {
        match name {
            "bwweightscale" => {
                self.bw_weight_scale = BoundedInt32::saturating_from(value);
            }
            "cbtdisabled" => {
                self.cbt_learning_disabled = BoundedInt32::saturating_from(value);
            }
            "cbtnummodes" => {
                self.cbt_num_xm_modes = BoundedInt32::saturating_from(value);
            }
            "cbtrecentcount" => {
                self.cbt_success_count = BoundedInt32::saturating_from(value);
            }
            "cbtmaxtimeouts" => {
                self.cbt_max_timeouts = BoundedInt32::saturating_from(value);
            }
            "cbtmincircs" => {
                self.cbt_min_circs_for_estimate = BoundedInt32::saturating_from(value);
            }
            "cbtquantile" => {
                self.cbt_timeout_quantile = Percentage::new(BoundedInt32::saturating_from(value));
            }
            "cbtclosequantile" => {
                self.cbt_abandon_quantile = Percentage::new(BoundedInt32::saturating_from(value));
            }
            "cbtlearntimeout" => {
                self.unused_client_circ_timeout_while_learning_cbt =
                    IntegerSeconds::new(BoundedInt32::saturating_from(value));
            }
            "cbtmintimeout" => {
                self.cbt_min_timeout =
                    IntegerMilliseconds::new(BoundedInt32::saturating_from(value));
            }
            "cbtinitialtimeout" => {
                self.cbt_initial_timeout =
                    IntegerMilliseconds::new(BoundedInt32::saturating_from(value));
            }
            "cbttestfreq" => {
                self.cbt_testing_delay = IntegerSeconds::new(BoundedInt32::saturating_from(value));
            }
            "cbtmaxopencircs" => {
                self.cbt_max_open_circuits_for_testing = BoundedInt32::saturating_from(value);
            }
            "circwindow" => {
                self.circuit_window = BoundedInt32::saturating_from(value);
            }
            "CircuitPriorityHalflifeMsec" => {
                self.circuit_priority_half_life =
                    IntegerMilliseconds::new(BoundedInt32::saturating_from(value))
            }
            "ExtendByEd25519ID" => {
                self.extend_by_ed25519_id = BoundedInt32::saturating_from(value);
            }
            "min_paths_for_circs_pct" => {
                self.min_circuit_path_threshold =
                    Percentage::new(BoundedInt32::saturating_from(value));
            }
            "nf_conntimeout_clients" => {
                self.unused_client_circ_timeout =
                    IntegerSeconds::new(BoundedInt32::saturating_from(value));
            }
            "sendme_accept_min_version" => {
                self.sendme_accept_min_version =
                    SendMeVersion::new(BoundedInt32::<0, 255>::saturating_from(value).into());
            }
            "sendme_emit_min_version" => {
                self.sendme_emit_min_version =
                    SendMeVersion::new(BoundedInt32::<0, 255>::saturating_from(value).into());
            }
            _ => {
                return false;
            } // unrecognized parameters are ignored.
        }
        true
    }

    /// Replace a list of parameters, using the logic of
    /// `saturating_update_override`.
    ///
    /// Return a vector of the parameter names we didn't recognize.
    pub(crate) fn saturating_update<'a>(
        &mut self,
        iter: impl Iterator<Item = (&'a String, &'a i32)>,
    ) -> Vec<&'a String> {
        let mut unrecognized = Vec::new();
        for (k, v) in iter {
            if !self.saturating_update_override(k, *v) {
                unrecognized.push(k);
            }
        }
        unrecognized
    }
}

#[cfg(test)]
#[allow(clippy::many_single_char_names)]
mod test {
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
        assert_eq!(u, vec![&String::from("This_is_not_a_real_key")])
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
}
