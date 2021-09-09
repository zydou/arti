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

use std::convert::TryInto;
use tor_units::{BoundedInt32, IntegerMilliseconds, IntegerSeconds, Percentage, SendMeVersion};

/// An object that can be constructed from an i32, with saturating semantics.
pub trait FromInt32Saturating {
    /// Construct an instance of this object from `val`.
    ///
    /// If `val` is too low, treat it as the lowest value that would be
    /// valid.  If `val` is too high, treat it as the highest value that
    /// would be valid.
    fn from_saturating(val: i32) -> Self;
}

impl FromInt32Saturating for i32 {
    fn from_saturating(val: i32) -> Self {
        val
    }
}
impl<const L: i32, const H: i32> FromInt32Saturating for BoundedInt32<L, H> {
    fn from_saturating(val: i32) -> Self {
        Self::saturating_new(val)
    }
}
impl<T: Copy + Into<f64> + FromInt32Saturating> FromInt32Saturating for Percentage<T> {
    fn from_saturating(val: i32) -> Self {
        Self::new(T::from_saturating(val))
    }
}
impl<T: FromInt32Saturating + TryInto<u64>> FromInt32Saturating for IntegerMilliseconds<T> {
    fn from_saturating(val: i32) -> Self {
        Self::new(T::from_saturating(val))
    }
}
impl<T: FromInt32Saturating + TryInto<u64>> FromInt32Saturating for IntegerSeconds<T> {
    fn from_saturating(val: i32) -> Self {
        Self::new(T::from_saturating(val))
    }
}
impl FromInt32Saturating for SendMeVersion {
    fn from_saturating(val: i32) -> Self {
        Self::new(val.clamp(0, 255) as u8)
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
                        T::from_saturating(val)
                    }, )*
                    _ => return false,
                }
                true
            }
        }
    }
}

declare_net_parameters! {

/// This structure holds recognised configuration parameters. All values are type-safe,
/// and where applicable clamped to be within range.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct NetParameters {
    /// A weighting factor for bandwidth calculations
    pub bw_weight_scale: BoundedInt32<0, { i32::MAX }> = (10_000)
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
    // XXXX-SPEC 10000 is greater than 1000 for cbt_success_count.
    pub cbt_max_timeouts: BoundedInt32<3, 10_000> = (18)
        from "cbtmaxtimeouts",
    /// Smallest number of circuit build times we have to view in order to use
    /// our Pareto-based circuit timeout estimator.
    // XXXX-SPEC 10000 disables this.
    pub cbt_min_circs_for_estimate: BoundedInt32<1, 10_000> = (100)
        from "cbtmincircs",
    /// Quantile to use when determining the correct circuit timeout value
    /// with our Pareto estimator.
    ///
    /// (We continue building circuits after this timeout, but only
    /// for build-tim measurement purposes.)
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

    /// The maximum cell window size?
    pub circuit_window: BoundedInt32<100, 1000> = (1_000)
        from "circwindow",
    /// The decay parameter for circuit priority
    pub circuit_priority_half_life: IntegerMilliseconds<BoundedInt32<1, { i32::MAX }>> = (30_000)
        from "CircuitPriorityHalflifeMsec",
    /// Whether to perform circuit extensions by Ed25519 ID
    pub extend_by_ed25519_id: BoundedInt32<0, 1> = (0)
        from "ExtendByEd25519ID",
    /// The minimum threshold for circuit patch construction
    pub min_circuit_path_threshold: Percentage<BoundedInt32<25, 95>> = (60)
        from "min_paths_for_circs_pct",

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

}

}

impl Default for NetParameters {
    fn default() -> Self {
        NetParameters::default_values().expect("Default parameters were out-of-bounds")
    }
}

impl NetParameters {
    /// Replace a list of parameters, using the logic of
    /// `saturating_update_override`.
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
#[allow(clippy::unwrap_used)]
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

    #[test]
    fn all_parameters() {
        use std::convert::TryFrom;
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
            ("ExtendByEd25519ID", 0),
            ("min_paths_for_circs_pct", 51),
            ("nf_conntimeout_clients", 606),
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
    }
}
