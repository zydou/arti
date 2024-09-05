//! Support for unit tests, in this crate and elsewhere.
//!
//! This module is only enabled when the `testing` feature is enabled.
//!
//! It is not covered by semver for the `tor-netdir` crate: see notes
//! on [`construct_network`].
//!
//! # Panics
//!
//! These functions can panic on numerous possible internal failures:
//! only use these functions for testing.

#![allow(clippy::unwrap_used)]

use crate::{MdDigest, MdReceiver, PartialNetDir};
use std::iter;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime};
#[cfg(feature = "geoip")]
use tor_geoip::GeoipDb;
use tor_netdoc::doc::microdesc::{Microdesc, MicrodescBuilder};
use tor_netdoc::doc::netstatus::{ConsensusBuilder, MdConsensus, MdConsensusRouterStatus};
use tor_netdoc::doc::netstatus::{Lifetime, RelayFlags, RelayWeight, RouterStatusBuilder};

pub use tor_netdoc::{BuildError, BuildResult};

/// A set of builder objects for a single node.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct NodeBuilders {
    /// Builds a routerstatus for a single node.
    ///
    /// Adjust fields in this builder to change the node's properties.
    pub rs: RouterStatusBuilder<MdDigest>,

    /// Builds a microdescriptor for a single node.
    ///
    /// Adjust fields in this builder in order to change the node's
    /// properties.
    pub md: MicrodescBuilder,

    /// Set this value to `true` to omit the microdesc from the network.
    pub omit_md: bool,

    /// Set this value to `true` to omit the routerdesc from the network.
    pub omit_rs: bool,
}

/// Helper: a customization function that does nothing.
pub fn simple_net_func(
    _idx: usize,
    _nb: &mut NodeBuilders,
    _bld: &mut ConsensusBuilder<MdConsensusRouterStatus>,
) {
}

/// As [`construct_network()`], but return a [`PartialNetDir`].
pub fn construct_netdir() -> PartialNetDir {
    construct_custom_netdir(simple_net_func).expect("failed to build default testing netdir")
}

/// As [`construct_custom_network()`], but return a [`PartialNetDir`],
/// and allow network parameter customisation.
pub fn construct_custom_netdir_with_params<F, P, PK>(
    func: F,
    params: P,
    lifetime: Option<Lifetime>,
) -> BuildResult<PartialNetDir>
where
    F: FnMut(usize, &mut NodeBuilders, &mut ConsensusBuilder<MdConsensusRouterStatus>),
    P: IntoIterator<Item = (PK, i32)>,
    PK: Into<String>,
{
    construct_custom_netdir_with_params_inner(
        func,
        params,
        lifetime,
        #[cfg(feature = "geoip")]
        None,
    )
}

/// Implementation of `construct_custom_netdir_with_params`, written this way to avoid
/// the GeoIP argument crossing a crate API boundary.
fn construct_custom_netdir_with_params_inner<F, P, PK>(
    func: F,
    params: P,
    lifetime: Option<Lifetime>,
    #[cfg(feature = "geoip")] geoip_db: Option<&GeoipDb>,
) -> BuildResult<PartialNetDir>
where
    F: FnMut(usize, &mut NodeBuilders, &mut ConsensusBuilder<MdConsensusRouterStatus>),
    P: IntoIterator<Item = (PK, i32)>,
    PK: Into<String>,
{
    let (consensus, microdescs) = construct_custom_network(func, lifetime)?;
    #[cfg(feature = "geoip")]
    let mut dir = if let Some(db) = geoip_db {
        PartialNetDir::new_with_geoip(consensus, Some(&params.into_iter().collect()), db)
    } else {
        PartialNetDir::new(consensus, Some(&params.into_iter().collect()))
    };
    #[cfg(not(feature = "geoip"))]
    let mut dir = PartialNetDir::new(consensus, Some(&params.into_iter().collect()));
    for md in microdescs {
        dir.add_microdesc(md);
    }

    Ok(dir)
}

/// As [`construct_custom_network()`], but return a [`PartialNetDir`].
pub fn construct_custom_netdir<F>(func: F) -> BuildResult<PartialNetDir>
where
    F: FnMut(usize, &mut NodeBuilders, &mut ConsensusBuilder<MdConsensusRouterStatus>),
{
    construct_custom_netdir_with_params(func, iter::empty::<(&str, _)>(), None)
}

#[cfg(feature = "geoip")]
/// As [`construct_custom_netdir()`], but with a `GeoipDb`.
pub fn construct_custom_netdir_with_geoip<F>(func: F, db: &GeoipDb) -> BuildResult<PartialNetDir>
where
    F: FnMut(usize, &mut NodeBuilders, &mut ConsensusBuilder<MdConsensusRouterStatus>),
{
    construct_custom_netdir_with_params_inner(func, iter::empty::<(&str, _)>(), None, Some(db))
}

/// As [`construct_custom_network`], but do not require a
/// customization function.
pub fn construct_network() -> BuildResult<(MdConsensus, Vec<Microdesc>)> {
    construct_custom_network(simple_net_func, None)
}

/// Build a fake network with enough information to enable some basic
/// tests.
///
/// By default, the constructed network will contain 40 relays,
/// numbered 0 through 39. They will have with RSA and Ed25519
/// identity fingerprints set to 0x0000...00 through 0x2727...27.
/// Each pair of relays is in a family with one another: 0x00..00 with
/// 0x01..01, and so on.
///
/// All relays are marked as usable.  The first ten are marked with no
/// additional flags.  The next ten are marked with the exit flag.
/// The next ten are marked with the guard flag.  The last ten are
/// marked with the exit _and_ guard flags.
///
/// TAP and Ntor onion keys are present, but unusable.
///
/// Odd-numbered exit relays are set to allow ports 80 and 443 on
/// IPv4.  Even-numbered exit relays are set to allow ports 1-65535
/// on IPv4.  No exit relays are marked to support IPv6.
///
/// Even-numbered relays support the `DirCache=2` protocol.
///
/// Every relay is given a measured weight based on its position
/// within its group of ten.  The weights for the ten relays in each
/// group are: 1000, 2000, 3000, ... 10000.  There is no additional
/// flag-based bandwidth weighting.
///
/// The consensus is declared as using method 34, and as being valid for
/// one day (in realtime) after the current `SystemTime`.
///
/// # Customization
///
/// Before each relay is added to the consensus or the network, it is
/// passed through the provided filtering function.  This function
/// receives as its arguments the current index (in range 0..40), a
/// [`RouterStatusBuilder`], and a [`MicrodescBuilder`].  If it
/// returns a `RouterStatusBuilder`, the corresponding router status
/// is added to the consensus.  If it returns a `MicrodescBuilder`,
/// the corresponding microdescriptor is added to the vector of
/// microdescriptor.
///
/// # Notes for future expansion
///
/// _Resist the temptation to make unconditional changes to this
/// function._ If the network generated by this function gets more and
/// more complex, then it will become harder and harder over time to
/// make it support new test cases and new behavior, and eventually
/// we'll have to throw the whole thing away.  (We ran into this
/// problem with Tor's unit tests.)
///
/// Instead, refactor this function so that it takes a
/// description of what kind of network to build, and then builds it from
/// that description.
pub fn construct_custom_network<F>(
    mut func: F,
    lifetime: Option<Lifetime>,
) -> BuildResult<(MdConsensus, Vec<Microdesc>)>
where
    F: FnMut(usize, &mut NodeBuilders, &mut ConsensusBuilder<MdConsensusRouterStatus>),
{
    let f = RelayFlags::RUNNING
        | RelayFlags::VALID
        | RelayFlags::V2DIR
        | RelayFlags::FAST
        | RelayFlags::STABLE;
    // define 4 groups of flags
    let flags = [
        f | RelayFlags::HSDIR,
        f | RelayFlags::EXIT,
        f | RelayFlags::GUARD,
        f | RelayFlags::EXIT | RelayFlags::GUARD,
    ];

    let lifetime = lifetime.map(Ok).unwrap_or_else(|| {
        let now = SystemTime::now();
        let one_day = Duration::new(86400, 0);

        Lifetime::new(now, now + one_day / 2, now + one_day)
    })?;

    let mut bld = MdConsensus::builder();
    bld.consensus_method(34)
        .lifetime(lifetime)
        .param("bwweightscale", 1)
        .weights("".parse()?);

    let mut microdescs = Vec::new();
    for idx in 0..40_u8 {
        // Each relay gets a couple of no-good onion keys.
        // Its identity fingerprints are set to `idx`, repeating.
        // They all get the same address.
        let flags = flags[(idx / 10) as usize];
        let policy = if flags.contains(RelayFlags::EXIT) {
            if idx % 2 == 1 {
                "accept 80,443"
            } else {
                "accept 1-65535"
            }
        } else {
            "reject 1-65535"
        };
        // everybody is family with the adjacent relay.
        let fam_id = [idx ^ 1; 20];
        let family = hex::encode(fam_id);

        let mut md_builder = Microdesc::builder();
        md_builder
            .ntor_key((*b"----nothing in dirmgr uses this-").into())
            .ed25519_id([idx; 32].into())
            .family(family.parse().unwrap())
            .parse_ipv4_policy(policy)
            .unwrap();
        let protocols = if idx % 2 == 0 {
            // even-numbered relays are dircaches.
            "DirCache=2".parse().unwrap()
        } else {
            "".parse().unwrap()
        };
        let weight = RelayWeight::Measured(1000 * u32::from(idx % 10 + 1));
        let mut rs_builder = bld.rs();
        rs_builder
            .identity([idx; 20].into())
            .add_or_port(SocketAddr::from(([idx % 5, 0, 0, 3], 9001)))
            .protos(protocols)
            .set_flags(flags)
            .weight(weight);

        let mut node_builders = NodeBuilders {
            rs: rs_builder,
            md: md_builder,
            omit_rs: false,
            omit_md: false,
        };

        func(idx as usize, &mut node_builders, &mut bld);

        let md = node_builders.md.testing_md()?;
        let md_digest = *md.digest();
        if !node_builders.omit_md {
            microdescs.push(md);
        }

        if !node_builders.omit_rs {
            node_builders
                .rs
                .doc_digest(md_digest)
                .build_into(&mut bld)?;
        }
    }

    let consensus = bld.testing_consensus()?;

    Ok((consensus, microdescs))
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
    #[test]
    fn try_with_function() {
        let mut val = 0_u32;
        let _net = construct_custom_netdir(|_idx, _nb, _bld| {
            val += 1;
        });
        assert_eq!(val, 40);
    }
}
