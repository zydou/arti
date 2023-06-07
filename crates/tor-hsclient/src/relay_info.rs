//! Translate relay information from the formats used in the onion service
//! protocol into `CircTarget`s that we can use for building circuits.
//!
//! (Later this will include support for INTRODUCE2 messages too.)

#![allow(dead_code, unreachable_pub)] // TODO HS remove these once this API is exposed.

use tor_error::into_internal;
use tor_linkspec::{
    decode::Strictness, verbatim::VerbatimLinkSpecCircTarget, CircTarget, EncodedLinkSpec,
    OwnedChanTargetBuilder, OwnedCircTarget,
};
use tor_llcrypto::pk::curve25519;
use tor_netdir::NetDir;
use tor_netdoc::doc::hsdesc::IntroPointDesc;

/// Helper: create a [`CircTarget`] from its component parts as provided by
/// another party on the network.
///
/// This function is used to build a `CircTarget` from an `IntroPointDesc` (for
/// extending to an introduction point).  Later, it can also be used to build a
/// CircTarget from an `Introduce2` message (for extending to a rendezvous
/// point).
fn circtarget_from_pieces(
    linkspecs: &[EncodedLinkSpec],
    ntor_onion_key: &curve25519::PublicKey,
    netdir: &NetDir,
) -> Result<impl CircTarget, InvalidTarget> {
    let mut bld = OwnedCircTarget::builder();
    // Decode the link specifiers and use them to find out what we can about
    // this relay.
    let linkspecs_decoded = linkspecs
        .iter()
        .map(|ls| ls.parse())
        .collect::<Result<Vec<_>, _>>()?;
    *bld.chan_target() =
        OwnedChanTargetBuilder::from_linkspecs(Strictness::Standard, &linkspecs_decoded[..])?;
    // Look up the relay in the directory, to see:
    //    1) if it is flatly impossible,
    //    2) what subprotocols we should assume it implements.
    let protocols = {
        let chan_target = bld.chan_target().build().map_err(into_internal!(
            "from_linkspecs gave us a non-working ChanTargetBuilder"
        ))?;
        match netdir.by_ids_detailed(&chan_target)? {
            Some(relay) => relay.protovers().clone(),
            None => netdir.relay_protocol_status().required_protocols().clone(),
        }
    };
    bld.protocols(protocols);
    bld.ntor_onion_key(*ntor_onion_key);
    let circ_target = bld.build().map_err(into_internal!(
        "somehow we made an invalid CircTargetBuilder"
    ))?;
    Ok(VerbatimLinkSpecCircTarget::new(
        circ_target,
        linkspecs.to_vec(),
    ))
}

/// Construct a [`CircTarget`] from a provided [`IntroPointDesc`].
///
/// Onion service clients use this function to convert an `IntroPointDesc` in
/// the onion service descriptor into a form that they can use when building a
/// circuit to an introduction point.
///
/// The `netdir` argument is used to fill in missing information about the
/// target relay, and to make sure that the target relay's identities are not
/// inconsistent with the rest of the network.
pub(crate) fn ipt_to_circtarget(
    desc: &IntroPointDesc,
    netdir: &NetDir,
) -> Result<impl CircTarget, InvalidTarget> {
    circtarget_from_pieces(desc.link_specifiers(), desc.ipt_ntor_key(), netdir)
}

/// We were given unusable information about an introduction point or rendezvous
/// point.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum InvalidTarget {
    /// The provided link specifiers included some that, when we tried to parse
    /// them, proved to be misformed.
    #[error("Misformed channel target information provided")]
    UnparseableChanTargetInfo(#[from] tor_bytes::Error),

    /// The provided link specifiers were inconsistent with one another, or missing
    /// key information.
    #[error("Invalid channel target information provided")]
    InvalidChanTargetInfo(#[from] tor_linkspec::decode::ChanTargetDecodeError),

    /// The provided relay identities (in the link specifiers) described a relay
    /// which, according to the network directory, cannot possibly exist.
    #[error("Impossible combination of relay identities")]
    ImpossibleRelayIds(#[from] tor_netdir::RelayLookupError),

    /// An internal error occurred.
    #[error("{0}")]
    Bug(#[from] tor_error::Bug),
}
