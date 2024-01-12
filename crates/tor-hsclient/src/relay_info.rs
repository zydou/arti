//! Translate relay information from the formats used in the onion service
//! protocol into `CircTarget`s that we can use for building circuits.
//!
//! (Later this will include support for INTRODUCE2 messages too.)

use tor_error::{into_internal, HasRetryTime, RetryTime};
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
//
// TODO (#1223): This function is very similar to a block of code in
// `tor-hsservice`.  Can/should we unify them?
fn circtarget_from_pieces(
    linkspecs: &[EncodedLinkSpec],
    ntor_onion_key: &curve25519::PublicKey,
    netdir: &NetDir,
) -> Result<impl CircTarget, InvalidTarget> {
    let mut bld = OwnedCircTarget::builder();
    // Decode the link specifiers and use them to find out what we can about
    // this relay.
    *bld.chan_target() =
        OwnedChanTargetBuilder::from_encoded_linkspecs(Strictness::Standard, linkspecs)?;
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
//
// This is returned by `ipt_to_circtarget`.  It will also be used for rendezvous
// points when we implement the HS server side.
// At that point, this module will need to move to a crate where it can be used
// by the HS server code.
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

/// When to maybe retry *with the same inputs* that generated this error.
///
/// When returned from `ipt_to_circtarget`, that means this is when to retry
/// the *same introduction point* for the *same hidden service*.
///
/// "The same introduction point" means one with precisely the same set of identities
/// and link specifiers.
//
// Note about correctness, and introduction point identity:
//
// We use this as part of HasRetryTime for FailedAttemptError.
// HasRetryTime for FailedAttemptError is used for selecting which intro point to retry.
// Our introduction point experiences are recorded according to *one* relay identity,
// not the complete set.
//
// Nevertheless, this is correct, because: we only select from, and record experiences for,
// *usable* introduction points.  An InvalidTarget error is detected early enough
// to avoid regarding the introduction point as usable at all.  So we never use
// this RetryTime impl, here, to choose between introduction points.
impl HasRetryTime for InvalidTarget {
    fn retry_time(&self) -> RetryTime {
        use InvalidTarget as IT;
        use RetryTime as RT;
        match self {
            IT::UnparseableChanTargetInfo(..) => RT::Never,
            IT::InvalidChanTargetInfo(..) => RT::Never,
            IT::ImpossibleRelayIds(..) => RT::Never,
            IT::Bug(..) => RT::Never,
        }
    }
}
