//! Translate relay information from the formats used in the onion service
//! protocol into `CircTarget`s that we can use for building circuits.
//!
//! (Later this will include support for INTRODUCE2 messages too.)

use tor_error::{HasRetryTime, RetryTime};
use tor_linkspec::CircTarget;
use tor_netdir::NetDir;
use tor_netdoc::doc::hsdesc::IntroPointDesc;

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
) -> Result<impl CircTarget + use<>, InvalidTarget> {
    Ok(netdir.circ_target_from_verbatim_linkspecs(desc.link_specifiers(), desc.ipt_ntor_key())?)
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
    /// them, proved to be malformed.
    #[error("Malformed channel target information provided")]
    UnparseableChanTargetInfo(#[from] tor_bytes::Error),

    /// We couldn't build a proper introduction point from the provided link specifiers.
    #[error("Unable to reconstruct introduction point")]
    InvalidIntroPoint(#[from] tor_netdir::VerbatimCircTargetDecodeError),

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
            IT::InvalidIntroPoint(..) => RT::Never,
            IT::Bug(..) => RT::Never,
        }
    }
}
