//! Wrapper types for subsets of ChanMsg and RelayMsg types.
//!
//! These wrappers define types that are valid in response to particular
//! request, or when received in particular circumstances.  They're used
//! so that Rust's typesafety can help enforce protocol properties.

use crate::{Error, Result};
use derive_deftly::{Deftly, define_derive_deftly};
use std::fmt::{self, Display};
use tor_cell::chancell::{
    ChanMsg,
    msg::{self as chanmsg, AnyChanMsg},
};
use tor_memquota::derive_deftly_template_HasMemoryCost;

define_derive_deftly! {
    /// Derives a `TryFrom<AnyChanMsg>` implementation for enums
    /// that represent restricted subsets of ChanMsgs
    ///
    /// # Limitations
    ///
    /// The variants of the enum this is derived for *must* be a
    /// subset of the variants of [`AnyChanMsg`].
    RestrictedChanMsgSet:

    impl TryFrom<AnyChanMsg> for $ttype {
        type Error = crate::Error;

        fn try_from(m: AnyChanMsg) -> Result<$ttype> {
            match m {
                $( AnyChanMsg::$vname(m) => Ok($ttype::$vname(m)), )
                _ => Err(Error::ChanProto(format!(
                    "Got a {} {}",
                    m.cmd(), ${tmeta(usage) as str},
                ))),
            }
        }
    }
}

/// A subclass of ChanMsg that can arrive in response to a CREATE* cell
/// that we send.
#[cfg_attr(docsrs, doc(cfg(feature = "testing")))]
#[derive(Debug, Deftly)]
#[allow(unreachable_pub)] // Only `pub` with feature `testing`; otherwise, visible in crate
#[allow(clippy::exhaustive_enums)]
#[derive_deftly(RestrictedChanMsgSet)]
#[deftly(usage = "in response to circuit creation")]
pub enum CreateResponse {
    /// Destroy cell: the CREATE failed.
    Destroy(chanmsg::Destroy),
    /// CreatedFast: good response to a CREATE cell.
    CreatedFast(chanmsg::CreatedFast),
    /// Created2: good response to a CREATE2 cell.
    Created2(chanmsg::Created2),
}

impl Display for CreateResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use CreateResponse as CR;
        match self {
            CR::Destroy(destroy) => write!(f, "DESTROY({})", destroy.reason()),
            CR::CreatedFast(_) => Display::fmt("CREATED_FAST", f),
            CR::Created2(_) => Display::fmt("CREATED2", f),
        }
    }
}

/// A subclass of ChanMsg that can correctly arrive on a live client
/// circuit (one where a CREATED* has been received).
#[derive(Debug, Deftly)]
#[allow(unreachable_pub)] // Only `pub` with feature `testing`; otherwise, visible in crate
#[derive_deftly(HasMemoryCost)]
#[derive_deftly(RestrictedChanMsgSet)]
#[deftly(usage = "on an open client circuit")]
pub enum ClientCircChanMsg {
    /// A relay cell telling us some kind of remote command from some
    /// party on the circuit.
    Relay(chanmsg::Relay),
    /// A cell telling us to destroy the circuit.
    Destroy(chanmsg::Destroy),
    // Note: RelayEarly is not valid for clients!
}

/// A subclass of ChanMsg that can correctly arrive on a live relay
/// circuit (one where a CREATE* has been received).
#[derive(Debug, Deftly)]
#[derive_deftly(HasMemoryCost)]
#[derive_deftly(RestrictedChanMsgSet)]
#[deftly(usage = "on an open relay circuit")]
#[cfg(feature = "relay")]
#[cfg_attr(not(test), allow(unused))] // TODO(relay)
pub(crate) enum RelayCircChanMsg {
    /// A relay cell telling us some kind of remote command from some
    /// party on the circuit.
    Relay(chanmsg::Relay),
    /// A relay early cell that is allowed to contain a CREATE message.
    RelayEarly(chanmsg::RelayEarly),
    /// A cell telling us to destroy the circuit.
    Destroy(chanmsg::Destroy),
    /// A cell telling us to enable/disable channel padding.
    PaddingNegotiate(chanmsg::PaddingNegotiate),
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
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;

    #[test]
    fn create_response() {
        use tor_cell::chancell::msg::{self, AnyChanMsg};
        fn good(m: AnyChanMsg) {
            assert!(CreateResponse::try_from(m).is_ok());
        }
        fn bad(m: AnyChanMsg) {
            assert!(CreateResponse::try_from(m).is_err());
        }

        good(msg::Destroy::new(2.into()).into());
        good(msg::CreatedFast::new(&b"this offer is unrepeatable"[..]).into());
        good(msg::Created2::new(&b"guaranteed guaranteed"[..]).into());
        bad(msg::CreateFast::new(&b"for a lifetime or more"[..]).into());
        bad(msg::Versions::new([1, 2, 3]).unwrap().into());
    }

    #[test]
    fn client_circ_chan_msg() {
        use tor_cell::chancell::msg::{self, AnyChanMsg};
        fn good(m: AnyChanMsg) {
            assert!(ClientCircChanMsg::try_from(m).is_ok());
        }
        fn bad(m: AnyChanMsg) {
            assert!(ClientCircChanMsg::try_from(m).is_err());
        }

        good(msg::Destroy::new(2.into()).into());
        bad(msg::CreatedFast::new(&b"guaranteed in this world"[..]).into());
        bad(msg::Created2::new(&b"and the next"[..]).into());
        good(msg::Relay::new(&b"guaranteed guaranteed"[..]).into());
        bad(msg::AnyChanMsg::RelayEarly(
            msg::Relay::new(&b"for the world and its mother"[..]).into(),
        ));
        bad(msg::Versions::new([1, 2, 3]).unwrap().into());
    }

    #[test]
    #[cfg(feature = "relay")]
    fn relay_circ_chan_msg() {
        use tor_cell::chancell::msg::{self, AnyChanMsg};
        fn good(m: AnyChanMsg) {
            assert!(RelayCircChanMsg::try_from(m).is_ok());
        }
        fn bad(m: AnyChanMsg) {
            assert!(RelayCircChanMsg::try_from(m).is_err());
        }

        good(msg::Destroy::new(2.into()).into());
        bad(msg::CreatedFast::new(&b"The great globular mass"[..]).into());
        bad(msg::Created2::new(&b"of protoplasmic slush"[..]).into());
        good(msg::Relay::new(&b"undulated slightly,"[..]).into());
        good(msg::AnyChanMsg::RelayEarly(
            msg::Relay::new(&b"as if aware of him"[..]).into(),
        ));
        bad(msg::Versions::new([1, 2, 3]).unwrap().into());
        good(msg::PaddingNegotiate::start_default().into());
        good(msg::RelayEarly::from(msg::Relay::new(b"snail-like unipedular organism")).into());
    }
}
