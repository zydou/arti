//! Wrapper types for subsets of ChanMsg and RelayMsg types.
//!
//! These wrappers define types that are valid in response to particular
//! request, or when received in particular circumstances.  They're used
//! so that Rust's typesafety can help enforce protocol properties.

use crate::{Error, Result};
use tor_cell::chancell::msg::{self as chanmsg, ChanMsg};

/// A subclass of ChanMsg that can arrive in response to a CREATE* cell
/// that we send.
#[cfg_attr(docsrs, doc(cfg(feature = "testing")))]
#[derive(Debug)]
#[allow(unreachable_pub)] // Only `pub` with feature `testing`; otherwise, visible in crate
#[allow(clippy::exhaustive_enums)]
pub enum CreateResponse {
    /// Destroy cell: the CREATE failed.
    Destroy(chanmsg::Destroy),
    /// CreatedFast: good response to a CREATE cell.
    CreatedFast(chanmsg::CreatedFast),
    /// Created2: good response to a CREATE2 cell.
    Created2(chanmsg::Created2),
}

impl TryFrom<ChanMsg> for CreateResponse {
    type Error = crate::Error;

    fn try_from(m: ChanMsg) -> Result<CreateResponse> {
        match m {
            ChanMsg::Destroy(m) => Ok(CreateResponse::Destroy(m)),
            ChanMsg::CreatedFast(m) => Ok(CreateResponse::CreatedFast(m)),
            ChanMsg::Created2(m) => Ok(CreateResponse::Created2(m)),
            _ => Err(Error::ChanProto(format!(
                "Got a {} in response to circuit creation",
                m.cmd()
            ))),
        }
    }
}

/// A subclass of ChanMsg that can correctly arrive on a live client
/// circuit (one where a CREATED* has been received).
#[derive(Debug)]
#[allow(unreachable_pub)] // Only `pub` with feature `testing`; otherwise, visible in crate
pub enum ClientCircChanMsg {
    /// A relay cell telling us some kind of remote command from some
    /// party on the circuit.
    Relay(chanmsg::Relay),
    /// A cell telling us to destroy the circuit.
    Destroy(chanmsg::Destroy),
    // Note: RelayEarly is not valid for clients!
}

impl TryFrom<ChanMsg> for ClientCircChanMsg {
    type Error = crate::Error;

    fn try_from(m: ChanMsg) -> Result<ClientCircChanMsg> {
        match m {
            ChanMsg::Destroy(m) => Ok(ClientCircChanMsg::Destroy(m)),
            ChanMsg::Relay(m) => Ok(ClientCircChanMsg::Relay(m)),
            _ => Err(Error::ChanProto(format!(
                "Got a {} cell on an open circuit",
                m.cmd()
            ))),
        }
    }
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;

    #[test]
    fn create_response() {
        use tor_cell::chancell::msg::{self, ChanMsg};
        fn good(m: ChanMsg) {
            assert!(CreateResponse::try_from(m).is_ok());
        }
        fn bad(m: ChanMsg) {
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
        use tor_cell::chancell::msg::{self, ChanMsg};
        fn good(m: ChanMsg) {
            assert!(ClientCircChanMsg::try_from(m).is_ok());
        }
        fn bad(m: ChanMsg) {
            assert!(ClientCircChanMsg::try_from(m).is_err());
        }

        good(msg::Destroy::new(2.into()).into());
        bad(msg::CreatedFast::new(&b"guaranteed in this world"[..]).into());
        bad(msg::Created2::new(&b"and the next"[..]).into());
        good(msg::Relay::new(&b"guaranteed guaranteed"[..]).into());
        bad(msg::ChanMsg::RelayEarly(msg::Relay::new(
            &b"for the world and its mother"[..],
        )));
        bad(msg::Versions::new([1, 2, 3]).unwrap().into());
    }
}
