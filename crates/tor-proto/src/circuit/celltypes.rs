//! Wrapper types for subsets of ChanMsg and RelayMsg types.
//!
//! These wrappers define types that are valid in response to particular
//! request, or when received in particular circumstances.  They're used
//! so that Rust's typesafety can help enforce protocol properties.

use derive_deftly::{Deftly, define_derive_deftly};
use std::fmt::{self, Display};
use tor_cell::chancell::msg::{self as chanmsg};

define_derive_deftly! {
    /// Derives a `TryFrom<AnyChanMsg>` implementation for enums
    /// that represent restricted subsets of ChanMsgs
    ///
    /// # Limitations
    ///
    /// The variants of the enum this is derived for *must* be a
    /// subset of the variants of [`AnyChanMsg`].
    RestrictedChanMsgSet:

    impl TryFrom<tor_cell::chancell::msg::AnyChanMsg> for $ttype {
        type Error = $crate::Error;

        fn try_from(m: tor_cell::chancell::msg::AnyChanMsg) -> $crate::Result<$ttype> {
            match m {
                $( tor_cell::chancell::msg::AnyChanMsg::$vname(m) => Ok($ttype::$vname(m)), )
                _ => Err($crate::Error::ChanProto(format!(
                    "Got a {} {}",
                    <tor_cell::chancell::msg::AnyChanMsg as tor_cell::chancell::ChanMsg>::cmd(&m),
                    ${tmeta(usage) as str},
                ))),
            }
        }
    }
}

pub(crate) use derive_deftly_template_RestrictedChanMsgSet;

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
}
