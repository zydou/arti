//! KIST-related parameters.

use caret::caret_int;
use tor_netdir::params::NetParameters;
use tor_units::BoundedInt32;

/// A set of parameters derived from the consensus document,
/// controlling the KIST behavior of channels.
#[derive(Debug, Clone, Copy, PartialEq, amplify::Getters)]
pub struct KistParams {
    /// Whether KIST is enabled.
    #[getter(as_copy)]
    kist_enabled: KistMode,
    /// The value to set for the [`TCP_NOTSENT_LOWAT`] socket option
    /// (on platforms that support it)
    /// if the `KistMode` is [`TcpNotSentLowat`](KistMode::TcpNotSentLowat).
    ///
    /// [`TCP_NOTSENT_LOWAT`]: https://lwn.net/Articles/560082/
    #[getter(as_copy)]
    tcp_notsent_lowat: u32,
}

impl From<&NetParameters> for KistParams {
    fn from(p: &NetParameters) -> Self {
        KistParams {
            kist_enabled: KistMode::from_net_parameter(p.kist_enabled),
            // NOTE: in theory, this cast shouldn't be needed
            // (kist_tcp_notsent_lowat is supposed to be a u32, not an i32).
            // In practice, however, the type conversion is needed
            // because consensus params are i32s.
            //
            // See the `NetParamaters::kist_tcp_notsent_lowat docs for more details.
            tcp_notsent_lowat: u32::from(p.kist_tcp_notsent_lowat),
        }
    }
}

/// A set of parameters, derived from the consensus document,
/// specifying the desired KIST behavior.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
#[non_exhaustive]
pub enum KistMode {
    /// KIST using TCP_NOTSENT_LOWAT.
    TcpNotSentLowat = 1,
    /// KIST is disabled.
    Disabled = 0,
}

impl KistMode {
    /// Build a `KistMode` from [`NetParameters`].
    ///
    /// Used for converting [`kist_enabled`](NetParameters::kist_enabled)
    /// to a corresponding `KistMode`.
    pub(crate) fn from_net_parameter(val: BoundedInt32<0, 1>) -> Self {
        match val.get().into() {
            KistType::DISABLED => KistMode::Disabled,
            KistType::TCP_NOTSENT_LOWAT => KistMode::TcpNotSentLowat,
            _ => unreachable!("BoundedInt32 was not bounded?!"),
        }
    }
}

caret_int! {
    /// KIST flavor, defined by a numerical value read from the consensus.
    struct KistType(i32) {
        /// KIST disabled
        DISABLED = 0,
        /// KIST using TCP_NOTSENT_LOWAT.
        TCP_NOTSENT_LOWAT = 1,
    }
}
