//! KIST-related parameters.

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

impl KistParams {
    /// Create a new `KistParams` from the given `KistMode` and options.
    pub fn new(kist_enabled: KistMode, tcp_notsent_lowat: u32) -> Self {
        Self {
            kist_enabled,
            tcp_notsent_lowat,
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
