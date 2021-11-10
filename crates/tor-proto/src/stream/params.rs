//! Declares a type to configure new streams.

use tor_cell::relaycell::msg::{BeginFlags, IpVersionPreference};

/// A set of preferences used to declare how a new stream should be opened.
#[derive(Clone, Debug, Default)]
pub struct StreamParameters {
    /// Preferred IP version to use.
    ip_version: IpVersionPreference,
    /// True if we are requesting an optimistic stream.
    optimistic: bool,
}

impl StreamParameters {
    /// Create a new [`StreamParameters`] using default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure which IP version (IPv4 or IPv6) you'd like to request,
    /// if you're connecting to a hostname.
    ///
    /// The default is to allow either version, but to prefer IPv4.
    pub fn ip_version(&mut self, preference: IpVersionPreference) -> &mut Self {
        self.ip_version = preference;
        self
    }

    /// Configure whether the stream should be opened "optimistically."
    ///
    /// By default, streams are not "optimistic". When you call
    /// [`ClientCirc::begin_stream()`](crate::circuit::ClientCirc::begin_stream),
    /// the function won't give you a stream until the exit node has
    /// confirmed that it has successfully opened a connection to your
    /// target address.  It's safer to wait in this way, but it is slower:
    /// it takes an entire round trip to get your confirmation.
    ///
    /// If a stream _is_ configured to be "optimistic", then
    /// `ClientCirc::begin_stream()` will return the stream
    /// immediately, without waiting for an answer from the exit.  You
    /// can start sending data on the stream right away, though of
    /// course this data will be lost if the connection is not
    /// actually successful.
    pub fn optimistic(&mut self, optimistic: bool) -> &mut Self {
        self.optimistic = optimistic;
        self
    }

    /// Crate-internal: Return true if the stream is optimistic.
    pub(crate) fn is_optimistic(&self) -> bool {
        self.optimistic
    }

    /// Crate-internal: Get a set of [`BeginFlags`] for this stream.
    pub(crate) fn begin_flags(&self) -> BeginFlags {
        self.ip_version.into()
    }
}
