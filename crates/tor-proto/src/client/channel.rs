//! Client channel code.
//!
//! This contains client specific channel code. In other words, everyting that a client needs to
//! establish a channel according to the Tor protocol.

pub(crate) mod handshake;

pub use handshake::ClientInitiatorHandshake;

use futures::{AsyncRead, AsyncWrite};

use tor_rtcompat::{CoarseTimeProvider, SleepProvider, StreamOps};

use crate::memquota::ChannelAccount;

/// Structure for building and launching a client Tor channel.
#[derive(Default)]
#[non_exhaustive]
pub struct ClientChannelBuilder {
    /// If present, a description of the address we're trying to connect to,
    /// and the way in which we are trying to connect to it.
    ///
    /// TODO: at some point, check this against the addresses in the netinfo
    /// cell too.
    target: Option<tor_linkspec::ChannelMethod>,
}

impl ClientChannelBuilder {
    /// Construct a new ChannelBuilder.
    pub fn new() -> Self {
        ClientChannelBuilder::default()
    }

    /// Set the declared target method of this channel.
    ///
    /// Note that nothing enforces the correctness of this method: it
    /// doesn't have to match the real method used to create the TLS
    /// stream.
    pub fn set_declared_method(&mut self, target: tor_linkspec::ChannelMethod) {
        self.target = Some(target);
    }

    /// Launch a new client handshake over a TLS stream.
    ///
    /// After calling this function, you'll need to call `connect()` on
    /// the result to start the handshake.  If that succeeds, you'll have
    /// authentication info from the relay: call `check()` on the result
    /// to check that.  Finally, to finish the handshake, call `finish()`
    /// on the result of _that_.
    pub fn launch<T, S>(
        self,
        tls: T,
        sleep_prov: S,
        memquota: ChannelAccount,
    ) -> ClientInitiatorHandshake<T, S>
    where
        T: AsyncRead + AsyncWrite + StreamOps + Send + Unpin + 'static,
        S: CoarseTimeProvider + SleepProvider,
    {
        handshake::ClientInitiatorHandshake::new(tls, self.target, sleep_prov, memquota)
    }
}
