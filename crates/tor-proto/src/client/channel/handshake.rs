//! Implementations for the client channel handshake

use futures::SinkExt;
use futures::io::{AsyncRead, AsyncWrite};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;
use tor_cell::chancell::msg;
use tracing::{debug, instrument, trace};

use tor_linkspec::{ChanTarget, ChannelMethod};
use tor_rtcompat::{CoarseTimeProvider, SleepProvider, StreamOps};

use crate::channel::handshake::{
    ChannelBaseHandshake, ChannelInitiatorHandshake, UnverifiedChannel, VerifiedChannel,
    unauthenticated_clock_skew,
};
use crate::channel::{Channel, ChannelFrame, ChannelType, Reactor, UniqId, new_frame};
use crate::memquota::ChannelAccount;
use crate::{ClockSkew, Result};

/// A raw client channel on which nothing has been done.
pub struct ClientInitiatorHandshake<
    T: AsyncRead + AsyncWrite + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
> {
    /// Runtime handle (insofar as we need it)
    sleep_prov: S,

    /// Memory quota account
    memquota: ChannelAccount,

    /// Cell encoder/decoder wrapping the underlying TLS stream
    ///
    /// (We don't enforce that this is actually TLS, but if it isn't, the
    /// connection won't be secure.)
    framed_tls: ChannelFrame<T>,

    /// Declared target method for this channel, if any.
    target_method: Option<ChannelMethod>,

    /// Logging identifier for this stream.  (Used for logging only.)
    unique_id: UniqId,
}

/// Implement the base channel handshake trait.
impl<T, S> ChannelBaseHandshake<T> for ClientInitiatorHandshake<T, S>
where
    T: AsyncRead + AsyncWrite + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
{
    fn framed_tls(&mut self) -> &mut ChannelFrame<T> {
        &mut self.framed_tls
    }
    fn unique_id(&self) -> &UniqId {
        &self.unique_id
    }
}

/// Implement the initiator channel handshake trait.
impl<T, S> ChannelInitiatorHandshake<T> for ClientInitiatorHandshake<T, S>
where
    T: AsyncRead + AsyncWrite + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
{
    fn is_expecting_auth_challenge(&self) -> bool {
        // Client never authenticate with a responder, only relay do.
        false
    }
}

impl<
    T: AsyncRead + AsyncWrite + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
> ClientInitiatorHandshake<T, S>
{
    /// Construct a new ClientInitiatorHandshake.
    pub(crate) fn new(
        tls: T,
        target_method: Option<ChannelMethod>,
        sleep_prov: S,
        memquota: ChannelAccount,
    ) -> Self {
        Self {
            framed_tls: new_frame(tls, ChannelType::ClientInitiator),
            target_method,
            unique_id: UniqId::new(),
            sleep_prov,
            memquota,
        }
    }

    /// Negotiate a link protocol version with the relay, and read
    /// the relay's handshake information.
    ///
    /// Takes a function that reports the current time.  In theory, this can just be
    /// `SystemTime::now()`.
    #[instrument(skip_all, level = "trace")]
    pub async fn connect<F>(mut self, now_fn: F) -> Result<UnverifiedClientChannel<T, S>>
    where
        F: FnOnce() -> SystemTime,
    {
        match &self.target_method {
            Some(method) => debug!(
                stream_id = %self.unique_id,
                "starting Tor handshake with {:?}",
                method
            ),
            None => debug!(stream_id = %self.unique_id, "starting Tor handshake"),
        }
        // Send versions cell.
        let (versions_flushed_at, versions_flushed_wallclock) =
            self.send_versions_cell(now_fn).await?;

        // Receive versions cell.
        let link_protocol = self.recv_versions_cell().await?;

        // Receive the relay responder cells. Ignore the AUTH_CHALLENGE cell, we don't need it as
        // we are not authenticating with our responder because we are a client.
        let (_, certs_cell, (netinfo_cell, netinfo_rcvd_at)) =
            self.recv_cells_from_responder().await?;

        // Get the clock skew.
        let clock_skew = unauthenticated_clock_skew(
            &netinfo_cell,
            netinfo_rcvd_at,
            versions_flushed_at,
            versions_flushed_wallclock,
        );

        trace!(stream_id = %self.unique_id, "received handshake, ready to verify.");

        Ok(UnverifiedClientChannel {
            inner: UnverifiedChannel {
                channel_type: ChannelType::ClientInitiator,
                link_protocol,
                framed_tls: self.framed_tls,
                certs_cell,
                clock_skew,
                target_method: self.target_method.take(),
                unique_id: self.unique_id,
                sleep_prov: self.sleep_prov.clone(),
                memquota: self.memquota.clone(),
            },
        })
    }
}

/// A client channel on which versions have been negotiated and the relay's handshake has been
/// read, but where the certs have not been checked.
pub struct UnverifiedClientChannel<
    T: AsyncRead + AsyncWrite + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
> {
    /// Inner generic unverified channel.
    inner: UnverifiedChannel<T, S>,
}

impl<
    T: AsyncRead + AsyncWrite + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
> UnverifiedClientChannel<T, S>
{
    /// Return the reported clock skew from this handshake.
    ///
    /// Note that the skew reported by this function might not be "true": the
    /// relay might have its clock set wrong, or it might be lying to us.
    ///
    /// The clock skew reported here is not yet authenticated; if you need to
    /// make sure that the skew is authenticated, use
    /// [`Channel::clock_skew`](crate::channel::Channel::clock_skew) instead.
    pub fn clock_skew(&self) -> ClockSkew {
        self.inner.clock_skew
    }

    /// Validate the certificates and keys in the relay's handshake.
    ///
    /// 'peer' is the peer that we want to make sure we're connecting to.
    ///
    /// 'peer_cert' is the x.509 certificate that the peer presented during
    /// its TLS handshake (ServerHello).
    ///
    /// 'now' is the time at which to check that certificates are
    /// valid.  `None` means to use the current time. It can be used
    /// for testing to override the current view of the time.
    ///
    /// This is a separate function because it's likely to be somewhat
    /// CPU-intensive.
    #[instrument(skip_all, level = "trace")]
    pub fn check<U: ChanTarget + ?Sized>(
        self,
        peer: &U,
        peer_cert: &[u8],
        now: Option<std::time::SystemTime>,
    ) -> Result<VerifiedClientChannel<T, S>> {
        let inner = self.inner.check(peer, peer_cert, now)?;
        Ok(VerifiedClientChannel { inner })
    }

    /// Return the link protocol version of this channel.
    #[cfg(test)]
    pub(crate) fn link_protocol(&self) -> u16 {
        self.inner.link_protocol
    }
}

/// A client channel on which versions have been negotiated, relay's handshake has been read, but
/// the client has not yet finished the handshake.
///
/// This type is separate from UnverifiedClientChannel, since finishing the handshake requires a
/// bunch of CPU, and you might want to do it as a separate task or after a yield.
pub struct VerifiedClientChannel<
    T: AsyncRead + AsyncWrite + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
> {
    /// Inner generic verified channel.
    inner: VerifiedChannel<T, S>,
}

impl<
    T: AsyncRead + AsyncWrite + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
> VerifiedClientChannel<T, S>
{
    /// Send a 'Netinfo' message to the relay to finish the handshake, and create an open channel
    /// and reactor.
    ///
    /// The channel is used to send cells, and to create outgoing circuits. The reactor is used to
    /// route incoming messages to their appropriate circuit.
    #[instrument(skip_all, level = "trace")]
    pub async fn finish(mut self) -> Result<(Arc<Channel>, Reactor<S>)> {
        // Send the NETINFO message.
        let peer_ip = self
            .inner
            .target_method
            .as_ref()
            .and_then(ChannelMethod::socket_addrs)
            .and_then(|addrs| addrs.first())
            .map(SocketAddr::ip);
        let netinfo = msg::Netinfo::from_client(peer_ip);
        trace!(stream_id = %self.inner.unique_id, "Sending netinfo cell.");
        self.inner.framed_tls.send(netinfo.into()).await?;

        // Finish the channel to get a reactor.
        self.inner.finish().await
    }
}
