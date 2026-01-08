//! Implementations for the client channel handshake

use async_trait::async_trait;
use futures::SinkExt;
use futures::io::{AsyncRead, AsyncWrite};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;
use tor_cell::chancell::msg;
use tracing::{debug, instrument, trace};

use tor_linkspec::{ChannelMethod, OwnedChanTarget};
use tor_rtcompat::{CoarseTimeProvider, SleepProvider, StreamOps};

use crate::channel::handshake::{
    ChannelBaseHandshake, ChannelInitiatorHandshake, UnverifiedChannel, VerifiedChannel,
    unauthenticated_clock_skew,
};
use crate::channel::{
    Channel, ChannelFrame, ChannelType, FinalizableChannel, Reactor, UniqId, VerifiableChannel,
    new_frame,
};
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
    pub async fn connect<F>(mut self, now_fn: F) -> Result<Box<dyn VerifiableChannel<T, S>>>
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

        Ok(Box::new(UnverifiedClientChannel {
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
        }))
    }
}

/// A client channel on which versions have been negotiated and the relay's handshake has been
/// read, but where the certs have not been checked.
struct UnverifiedClientChannel<
    T: AsyncRead + AsyncWrite + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
> {
    /// Inner generic unverified channel.
    inner: UnverifiedChannel<T, S>,
}

impl<
    T: AsyncRead + AsyncWrite + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
> VerifiableChannel<T, S> for UnverifiedClientChannel<T, S>
{
    fn clock_skew(&self) -> ClockSkew {
        self.inner.clock_skew
    }

    #[instrument(skip_all, level = "trace")]
    fn check(
        self: Box<Self>,
        peer: &OwnedChanTarget,
        peer_cert: &[u8],
        now: Option<std::time::SystemTime>,
    ) -> Result<Box<dyn FinalizableChannel<T, S>>> {
        let inner = self.inner.check(peer, peer_cert, now)?;
        Ok(Box::new(VerifiedClientChannel { inner }))
    }

    /// Return the link protocol version of this channel.
    #[cfg(test)]
    fn link_protocol(&self) -> u16 {
        self.inner.link_protocol
    }
}

impl<T, S> crate::channel::seal::Sealed for UnverifiedClientChannel<T, S>
where
    T: AsyncRead + AsyncWrite + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
{
}

/// A client channel on which versions have been negotiated, relay's handshake has been read, but
/// the client has not yet finished the handshake.
///
/// This type is separate from UnverifiedClientChannel, since finishing the handshake requires a
/// bunch of CPU, and you might want to do it as a separate task or after a yield.
struct VerifiedClientChannel<
    T: AsyncRead + AsyncWrite + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
> {
    /// Inner generic verified channel.
    inner: VerifiedChannel<T, S>,
}

#[async_trait]
impl<
    T: AsyncRead + AsyncWrite + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
> FinalizableChannel<T, S> for VerifiedClientChannel<T, S>
{
    #[instrument(skip_all, level = "trace")]
    async fn finish(mut self: Box<Self>) -> Result<(Arc<Channel>, Reactor<S>)> {
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

impl<T, S> crate::channel::seal::Sealed for VerifiedClientChannel<T, S>
where
    T: AsyncRead + AsyncWrite + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
{
}
