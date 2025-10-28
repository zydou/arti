//! Implementations for the client channel handshake

use futures::io::{AsyncRead, AsyncWrite};
use std::time::SystemTime;
use tracing::{debug, instrument, trace};

use tor_linkspec::ChannelMethod;
use tor_rtcompat::{CoarseTimeProvider, SleepProvider, StreamOps};

use crate::Result;
use crate::channel::handshake::{
    ChannelBaseHandshake, ChannelInitiatorHandshake, UnverifiedChannel, unauthenticated_clock_skew,
};
use crate::channel::{ChannelFrame, ChannelType, UniqId, new_frame};
use crate::memquota::ChannelAccount;

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
    /// Construct a new OutboundClientHandshake.
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
    pub async fn connect<F>(mut self, now_fn: F) -> Result<UnverifiedChannel<T, S>>
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

        Ok(UnverifiedChannel {
            channel_type: ChannelType::ClientInitiator,
            link_protocol,
            framed_tls: self.framed_tls,
            certs_cell,
            clock_skew,
            target_method: self.target_method.take(),
            unique_id: self.unique_id,
            sleep_prov: self.sleep_prov.clone(),
            memquota: self.memquota.clone(),
        })
    }
}
