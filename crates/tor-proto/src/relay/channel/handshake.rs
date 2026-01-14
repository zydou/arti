//! Implementations for the relay channel handshake

use futures::io::{AsyncRead, AsyncWrite};
use std::{sync::Arc, time::SystemTime};
use tracing::trace;

use tor_rtcompat::{CoarseTimeProvider, SleepProvider, StreamOps};

use crate::Result;
use crate::channel::handshake::{
    ChannelBaseHandshake, ChannelInitiatorHandshake, UnverifiedChannel, unauthenticated_clock_skew,
};
use crate::channel::{ChannelFrame, ChannelType, UniqId, VerifiableChannel, new_frame};
use crate::memquota::ChannelAccount;
use crate::relay::channel::{RelayIdentities, UnverifiedRelayChannel};

/// A relay channel handshake as the initiator.
pub struct RelayInitiatorHandshake<
    T: AsyncRead + AsyncWrite + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
> {
    /// Runtime handle (insofar as we need it)
    sleep_prov: S,
    /// Memory quota account
    memquota: ChannelAccount,
    /// Underlying TLS stream in a channel frame.
    ///
    /// (We don't enforce that this is actually TLS, but if it isn't, the
    /// connection won't be secure.)
    framed_tls: ChannelFrame<T>,
    /// Logging identifier for this stream.  (Used for logging only.)
    unique_id: UniqId,
    /// Our identity keys needed for authentication.
    identities: Arc<RelayIdentities>,
}

/// Implement the base channel handshake trait.
impl<T, S> ChannelBaseHandshake<T> for RelayInitiatorHandshake<T, S>
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
impl<T, S> ChannelInitiatorHandshake<T> for RelayInitiatorHandshake<T, S>
where
    T: AsyncRead + AsyncWrite + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
{
    fn is_expecting_auth_challenge(&self) -> bool {
        // Relay always authenticate and thus expect a AUTH_CHALLENGE.
        true
    }
}

impl<
    T: AsyncRead + AsyncWrite + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
> RelayInitiatorHandshake<T, S>
{
    /// Constructor.
    pub(crate) fn new(
        tls: T,
        sleep_prov: S,
        identities: Arc<RelayIdentities>,
        memquota: ChannelAccount,
    ) -> Self {
        Self {
            framed_tls: new_frame(tls, ChannelType::RelayInitiator),
            unique_id: UniqId::new(),
            sleep_prov,
            identities,
            memquota,
        }
    }

    /// Connect to another relay as the relay Initiator.
    ///
    /// Takes a function that reports the current time.  In theory, this can just be
    /// `SystemTime::now()`.
    pub async fn connect<F>(mut self, now_fn: F) -> Result<Box<dyn VerifiableChannel<T, S>>>
    where
        F: FnOnce() -> SystemTime,
    {
        // Send the VERSIONS.
        let (versions_flushed_at, versions_flushed_wallclock) =
            self.send_versions_cell(now_fn).await?;

        // Receive the VERSIONS.
        let link_protocol = self.recv_versions_cell().await?;

        // Read until we have all the remaining cells from the responder.
        let (auth_challenge_cell, certs_cell, (netinfo_cell, netinfo_rcvd_at)) =
            self.recv_cells_from_responder().await?;

        trace!(stream_id = %self.unique_id,
            "received handshake, ready to verify.",
        );

        // Calculate our clock skew from the timings we just got/calculated.
        let clock_skew = unauthenticated_clock_skew(
            &netinfo_cell,
            netinfo_rcvd_at,
            versions_flushed_at,
            versions_flushed_wallclock,
        );

        Ok(Box::new(UnverifiedRelayChannel {
            inner: UnverifiedChannel {
                channel_type: ChannelType::RelayInitiator,
                link_protocol,
                framed_tls: self.framed_tls,
                clock_skew,
                memquota: self.memquota,
                target_method: None, // TODO(relay): We might use it for NETINFO canonicity.
                unique_id: self.unique_id,
                sleep_prov: self.sleep_prov.clone(),
                certs_cell,
            },
            auth_challenge_cell,
            netinfo_cell,
            identities: self.identities,
        }))
    }
}
