//! Relay initiator channel.
//!
//! Code only related to a relay channel opened as an initiator. The handshake code is responsible
//! for creating an [`UnverifiedInitiatorRelayChannel`] when connecting to another relay in order
//! to build a tor channel.
//!
//! The [`UnverifiedInitiatorRelayChannel::verify`] function needs to be called to verify the
//! underlying channel and build a [`VerifiedInitiatorRelayChannel`] channel which needs to be
//! finished with [`VerifiedInitiatorRelayChannel::finish`] to get a Channel/Reactor.
//!
//! Note that channel cells are sent in the handshake upon connection. And then in the finish()
//! process. The verify can be CPU intensive and thus in its own function.

use futures::{AsyncRead, AsyncWrite, SinkExt};
use std::{net::IpAddr, ops::Deref, sync::Arc};
use tracing::trace;

use tor_cell::chancell::msg;
use tor_error::internal;
use tor_linkspec::{ChannelMethod, OwnedChanTarget};
use tor_rtcompat::{CertifiedConn, CoarseTimeProvider, SleepProvider, StreamOps};

use crate::{
    ClockSkew, Error, RelayIdentities, Result,
    channel::{
        Channel, ChannelType, Reactor,
        handshake::{UnverifiedChannel, VerifiedChannel},
    },
    relay::channel::ChannelAuthenticationData,
};

/// An unverified relay initiator channel.
///
/// This is built by the [`crate::relay::channel::handshake::RelayInitiatorHandshake`] upon a
/// connect. It has everything needed to verify in order to get a verified channel.
pub struct UnverifiedInitiatorRelayChannel<
    T: AsyncRead + AsyncWrite + CertifiedConn + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
> {
    /// The common unverified channel that both client and relays use.
    pub(crate) inner: UnverifiedChannel<T, S>,
    /// AUTH_CHALLENGE cell received from the responder.
    pub(crate) auth_challenge_cell: msg::AuthChallenge,
    /// The netinfo cell received from the responder.
    pub(crate) netinfo_cell: msg::Netinfo,
    /// Our identity keys needed for authentication.
    pub(crate) identities: Arc<RelayIdentities>,
    /// Our advertised IP addresses for the final NETINFO
    pub(crate) my_addrs: Vec<IpAddr>,
}

impl<T, S> UnverifiedInitiatorRelayChannel<T, S>
where
    T: AsyncRead + AsyncWrite + CertifiedConn + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
{
    /// Validate the certificates and keys in the relay's handshake. As an initiator, we always
    /// authenticate no matter what.
    ///
    /// 'peer' is the peer that we want to make sure we're connecting to.
    ///
    /// 'peer_cert' is the x.509 certificate that the peer presented during its TLS handshake
    /// (ServerHello).
    ///
    /// 'now' is the time at which to check that certificates are valid.  `None` means to use the
    /// current time. It can be used for testing to override the current view of the time.
    ///
    /// This is a separate function because it's likely to be somewhat CPU-intensive.
    pub fn verify(
        self,
        peer: &OwnedChanTarget,
        peer_cert: &[u8],
        now: Option<std::time::SystemTime>,
    ) -> Result<VerifiedInitiatorRelayChannel<T, S>> {
        // Get these object out as we consume "self" in the inner check().
        let auth_challenge_cell = self.auth_challenge_cell;
        let identities = self.identities;
        let my_addrs = self.my_addrs;
        let netinfo_cell = self.netinfo_cell;

        // Verify our inner channel and then proceed to handle the authentication challenge if any.
        let mut verified = self.inner.check(peer, peer_cert, now)?;

        // By building the ChannelAuthenticationData, we are certain that the authentication
        // type requested by the responder is supported by us.
        let auth_cell = ChannelAuthenticationData::build(
            Some(&auth_challenge_cell),
            &identities,
            &mut verified,
            None,
        )?
        .into_authenticate(verified.framed_tls.deref(), &identities.link_sign_kp)?;

        // This part is very important as we now flag that we are authenticated. The responder
        // checks the received AUTHENTICATE and the initiator just needs to verify the channel.
        //
        // At this point, the underlying cell handler is in the Handshake state. Setting the
        // channel type here as authenticated means that once the handler transition to the Open
        // state, it will carry this authenticated flag leading to the message filter of the
        // channel codec to adapt its restricted message sets (meaning R2R only).
        //
        // After this call, it is considered a R2R channel.
        verified.set_authenticated()?;

        Ok(VerifiedInitiatorRelayChannel {
            inner: verified,
            identities,
            netinfo_cell,
            auth_cell,
            my_addrs,
        })
    }

    /// Return the clock skew of this channel.
    pub fn clock_skew(&self) -> ClockSkew {
        self.inner.clock_skew
    }
}

/// A verified relay initiator channel.
///
/// Holding this object means the channel TLS layer has been verified against the received CERTS
/// cell and we now believe that we are talking to the right relay end point.
///
/// The finish() function needs to be called in order to finalize this channel into a generic
/// Channel/Reactor.
pub struct VerifiedInitiatorRelayChannel<
    T: AsyncRead + AsyncWrite + CertifiedConn + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
> {
    /// The common unverified channel that both client and relays use.
    inner: VerifiedChannel<T, S>,
    /// Relay identities.
    identities: Arc<RelayIdentities>,
    /// The netinfo cell that we got from the relay.
    netinfo_cell: msg::Netinfo,
    /// The AUTHENTICATE cell built during verification process.
    auth_cell: msg::Authenticate,
    /// Our advertised IP addresses.
    my_addrs: Vec<IpAddr>,
}

impl<T, S> VerifiedInitiatorRelayChannel<T, S>
where
    T: AsyncRead + AsyncWrite + CertifiedConn + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
{
    /// Send our [`msg::Certs`], [`msg::Authenticate`] and [`msg::Netinfo`] to the relay to finish
    /// the handshake, which will create an open channel and reactor.
    ///
    /// The resulting channel is considered, by Tor protocol standard, an authenticated relay
    /// channel on which circuits can be opened.
    pub async fn finish(mut self) -> Result<(Arc<Channel>, Reactor<S>)> {
        // Send CERTS, AUTHENTICATE, NETINFO
        let certs = super::build_certs_cell(&self.identities, ChannelType::RelayInitiator);
        trace!(channel_id = %self.inner.unique_id, "Sending CERTS as initiator cell.");
        self.inner.framed_tls.send(certs.into()).await?;
        trace!(channel_id = %self.inner.unique_id, "Sending AUTHENTICATE as initiator cell.");
        self.inner.framed_tls.send(self.auth_cell.into()).await?;

        let peer_ip = self
            .inner
            .target_method
            .as_ref()
            .and_then(ChannelMethod::unique_direct_addr)
            .ok_or(Error::from(internal!("Target method address invalid")))?
            .ip();
        // Send our NETINFO cell. This will indicate the end of the handshake.
        let netinfo =
            super::build_netinfo_cell(peer_ip, self.my_addrs.clone(), &self.inner.sleep_prov)?;
        trace!(channel_id = %self.inner.unique_id, "Sending NETINFO as initiator cell.");
        self.inner.framed_tls.send(netinfo.into()).await?;

        // Get a Channel and a Reactor.
        self.inner
            .finish(&self.netinfo_cell, &self.my_addrs, peer_ip)
            .await
    }
}
