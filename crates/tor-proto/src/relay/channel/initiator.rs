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

use digest::Digest;
use futures::{AsyncRead, AsyncWrite, SinkExt};
use safelog::MaybeSensitive;
use std::{net::IpAddr, ops::Deref, sync::Arc};
use tracing::trace;

use tor_cell::chancell::msg;
use tor_linkspec::OwnedChanTarget;
use tor_rtcompat::{CertifiedConn, CoarseTimeProvider, Runtime, SleepProvider, StreamOps};

use crate::{
    ClockSkew, RelayChannelAuthMaterial, Result,
    channel::{
        AuthLogDigest, Channel, Reactor,
        handshake::{UnverifiedInitiatorChannel, VerifiedChannel},
    },
    peer::{PeerAddr, PeerInfo},
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
    pub(crate) inner: UnverifiedInitiatorChannel<T, S>,
    /// AUTH_CHALLENGE cell received from the responder.
    pub(crate) auth_challenge_cell: msg::AuthChallenge,
    /// The SLOG digest.
    pub(crate) slog_digest: AuthLogDigest,
    /// The netinfo cell received from the responder.
    pub(crate) netinfo_cell: msg::Netinfo,
    /// Our channel key material needed for authentication.
    pub(crate) auth_material: Arc<RelayChannelAuthMaterial>,
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
    /// 'peer_target' is the peer that we want to make sure we're connecting to.
    ///
    /// 'peer_tls_cert' is the x.509 certificate that the peer presented during its TLS handshake
    /// (ServerHello).
    ///
    /// 'now' is the time at which to check that certificates are valid.  `None` means to use the
    /// current time. It can be used for testing to override the current view of the time.
    ///
    /// This is a separate function because it's likely to be somewhat CPU-intensive.
    pub fn verify(
        self,
        peer_target: &OwnedChanTarget,
        peer_tls_cert: &[u8],
        now: Option<std::time::SystemTime>,
    ) -> Result<VerifiedInitiatorRelayChannel<T, S>> {
        // Get these object out as we consume "self" in the inner check().
        let auth_challenge_cell = self.auth_challenge_cell;
        let identities = self.auth_material;
        let my_addrs = self.my_addrs;
        let netinfo_cell = self.netinfo_cell;

        let peer_tls_cert_digest = tor_llcrypto::d::Sha256::digest(peer_tls_cert).into();

        // Verify our inner channel and then proceed to handle the authentication challenge if any.
        let verified = self.inner.verify(peer_target, peer_tls_cert_digest, now)?;

        Ok(VerifiedInitiatorRelayChannel {
            inner: verified,
            auth_material: identities,
            netinfo_cell,
            auth_challenge_cell,
            peer_tls_cert_digest,
            slog_digest: self.slog_digest,
            my_addrs,
        })
    }

    /// Return the clock skew of this channel.
    pub fn clock_skew(&self) -> ClockSkew {
        self.inner.inner.clock_skew
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
    /// Relay channel authentication material.
    auth_material: Arc<RelayChannelAuthMaterial>,
    /// The netinfo cell that we got from the relay.
    netinfo_cell: msg::Netinfo,
    /// The AUTH_CHALLENGE cell that we got from the relay.
    auth_challenge_cell: msg::AuthChallenge,
    /// The peer TLS certificate digest.
    peer_tls_cert_digest: [u8; 32],
    /// The SLOG digest.
    slog_digest: AuthLogDigest,
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
    pub async fn finish(mut self, peer_addr: PeerAddr) -> Result<(Arc<Channel>, Reactor<S>)>
    where
        S: Runtime,
    {
        // Send the CERTS cell.
        let certs = super::build_certs_cell(&self.auth_material, /* is_responder */ false);
        trace!(channel_id = %self.inner.unique_id, "Sending CERTS as initiator cell.");
        self.inner.framed_tls.send(certs.into()).await?;

        // We're the initiator, which means that the send log is the CLOG.
        //
        // We can finalize the CLOG now that we're about to send the AUTHENTICATE cell.
        //
        // > The CLOG field is computed as the SHA-256 digest of all bytes sent within
        // > the TLS channel up to but not including the AUTHENTICATE cell.
        let clog_digest = self.inner.framed_tls.codec_mut().take_send_log_digest()?;

        // Build the AUTHENTICATE cell.
        //
        // By building the ChannelAuthenticationData, we are certain that the authentication
        // type requested by the responder is supported by us.
        let auth_cell = ChannelAuthenticationData::build_initiator(
            &self.auth_challenge_cell,
            &self.auth_material,
            clog_digest,
            self.slog_digest,
            &mut self.inner,
            self.peer_tls_cert_digest,
        )?
        .into_authenticate(
            self.inner.framed_tls.deref(),
            &self.auth_material.link_sign_kp,
        )?;

        // Send the AUTHENTICATE cell.
        trace!(channel_id = %self.inner.unique_id, "Sending AUTHENTICATE as initiator cell.");
        self.inner.framed_tls.send(auth_cell.into()).await?;

        // Send our NETINFO cell. This will indicate the end of the handshake.
        let netinfo = super::build_netinfo_cell(
            peer_addr.netinfo_addr(),
            self.my_addrs.clone(),
            &self.inner.sleep_prov,
        )?;
        trace!(channel_id = %self.inner.unique_id, "Sending NETINFO as initiator cell.");
        self.inner.framed_tls.send(netinfo.into()).await?;

        // Relay only initiate to another relay so NOT sensitive.
        let peer_info =
            MaybeSensitive::not_sensitive(PeerInfo::new(peer_addr, self.inner.relay_ids().clone()));

        // Get a Channel and a Reactor.
        self.inner
            .finish(&self.netinfo_cell, &self.my_addrs, peer_info)
            .await
    }
}
