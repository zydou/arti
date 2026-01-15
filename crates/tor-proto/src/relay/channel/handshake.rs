//! Implementations for the relay channel handshake

use futures::SinkExt;
use futures::io::{AsyncRead, AsyncWrite};
use futures::stream::StreamExt;
use rand::Rng;
use std::net::IpAddr;
use std::{sync::Arc, time::SystemTime};
use tracing::trace;

use safelog::Sensitive;
use tor_cell::chancell::{
    ChanMsg,
    msg::{self},
};
use tor_error::internal;
use tor_linkspec::ChannelMethod;
use tor_rtcompat::{CertifiedConn, CoarseTimeProvider, SleepProvider, StreamOps};

use crate::channel::handshake::{
    ChannelBaseHandshake, ChannelInitiatorHandshake, UnverifiedChannel, unauthenticated_clock_skew,
};
use crate::channel::{ChannelFrame, ChannelType, UniqId, VerifiableChannel, new_frame};
use crate::memquota::ChannelAccount;
use crate::relay::channel::{
    RelayIdentities, UnverifiedRelayChannel, build_certs_cell, build_netinfo_cell,
};
use crate::{Error, Result};

/// The "Ed25519-SHA256-RFC5705" link authentication which is value "00 03".
static AUTHTYPE_ED25519_SHA256_RFC5705: u16 = 3;

/// A relay channel handshake as the initiator.
pub struct RelayInitiatorHandshake<
    T: AsyncRead + AsyncWrite + CertifiedConn + StreamOps + Send + Unpin + 'static,
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
    /// Our advertised addresses. Needed for the NETINFO.
    my_addrs: Vec<IpAddr>,
}

/// Implement the base channel handshake trait.
impl<T, S> ChannelBaseHandshake<T> for RelayInitiatorHandshake<T, S>
where
    T: AsyncRead + AsyncWrite + CertifiedConn + StreamOps + Send + Unpin + 'static,
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
    T: AsyncRead + AsyncWrite + CertifiedConn + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
{
    fn is_expecting_auth_challenge(&self) -> bool {
        // Relay always authenticate and thus expect a AUTH_CHALLENGE.
        true
    }
}

impl<
    T: AsyncRead + AsyncWrite + CertifiedConn + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
> RelayInitiatorHandshake<T, S>
{
    /// Constructor.
    pub(crate) fn new(
        tls: T,
        sleep_prov: S,
        identities: Arc<RelayIdentities>,
        my_addrs: Vec<IpAddr>,
        memquota: ChannelAccount,
    ) -> Self {
        Self {
            framed_tls: new_frame(tls, ChannelType::RelayInitiator),
            unique_id: UniqId::new(),
            sleep_prov,
            identities,
            memquota,
            my_addrs,
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
                certs_cell: Some(certs_cell),
            },
            auth_cell: auth_challenge_cell.map(super::AuthenticationCell::AuthChallenge),
            netinfo_cell,
            identities: self.identities,
            my_addrs: self.my_addrs,
        }))
    }
}

/// A relay channel handshake as the responder.
pub struct RelayResponderHandshake<
    T: AsyncRead + AsyncWrite + CertifiedConn + StreamOps + Send + Unpin + 'static,
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
    /// The peer IP address as in the address the initiator is connecting from.
    peer: Sensitive<std::net::SocketAddr>,
    /// Our advertised addresses. Needed for the NETINFO.
    my_addrs: Vec<IpAddr>,
    /// Logging identifier for this stream.  (Used for logging only.)
    unique_id: UniqId,
    /// Our identity keys needed for authentication.
    identities: Arc<RelayIdentities>,
}

/// Implement the base channel handshake trait.
impl<T, S> ChannelBaseHandshake<T> for RelayResponderHandshake<T, S>
where
    T: AsyncRead + AsyncWrite + CertifiedConn + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
{
    fn framed_tls(&mut self) -> &mut ChannelFrame<T> {
        &mut self.framed_tls
    }
    fn unique_id(&self) -> &UniqId {
        &self.unique_id
    }
}

impl<
    T: AsyncRead + AsyncWrite + CertifiedConn + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
> RelayResponderHandshake<T, S>
{
    /// Constructor.
    pub(crate) fn new(
        peer: Sensitive<std::net::SocketAddr>,
        my_addrs: Vec<IpAddr>,
        tls: T,
        sleep_prov: S,
        identities: Arc<RelayIdentities>,
        memquota: ChannelAccount,
    ) -> Self {
        Self {
            peer,
            my_addrs,
            framed_tls: new_frame(
                tls,
                ChannelType::RelayResponder {
                    authenticated: false,
                },
            ),
            unique_id: UniqId::new(),
            sleep_prov,
            identities,
            memquota,
        }
    }

    /// Begin the handshake process.
    ///
    /// Takes a function that reports the current time.  In theory, this can just be
    /// `SystemTime::now()`.
    pub async fn handshake<F>(mut self, now_fn: F) -> Result<Box<dyn VerifiableChannel<T, S>>>
    where
        F: FnOnce() -> SystemTime,
    {
        // Receive initiator VERSIONS.
        let link_protocol = self.recv_versions_cell().await?;

        // Send VERSION, CERTS, AUTH_CHALLENGE and NETINFO
        let (versions_flushed_at, versions_flushed_wallclock) =
            self.send_cells_to_initiator(now_fn).await?;

        // Receive NETINFO and possibly [CERTS, AUTHENTICATE]. The connection could be from a
        // client/bridge and thus no authentication meaning no CERTS/AUTHENTICATE cells.
        let (auth_cell, certs_cell, (netinfo_cell, netinfo_rcvd_at)) =
            self.recv_cells_from_initiator().await?;

        // Calculate our clock skew from the timings we just got/calculated.
        let clock_skew = unauthenticated_clock_skew(
            &netinfo_cell,
            netinfo_rcvd_at,
            versions_flushed_at,
            versions_flushed_wallclock,
        );

        Ok(Box::new(UnverifiedRelayChannel {
            inner: UnverifiedChannel {
                channel_type: ChannelType::RelayResponder {
                    authenticated: false,
                },
                link_protocol,
                framed_tls: self.framed_tls,
                clock_skew,
                memquota: self.memquota,
                target_method: Some(ChannelMethod::Direct(vec![self.peer.into_inner()])),
                unique_id: self.unique_id,
                sleep_prov: self.sleep_prov,
                certs_cell,
            },
            auth_cell: auth_cell.map(super::AuthenticationCell::Authenticate),
            netinfo_cell,
            identities: self.identities,
            my_addrs: self.my_addrs,
        }))
    }

    /// Receive all the cells expected from the initiator of the connection. Keep in mind that it
    /// can be either a relay or client or bridge.
    async fn recv_cells_from_initiator(
        &mut self,
    ) -> Result<(
        Option<msg::Authenticate>,
        Option<msg::Certs>,
        (msg::Netinfo, coarsetime::Instant),
    )> {
        let mut auth_cell: Option<msg::Authenticate> = None;
        let mut certs_cell: Option<msg::Certs> = None;
        let mut netinfo_cell: Option<(msg::Netinfo, coarsetime::Instant)> = None;

        // IMPORTANT: Protocol wise, we MUST only allow one single cell of each type for a valid
        // handshake. Any duplicates lead to a failure. They can arrive in any order unfortunately
        // and the NETINFO indicates the end of the handshake.

        // Read until we have the netinfo cell.
        while let Some(cell) = self.framed_tls().next().await.transpose()? {
            use tor_cell::chancell::msg::AnyChanMsg::*;
            let (_, m) = cell.into_circid_and_msg();
            trace!(stream_id = %self.unique_id(), "received a {} cell.", m.cmd());
            match m {
                // Ignore the padding. Only VPADDING cell can be sent during handshaking.
                Vpadding(_) => (),
                // Clients don't care about AuthChallenge
                Authenticate(a) => {
                    if auth_cell.replace(a).is_some() {
                        return Err(Error::HandshakeProto("Duplicate AUTHENTICATE cell".into()));
                    }
                }
                Certs(c) => {
                    if certs_cell.replace(c).is_some() {
                        return Err(Error::HandshakeProto("Duplicate CERTS cell".into()));
                    }
                }
                Netinfo(n) => {
                    if netinfo_cell.is_some() {
                        // This should be impossible, since we would
                        // exit this loop on the first netinfo cell.
                        return Err(Error::from(internal!(
                            "Somehow tried to record a duplicate NETINFO cell"
                        )));
                    }
                    netinfo_cell = Some((n, coarsetime::Instant::now()));
                    break;
                }
                // This should not happen because the ChannelFrame makes sure that only allowed cell on
                // the channel are decoded. However, Rust wants us to consider all AnyChanMsg.
                _ => {
                    return Err(Error::from(internal!(
                        "Unexpected cell during initiator handshake: {m:?}"
                    )));
                }
            }
        }

        // NETINFO is mandatory regardless of who connects.
        let Some((netinfo, netinfo_rcvd_at)) = netinfo_cell else {
            return Err(Error::HandshakeProto("Missing NETINFO cell".into()));
        };

        Ok((auth_cell, certs_cell, (netinfo, netinfo_rcvd_at)))
    }

    /// Send all expected cells to the initiator of the channel as the responder.
    ///
    /// Return the sending times of the [`msg::Versions`] so it can be used for clock skew
    /// validation.
    async fn send_cells_to_initiator<F>(
        &mut self,
        now_fn: F,
    ) -> Result<(coarsetime::Instant, SystemTime)>
    where
        F: FnOnce() -> SystemTime,
    {
        // Send the VERSIONS message.
        let (versions_flushed_at, versions_flushed_wallclock) =
            self.send_versions_cell(now_fn).await?;

        // Send the CERTS message.
        let certs = build_certs_cell(
            &self.identities,
            ChannelType::RelayResponder {
                authenticated: false,
            },
        );
        trace!(channel_id = %self.unique_id, "Sending CERTS as responder cell.");
        self.framed_tls.send(certs.into()).await?;

        // Send the AUTH_CHALLENGE.
        let challenge: [u8; 32] = rand::rng().random();
        let auth_challenge = msg::AuthChallenge::new(challenge, [AUTHTYPE_ED25519_SHA256_RFC5705]);
        trace!(channel_id = %self.unique_id, "Sending AUTH_CHALLENGE as responder cell.");
        self.framed_tls.send(auth_challenge.into()).await?;

        // Send the NETINFO message.
        let peer_ip = self.peer.into_inner().ip();
        let netinfo = build_netinfo_cell(Some(peer_ip), self.my_addrs.clone(), &self.sleep_prov)?;
        trace!(channel_id = %self.unique_id, "Sending NETINFO as responder cell.");
        self.framed_tls.send(netinfo.into()).await?;

        Ok((versions_flushed_at, versions_flushed_wallclock))
    }
}
