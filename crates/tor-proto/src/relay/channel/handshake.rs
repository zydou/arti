//! Implementations for the relay channel handshake

use futures::SinkExt;
use futures::io::{AsyncRead, AsyncWrite};
use rand::Rng;
use safelog::Sensitive;
use std::net::{IpAddr, SocketAddr};
use std::{sync::Arc, time::SystemTime};
use tracing::trace;

use tor_cell::chancell::msg;
use tor_cell::restrict::restricted_msg;
use tor_error::internal;
use tor_linkspec::{ChannelMethod, HasChanMethod, OwnedChanTarget};
use tor_rtcompat::{CertifiedConn, CoarseTimeProvider, SleepProvider, StreamOps};

use crate::Result;
use crate::channel::handshake::{
    AuthLogAction, ChannelBaseHandshake, ChannelInitiatorHandshake, UnverifiedChannel,
    UnverifiedInitiatorChannel, read_msg, unauthenticated_clock_skew,
};
use crate::channel::{ChannelFrame, ChannelType, ClogDigest, SlogDigest, UniqId, new_frame};
use crate::memquota::ChannelAccount;
use crate::peer::PeerAddr;
use crate::relay::CreateRequestHandler;
use crate::relay::channel::initiator::UnverifiedInitiatorRelayChannel;
use crate::relay::channel::responder::{
    MaybeVerifiableRelayResponderChannel, NonVerifiableResponderRelayChannel,
    UnverifiedResponderRelayChannel,
};
use crate::relay::channel::{RelayChannelAuthMaterial, build_certs_cell, build_netinfo_cell};

/// The "Ed25519-SHA256-RFC5705" link authentication which is value "00 03".
pub(super) static AUTHTYPE_ED25519_SHA256_RFC5705: u16 = 3;

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
    auth_material: Arc<RelayChannelAuthMaterial>,
    /// The peer we are attempting to connect to.
    target_method: ChannelMethod,
    /// Our advertised addresses. Needed for the NETINFO.
    my_addrs: Vec<IpAddr>,
    /// Provided to each new channel so that they can handle CREATE* requests.
    create_request_handler: Arc<CreateRequestHandler>,
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
        auth_material: Arc<RelayChannelAuthMaterial>,
        my_addrs: Vec<SocketAddr>,
        peer_target: &OwnedChanTarget,
        memquota: ChannelAccount,
        create_request_handler: Arc<CreateRequestHandler>,
    ) -> Self {
        Self {
            framed_tls: new_frame(tls, ChannelType::RelayInitiator),
            unique_id: UniqId::new(),
            sleep_prov,
            auth_material,
            memquota,
            my_addrs: my_addrs.into_iter().map(|a| a.ip()).collect(),
            target_method: peer_target.chan_method(),
            create_request_handler,
        }
    }

    /// Connect to another relay as the relay Initiator.
    ///
    /// Takes a function that reports the current time.  In theory, this can just be
    /// `SystemTime::get()`.
    pub async fn connect<F>(mut self, now_fn: F) -> Result<UnverifiedInitiatorRelayChannel<T, S>>
    where
        F: FnOnce() -> SystemTime,
    {
        // Send the VERSIONS.
        let (versions_flushed_at, versions_flushed_wallclock) =
            self.send_versions_cell(now_fn).await?;

        // Receive the VERSIONS.
        let link_protocol = self.recv_versions_cell().await?;

        // VERSIONS cell have been exchanged, set the link protocol into our channel frame.
        self.set_link_protocol(link_protocol)?;

        // Read until we have all the remaining cells from the responder.
        let (auth_challenge_cell, certs_cell, (netinfo_cell, netinfo_rcvd_at), slog_digest) =
            self.recv_cells_from_responder(AuthLogAction::Take).await?;

        // TODO: It would be nice to come up with a better design for getting the SLOG.
        let slog_digest = slog_digest.ok_or(internal!("Asked for SLOG, but `None` returned?"))?;

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

        Ok(UnverifiedInitiatorRelayChannel {
            inner: UnverifiedInitiatorChannel {
                inner: UnverifiedChannel {
                    link_protocol,
                    framed_tls: self.framed_tls,
                    clock_skew,
                    memquota: self.memquota,
                    target_method: Some(self.target_method),
                    unique_id: self.unique_id,
                    sleep_prov: self.sleep_prov.clone(),
                },
                certs_cell,
            },
            auth_challenge_cell,
            slog_digest,
            netinfo_cell,
            auth_material: self.auth_material,
            my_addrs: self.my_addrs,
            create_request_handler: self.create_request_handler,
        })
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
    /// The peer IP address as in the address the initiator is connecting from. This can be a
    /// client so keep it sensitive.
    peer_addr: Sensitive<PeerAddr>,
    /// Our advertised addresses. Needed for the NETINFO.
    my_addrs: Vec<IpAddr>,
    /// Logging identifier for this stream.  (Used for logging only.)
    unique_id: UniqId,
    /// Our identity keys needed for authentication.
    auth_material: Arc<RelayChannelAuthMaterial>,
    /// Provided to each new channel so that they can handle CREATE* requests.
    create_request_handler: Arc<CreateRequestHandler>,
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
        peer_addr: Sensitive<PeerAddr>,
        my_addrs: Vec<SocketAddr>,
        tls: T,
        sleep_prov: S,
        auth_material: Arc<RelayChannelAuthMaterial>,
        memquota: ChannelAccount,
        create_request_handler: Arc<CreateRequestHandler>,
    ) -> Self {
        Self {
            peer_addr,
            my_addrs: my_addrs.into_iter().map(|a| a.ip()).collect(),
            framed_tls: new_frame(
                tls,
                ChannelType::RelayResponder {
                    authenticated: false,
                },
            ),
            unique_id: UniqId::new(),
            sleep_prov,
            auth_material,
            memquota,
            create_request_handler,
        }
    }

    /// Begin the handshake process.
    ///
    /// Takes a function that reports the current time.  In theory, this can just be
    /// `SystemTime::get()`.
    pub async fn handshake<F>(
        mut self,
        now_fn: F,
    ) -> Result<MaybeVerifiableRelayResponderChannel<T, S>>
    where
        F: FnOnce() -> SystemTime,
    {
        // Receive initiator VERSIONS.
        let link_protocol = self.recv_versions_cell().await?;

        // Send the VERSIONS message.
        let (versions_flushed_at, versions_flushed_wallclock) =
            self.send_versions_cell(now_fn).await?;

        // VERSIONS cell have been exchanged, set the link protocol into our channel frame.
        self.set_link_protocol(link_protocol)?;

        // Send CERTS, AUTH_CHALLENGE and NETINFO
        let slog_digest = self.send_cells_to_initiator().await?;

        // Receive NETINFO and possibly [CERTS, AUTHENTICATE]. The connection could be from a
        // client/bridge and thus no authentication meaning no CERTS/AUTHENTICATE cells.
        let (certs_and_auth_and_clog, (netinfo_cell, netinfo_rcvd_at)) =
            self.recv_cells_from_initiator().await?;

        // Try to unpack these into something we can use later.
        let (certs_cell, auth_and_clog) = match certs_and_auth_and_clog {
            Some((certs, auth, clog)) => (Some(certs), Some((auth, clog))),
            None => (None, None),
        };

        // Calculate our clock skew from the timings we just got/calculated.
        let clock_skew = unauthenticated_clock_skew(
            &netinfo_cell,
            netinfo_rcvd_at,
            versions_flushed_at,
            versions_flushed_wallclock,
        );

        let inner = UnverifiedChannel {
            link_protocol,
            framed_tls: self.framed_tls,
            clock_skew,
            memquota: self.memquota,
            target_method: None,
            unique_id: self.unique_id,
            sleep_prov: self.sleep_prov,
        };

        // With an AUTHENTICATE cell, we can verify (relay). Else (client/bridge), we can't.
        Ok(match auth_and_clog {
            Some((auth_cell, clog_digest)) => {
                MaybeVerifiableRelayResponderChannel::Verifiable(UnverifiedResponderRelayChannel {
                    inner,
                    auth_cell,
                    netinfo_cell,
                    // TODO(relay): Should probably put that in the match {} and not assume.
                    certs_cell: certs_cell.expect("AUTHENTICATE cell without CERTS cell"),
                    auth_material: self.auth_material,
                    my_addrs: self.my_addrs,
                    peer_addr: self.peer_addr.into_inner(), // Relay address.
                    clog_digest,
                    slog_digest,
                    create_request_handler: self.create_request_handler,
                })
            }
            None => MaybeVerifiableRelayResponderChannel::NonVerifiable(
                NonVerifiableResponderRelayChannel {
                    inner,
                    netinfo_cell,
                    my_addrs: self.my_addrs,
                    peer_addr: self.peer_addr,
                    create_request_handler: self.create_request_handler,
                    our_ed25519_id: self.auth_material.ed_id,
                    our_rsa_id: self.auth_material.rsa_id,
                },
            ),
        })
    }

    /// Receive all the cells expected from the initiator of the connection. Keep in mind that it
    /// can be either a relay or client or bridge.
    async fn recv_cells_from_initiator(
        &mut self,
    ) -> Result<(
        Option<(msg::Certs, msg::Authenticate, ClogDigest)>,
        (msg::Netinfo, coarsetime::Instant),
    )> {
        // IMPORTANT: Protocol wise, we MUST only allow one single cell of each type for a valid
        // handshake. Any duplicates lead to a failure.
        // They must arrive in a specific order in order for the CLOG calculation to be valid.

        // Note that the `ChannelFrame` already restricts the messages due to its handshake cell
        // handler.

        // This is kind of ugly, but I don't see a nicer way to write the authentication branch
        // without a bunch of boilerplate for a state machine.
        let (certs_and_auth_and_clog, netinfo, netinfo_rcvd_at) = 'outer: {
            // CERTS or NETINFO cell.
            let certs = loop {
                restricted_msg! {
                    enum CertsNetinfoMsg : ChanMsg {
                        // VPADDING cells (but not PADDING) can be sent during handshaking.
                        Vpadding,
                        Netinfo,
                        Certs,
                   }
                }

                break match read_msg(*self.unique_id(), self.framed_tls()).await? {
                    CertsNetinfoMsg::Vpadding(_) => continue,
                    // If a NETINFO cell, the initiator did not authenticate and we can stop early.
                    CertsNetinfoMsg::Netinfo(msg) => {
                        break 'outer (None, msg, coarsetime::Instant::now());
                    }
                    // If a CERTS cell, the initiator is authenticating.
                    CertsNetinfoMsg::Certs(msg) => msg,
                };
            };

            // We're the responder, which means that the recv log is the CLOG.
            let clog_digest =
                ClogDigest::new(self.framed_tls().codec_mut().take_recv_log_digest()?);

            // AUTHENTICATE cell.
            let auth = loop {
                restricted_msg! {
                    enum AuthenticateMsg : ChanMsg {
                        // VPADDING cells (but not PADDING) can be sent during handshaking.
                        Vpadding,
                        Authenticate,
                   }
                }

                break match read_msg(*self.unique_id(), self.framed_tls()).await? {
                    AuthenticateMsg::Vpadding(_) => continue,
                    AuthenticateMsg::Authenticate(msg) => msg,
                };
            };

            // NETINFO cell (if we didn't receive it earlier).
            let (netinfo, netinfo_rcvd_at) = loop {
                restricted_msg! {
                    enum NetinfoMsg : ChanMsg {
                        // VPADDING cells (but not PADDING) can be sent during handshaking.
                        Vpadding,
                        Netinfo,
                   }
                }

                break match read_msg(*self.unique_id(), self.framed_tls()).await? {
                    NetinfoMsg::Vpadding(_) => continue,
                    NetinfoMsg::Netinfo(msg) => (msg, coarsetime::Instant::now()),
                };
            };

            (Some((certs, auth, clog_digest)), netinfo, netinfo_rcvd_at)
        };

        Ok((certs_and_auth_and_clog, (netinfo, netinfo_rcvd_at)))
    }

    /// Send all expected cells to the initiator of the channel as the responder.
    ///
    /// Return the SLOG (send log) digest to be later used when verifying the initiator's
    /// AUTHENTICATE cell.
    async fn send_cells_to_initiator(&mut self) -> Result<SlogDigest> {
        // Send the CERTS message.
        let certs = build_certs_cell(&self.auth_material, /* is_responder */ true);
        trace!(channel_id = %self.unique_id, "Sending CERTS as responder cell.");
        self.framed_tls.send(certs.into()).await?;

        // Send the AUTH_CHALLENGE.
        let challenge: [u8; 32] = rand::rng().random();
        let auth_challenge = msg::AuthChallenge::new(challenge, [AUTHTYPE_ED25519_SHA256_RFC5705]);
        trace!(channel_id = %self.unique_id, "Sending AUTH_CHALLENGE as responder cell.");
        self.framed_tls.send(auth_challenge.into()).await?;

        // We're the responder, which means that the send log is the SLOG.
        let slog_digest = SlogDigest::new(self.framed_tls.codec_mut().take_send_log_digest()?);

        // Send the NETINFO message.
        let peer_ip = self.peer_addr.netinfo_addr();
        let netinfo = build_netinfo_cell(peer_ip, self.my_addrs.clone(), &self.sleep_prov)?;
        trace!(channel_id = %self.unique_id, "Sending NETINFO as responder cell.");
        self.framed_tls.send(netinfo.into()).await?;

        Ok(slog_digest)
    }
}
