//! Implementations for the relay channel handshake

use async_trait::async_trait;
use futures::SinkExt;
use futures::io::{AsyncRead, AsyncWrite};
use rand::Rng;
use std::net::SocketAddr;
use std::time::UNIX_EPOCH;
use std::{sync::Arc, time::SystemTime};
use tor_error::internal;
use tracing::{instrument, trace};

use tor_cell::chancell::msg;
use tor_linkspec::{ChannelMethod, OwnedChanTarget};
use tor_llcrypto::pk::ed25519::Ed25519SigningKey;
use tor_relay_crypto::pk::RelayLinkSigningKeypair;
use tor_rtcompat::{CertifiedConn, CoarseTimeProvider, SleepProvider, StreamOps};

use crate::channel::handshake::{
    ChannelBaseHandshake, ChannelInitiatorHandshake, UnverifiedChannel, VerifiedChannel,
    unauthenticated_clock_skew,
};
use crate::channel::{Channel, ChannelFrame, FinalizableChannel, Reactor, VerifiableChannel};
use crate::channel::{ChannelType, UniqId, new_frame};
use crate::memquota::ChannelAccount;
use crate::relay::channel::RelayIdentities;
use crate::{ClockSkew, Error, Result};

// TODO(relay): We should probably get those values from protover crate or some other
// crate that have all "network parameters" we support?
/// A list of link authentication that we support (LinkAuth).
pub(crate) static LINK_AUTH: &[u16] = &[3];

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

/// Channel authentication data. This is only relevant for a Relay to Relay channel which are
/// authenticated using this buffet of bytes.
#[derive(Debug)]
pub(crate) struct ChannelAuthenticationData {
    /// Authentication method to use.
    pub(crate) link_auth: u16,
    /// SHA256 digest of the initiator KP_relayid_rsa.
    pub(crate) cid: [u8; 32],
    /// SHA256 digest of the responder KP_relayid_rsa.
    pub(crate) sid: [u8; 32],
    /// The initiator KP_relayid_ed.
    pub(crate) cid_ed: [u8; 32],
    /// The responder KP_relayid_ed.
    pub(crate) sid_ed: [u8; 32],
    /// Initiator log SHA256 digest.
    pub(crate) clog: [u8; 32],
    /// Responder log SHA256 digest.
    pub(crate) slog: [u8; 32],
    /// SHA256 of responder's TLS certificate.
    pub(crate) scert: [u8; 32],
}

#[expect(unused)] // TODO(relay). remove
impl ChannelAuthenticationData {
    /// Helper: return the authentication type string from the given link auth version.
    const fn auth_type_bytes(link_auth: u16) -> Result<&'static [u8]> {
        match link_auth {
            3 => Ok(b"AUTH0003"),
            _ => Err(Error::BadCellAuth),
        }
    }

    /// Helper: return the keying material label from the given link auth version.
    const fn keying_material_label_bytes(link_auth: u16) -> Result<&'static [u8]> {
        match link_auth {
            3 => Ok(b"EXPORTER FOR TOR TLS CLIENT BINDING AUTH0003"),
            _ => Err(Error::BadCellAuth),
        }
    }

    /// Consume ourself and return an AUTHENTICATE cell from the data we hold.
    pub(crate) fn into_authenticate<C: CertifiedConn>(
        self,
        tls: &C,
        link_ed: &RelayLinkSigningKeypair,
    ) -> Result<msg::Authenticate> {
        // The body is exactly 352 bytes so optimize a bit memory.
        let mut body = Vec::with_capacity(352);

        // Obviously, ordering matteres. See tor-spec section Ed25519-SHA256-RFC5705
        body.extend_from_slice(Self::auth_type_bytes(self.link_auth)?);
        body.extend_from_slice(&self.cid);
        body.extend_from_slice(&self.sid);
        body.extend_from_slice(&self.cid_ed);
        body.extend_from_slice(&self.sid_ed);
        body.extend_from_slice(&self.slog);
        body.extend_from_slice(&self.clog);
        body.extend_from_slice(&self.scert);

        // TLSSECRETS is built from the CID.
        let tls_secrets = tls.export_keying_material(
            32,
            Self::keying_material_label_bytes(self.link_auth)?,
            Some(&self.cid[..]),
        )?;
        body.extend_from_slice(tls_secrets.as_slice());

        // Add the random bytes.
        let mut rng = rand::rng();
        let random: [u8; 24] = rand::rng().random();
        body.extend_from_slice(&random);

        // Create signature with our KP_link_ed and append it to body. We hard expect the
        // KP_link_ed because this would be a code flow error.
        let sig = link_ed.sign(&body);
        body.extend_from_slice(&sig.to_bytes());

        // Lets go with the AUTHENTICATE cell.
        Ok(msg::Authenticate::new(self.link_auth, body))
    }
}

/// A relay unverified channel which is a channel where the version has been negotiated and the
/// handshake has been done but where the certificates and keys have not been validated hence
/// unverified.
///
/// This is used for both initiator and responder channels.
#[expect(unused)] // TODO(relay). remove
struct UnverifiedRelayChannel<
    T: AsyncRead + AsyncWrite + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
> {
    /// The common unverified channel that both client and relays use.
    inner: UnverifiedChannel<T, S>,
    /// The AUTH_CHALLENGE cell that we got from the relay. This is only relevant if the channel is
    /// the initiator as this message is sent by the responder.
    auth_challenge_cell: Option<msg::AuthChallenge>,
    /// The netinfo cell that we got from the relay.
    netinfo_cell: msg::Netinfo,
    /// Our identity keys needed for authentication.
    identities: Arc<RelayIdentities>,
}

impl<
    T: AsyncRead + AsyncWrite + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
> VerifiableChannel<T, S> for UnverifiedRelayChannel<T, S>
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
        // Verify our inner channel and then proceed to handle the authentication challenge if any.
        let mut verified = self.inner.check(peer, peer_cert, now)?;

        let auth_data = if let Some(auth_challenge_cell) = self.auth_challenge_cell {
            // Validate our link authentication protocol version.
            let link_auth = *LINK_AUTH
                .iter()
                .filter(|m| auth_challenge_cell.methods().contains(m))
                .max()
                .ok_or(Error::BadCellAuth)?;
            // Having a AUTH_CHALLENGE implies we are the initiator as it is the responder that
            // sends that message. Thus the ordering of these keys is for the initiator.
            let cid = self.identities.rsa_x509_digest();
            let sid = verified.rsa_cert_digest;
            let cid_ed = self.identities.ed_id_bytes();
            let sid_ed = verified.ed25519_id.into();

            Some(ChannelAuthenticationData {
                link_auth,
                cid,
                sid,
                cid_ed,
                sid_ed,
                clog: verified.framed_tls.codec_mut().get_clog_digest()?,
                slog: verified.framed_tls.codec_mut().get_slog_digest()?,
                scert: verified.peer_cert_digest,
            })
        } else {
            None
        };

        Ok(Box::new(VerifiedRelayChannel {
            inner: verified,
            auth_data,
        }))
    }

    /// Return the link protocol version of this channel.
    #[cfg(test)]
    fn link_protocol(&self) -> u16 {
        self.inner.link_protocol
    }
}

impl<T, S> crate::channel::seal::Sealed for UnverifiedRelayChannel<T, S>
where
    T: AsyncRead + AsyncWrite + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
{
}

/// A verified relay channel on which versions have been negotiated, the handshake has been read,
/// but the relay has not yet finished the handshake.
///
/// This type is separate from UnverifiedRelayChannel, since finishing the handshake requires a
/// bunch of CPU, and you might want to do it as a separate task or after a yield.
#[expect(unused)] // TODO(relay). remove
struct VerifiedRelayChannel<
    T: AsyncRead + AsyncWrite + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
> {
    /// The common unverified channel that both client and relays use.
    inner: VerifiedChannel<T, S>,
    /// Authentication data for the [msg::Authenticate] cell. It is sent during the finalization
    /// process because the channel needs to be verified before this is sent.
    auth_data: Option<ChannelAuthenticationData>,
}

#[async_trait]
impl<
    T: AsyncRead + AsyncWrite + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
> FinalizableChannel<T, S> for VerifiedRelayChannel<T, S>
{
    #[instrument(skip_all, level = "trace")]
    async fn finish(mut self: Box<Self>) -> Result<(Arc<Channel>, Reactor<S>)> {
        let peer_ip = self
            .inner
            .target_method
            .as_ref()
            .and_then(ChannelMethod::socket_addrs)
            .and_then(|addrs| addrs.first())
            .map(SocketAddr::ip);

        // Unix timestamp but over 32bit. This will be sad in 2038 but proposal 338 addresses this
        // issue with a change to 64bit.
        let timestamp = self
            .inner
            .sleep_prov
            .wallclock()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| internal!("Wallclock may have gone backwards: {e}"))?
            .as_secs()
            .try_into()
            .map_err(|e| internal!("Wallclock secs fail to convert to 32bit: {e}"))?;
        // TODO(relay): Get our IP address(es) either directly or take them from the
        // VerifiedRelayChannel values?
        let my_addrs = Vec::new();

        // Send the NETINFO message.
        let netinfo = msg::Netinfo::from_relay(timestamp, peer_ip, my_addrs);
        trace!(stream_id = %self.inner.unique_id, "Sending netinfo cell.");
        self.inner.framed_tls.send(netinfo.into()).await?;

        // TODO(relay): If we are authenticating that is self.auth_data.is_some(), send the CERTS
        // and AUTHENTICATE.

        // TODO(relay): This would be the time to set a "is_canonical" flag to Channel which is
        // true if the Netinfo address matches the address we are connected to. Canonical
        // definition is if the address we are connected to is what we expect it to be. This only
        // makes sense for relay channels.

        self.inner.finish().await
    }
}

impl<T, S> crate::channel::seal::Sealed for VerifiedRelayChannel<T, S>
where
    T: AsyncRead + AsyncWrite + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
{
}
