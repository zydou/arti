//! Relay channel code.
//!
//! This contains relay specific channel code. In other words, everyting that a relay needs to
//! establish a channel according to the Tor protocol.

pub(crate) mod handshake;

use async_trait::async_trait;
use digest::Digest;
use futures::{AsyncRead, AsyncWrite, SinkExt};
use rand::Rng;
use safelog::Sensitive;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::UNIX_EPOCH;
use tracing::{instrument, trace};

use tor_cell::chancell::msg;
use tor_cert::{Ed25519Cert, rsa::RsaCrosscert};
use tor_error::internal;
use tor_linkspec::{ChannelMethod, OwnedChanTarget};
use tor_llcrypto as ll;
use tor_llcrypto::pk::{
    ed25519::{Ed25519Identity, Ed25519SigningKey},
    rsa::RsaIdentity,
};
use tor_relay_crypto::pk::RelayLinkSigningKeypair;
use tor_rtcompat::{CertifiedConn, CoarseTimeProvider, SleepProvider, StreamOps};

use crate::ClockSkew;
use crate::channel::handshake::{UnverifiedChannel, VerifiedChannel};
use crate::channel::{Channel, ChannelType, FinalizableChannel, Reactor, VerifiableChannel};
use crate::relay::channel::handshake::RelayResponderHandshake;
use crate::{Error, Result, channel::RelayInitiatorHandshake, memquota::ChannelAccount};

// TODO(relay): We should probably get those values from protover crate or some other
// crate that have all "network parameters" we support?
/// A list of link authentication that we support (LinkAuth).
pub(crate) static LINK_AUTH: &[u16] = &[3];

/// Object containing the key and certificate that basically identifies us as a relay. They are
/// used for channel authentication.
///
/// We use this intermediary object in order to not have tor-proto crate have access to the KeyMgr
/// meaning access to all keys. This restricts the view to what is needed.
#[expect(unused)] // TODO(relay). remove
pub struct RelayIdentities {
    /// As a relay, our RSA identity key: KP_relayid_rsa
    pub(crate) rsa_id: RsaIdentity,
    /// As a relay, our Ed identity key: KP_relayid_ed
    pub(crate) ed_id: Ed25519Identity,
    /// As a relay, our link signing keypair.
    pub(crate) link_sign_kp: RelayLinkSigningKeypair,
    /// The Ed25519 identity signing cert (CertType 4)
    pub(crate) cert_id_sign_ed: Ed25519Cert,
    /// The Ed25519 signing TLS cert (CertType 5)
    pub(crate) cert_sign_tls_ed: Ed25519Cert,
    /// The Ed25519 signing link auth cert (CertType 6)
    pub(crate) cert_sign_link_auth_ed: Ed25519Cert,
    /// Legacy: the RSA identity X509 cert (CertType 2). We only have the bytes here as
    /// create_legacy_rsa_id_cert() takes a key and gives us back the encoded cert.
    pub(crate) cert_id_x509_rsa: Vec<u8>,
    /// Legacy: the RSA identity cert (CertType 7)
    pub(crate) cert_id_rsa: RsaCrosscert,
}

impl RelayIdentities {
    /// Constructor.
    #[allow(clippy::too_many_arguments)] // Yes, plethora of keys...
    pub fn new(
        rsa_id: RsaIdentity,
        ed_id: Ed25519Identity,
        link_sign_kp: RelayLinkSigningKeypair,
        cert_id_sign_ed: Ed25519Cert,
        cert_sign_tls_ed: Ed25519Cert,
        cert_sign_link_auth_ed: Ed25519Cert,
        cert_id_x509_rsa: Vec<u8>,
        cert_id_rsa: RsaCrosscert,
    ) -> Self {
        Self {
            rsa_id,
            ed_id,
            link_sign_kp,
            cert_id_sign_ed,
            cert_sign_tls_ed,
            cert_sign_link_auth_ed,
            cert_id_x509_rsa,
            cert_id_rsa,
        }
    }
}

impl RelayIdentities {
    /// Return our Ed identity key (KP_relayid_ed) as bytes.
    pub(crate) fn ed_id_bytes(&self) -> [u8; 32] {
        self.ed_id.into()
    }

    /// Return the digest of the RSA x509 certificate (CertType 2) as bytes.
    pub(crate) fn rsa_x509_digest(&self) -> [u8; 32] {
        ll::d::Sha256::digest(&self.cert_id_x509_rsa).into()
    }
}

/// Structure for building and launching a relay Tor channel.
#[derive(Default)]
#[non_exhaustive]
pub struct RelayChannelBuilder;

impl RelayChannelBuilder {
    /// Constructor.
    pub fn new() -> Self {
        Self::default()
    }

    /// Launch a new handshake over a TLS stream.
    ///
    /// After calling this function, you'll need to call `connect()` on the result to start the
    /// handshake.  If that succeeds, you'll have authentication info from the relay: call
    /// `check()` on the result to check that.  Finally, to finish the handshake, call `finish()`
    /// on the result of _that_.
    pub fn launch<T, S>(
        self,
        tls: T,
        sleep_prov: S,
        identities: Arc<RelayIdentities>,
        memquota: ChannelAccount,
    ) -> RelayInitiatorHandshake<T, S>
    where
        T: AsyncRead + AsyncWrite + StreamOps + Send + Unpin + 'static,
        S: CoarseTimeProvider + SleepProvider,
    {
        RelayInitiatorHandshake::new(tls, sleep_prov, identities, memquota)
    }

    /// Accept a new handshake over a TLS stream.
    pub fn accept<T, S>(
        self,
        peer: Sensitive<std::net::SocketAddr>,
        my_addrs: Vec<IpAddr>,
        tls: T,
        sleep_prov: S,
        identities: Arc<RelayIdentities>,
        memquota: ChannelAccount,
    ) -> RelayResponderHandshake<T, S>
    where
        T: AsyncRead + AsyncWrite + StreamOps + Send + Unpin + 'static,
        S: CoarseTimeProvider + SleepProvider,
    {
        RelayResponderHandshake::new(peer, my_addrs, tls, sleep_prov, identities, memquota)
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
> UnverifiedRelayChannel<T, S>
{
    /// Build the [`ChannelAuthenticationData`] given a [`VerifiedChannel`].
    ///
    /// We should never check or build authentication data if the channel is not verified thus the
    /// requirement to pass the verified channel to this function.
    ///
    /// Both initiator and responder handshake build this data in order to authenticate.
    fn build_auth_data(
        auth_challenge_cell: &Option<msg::AuthChallenge>,
        identities: &Arc<RelayIdentities>,
        verified: &mut VerifiedChannel<T, S>,
    ) -> Result<ChannelAuthenticationData> {
        // Are we a relay Responder or Initiator?
        let is_responder = verified.channel_type.is_responder();

        // Safety check. Only the initiator has an AUTH_CHALLENGE.
        if is_responder && auth_challenge_cell.is_some() {
            return Err(Error::from(internal!(
                "Relay responder has a AUTH_CHALLENGE"
            )));
        }

        // Without an AUTH_CHALLENGE, we use our known link protocol value.
        let link_auth = *LINK_AUTH
            .iter()
            .filter(|m| auth_challenge_cell.is_some_and(|cell| cell.methods().contains(m)))
            .max()
            .ok_or(Error::BadCellAuth)?;
        // The ordering matter based on if initiator or responder.
        let cid = identities.rsa_x509_digest();
        let sid = verified.rsa_cert_digest.ok_or(Error::from(internal!(
            "AUTH_CHALLENGE cell without RSA identity"
        )))?;
        let cid_ed = identities.ed_id_bytes();
        let sid_ed = verified
            .ed25519_id
            .ok_or(Error::from(internal!(
                "Verified channel without an ed25519 identity"
            )))?
            .into();
        let clog = verified.framed_tls.codec_mut().get_clog_digest()?;
        let slog = verified.framed_tls.codec_mut().get_slog_digest()?;

        let (cid, sid, cid_ed, sid_ed) = if is_responder {
            // Reverse when responder as in CID becomes SID, and so on.
            (sid, cid, sid_ed, cid_ed)
        } else {
            // Keep it that way if we are initiator.
            (cid, sid, cid_ed, sid_ed)
        };

        let (clog, slog) = if is_responder {
            // Reverse as the SLOG is the responder log digest meaning the clog as a responder.
            (slog, clog)
        } else {
            // Keep ordering.
            (clog, slog)
        };

        let scert = if is_responder {
            // TODO(relay): This is the peer certificate but as a responder, we need our
            // certificate which requires lot more work and a rustls provider configured as a
            // server side. See arti#2316.
            todo!()
        } else {
            verified.peer_cert_digest
        };

        Ok(ChannelAuthenticationData {
            link_auth,
            cid,
            sid,
            cid_ed,
            sid_ed,
            clog,
            slog,
            scert,
        })
    }
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
        // Get these object out as we consume "self" in the inner check().
        let identities = self.identities;
        let auth_challenge_cell = self.auth_challenge_cell;
        let netinfo_cell = self.netinfo_cell;

        // Verify our inner channel and then proceed to handle the authentication challenge if any.
        let mut verified = self.inner.check(peer, peer_cert, now)?;

        let auth_data = Some(Self::build_auth_data(
            &auth_challenge_cell,
            &identities,
            &mut verified,
        )?);

        Ok(Box::new(VerifiedRelayChannel {
            inner: verified,
            auth_data,
            identities,
            netinfo_cell,
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
    /// Relay identities.
    identities: Arc<RelayIdentities>,
    /// The netinfo cell that we got from the relay.
    netinfo_cell: msg::Netinfo,
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

        // TODO(relay): Get our IP address(es) either directly or take them from the
        // VerifiedRelayChannel values?
        let my_addrs = Vec::new();

        // Send the NETINFO message.
        let netinfo = build_netinfo_cell(peer_ip, my_addrs, &self.inner.sleep_prov)?;
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

/// Helper: Build a [`msg::Certs`] cell for the given relay identities and channel type.
///
/// Both relay initiator and responder handshake use this.
pub(crate) fn build_certs_cell(
    identities: &Arc<RelayIdentities>,
    _chan_type: ChannelType,
) -> msg::Certs {
    let mut certs = msg::Certs::new_empty();
    // Push into the cell the CertType 2 RSA
    certs.push_cert_body(
        tor_cert::CertType::RSA_ID_X509,
        identities.cert_id_x509_rsa.clone(),
    );
    /* TODO(relay): Need to push these into the CERTS. The current types in RelayIdentities are
     * wrong as they are not encodable. The types returned by the KeyMgr has encodable cert types
     * so we'll use then when addressing this.

    // Push into the cell the CertType 7 RSA
    certs.push_cert_body(
        self.identities.cert_id_rsa.cert_type(),
        &self.identities.cert_id_rsa,
    );

    // Push into the cell the CertType 4 Ed25519
    certs.push_cert_body(
        self.identities.cert_id_sign_ed.cert_type(),
        &self.identities.cert_id_sign_ed,
    );
    // Push into the cell the CertType 5/6 Ed25519
    if chan_type.is_responder() {
        // Responder has CertType 5
        certs.push_cert_body(
            self.identities.cert_sign_tls_ed.cert_type(),
            &self.identities.cert_sign_tls_ed,
        );
    } else {
        // Initiator has CertType 6
        certs.push_cert_body(
            self.identities.cert_sign_link_auth_ed.cert_type(),
            &self.identities.cert_sign_link_auth_ed,
        );
    }
    */
    certs
}

/// Build a [`msg::Netinfo`] cell from the given peer IPs and our advertised addresses.
///
/// Both relay initiator and responder handshake use this.
pub(crate) fn build_netinfo_cell<S>(
    peer_ip: Option<IpAddr>,
    my_addrs: Vec<IpAddr>,
    sleep_prov: &S,
) -> Result<msg::Netinfo>
where
    S: CoarseTimeProvider + SleepProvider,
{
    // Unix timestamp but over 32bit. This will be sad in 2038 but proposal 338 addresses this
    // issue with a change to 64bit.
    let timestamp = sleep_prov
        .wallclock()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| internal!("Wallclock may have gone backwards: {e}"))?
        .as_secs()
        .try_into()
        .map_err(|e| internal!("Wallclock secs fail to convert to 32bit: {e}"))?;
    Ok(msg::Netinfo::from_relay(timestamp, peer_ip, my_addrs))
}
