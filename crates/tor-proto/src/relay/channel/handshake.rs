//! Implementations for the relay channel handshake

use derive_builder::Builder;
use digest::Digest;
use futures::io::{AsyncRead, AsyncWrite};
use rand::Rng;
use std::time::SystemTime;
use tracing::trace;

use tor_cell::chancell::msg;
use tor_llcrypto as ll;
use tor_llcrypto::pk::ed25519::{Ed25519Identity, Ed25519SigningKey};
use tor_llcrypto::pk::rsa::RsaIdentity;
use tor_relay_crypto::pk::RelayLinkSigningKeypair;
use tor_rtcompat::{CertifiedConn, CoarseTimeProvider, SleepProvider, StreamOps};

use crate::channel::ChannelFrame;
use crate::channel::handshake::{
    ChannelBaseHandshake, ChannelInitiatorHandshake, UnverifiedChannel, unauthenticated_clock_skew,
};
use crate::channel::{ChannelType, UniqId, new_frame};
use crate::memquota::ChannelAccount;
use crate::relay::channel::RelayIdentities;
use crate::{Error, Result};

// TODO(relay): We should probably get those values from protover crate or some other
// crate that have all "network parameters" we support?
/// A list of link authentication that we support (LinkAuth).
static LINK_AUTH: &[u16] = &[3];

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
    identities: RelayIdentities,
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
    /// Prefix to every log line.
    const LOG_PREFIX: &'static str = "Relay Initiator Handshake";

    /// Constructor.
    pub(crate) fn new(
        tls: T,
        sleep_prov: S,
        identities: RelayIdentities,
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
    pub async fn connect<F>(mut self, now_fn: F) -> Result<UnverifiedChannel<T, S>>
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
            "{}: received handshake, ready to verify.",
            Self::LOG_PREFIX,
        );

        // Calculate our clock skew from the timings we just got/calculated.
        let clock_skew = unauthenticated_clock_skew(
            &netinfo_cell,
            netinfo_rcvd_at,
            versions_flushed_at,
            versions_flushed_wallclock,
        );

        Ok(UnverifiedChannel {
            channel_type: ChannelType::RelayInitiator,
            link_protocol,
            framed_tls: self.framed_tls,
            clock_skew,
            memquota: self.memquota,
            target_method: None, // TODO(relay): We might use it for NETINFO canonicity.
            unique_id: self.unique_id,
            sleep_prov: self.sleep_prov.clone(),
            auth_challenge_cell,
            certs_cell,
            netinfo_cell,
            identities: Some(self.identities),
        })
    }
}

/// Channel authentication data. This is only relevant for a Relay to Relay channel which are
/// authenticated using this buffet of bytes.
#[derive(Builder)]
pub(crate) struct ChannelAuthenticationData {
    /// Authentication method to use.
    #[builder(setter(custom))]
    link_auth: u16,
    /// SHA256 digest of the initiator KP_relayid_rsa.
    #[builder(setter(custom))]
    cid: [u8; 32],
    /// SHA256 digest of the responder KP_relayid_rsa.
    #[builder(setter(custom))]
    sid: [u8; 32],
    /// The initiator KP_relayid_ed.
    #[builder(setter(custom))]
    cid_ed: [u8; 32],
    /// The responder KP_relayid_ed.
    #[builder(setter(custom))]
    sid_ed: [u8; 32],
    /// Initiator log SHA256 digest.
    clog: [u8; 32],
    /// Responder log SHA256 digest.
    slog: [u8; 32],
    /// SHA256 of responder's TLS certificate.
    scert: [u8; 32],
}

impl ChannelAuthenticationDataBuilder {
    /// Custom setter for the link auth version.
    pub(crate) fn set_link_auth(
        &mut self,
        auth_challenge_cell: &msg::AuthChallenge,
    ) -> Result<&mut Self> {
        let link_auth = *LINK_AUTH
            .iter()
            .filter(|m| auth_challenge_cell.methods().contains(m))
            .max()
            .ok_or(Error::BadCellAuth)?;
        self.link_auth = Some(link_auth);
        Ok(self)
    }

    /// Set the Initiator identity keys.
    // TODO(relay): rsa should be the DER bytes of the cert.
    pub(crate) fn set_initiator_identity(
        &mut self,
        rsa: &RsaIdentity,
        ed: &Ed25519Identity,
    ) -> &mut Self {
        self.cid = Some(ll::d::Sha256::digest(rsa.as_bytes()).into());
        let mut cid_ed: [u8; 32] = [0; 32];
        cid_ed.copy_from_slice(ed.as_bytes());
        self.cid_ed = Some(cid_ed);
        self
    }

    /// Set the Responder identity keys.
    // TODO(relay): rsa should be the DER bytes of the cert.
    pub(crate) fn set_responder_identity(
        &mut self,
        rsa: &RsaIdentity,
        ed: &Ed25519Identity,
    ) -> &mut Self {
        self.sid = Some(ll::d::Sha256::digest(rsa.as_bytes()).into());
        let mut sid_ed: [u8; 32] = [0; 32];
        sid_ed.copy_from_slice(ed.as_bytes());
        self.sid_ed = Some(sid_ed);
        self
    }
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
