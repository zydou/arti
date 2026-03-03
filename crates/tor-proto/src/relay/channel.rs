//! Relay channel code.
//!
//! This contains relay specific channel code. In other words, everyting that a relay needs to
//! establish a channel according to the Tor protocol.

pub(crate) mod handshake;
pub(crate) mod initiator;
pub(crate) mod responder;

pub use responder::MaybeVerifiableRelayResponderChannel;

use digest::Digest;
use futures::{AsyncRead, AsyncWrite};
use rand::Rng;
use safelog::Sensitive;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::UNIX_EPOCH;

use tor_cell::chancell::msg;
use tor_cert::rsa::EncodedRsaCrosscert;
use tor_cert::x509::TlsKeyAndCert;
use tor_cert::{CertType, EncodedEd25519Cert};
use tor_error::internal;
use tor_linkspec::{HasRelayIds, OwnedChanTarget, RelayIdRef, RelayIdType};
use tor_llcrypto as ll;
use tor_llcrypto::pk::{
    ed25519::{Ed25519Identity, Ed25519SigningKey},
    rsa,
    rsa::RsaIdentity,
};
use tor_relay_crypto::pk::RelayLinkSigningKeypair;
use tor_rtcompat::{CertifiedConn, CoarseTimeProvider, SleepProvider, StreamOps};

use crate::channel::handshake::VerifiedChannel;
use crate::relay::channel::handshake::{AUTHTYPE_ED25519_SHA256_RFC5705, RelayResponderHandshake};
use crate::{Error, Result, channel::RelayInitiatorHandshake, memquota::ChannelAccount};

// TODO(relay): We should probably get those values from protover crate or some other
// crate that have all "network parameters" we support?
/// A list of link authentication that we support (LinkAuth).
pub(crate) static LINK_AUTH: &[u16] = &[AUTHTYPE_ED25519_SHA256_RFC5705];

/// Object containing the key and certificate that basically identifies us as a relay. They are
/// used for channel authentication.
///
/// We use this intermediary object in order to not have tor-proto crate have access to the KeyMgr
/// meaning access to all keys. This restricts the view to what is needed.
pub struct RelayIdentities {
    /// The SHA256(DER(KP_relayid_rsa)) digest for the AUTHENTICATE cell CID.
    pub(crate) rsa_id_der_digest: [u8; 32],
    /// Our RSA identity `KP_relayid_rsa` (SHA1). Needed for HasRelayIds which is required to
    /// compare this with a [`tor_linkspec::ChanTarget`].
    pub(crate) rsa_id: RsaIdentity,
    /// Our Ed identity key (KP_relayid_ed). For the [`msg::Authenticate`] cell CID_ED field.
    pub(crate) ed_id: Ed25519Identity,
    /// Our link signing keypair. Used to sign the [`msg::Authenticate`] cell.
    pub(crate) link_sign_kp: RelayLinkSigningKeypair,
    /// The Ed25519 identity signing cert (CertType 4) for the [`msg::Certs`] cell.
    pub(crate) cert_id_sign_ed: EncodedEd25519Cert,
    /// The Ed25519 signing TLS cert (CertType 5) for the [`msg::Certs`] cell.
    pub(crate) cert_sign_tls_ed: EncodedEd25519Cert,
    /// The Ed25519 signing link auth cert (CertType 6) for the [`msg::Certs`] cell.
    pub(crate) cert_sign_link_auth_ed: EncodedEd25519Cert,
    /// Legacy: the RSA identity X509 cert (CertType 2) for the [`msg::Certs`] cell.
    ///
    /// We only have the bytes here as create_legacy_rsa_id_cert() takes a key and gives us back
    /// the encoded cert.
    pub(crate) cert_id_x509_rsa: Vec<u8>,
    /// Legacy: the RSA identity cert (CertType 7) for the [`msg::Certs`] cell.
    pub(crate) cert_id_rsa: EncodedRsaCrosscert,
    /// Tls key and cert. This is for the TLS acceptor object needed to be a responder (TLS server
    /// side).
    pub(crate) tls_key_and_cert: TlsKeyAndCert,
}

impl RelayIdentities {
    /// Constructor.
    #[allow(clippy::too_many_arguments)] // Yes, plethora of keys...
    pub fn new(
        rsa_id_pk: &rsa::PublicKey,
        ed_id: Ed25519Identity,
        link_sign_kp: RelayLinkSigningKeypair,
        cert_id_sign_ed: EncodedEd25519Cert,
        cert_sign_tls_ed: EncodedEd25519Cert,
        cert_sign_link_auth_ed: EncodedEd25519Cert,
        cert_id_x509_rsa: Vec<u8>,
        cert_id_rsa: EncodedRsaCrosscert,
        tls_key_and_cert: TlsKeyAndCert,
    ) -> Self {
        Self {
            rsa_id_der_digest: ll::d::Sha256::digest(rsa_id_pk.to_der()).into(),
            rsa_id: rsa_id_pk.to_rsa_identity(),
            ed_id,
            link_sign_kp,
            cert_id_sign_ed,
            cert_sign_tls_ed,
            cert_sign_link_auth_ed,
            cert_id_x509_rsa,
            cert_id_rsa,
            tls_key_and_cert,
        }
    }

    /// Return the TLS key and certificate to use for the underlying TLS provider.
    ///
    /// This is used by the TLS acceptor that acts as the TLS server provider.
    pub fn tls_key_and_cert(&self) -> &TlsKeyAndCert {
        &self.tls_key_and_cert
    }

    /// Return our Ed identity key (KP_relayid_ed) as bytes.
    pub(crate) fn ed_id_bytes(&self) -> [u8; 32] {
        self.ed_id.into()
    }
}

impl HasRelayIds for RelayIdentities {
    fn identity(&self, key_type: RelayIdType) -> Option<RelayIdRef<'_>> {
        match key_type {
            RelayIdType::Ed25519 => Some(RelayIdRef::from(&self.ed_id)),
            RelayIdType::Rsa => Some(RelayIdRef::from(&self.rsa_id)),
            _ => None, // Non-exhaustive...
        }
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
    #[allow(clippy::too_many_arguments)] // TODO consider if we want a builder
    pub fn launch<T, S>(
        self,
        tls: T,
        sleep_prov: S,
        identities: Arc<RelayIdentities>,
        my_addrs: Vec<IpAddr>,
        peer: &OwnedChanTarget,
        memquota: ChannelAccount,
    ) -> RelayInitiatorHandshake<T, S>
    where
        T: AsyncRead + AsyncWrite + CertifiedConn + StreamOps + Send + Unpin + 'static,
        S: CoarseTimeProvider + SleepProvider,
    {
        RelayInitiatorHandshake::new(tls, sleep_prov, identities, my_addrs, peer, memquota)
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
        T: AsyncRead + AsyncWrite + CertifiedConn + StreamOps + Send + Unpin + 'static,
        S: CoarseTimeProvider + SleepProvider,
    {
        RelayResponderHandshake::new(
            peer.into_inner().into(),
            my_addrs,
            tls,
            sleep_prov,
            identities,
            memquota,
        )
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
        let random: [u8; 24] = rand::rng().random();
        body.extend_from_slice(&random);

        // Create signature with our KP_link_ed and append it to body. We hard expect the
        // KP_link_ed because this would be a code flow error.
        let sig = link_ed.sign(&body);
        body.extend_from_slice(&sig.to_bytes());

        // Lets go with the AUTHENTICATE cell.
        Ok(msg::Authenticate::new(self.link_auth, body))
    }

    /// Build the [`ChannelAuthenticationData`] given a [`VerifiedChannel`].
    ///
    /// We should never check or build authentication data if the channel is not verified thus the
    /// requirement to pass the verified channel to this function.
    ///
    /// The `our_cert` parameter is for the responder case only that is it contains our certificate
    /// that we presented as the TLS server side. This MUST be Some() if auth_challenge_cell is
    /// None.
    ///
    /// Both initiator and responder handshake build this data in order to authenticate.
    ///
    /// IMPORTANT: The CLOG and SLOG from the framed_tls codec is consumed here so calling twice
    /// build_auth_data() will result in different AUTHENTICATE cells.
    pub(crate) fn build<T, S>(
        auth_challenge_cell: Option<&msg::AuthChallenge>,
        identities: &Arc<RelayIdentities>,
        verified: &mut VerifiedChannel<T, S>,
        our_cert: Option<[u8; 32]>,
    ) -> Result<ChannelAuthenticationData>
    where
        T: AsyncRead + AsyncWrite + CertifiedConn + StreamOps + Send + Unpin + 'static,
        S: CoarseTimeProvider + SleepProvider,
    {
        // With an AUTH_CHALLENGE, we are the Initiator. With an AUTHENTICATE, we are the
        // Responder. See tor-spec for a diagram of messages.
        let is_responder = auth_challenge_cell.is_none();

        // Without an AUTH_CHALLENGE, we use our known link protocol value. Else, we only keep what
        // we know from the AUTH_CHALLENGE and we max() on it.
        let link_auth = *LINK_AUTH
            .iter()
            .filter(|m| auth_challenge_cell.is_none_or(|cell| cell.methods().contains(m)))
            .max()
            .ok_or(Error::BadCellAuth)?;
        // The ordering matter based on if initiator or responder.
        let cid = identities.rsa_id_der_digest;
        let sid = verified.rsa_id_digest;
        let cid_ed = identities.ed_id_bytes();
        let sid_ed = verified.ed25519_id.into();
        // Both values are consumed from the underlying codec.
        let send_log = verified.framed_tls.codec_mut().take_send_log_digest()?;
        let recv_log = verified.framed_tls.codec_mut().take_recv_log_digest()?;

        let (cid, sid, cid_ed, sid_ed) = if is_responder {
            // Reverse when responder as in CID becomes SID, and so on.
            (sid, cid, sid_ed, cid_ed)
        } else {
            // Keep it that way if we are initiator.
            (cid, sid, cid_ed, sid_ed)
        };

        let (clog, slog) = if is_responder {
            // We're the responder (acting like a server),
            // so the SLOG is the digest of the bytes we sent.
            (recv_log, send_log)
        } else {
            // We're the initiator (acting like a client),
            // so the CLOG is the digest of the bytes we sent.
            (send_log, recv_log)
        };

        let scert = if is_responder {
            our_cert.ok_or(internal!("Responder channel without own certificate"))?
        } else {
            verified.peer_cert_digest
        };

        Ok(Self {
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

/// Helper: Build a [`msg::Certs`] cell for the given relay identities and channel type.
///
/// Both relay initiator and responder handshake use this.
pub(crate) fn build_certs_cell(
    identities: &Arc<RelayIdentities>,
    is_responder: bool,
) -> msg::Certs {
    let mut certs = msg::Certs::new_empty();
    // Push into the cell the CertType 2 RSA
    certs.push_cert_body(
        tor_cert::CertType::RSA_ID_X509,
        identities.cert_id_x509_rsa.clone(),
    );

    // Push into the cell the CertType 7 RSA
    certs.push_cert_body(CertType::RSA_ID_V_IDENTITY, identities.cert_id_rsa.clone());

    // Push into the cell the CertType 4 Ed25519
    certs.push_cert_body(
        CertType::IDENTITY_V_SIGNING,
        identities.cert_id_sign_ed.clone(),
    );
    // Push into the cell the CertType 5/6 Ed25519
    if is_responder {
        // Responder has CertType 5
        certs.push_cert_body(
            CertType::SIGNING_V_TLS_CERT,
            identities.cert_sign_tls_ed.clone(),
        );
    } else {
        // Initiator has CertType 6
        certs.push_cert_body(
            CertType::SIGNING_V_LINK_AUTH,
            identities.cert_sign_link_auth_ed.clone(),
        );
    }
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
