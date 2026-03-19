//! Relay responder channel.
//!
//! Code related to the relay channel opened as a responder. The handshake code is responsible for
//! creating an [`MaybeVerifiableRelayResponderChannel`] when accepting an inbound connection.
//!
//! It can then be used to get a fully working channel.

use digest::Digest;
use futures::{AsyncRead, AsyncWrite};
use safelog::{MaybeSensitive, Sensitive};
use std::{net::IpAddr, ops::Deref, sync::Arc, time::SystemTime};
use subtle::ConstantTimeEq;
use tracing::instrument;

use tor_cell::chancell::msg;
use tor_linkspec::{OwnedChanTarget, RelayIds};
use tor_llcrypto as ll;
use tor_rtcompat::{CertifiedConn, CoarseTimeProvider, SleepProvider, StreamOps};

use crate::{
    ClockSkew, Error, RelayIdentities, Result,
    channel::{
        Channel, Reactor,
        handshake::{UnverifiedChannel, VerifiedChannel},
    },
    peer::{PeerAddr, PeerInfo},
    relay::channel::ChannelAuthenticationData,
};

/// An enum combining both the possibility of a verifable (relay) or non verifiable channel
/// (client/bridge).
#[allow(clippy::exhaustive_enums)]
pub enum MaybeVerifiableRelayResponderChannel<
    T: AsyncRead + AsyncWrite + CertifiedConn + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
> {
    /// Verifiable channel (relay).
    Verifiable(UnverifiedResponderRelayChannel<T, S>),
    /// Non verifiable channel (client/bridge).
    NonVerifiable(NonVerifiableResponderRelayChannel<T, S>),
}

/// A channel that can NOT be verified. This is solely either a client or bridge on the other end.
///
/// This can only be built if no [`msg::Authenticate`] was ever received.
pub struct NonVerifiableResponderRelayChannel<
    T: AsyncRead + AsyncWrite + CertifiedConn + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
> {
    /// The common unverified channel that both client and relays use.
    pub(crate) inner: UnverifiedChannel<T, S>,
    /// The netinfo cell received from the initiator.
    pub(crate) netinfo_cell: msg::Netinfo,
    /// Our advertised addresses.
    pub(crate) my_addrs: Vec<IpAddr>,
    /// The peer address which is sensitive considering it is either client or bridge.
    pub(crate) peer_addr: Sensitive<PeerAddr>,
}

/// A verifiable relay responder channel that is currently unverified. This can only be a relay on
/// the other end.
///
/// The verify() and then finish() functions are to be used to get a final Channel/Reactor.
pub struct UnverifiedResponderRelayChannel<
    T: AsyncRead + AsyncWrite + CertifiedConn + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
> {
    /// The common unverified channel that both client and relays use.
    pub(crate) inner: UnverifiedChannel<T, S>,
    /// AUTHENTICATE cell received from the initiator.
    pub(crate) auth_cell: msg::Authenticate,
    /// The netinfo cell received from the initiator.
    pub(crate) netinfo_cell: msg::Netinfo,
    /// The [`msg::Certs`] cell received from the initiator.
    pub(crate) certs_cell: msg::Certs,
    /// Our identity keys needed for authentication.
    pub(crate) identities: Arc<RelayIdentities>,
    /// Our advertised addresses.
    pub(crate) my_addrs: Vec<IpAddr>,
    /// The peer address which we know is a relay.
    pub(crate) peer_addr: PeerAddr,
    /// The CLOG digest.
    pub(crate) clog_digest: [u8; 32],
    /// The SLOG digest.
    pub(crate) slog_digest: [u8; 32],
}

/// A verified relay responder channel.
///
/// Only finish() remains to transform this into a fully usable [`crate::channel::Channel`] and
/// [`crate::channel::Reactor`].
pub struct VerifiedResponderRelayChannel<
    T: AsyncRead + AsyncWrite + CertifiedConn + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
> {
    /// The common unverified channel that both client and relays use.
    inner: VerifiedChannel<T, S>,
    /// The netinfo cell that we got from the relay. Canonicity decision.
    netinfo_cell: msg::Netinfo,
    /// Our advertised addresses.
    my_addrs: Vec<IpAddr>,
    /// The peer address which we know is a relay.
    peer_addr: PeerAddr,
}

impl<T, S> UnverifiedResponderRelayChannel<T, S>
where
    T: AsyncRead + AsyncWrite + CertifiedConn + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
{
    /// Validate the certificates and keys in the relay's handshake.
    ///
    /// 'peer_no_ids' is the peer, without identities as we are accepting a connection and thus
    /// don't have expectations on any identity, that we want to make sure we're connecting to.
    ///
    /// 'our_cert' is the x.509 certificate that we presented during the TLS handshake.
    ///
    /// 'now' is the time at which to check that certificates are valid.  `None` means to use the
    /// current time. It can be used for testing to override the current view of the time.
    ///
    /// This is a separate function because it's likely to be somewhat CPU-intensive.
    #[instrument(skip_all, level = "trace")]
    pub fn verify(
        self,
        peer_no_ids: &OwnedChanTarget,
        our_cert: &[u8],
        now: Option<std::time::SystemTime>,
    ) -> Result<VerifiedResponderRelayChannel<T, S>> {
        // Get these object out as we consume "self" in the inner check().
        let identities = self.identities;
        let netinfo_cell = self.netinfo_cell;
        let initiator_auth_cell = self.auth_cell;
        let my_addrs = self.my_addrs;

        let now = now.unwrap_or_else(SystemTime::now);

        // We are a client initiating a channel to a relay or a bridge. We have received a CERTS
        // cell and we need to verify these certs:
        //
        //   Relay Identities:
        //      IDENTITY_V_SIGNING_CERT (CertType 4)
        //      RSA_ID_X509             (CertType 2)
        //      RSA_ID_V_IDENTITY       (CertType 7)
        //
        //   Connection Cert:
        //      SIGNING_V_TLS_CERT      (CertType 5)
        //
        // Validating the relay identities first so we can make sure we are talking to the relay
        // (peer) we wanted. Then, check the TLS cert validity.
        //
        // The end result is a verified channel (not authenticated yet) which guarantee that we are
        // talking to the right relay that we wanted.

        // Check the relay identities in the CERTS cell.
        let (relay_ids, kp_relaysign_ed, rsa_id_digest) =
            self.inner
                .check_relay_identities(peer_no_ids, &self.certs_cell, now)?;

        // Next, verify the LINK_AUTH cert (CertType 6).
        let peer_kp_link_ed = crate::channel::handshake::verify_link_auth_cert(
            &self.certs_cell,
            &kp_relaysign_ed,
            Some(now),
            self.inner.clock_skew,
        )?;

        // Verify our inner channel and then proceed to handle the authentication challenge if any.
        let mut verified = self.inner.into_verified(relay_ids, rsa_id_digest);

        let our_cert_digest = ll::d::Sha256::digest(our_cert).into();

        // By building the ChannelAuthenticationData, we are certain that the authentication type
        // of the initiator is supported by us.
        let auth_body = ChannelAuthenticationData::build_responder(
            initiator_auth_cell.auth_type(),
            &identities,
            self.clog_digest,
            self.slog_digest,
            &mut verified,
            our_cert_digest,
        )?
        .as_body_no_rand(verified.framed_tls.deref())?;

        // CRITICAL: This if is what authenticates a channel on the responder side. We compare
        // what we expected to what we received.
        let initiator_body_no_rand = initiator_auth_cell
            .body_no_rand()
            .map_err(|e| Error::ChanProto(format!("AUTHENTICATE body_no_rand malformed: {e}")))?;
        // This equality is in constant-time to avoid timing attack oracle.
        if initiator_body_no_rand.ct_eq(&auth_body).into() {
            return Err(Error::ChanProto(
                "AUTHENTICATE was unexpected. Failing authentication".into(),
            ));
        }

        // CRITICAL: Verify the signature of the AUTHENTICATE cell with the peer KP_link_ed.
        let pk: tor_llcrypto::pk::ed25519::PublicKey = peer_kp_link_ed
            .try_into()
            .expect("Peer KP_link_ed fails to convert to PublicKey");
        let sig =
            tor_llcrypto::pk::ed25519::Signature::from_bytes(initiator_auth_cell.sig().map_err(
                |e| Error::ChanProto(format!("AUTHENTICATE sig field is invalid: {e}")),
            )?);
        let initiator_body = initiator_auth_cell
            .body()
            .map_err(|e| Error::ChanProto(format!("AUTHENTICATE body malformed: {e}")))?;
        pk.verify(initiator_body, &sig).map_err(|e| {
            Error::ChanProto(format!("AUTHENTICATE cell signature failed to verify: {e}"))
        })?;

        // This part is very important as we now flag that we are verified and thus authenticated.
        //
        // At this point, the underlying cell handler is in the Handshake state. Setting the
        // channel type here as authenticated means that once the handler transition to the Open
        // state, it will carry this authenticated flag leading to the message filter of the
        // channel codec to adapt its restricted message sets (meaning R2R only).
        //
        // After this call, it is considered a R2R channel.
        verified.set_authenticated()?;

        Ok(VerifiedResponderRelayChannel {
            inner: verified,
            netinfo_cell,
            my_addrs,
            peer_addr: self.peer_addr,
        })
    }

    /// Return the clock skew of this channel.
    pub fn clock_skew(&self) -> ClockSkew {
        self.inner.clock_skew
    }
}

impl<T, S> VerifiedResponderRelayChannel<T, S>
where
    T: AsyncRead + AsyncWrite + CertifiedConn + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
{
    /// Finish the handhshake which will create an open channel and reactor.
    ///
    /// The resulting channel is considered, by Tor protocol standard, an authenticated relay
    /// channel on which circuits can be opened.
    #[instrument(skip_all, level = "trace")]
    pub async fn finish(self) -> Result<(Arc<Channel>, Reactor<S>)> {
        // Relay<->Relay channels are NOT sensitive as we need their info in the log.
        let peer_info = MaybeSensitive::not_sensitive(PeerInfo::new(
            self.peer_addr,
            self.inner.relay_ids().clone(),
        ));
        self.inner
            .finish(&self.netinfo_cell, &self.my_addrs, peer_info)
            .await
    }
}

impl<T, S> NonVerifiableResponderRelayChannel<T, S>
where
    T: AsyncRead + AsyncWrite + CertifiedConn + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
{
    /// Finish the handhshake which will create an open channel and reactor.
    ///
    /// The resulting channel is considered, by Tor protocol standard, a client/bridge relay
    /// channel meaning not authenticated. Circuit can be opened on it.
    #[instrument(skip_all, level = "trace")]
    pub fn finish(self) -> Result<(Arc<Channel>, Reactor<S>)> {
        // This is either a client or a bridge so very sensitive.
        let peer_info = MaybeSensitive::sensitive(PeerInfo::new(
            self.peer_addr.into_inner(),
            RelayIds::empty(),
        ));
        // Non verifiable responder channel, we simply finalize our underlying channel and we are
        // done. We are connected to a client or bridge.
        self.inner
            .finish(&self.netinfo_cell, &self.my_addrs, peer_info)
    }
}
