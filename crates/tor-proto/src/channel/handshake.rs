//! Implementations for the channel handshake

use futures::io::{AsyncRead, AsyncWrite};
use futures::sink::SinkExt;
use futures::stream::StreamExt;
use tor_cell::chancell::msg::AnyChanMsg;
use tor_error::internal;

use crate::channel::{ChannelFrame, ChannelType, UniqId, new_frame};
use crate::memquota::ChannelAccount;
use crate::util::skew::ClockSkew;
use crate::{Error, Result};
use tor_cell::chancell::{AnyChanCell, ChanMsg, msg};
use tor_rtcompat::{CoarseTimeProvider, SleepProvider, StreamOps};

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;

use tor_linkspec::{ChanTarget, ChannelMethod, OwnedChanTargetBuilder, RelayIds};
use tor_llcrypto as ll;
use tor_llcrypto::pk::ed25519::Ed25519Identity;
use tor_llcrypto::pk::rsa::RsaIdentity;

use digest::Digest;

use tracing::{debug, instrument, trace};

#[cfg(feature = "relay")]
use crate::relay::channel::{RelayIdentities, handshake::ChannelAuthenticationData};

/// A list of the link protocols that we support.
pub(crate) static LINK_PROTOCOLS: &[u16] = &[4, 5];

/// Base trait that all handshake type must implement.
///
/// It has common code that all handshake share including getters for the channel frame for cell
/// decoding/encoding and the unique ID used for logging.
///
/// It has both a recv() and send() function for the VERSIONS cell since every handshake must start
/// with this cell to negotiate the link protocol version.
pub(crate) trait ChannelBaseHandshake<T>
where
    T: AsyncRead + AsyncWrite + StreamOps + Send + Unpin + 'static,
{
    /// Return a mutable reference to the channel frame.
    fn framed_tls(&mut self) -> &mut ChannelFrame<T>;
    /// Return a reference to the unique ID of this handshake.
    fn unique_id(&self) -> &UniqId;

    /// Send a [msg::Versions] cell.
    ///
    /// A tuple is returned that is respectively the instant and wallclock of the send.
    async fn send_versions_cell<F>(
        &mut self,
        now_fn: F,
    ) -> Result<(coarsetime::Instant, SystemTime)>
    where
        F: FnOnce() -> SystemTime,
    {
        trace!(stream_id = %self.unique_id(), "sending versions");
        // Send versions cell
        let version_cell = AnyChanCell::new(
            None,
            msg::Versions::new(LINK_PROTOCOLS)
                .map_err(|e| Error::from_cell_enc(e, "versions message"))?
                .into(),
        );
        self.framed_tls().send(version_cell).await?;
        Ok((
            coarsetime::Instant::now(), // Flushed at instant
            now_fn(),                   // Flushed at wallclock
        ))
    }

    /// Receive a [msg::Versions] cell.
    ///
    /// The negotiated link protocol is returned, and also recorded in the underlying channel
    /// frame. This automatically transitions the frame into the "Handshake" state of the
    /// underlying cell handler. In other words, once the link protocol version is negotiated, the
    /// handler can encode and decode cells for that version in order to continue the handshake.
    async fn recv_versions_cell(&mut self) -> Result<u16> {
        // Get versions cell.
        // Get versions cell.
        trace!(stream_id = %self.unique_id(), "waiting for versions");
        // This can be None if we've reached EOF or any type of I/O error on the underlying TCP or
        // TLS stream. Either case, it is unexpected.
        let Some(cell) = self.framed_tls().next().await.transpose()? else {
            return Err(Error::ChanIoErr(Arc::new(std::io::Error::from(
                std::io::ErrorKind::UnexpectedEof,
            ))));
        };
        let AnyChanMsg::Versions(their_versions) = cell.into_circid_and_msg().1 else {
            return Err(Error::from(internal!(
                "Unexpected cell, expecting a VERSIONS cell",
            )));
        };
        trace!(stream_id = %self.unique_id(), "received their VERSIONS {:?}", their_versions);

        // Determine which link protocol we negotiated.
        let link_protocol = their_versions
            .best_shared_link_protocol(LINK_PROTOCOLS)
            .ok_or_else(|| Error::HandshakeProto("No shared link protocols".into()))?;
        trace!(stream_id = %self.unique_id(), "negotiated version {}", link_protocol);

        // Set the link protocol into our channel frame.
        self.framed_tls()
            .codec_mut()
            .set_link_version(link_protocol)?;
        Ok(link_protocol)
    }
}

/// Handshake initiator base trait. All initiator handshake should implement this trait in order to
/// enjoy the helper functions.
///
/// It requires the base handshake trait to be implement for access to the base getters.
pub(crate) trait ChannelInitiatorHandshake<T>: ChannelBaseHandshake<T>
where
    T: AsyncRead + AsyncWrite + StreamOps + Send + Unpin + 'static,
{
    /// Return true iff this handshake is expecting to receive an AUTH_CHALLENGE from the
    /// responder. As a handshake initiator, we always know if we expect one or not. A client or
    /// bridge do not authenticate with the responder while relays will always do.
    fn is_expecting_auth_challenge(&self) -> bool;

    /// As an initiator, we are expecting the responder's cells which are (not in that order):
    ///     - [msg::AuthChallenge], [msg::Certs], [msg::Netinfo]
    ///
    /// Any duplicate, missing cell or unexpected results in a protocol level error.
    ///
    /// This returns the [msg::AuthChallenge], [msg::Certs] and [msg::Netinfo] cells along the
    /// instant when the netinfo cell was received. This is needed for the clock skew calculation.
    async fn recv_cells_from_responder(
        &mut self,
    ) -> Result<(
        Option<msg::AuthChallenge>,
        msg::Certs,
        (msg::Netinfo, coarsetime::Instant),
    )> {
        let mut auth_challenge_cell: Option<msg::AuthChallenge> = None;
        let mut certs_cell: Option<msg::Certs> = None;
        let mut netinfo_cell: Option<(msg::Netinfo, coarsetime::Instant)> = None;

        // IMPORTANT: Protocol wise, we MUST only allow one single cell of each type for a valid
        // handshake. Any duplicates lead to a failure. They can arrive in any order unfortunately.

        // Read until we have the netinfo cell.
        while let Some(cell) = self.framed_tls().next().await.transpose()? {
            use super::AnyChanMsg::*;
            let (_, m) = cell.into_circid_and_msg();
            trace!(stream_id = %self.unique_id(), "received a {} cell.", m.cmd());
            match m {
                // Ignore the padding. Only VPADDING cell can be sent during handshaking.
                Vpadding(_) => (),
                // Clients don't care about AuthChallenge
                AuthChallenge(ac) => {
                    if auth_challenge_cell.replace(ac).is_some() {
                        return Err(Error::HandshakeProto(
                            "Duplicate AUTH_CHALLENGE cell".into(),
                        ));
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

        // Missing any of the above means we are not connected to a Relay and so we abort the
        // handshake protocol.
        let Some((netinfo, netinfo_rcvd_at)) = netinfo_cell else {
            return Err(Error::HandshakeProto("Missing NETINFO cell".into()));
        };
        let Some(certs) = certs_cell else {
            return Err(Error::HandshakeProto("Missing CERTS cell".into()));
        };
        // If we plan to authenticate, we require an AUTH_CHALLENGE cell from the responder.
        if self.is_expecting_auth_challenge() && auth_challenge_cell.is_none() {
            return Err(Error::HandshakeProto("Missing AUTH_CHALLENGE cell".into()));
        };

        Ok((auth_challenge_cell, certs, (netinfo, netinfo_rcvd_at)))
    }
}

/// A raw client channel on which nothing has been done.
pub struct ClientInitiatorHandshake<
    T: AsyncRead + AsyncWrite + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
> {
    /// Runtime handle (insofar as we need it)
    sleep_prov: S,

    /// Memory quota account
    memquota: ChannelAccount,

    /// Cell encoder/decoder wrapping the underlying TLS stream
    ///
    /// (We don't enforce that this is actually TLS, but if it isn't, the
    /// connection won't be secure.)
    framed_tls: ChannelFrame<T>,

    /// Declared target method for this channel, if any.
    target_method: Option<ChannelMethod>,

    /// Logging identifier for this stream.  (Used for logging only.)
    unique_id: UniqId,
}

/// Implement the base channel handshake trait.
impl<T, S> ChannelBaseHandshake<T> for ClientInitiatorHandshake<T, S>
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
impl<T, S> ChannelInitiatorHandshake<T> for ClientInitiatorHandshake<T, S>
where
    T: AsyncRead + AsyncWrite + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
{
    fn is_expecting_auth_challenge(&self) -> bool {
        // Client never authenticate with a responder, only relay do.
        false
    }
}

/// A client channel on which versions have been negotiated and the
/// relay's handshake has been read, but where the certs have not
/// been checked.
// TODO(relay): Split this into a Client and relay version.
pub struct UnverifiedChannel<
    T: AsyncRead + AsyncWrite + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
> {
    /// Indicate what type of channel this is.
    pub(crate) channel_type: ChannelType,
    /// Runtime handle (insofar as we need it)
    pub(crate) sleep_prov: S,
    /// Memory quota account
    pub(crate) memquota: ChannelAccount,
    /// The negotiated link protocol.  Must be a member of LINK_PROTOCOLS
    pub(crate) link_protocol: u16,
    /// The Source+Sink on which we're reading and writing cells.
    pub(crate) framed_tls: ChannelFrame<T>,
    /// The certs cell that we got from the relay.
    pub(crate) certs_cell: msg::Certs,
    /// Declared target method for this channel, if any.
    pub(crate) target_method: Option<ChannelMethod>,
    /// The netinfo cell that we got from the relay.
    #[expect(unused)] // TODO(relay): Relays need this.
    pub(crate) netinfo_cell: msg::Netinfo,
    /// The AUTH_CHALLENGE cell that we got from the relay. Client ignore this field, only relay
    /// care for authentication purposes.
    pub(crate) auth_challenge_cell: Option<msg::AuthChallenge>,
    /// How much clock skew did we detect in this handshake?
    ///
    /// This value is _unauthenticated_, since we have not yet checked whether
    /// the keys in the handshake are the ones we expected.
    pub(crate) clock_skew: ClockSkew,
    /// Logging identifier for this stream.  (Used for logging only.)
    pub(crate) unique_id: UniqId,
    /// Relay only: Our identity keys needed for authentication.
    #[cfg(feature = "relay")]
    pub(crate) identities: Option<Arc<RelayIdentities>>,
}

/// A client channel on which versions have been negotiated,
/// relay's handshake has been read, but the client has not yet
/// finished the handshake.
///
/// This type is separate from UnverifiedChannel, since finishing the
/// handshake requires a bunch of CPU, and you might want to do it as
/// a separate task or after a yield.
// TODO(relay): Split this into a Client and relay version.
pub struct VerifiedChannel<
    T: AsyncRead + AsyncWrite + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
> {
    /// Indicate what type of channel this is.
    channel_type: ChannelType,
    /// Runtime handle (insofar as we need it)
    sleep_prov: S,
    /// Memory quota account
    memquota: ChannelAccount,
    /// The negotiated link protocol.
    link_protocol: u16,
    /// The Source+Sink on which we're reading and writing cells.
    framed_tls: ChannelFrame<T>,
    /// Declared target method for this stream, if any.
    target_method: Option<ChannelMethod>,
    /// Logging identifier for this stream.  (Used for logging only.)
    unique_id: UniqId,
    /// Validated Ed25519 identity for this peer.
    ed25519_id: Ed25519Identity,
    /// Validated RSA identity for this peer.
    rsa_id: RsaIdentity,
    /// Authenticated clock skew for this peer.
    clock_skew: ClockSkew,
    /// Authentication data for the [msg::Authenticate] cell. It is sent during the finalization
    /// process because the channel needs to be verified before it is sent.
    #[cfg(feature = "relay")]
    #[expect(unused)] // TODO(relay): Remove once used.
    auth_data: Option<ChannelAuthenticationData>,
}

impl<
    T: AsyncRead + AsyncWrite + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
> ClientInitiatorHandshake<T, S>
{
    /// Construct a new OutboundClientHandshake.
    pub(crate) fn new(
        tls: T,
        target_method: Option<ChannelMethod>,
        sleep_prov: S,
        memquota: ChannelAccount,
    ) -> Self {
        Self {
            framed_tls: new_frame(tls, ChannelType::ClientInitiator),
            target_method,
            unique_id: UniqId::new(),
            sleep_prov,
            memquota,
        }
    }

    /// Negotiate a link protocol version with the relay, and read
    /// the relay's handshake information.
    ///
    /// Takes a function that reports the current time.  In theory, this can just be
    /// `SystemTime::now()`.
    #[instrument(skip_all, level = "trace")]
    pub async fn connect<F>(mut self, now_fn: F) -> Result<UnverifiedChannel<T, S>>
    where
        F: FnOnce() -> SystemTime,
    {
        match &self.target_method {
            Some(method) => debug!(
                stream_id = %self.unique_id,
                "starting Tor handshake with {:?}",
                method
            ),
            None => debug!(stream_id = %self.unique_id, "starting Tor handshake"),
        }
        // Send versions cell.
        let (versions_flushed_at, versions_flushed_wallclock) =
            self.send_versions_cell(now_fn).await?;

        // Receive versions cell.
        let link_protocol = self.recv_versions_cell().await?;

        // Receive the relay responder cells. Ignore the AUTH_CHALLENGE cell, we don't need it as
        // we are not authenticating with our responder because we are a client.
        let (_, certs_cell, (netinfo_cell, netinfo_rcvd_at)) =
            self.recv_cells_from_responder().await?;

        // Get the clock skew.
        let clock_skew = unauthenticated_clock_skew(
            &netinfo_cell,
            netinfo_rcvd_at,
            versions_flushed_at,
            versions_flushed_wallclock,
        );

        trace!(stream_id = %self.unique_id, "received handshake, ready to verify.");

        Ok(UnverifiedChannel {
            channel_type: ChannelType::ClientInitiator,
            link_protocol,
            framed_tls: self.framed_tls,
            certs_cell,
            netinfo_cell,
            auth_challenge_cell: None,
            clock_skew,
            target_method: self.target_method.take(),
            unique_id: self.unique_id,
            sleep_prov: self.sleep_prov.clone(),
            memquota: self.memquota.clone(),
            #[cfg(feature = "relay")]
            identities: None,
        })
    }
}

impl<
    T: AsyncRead + AsyncWrite + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
> UnverifiedChannel<T, S>
{
    /// Return the reported clock skew from this handshake.
    ///
    /// Note that the skew reported by this function might not be "true": the
    /// relay might have its clock set wrong, or it might be lying to us.
    ///
    /// The clock skew reported here is not yet authenticated; if you need to
    /// make sure that the skew is authenticated, use
    /// [`Channel::clock_skew`](super::Channel::clock_skew) instead.
    pub fn clock_skew(&self) -> ClockSkew {
        self.clock_skew
    }

    /// Validate the certificates and keys in the relay's handshake.
    ///
    /// 'peer' is the peer that we want to make sure we're connecting to.
    ///
    /// 'peer_cert' is the x.509 certificate that the peer presented during
    /// its TLS handshake (ServerHello).
    ///
    /// 'now' is the time at which to check that certificates are
    /// valid.  `None` means to use the current time. It can be used
    /// for testing to override the current view of the time.
    ///
    /// This is a separate function because it's likely to be somewhat
    /// CPU-intensive.
    #[instrument(skip_all, level = "trace")]
    pub fn check<U: ChanTarget + ?Sized>(
        self,
        peer: &U,
        peer_cert: &[u8],
        now: Option<std::time::SystemTime>,
    ) -> Result<VerifiedChannel<T, S>> {
        let peer_cert_sha256 = ll::d::Sha256::digest(peer_cert);
        self.check_internal(peer, &peer_cert_sha256[..], now)
    }

    /// Same as `check`, but takes the SHA256 hash of the peer certificate,
    /// since that is all we use.
    fn check_internal<U: ChanTarget + ?Sized>(
        mut self,
        peer: &U,
        peer_cert_sha256: &[u8],
        now: Option<SystemTime>,
    ) -> Result<VerifiedChannel<T, S>> {
        use tor_cert::CertType;
        use tor_checkable::*;

        /// Helper: given a time-bound input, give a result reflecting its
        /// validity at `now`, and the inner object.
        ///
        /// We use this here because we want to validate the whole handshake
        /// regardless of whether the certs are expired, so we can determine
        /// whether we got a plausible handshake with a skewed partner, or
        /// whether the handshake is definitely bad.
        fn check_timeliness<C, T>(checkable: C, now: SystemTime, skew: ClockSkew) -> (Result<()>, T)
        where
            C: Timebound<T, Error = TimeValidityError>,
        {
            let status = checkable.is_valid_at(&now).map_err(|e| match (e, skew) {
                (TimeValidityError::Expired(expired_by), ClockSkew::Fast(skew))
                    if expired_by < skew =>
                {
                    Error::HandshakeCertsExpired { expired_by }
                }
                // As it so happens, we don't need to check for this case, since the certs in use
                // here only have an expiration time in them.
                // (TimeValidityError::NotYetValid(_), ClockSkew::Slow(_)) => todo!(),
                (_, _) => Error::HandshakeProto("Certificate expired or not yet valid".into()),
            });
            let cert = checkable.dangerously_assume_timely();
            (status, cert)
        }
        // Replace 'now' with the real time to use.
        let now = now.unwrap_or_else(SystemTime::now);

        // We need to check the following lines of authentication:
        //
        // First, to bind the ed identity to the channel.
        //    peer.ed_identity() matches the key in...
        //    IDENTITY_V_SIGNING cert, which signs...
        //    SIGNING_V_TLS_CERT cert, which signs peer_cert.
        //
        // Second, to bind the rsa identity to the ed identity:
        //    peer.rsa_identity() matches the key in...
        //    the x.509 RSA identity certificate (type 2), which signs...
        //    the RSA->Ed25519 crosscert (type 7), which signs...
        //    peer.ed_identity().

        let c = &self.certs_cell;
        /// Helper: get a cert from a Certs cell, and convert errors appropriately.
        fn get_cert(
            certs: &tor_cell::chancell::msg::Certs,
            tp: CertType,
        ) -> Result<tor_cert::KeyUnknownCert> {
            match certs.parse_ed_cert(tp) {
                Ok(c) => Ok(c),
                Err(tor_cell::Error::ChanProto(e)) => Err(Error::HandshakeProto(e)),
                Err(e) => Err(Error::HandshakeProto(e.to_string())),
            }
        }

        let id_sk = get_cert(c, CertType::IDENTITY_V_SIGNING)?;
        let sk_tls = get_cert(c, CertType::SIGNING_V_TLS_CERT)?;

        let mut sigs = Vec::new();

        // Part 1: validate ed25519 stuff.
        //
        // (We are performing our timeliness checks now, but not inspecting them
        // until later in the function, so that we can distinguish failures that
        // might be caused by clock skew from failures that are definitely not
        // clock skew.)

        // Check the identity->signing cert
        let (id_sk, id_sk_sig) = id_sk
            .should_have_signing_key()
            .map_err(Error::HandshakeCertErr)?
            .dangerously_split()
            .map_err(Error::HandshakeCertErr)?;
        sigs.push(&id_sk_sig);
        let (id_sk_timeliness, id_sk) = check_timeliness(id_sk, now, self.clock_skew);

        // Take the identity key from the identity->signing cert
        let identity_key = id_sk.signing_key().ok_or_else(|| {
            Error::HandshakeProto("Missing identity key in identity->signing cert".into())
        })?;

        // Take the signing key from the identity->signing cert
        let signing_key = id_sk.subject_key().as_ed25519().ok_or_else(|| {
            Error::HandshakeProto("Bad key type in identity->signing cert".into())
        })?;

        // Now look at the signing->TLS cert and check it against the
        // peer certificate.
        let (sk_tls, sk_tls_sig) = sk_tls
            .should_be_signed_with(signing_key)
            .map_err(Error::HandshakeCertErr)?
            .dangerously_split()
            .map_err(Error::HandshakeCertErr)?;
        sigs.push(&sk_tls_sig);
        let (sk_tls_timeliness, sk_tls) = check_timeliness(sk_tls, now, self.clock_skew);

        if peer_cert_sha256 != sk_tls.subject_key().as_bytes() {
            return Err(Error::HandshakeProto(
                "Peer cert did not authenticate TLS cert".into(),
            ));
        }

        // Batch-verify the ed25519 certificates in this handshake.
        //
        // In theory we could build a list of _all_ the certificates here
        // and call pk::validate_all_sigs() instead, but that doesn't gain
        // any performance.
        if !ll::pk::ed25519::validate_batch(&sigs[..]) {
            return Err(Error::HandshakeProto(
                "Invalid ed25519 signature in handshake".into(),
            ));
        }

        // Part 2: validate rsa stuff.

        // What is the RSA identity key, according to the X.509 certificate
        // in which it is self-signed?
        //
        // (We don't actually check this self-signed certificate, and we use
        // a kludge to extract the RSA key)
        let pkrsa = c
            .cert_body(CertType::RSA_ID_X509)
            .and_then(ll::util::x509_extract_rsa_subject_kludge)
            .ok_or_else(|| Error::HandshakeProto("Couldn't find RSA identity key".into()))?;

        // Now verify the RSA identity -> Ed Identity crosscert.
        //
        // This proves that the RSA key vouches for the Ed key.  Note that
        // the Ed key does not vouch for the RSA key: The RSA key is too
        // weak.
        let rsa_cert = c
            .cert_body(CertType::RSA_ID_V_IDENTITY)
            .ok_or_else(|| Error::HandshakeProto("No RSA->Ed crosscert".into()))?;
        let rsa_cert = tor_cert::rsa::RsaCrosscert::decode(rsa_cert)
            .map_err(|e| Error::from_bytes_err(e, "RSA identity cross-certificate"))?
            .check_signature(&pkrsa)
            .map_err(|_| Error::HandshakeProto("Bad RSA->Ed crosscert signature".into()))?;
        let (rsa_cert_timeliness, rsa_cert) = check_timeliness(rsa_cert, now, self.clock_skew);

        if !rsa_cert.subject_key_matches(identity_key) {
            return Err(Error::HandshakeProto(
                "RSA->Ed crosscert certifies incorrect key".into(),
            ));
        }

        let rsa_id = pkrsa.to_rsa_identity();

        trace!(
            stream_id = %self.unique_id,
            "Validated identity as {} [{}]",
            identity_key,
            rsa_id
        );

        // Now that we've done all the verification steps on the
        // certificates, we know who we are talking to.  It's time to
        // make sure that the peer we are talking to is the peer we
        // actually wanted.
        //
        // We do this _last_, since "this is the wrong peer" is
        // usually a different situation than "this peer couldn't even
        // identify itself right."

        let actual_identity = RelayIds::builder()
            .ed_identity(*identity_key)
            .rsa_identity(rsa_id)
            .build()
            .expect("Unable to build RelayIds");

        // We enforce that the relay proved that it has every ID that we wanted:
        // it may also have additional IDs that we didn't ask for.
        match super::check_id_match_helper(&actual_identity, peer) {
            Err(Error::ChanMismatch(msg)) => Err(Error::HandshakeProto(msg)),
            other => other,
        }?;

        // If we reach this point, the clock skew might be may now be considered
        // authenticated: The certificates are what we wanted, and everything
        // was well signed.
        //
        // The only remaining concern is certificate timeliness.  If the
        // certificates are expired by an amount that is too large for the
        // declared clock skew to explain, then  we'll return
        // `Error::HandshakeProto`: in that case the clock skew is _not_
        // authenticated.  But if the certs are only expired by a little bit,
        // we'll reject the handshake with `Error::HandshakeCertsExpired`, and
        // the caller can trust the clock skew.
        //
        // We note expired certs last, since we only want to return
        // `HandshakeCertsExpired` when there are no other errors.
        id_sk_timeliness?;
        sk_tls_timeliness?;
        rsa_cert_timeliness?;

        // This part is relay specific as only relay will process an AUTH_CHALLENGE message.
        //
        // TODO(relay). We should somehow find a way to have this to be in the relay module. For
        // this, I suspect we will need a relay specific UnverifiedChannel and VerifiedChannel
        // which yields a Channel upon validation. Client and relay channels would share a lot of
        // code so we would need to find an elegant way to do this. Until then, it lives here.
        #[cfg(feature = "relay")]
        let auth_data: Option<ChannelAuthenticationData>;
        #[cfg(feature = "relay")]
        {
            auth_data = match (self.auth_challenge_cell, self.identities) {
                (Some(auth_challenge_cell), Some(identities)) => {
                    // Depending on if we are initiator or responder, we flip the identities in the
                    // authentication challenge. See tor-spec.
                    let (cid, sid, cid_ed, sid_ed) = if self.channel_type.is_initiator() {
                        (
                            ll::d::Sha256::digest(&identities.cert_id_x509_rsa).into(),
                            (*rsa_cert.digest()),
                            &identities.ed_id,
                            identity_key,
                        )
                    } else {
                        (
                            (*rsa_cert.digest()),
                            ll::d::Sha256::digest(&identities.cert_id_x509_rsa).into(),
                            identity_key,
                            &identities.ed_id,
                        )
                    };
                    let link_auth = *crate::relay::channel::handshake::LINK_AUTH
                        .iter()
                        .filter(|m| auth_challenge_cell.methods().contains(m))
                        .max()
                        .ok_or(Error::BadCellAuth)?;

                    let auth_data = ChannelAuthenticationData {
                        link_auth,
                        cid,
                        sid,
                        cid_ed: cid_ed
                            .as_bytes()
                            .try_into()
                            .expect("ed25519 had an unexpected size"),
                        sid_ed: sid_ed
                            .as_bytes()
                            .try_into()
                            .expect("ed25519 had an unexpected size"),
                        clog: self.framed_tls.codec_mut().get_clog_digest()?,
                        slog: self.framed_tls.codec_mut().get_slog_digest()?,
                        scert: peer_cert_sha256.try_into().expect("Peer cert not 32 bytes"),
                    };
                    Some(auth_data)
                }
                _ => None,
            };
        }

        Ok(VerifiedChannel {
            channel_type: self.channel_type,
            link_protocol: self.link_protocol,
            framed_tls: self.framed_tls,
            unique_id: self.unique_id,
            target_method: self.target_method,
            ed25519_id: *identity_key,
            rsa_id,
            clock_skew: self.clock_skew,
            sleep_prov: self.sleep_prov,
            memquota: self.memquota,
            #[cfg(feature = "relay")]
            auth_data,
        })
    }
}

impl<
    T: AsyncRead + AsyncWrite + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
> VerifiedChannel<T, S>
{
    /// Send a 'Netinfo' message to the relay to finish the handshake,
    /// and create an open channel and reactor.
    ///
    /// The channel is used to send cells, and to create outgoing circuits.
    /// The reactor is used to route incoming messages to their appropriate
    /// circuit.
    #[instrument(skip_all, level = "trace")]
    pub async fn finish(mut self) -> Result<(Arc<super::Channel>, super::reactor::Reactor<S>)> {
        // We treat a completed channel -- that is to say, one where the
        // authentication is finished -- as incoming traffic.
        //
        // TODO: conceivably we should remember the time when we _got_ the
        // final cell on the handshake, and update the channel completion
        // time to be no earlier than _that_ timestamp.
        crate::note_incoming_traffic();
        trace!(stream_id = %self.unique_id, "Sending netinfo cell.");

        // We do indeed want the real IP here, regardless of whether the
        // ChannelMethod is Direct connection or not.  The role of the IP in a
        // NETINFO cell is to tell our peer what address we believe they had, so
        // that they can better notice MITM attacks and such.
        let peer_ip = self
            .target_method
            .as_ref()
            .and_then(ChannelMethod::socket_addrs)
            .and_then(|addrs| addrs.first())
            .map(SocketAddr::ip);
        let netinfo = msg::Netinfo::from_client(peer_ip);
        self.framed_tls.send(netinfo.into()).await?;

        // We have finalized the handshake, move our codec to Open.
        self.framed_tls.codec_mut().set_open()?;

        debug!(
            stream_id = %self.unique_id,
            "Completed handshake with {} [{}]",
            self.ed25519_id, self.rsa_id
        );

        // Grab a new handle on which we can apply StreamOps (needed for KIST).
        // On Unix platforms, this handle is a wrapper over the fd of the socket.
        //
        // Note: this is necessary because after `StreamExit::split()`,
        // we no longer have access to the underlying stream
        // or its StreamOps implementation.
        let stream_ops = self.framed_tls.new_handle();
        let (tls_sink, tls_stream) = self.framed_tls.split();

        let mut peer_builder = OwnedChanTargetBuilder::default();
        if let Some(target_method) = self.target_method {
            if let Some(addrs) = target_method.socket_addrs() {
                peer_builder.addrs(addrs.to_owned());
            }
            peer_builder.method(target_method);
        }
        let peer_id = peer_builder
            .ed_identity(self.ed25519_id)
            .rsa_identity(self.rsa_id)
            .build()
            .expect("OwnedChanTarget builder failed");

        // TODO(relay): This would be the time to set a "is_canonical" flag to Channel which is
        // true if the Netinfo address matches the address we are connected to. Canonical
        // definition is if the address we are connected to is what we expect it to be. This only
        // makes sense for relay channels.

        super::Channel::new(
            self.channel_type,
            self.link_protocol,
            Box::new(tls_sink),
            Box::new(tls_stream),
            stream_ops,
            self.unique_id,
            peer_id,
            self.clock_skew,
            self.sleep_prov,
            self.memquota,
        )
    }
}

/// Helper: Calculate a clock skew from the [msg::Netinfo] cell data and the time at which we sent
/// the [msg::Versions] cell.
///
/// This is unauthenticated as in not validated with the certificates. Before using it, make sure
/// that you have authenticated the other party.
pub(crate) fn unauthenticated_clock_skew(
    netinfo_cell: &msg::Netinfo,
    netinfo_rcvd_at: coarsetime::Instant,
    versions_flushed_at: coarsetime::Instant,
    versions_flushed_wallclock: SystemTime,
) -> ClockSkew {
    // Try to compute our clock skew.  It won't be authenticated yet, since we haven't checked
    // the certificates.
    if let Some(netinfo_timestamp) = netinfo_cell.timestamp() {
        let delay = netinfo_rcvd_at - versions_flushed_at;
        ClockSkew::from_handshake_timestamps(
            versions_flushed_wallclock,
            netinfo_timestamp,
            delay.into(),
        )
    } else {
        ClockSkew::None
    }
}

#[cfg(test)]
pub(super) mod test {
    #![allow(clippy::unwrap_used)]
    use hex_literal::hex;
    use regex::Regex;
    use std::time::{Duration, SystemTime};

    use super::*;
    use crate::Result;
    use crate::channel::handler::test::MsgBuf;
    use crate::util::fake_mq;
    use tor_cell::chancell::msg;
    use tor_linkspec::OwnedChanTarget;
    use tor_rtcompat::{PreferredRuntime, Runtime};

    const VERSIONS: &[u8] = &hex!("0000 07 0006 0003 0004 0005");
    // no certificates in this cell, but connect() doesn't care.
    const NOCERTS: &[u8] = &hex!("00000000 81 0001 00");
    const NETINFO_PREFIX: &[u8] = &hex!(
        "00000000 08 00000000
         04 04 7f 00 00 02
         01
         04 04 7f 00 00 03"
    );
    const NETINFO_PREFIX_WITH_TIME: &[u8] = &hex!(
        "00000000 08 48949290
         04 04 7f 00 00 02
         01
         04 04 7f 00 00 03"
    );
    const AUTHCHALLENGE: &[u8] = &hex!(
        "00000000 82 0026
         FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
         FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
         0002 0003 00ff"
    );

    const VPADDING: &[u8] = &hex!("00000000 80 0003 FF FF FF");

    fn add_padded(buf: &mut Vec<u8>, cell: &[u8]) {
        let len_prev = buf.len();
        buf.extend_from_slice(cell);
        buf.resize(len_prev + 514, 0);
    }
    fn add_netinfo(buf: &mut Vec<u8>) {
        add_padded(buf, NETINFO_PREFIX);
    }

    #[test]
    fn connect_ok() -> Result<()> {
        tor_rtcompat::test_with_one_runtime!(|rt| async move {
            let now = humantime::parse_rfc3339("2008-08-02T17:00:00Z").unwrap();
            let mut buf = Vec::new();
            // versions cell
            buf.extend_from_slice(VERSIONS);
            // certs cell -- no certs in it, but this function doesn't care.
            buf.extend_from_slice(NOCERTS);
            // netinfo cell -- quite minimal.
            add_padded(&mut buf, NETINFO_PREFIX);
            let mb = MsgBuf::new(&buf[..]);
            let handshake = ClientInitiatorHandshake::new(mb, None, rt.clone(), fake_mq());
            let unverified = handshake.connect(|| now).await?;

            assert_eq!(unverified.link_protocol, 5);
            // No timestamp in the NETINFO, so no skew.
            assert_eq!(unverified.clock_skew(), ClockSkew::None);

            // Try again with some padding.
            let mut buf = Vec::new();
            buf.extend_from_slice(VERSIONS);
            buf.extend_from_slice(NOCERTS);
            buf.extend_from_slice(VPADDING);
            buf.extend_from_slice(AUTHCHALLENGE);
            buf.extend_from_slice(VPADDING);
            add_padded(&mut buf, NETINFO_PREFIX_WITH_TIME);
            let mb = MsgBuf::new(&buf[..]);
            let handshake = ClientInitiatorHandshake::new(mb, None, rt.clone(), fake_mq());
            let unverified = handshake.connect(|| now).await?;
            // Correct timestamp in the NETINFO, so no skew.
            assert_eq!(unverified.clock_skew(), ClockSkew::None);

            // Now pretend our clock is fast.
            let now2 = now + Duration::from_secs(3600);
            let mb = MsgBuf::new(&buf[..]);
            let handshake = ClientInitiatorHandshake::new(mb, None, rt.clone(), fake_mq());
            let unverified = handshake.connect(|| now2).await?;
            assert_eq!(
                unverified.clock_skew(),
                ClockSkew::Fast(Duration::from_secs(3600))
            );

            Ok(())
        })
    }

    async fn connect_err<T: Into<Vec<u8>>, S>(input: T, sleep_prov: S) -> Error
    where
        S: CoarseTimeProvider + SleepProvider,
    {
        let mb = MsgBuf::new(input);
        let handshake = ClientInitiatorHandshake::new(mb, None, sleep_prov, fake_mq());
        handshake.connect(SystemTime::now).await.err().unwrap()
    }

    #[test]
    fn connect_badver() {
        tor_rtcompat::test_with_one_runtime!(|rt| async move {
            let err = connect_err(&b"HTTP://"[..], rt.clone()).await;
            assert!(matches!(err, Error::HandshakeProto(_)));
            assert_eq!(
                format!("{}", err),
                "Handshake protocol violation: Invalid CircID in variable cell"
            );

            let err = connect_err(&hex!("0000 07 0004 1234 ffff")[..], rt.clone()).await;
            assert!(matches!(err, Error::HandshakeProto(_)));
            assert_eq!(
                format!("{}", err),
                "Handshake protocol violation: No shared link protocols"
            );
        });
    }

    #[test]
    fn connect_cellparse() {
        tor_rtcompat::test_with_one_runtime!(|rt| async move {
            let mut buf = Vec::new();
            buf.extend_from_slice(VERSIONS);
            // Here's a certs cell that will fail.
            buf.extend_from_slice(&hex!("00000000 81 0001 01")[..]);
            let err = connect_err(buf, rt.clone()).await;
            assert!(matches!(err, Error::HandshakeProto { .. }));
        });
    }

    #[test]
    fn connect_duplicates() {
        tor_rtcompat::test_with_one_runtime!(|rt| async move {
            let mut buf = Vec::new();
            buf.extend_from_slice(VERSIONS);
            buf.extend_from_slice(NOCERTS);
            buf.extend_from_slice(NOCERTS);
            add_netinfo(&mut buf);
            let err = connect_err(buf, rt.clone()).await;
            assert!(matches!(err, Error::HandshakeProto(_)));
            assert_eq!(
                format!("{}", err),
                "Handshake protocol violation: Duplicate CERTS cell"
            );

            let mut buf = Vec::new();
            buf.extend_from_slice(VERSIONS);
            buf.extend_from_slice(NOCERTS);
            buf.extend_from_slice(AUTHCHALLENGE);
            buf.extend_from_slice(AUTHCHALLENGE);
            add_netinfo(&mut buf);
            let err = connect_err(buf, rt.clone()).await;
            assert!(matches!(err, Error::HandshakeProto(_)));
            assert_eq!(
                format!("{}", err),
                "Handshake protocol violation: Duplicate AUTH_CHALLENGE cell"
            );
        });
    }

    #[test]
    fn connect_missing_certs() {
        tor_rtcompat::test_with_one_runtime!(|rt| async move {
            let mut buf = Vec::new();
            buf.extend_from_slice(VERSIONS);
            add_netinfo(&mut buf);
            let err = connect_err(buf, rt.clone()).await;
            assert!(matches!(err, Error::HandshakeProto(_)));
            assert_eq!(
                format!("{}", err),
                "Handshake protocol violation: Missing CERTS cell"
            );
        });
    }

    #[test]
    fn connect_missing_netinfo() {
        tor_rtcompat::test_with_one_runtime!(|rt| async move {
            let mut buf = Vec::new();
            buf.extend_from_slice(VERSIONS);
            buf.extend_from_slice(NOCERTS);
            let err = connect_err(buf, rt.clone()).await;
            assert!(matches!(err, Error::HandshakeProto(_)));
            assert_eq!(
                format!("{}", err),
                "Handshake protocol violation: Missing NETINFO cell"
            );
        });
    }

    #[test]
    fn connect_misplaced_cell() {
        tor_rtcompat::test_with_one_runtime!(|rt| async move {
            let mut buf = Vec::new();
            buf.extend_from_slice(VERSIONS);
            // here's a create cell.
            add_padded(&mut buf, &hex!("00000001 01")[..]);
            let err = connect_err(buf, rt.clone()).await;
            assert!(matches!(err, Error::HandshakeProto(_)));
            assert_eq!(
                format!("{}", err),
                "Handshake protocol violation: Decoding cell error: Error while parsing channel cell: Bad object: Unexpected command CREATE in HandshakeRelayResponderMsg"
            );
        });
    }

    fn make_unverified<R>(certs: msg::Certs, runtime: R) -> UnverifiedChannel<MsgBuf, R>
    where
        R: Runtime,
    {
        let localhost = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let netinfo_cell = msg::Netinfo::from_client(Some(localhost));
        let mut framed_tls = new_frame(MsgBuf::new(&b""[..]), ChannelType::ClientInitiator);
        let _ = framed_tls.codec_mut().set_link_version(4);
        let _ = framed_tls.codec_mut().set_open();
        let clock_skew = ClockSkew::None;
        UnverifiedChannel {
            channel_type: ChannelType::ClientInitiator,
            link_protocol: 4,
            framed_tls,
            certs_cell: certs,
            netinfo_cell,
            auth_challenge_cell: None,
            clock_skew,
            target_method: None,
            unique_id: UniqId::new(),
            sleep_prov: runtime,
            memquota: fake_mq(),
            #[cfg(feature = "relay")]
            identities: None,
        }
    }

    // Timestamp when the example certificates were all valid.
    fn cert_timestamp() -> SystemTime {
        use humantime::parse_rfc3339;
        parse_rfc3339("2020-09-26T18:01:20Z").unwrap()
    }

    fn certs_test<R>(
        certs: msg::Certs,
        when: Option<SystemTime>,
        peer_ed: &[u8],
        peer_rsa: &[u8],
        peer_cert_sha256: &[u8],
        runtime: &R,
    ) -> Result<VerifiedChannel<MsgBuf, R>>
    where
        R: Runtime,
    {
        let unver = make_unverified(certs, runtime.clone());
        let ed = Ed25519Identity::from_bytes(peer_ed).unwrap();
        let rsa = RsaIdentity::from_bytes(peer_rsa).unwrap();
        let chan = OwnedChanTarget::builder()
            .ed_identity(ed)
            .rsa_identity(rsa)
            .build()
            .unwrap();
        unver.check_internal(&chan, peer_cert_sha256, when)
    }

    // no certs at all!
    #[test]
    fn certs_none() {
        let rt = PreferredRuntime::create().unwrap();
        let err = certs_test(
            msg::Certs::new_empty(),
            None,
            &[0_u8; 32],
            &[0_u8; 20],
            &[0_u8; 128],
            &rt,
        )
        .err()
        .unwrap();
        assert_eq!(
            format!("{}", err),
            "Handshake protocol violation: Missing IDENTITY_V_SIGNING certificate"
        );
    }

    #[test]
    fn certs_good() {
        let rt = PreferredRuntime::create().unwrap();
        let mut certs = msg::Certs::new_empty();

        certs.push_cert_body(2.into(), certs::CERT_T2);
        certs.push_cert_body(5.into(), certs::CERT_T5);
        certs.push_cert_body(7.into(), certs::CERT_T7);
        certs.push_cert_body(4.into(), certs::CERT_T4);
        let res = certs_test(
            certs,
            Some(cert_timestamp()),
            certs::PEER_ED,
            certs::PEER_RSA,
            certs::PEER_CERT_DIGEST,
            &rt,
        );
        let _ = res.unwrap();
    }

    #[test]
    fn certs_missing() {
        let rt = PreferredRuntime::create().unwrap();
        let all_certs = [
            (2, certs::CERT_T2, "Couldn't find RSA identity key"),
            (7, certs::CERT_T7, "No RSA->Ed crosscert"),
            (4, certs::CERT_T4, "Missing IDENTITY_V_SIGNING certificate"),
            (5, certs::CERT_T5, "Missing SIGNING_V_TLS_CERT certificate"),
        ];

        for omit_idx in 0..4 {
            // build a certs cell with all but one certificate
            let mut certs = msg::Certs::new_empty();
            let mut expect_err = None;
            for (idx, (ctype, cert, err)) in all_certs.iter().enumerate() {
                if idx == omit_idx {
                    expect_err = Some(err);
                    continue;
                }

                certs.push_cert_body((*ctype).into(), &cert[..]);
            }
            let res = certs_test(
                certs,
                Some(cert_timestamp()),
                certs::PEER_ED,
                certs::PEER_RSA,
                certs::PEER_CERT_DIGEST,
                &rt,
            )
            .err()
            .unwrap();

            assert_eq!(
                format!("{}", res),
                format!("Handshake protocol violation: {}", expect_err.unwrap())
            );
        }
    }

    #[test]
    fn certs_wrongtarget() {
        let rt = PreferredRuntime::create().unwrap();
        let mut certs = msg::Certs::new_empty();
        certs.push_cert_body(2.into(), certs::CERT_T2);
        certs.push_cert_body(5.into(), certs::CERT_T5);
        certs.push_cert_body(7.into(), certs::CERT_T7);
        certs.push_cert_body(4.into(), certs::CERT_T4);
        let err = certs_test(
            certs.clone(),
            Some(cert_timestamp()),
            &[0x10; 32],
            certs::PEER_RSA,
            certs::PEER_CERT_DIGEST,
            &rt,
        )
        .err()
        .unwrap();

        let re = Regex::new(
            // identities might be scrubbed by safelog
            r"Identity .* does not match target .*",
        )
        .unwrap();
        assert!(re.is_match(&format!("{}", err)));

        let err = certs_test(
            certs.clone(),
            Some(cert_timestamp()),
            certs::PEER_ED,
            &[0x99; 20],
            certs::PEER_CERT_DIGEST,
            &rt,
        )
        .err()
        .unwrap();

        let re = Regex::new(
            // identities might be scrubbed by safelog
            r"Identity .* does not match target .*",
        )
        .unwrap();
        assert!(re.is_match(&format!("{}", err)));

        let err = certs_test(
            certs,
            Some(cert_timestamp()),
            certs::PEER_ED,
            certs::PEER_RSA,
            &[0; 32],
            &rt,
        )
        .err()
        .unwrap();

        assert_eq!(
            format!("{}", err),
            "Handshake protocol violation: Peer cert did not authenticate TLS cert"
        );
    }

    #[test]
    fn certs_badsig() {
        let rt = PreferredRuntime::create().unwrap();
        fn munge(inp: &[u8]) -> Vec<u8> {
            let mut v: Vec<u8> = inp.into();
            v[inp.len() - 1] ^= 0x10;
            v
        }
        let mut certs = msg::Certs::new_empty();
        certs.push_cert_body(2.into(), certs::CERT_T2);
        certs.push_cert_body(5.into(), munge(certs::CERT_T5)); // munge an ed signature
        certs.push_cert_body(7.into(), certs::CERT_T7);
        certs.push_cert_body(4.into(), certs::CERT_T4);
        let res = certs_test(
            certs,
            Some(cert_timestamp()),
            certs::PEER_ED,
            certs::PEER_RSA,
            certs::PEER_CERT_DIGEST,
            &rt,
        )
        .err()
        .unwrap();

        assert_eq!(
            format!("{}", res),
            "Handshake protocol violation: Invalid ed25519 signature in handshake"
        );

        let mut certs = msg::Certs::new_empty();
        certs.push_cert_body(2.into(), certs::CERT_T2);
        certs.push_cert_body(5.into(), certs::CERT_T5);
        certs.push_cert_body(7.into(), munge(certs::CERT_T7)); // munge an RSA signature
        certs.push_cert_body(4.into(), certs::CERT_T4);
        let res = certs_test(
            certs,
            Some(cert_timestamp()),
            certs::PEER_ED,
            certs::PEER_RSA,
            certs::PEER_CERT_DIGEST,
            &rt,
        )
        .err()
        .unwrap();

        assert_eq!(
            format!("{}", res),
            "Handshake protocol violation: Bad RSA->Ed crosscert signature"
        );
    }

    /// This module has a few certificates to play with. They're taken
    /// from a chutney network. They match those used in the CERTS
    /// cell test vector in the tor-cell crate.
    ///
    /// The names are taken from the type of the certificate.
    mod certs {
        use hex_literal::hex;

        pub(crate) const CERT_T2: &[u8] = &hex!(
            "308201B930820122A0030201020208607C28BE6C390943300D06092A864886F70D01010B0500301F311D301B06035504030C147777772E74636A76356B766A646472322E636F6D301E170D3230303831303030303030305A170D3231303831303030303030305A301F311D301B06035504030C147777772E74636A76356B766A646472322E636F6D30819F300D06092A864886F70D010101050003818D0030818902818100D38B1E6CEB946E0DB0751F4CBACE3DCB9688B6C25304227B4710C35AFB73627E50500F5913E158B621802612D1C75827003703338375237552EB3CD3C12F6AB3604E60C1A2D26BB1FBAD206FF023969A90909D6A65A5458A5312C26EBD3A3DAD30302D4515CDCD264146AC18E6FC60A04BD3EC327F04294D96BA5AA25B464C3F0203010001300D06092A864886F70D01010B0500038181003BCE561EA7F95CC00B78AAB5D69573FF301C282A751D4A651921D042F1BECDBA24D918A6D8A5E138DC07BBA0B335478AE37ABD2C93A93932442AE9084329E846170FE0FC4A50AAFC804F311CC3CA4F41D845A7BA5901CBBC3E021E9794AAC70CE1F37B0A951592DB1B64F2B4AFB81AE52DBD9B6FEDE96A5FB8125EB6251EE50A"
        );

        pub(crate) const CERT_T4: &[u8] = &hex!(
            "01040006CC2A01F82294B866A31F01FC5D0DA8572850A9B929545C3266558D7D2316E3B74172B00100200400DCB604DB2034B00FD16986D4ADB9D16B21CB4E4457A33DEC0F538903683E96E9FF1A5203FA27F86EF7528D89A0845D2520166E340754FFEA2AAE0F612B7CE5DA094A0236CDAC45034B0B6842C18E7F6B51B93A3CF7E60663B8AD061C30A62602"
        );
        pub(crate) const CERT_T5: &[u8] = &hex!(
            "01050006C98A03B4FD606B64E4CBD466B8D76CB131069BAE6F3AA1878857C9F624E31D77A799B8007173E5F8068431D0D3F5EE16B4C9FFD59DF373E152A87281BAE744AA5FCF72171BF4B27C4E8FC1C6A9FC5CA11058BC49647063D7903CFD9F512F89099B27BC0C"
        );

        pub(crate) const CERT_T7: &[u8] = &hex!(
            "DCB604DB2034B00FD16986D4ADB9D16B21CB4E4457A33DEC0F538903683E96E90006DA3A805CF6006F9179066534DE6B45AD47A5C469063EE462762723396DC9F25452A0A52DA3F5087DD239F2A311F6B0D4DFEFF4ABD089DC3D0237A0ABAB19EB2045B91CDCAF04BE0A72D548A27BF2E77BD876ECFE5E1BE622350DA6BF31F6E306ED896488DD5B39409B23FC3EB7B2C9F7328EB18DA36D54D80575899EA6507CCBFCDF1F"
        );

        pub(crate) const PEER_CERT_DIGEST: &[u8] =
            &hex!("b4fd606b64e4cbd466b8d76cb131069bae6f3aa1878857c9f624e31d77a799b8");

        pub(crate) const PEER_ED: &[u8] =
            &hex!("dcb604db2034b00fd16986d4adb9d16b21cb4e4457a33dec0f538903683e96e9");
        pub(crate) const PEER_RSA: &[u8] = &hex!("2f1fb49bb332a9eec617e41e911c33fb3890aef3");
    }

    #[test]
    fn test_finish() {
        tor_rtcompat::test_with_one_runtime!(|rt| async move {
            let ed25519_id = [3_u8; 32].into();
            let rsa_id = [4_u8; 20].into();
            let peer_addr = "127.1.1.2:443".parse().unwrap();
            let mut framed_tls = new_frame(MsgBuf::new(&b""[..]), ChannelType::ClientInitiator);
            let _ = framed_tls.codec_mut().set_link_version(4);
            let ver = VerifiedChannel {
                channel_type: ChannelType::ClientInitiator,
                link_protocol: 4,
                framed_tls,
                unique_id: UniqId::new(),
                target_method: Some(ChannelMethod::Direct(vec![peer_addr])),
                ed25519_id,
                rsa_id,
                clock_skew: ClockSkew::None,
                sleep_prov: rt,
                memquota: fake_mq(),
                #[cfg(feature = "relay")]
                auth_data: None,
            };

            let (_chan, _reactor) = ver.finish().await.unwrap();

            // TODO: check contents of netinfo cell
        });
    }
}
