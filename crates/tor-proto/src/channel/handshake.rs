//! Implementations for the channel handshake

use futures::io::{AsyncRead, AsyncWrite};
use futures::sink::SinkExt;
use futures::stream::{Stream, StreamExt};
use std::net::IpAddr;
use std::sync::Arc;
use tor_llcrypto::pk::ValidatableSignature;

use crate::channel::handler::AuthLogDigest;
use crate::channel::{Canonicity, ChannelFrame, UniqId};
use crate::memquota::ChannelAccount;
use crate::peer::PeerInfo;
use crate::util::skew::ClockSkew;
use crate::{Error, Result};
use safelog::{MaybeSensitive, Redacted};
use tor_cell::chancell::msg::AnyChanMsg;
use tor_cell::chancell::{AnyChanCell, ChanMsg, msg};
use tor_cell::restrict::{RestrictedMsg, restricted_msg};
use tor_cert::CertType;
use tor_checkable::{TimeValidityError, Timebound};
use tor_error::internal;
use tor_linkspec::{
    ChanTarget, ChannelMethod, OwnedChanTarget, OwnedChanTargetBuilder, RelayIds, RelayIdsBuilder,
};
use tor_llcrypto as ll;
use tor_llcrypto::pk::ed25519::Ed25519Identity;
use tor_rtcompat::{CoarseTimeProvider, SleepProvider, StreamOps};
use web_time_compat::{SystemTime, SystemTimeExt};

use digest::Digest;

use tracing::{debug, instrument, trace};

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

        Ok(link_protocol)
    }

    /// Given a link protocol version, set it into our channel cell handler. All channel type do
    /// this after negotiating a [`msg::Versions`] cell.
    ///
    /// This will effectively transition the handler's state from New to Handshake.
    fn set_link_protocol(&mut self, link_protocol: u16) -> Result<()> {
        self.framed_tls()
            .codec_mut()
            .set_link_version(link_protocol)
    }
}

/// Helper: This enum is for adding semantic to the function receiving cells indicating it to
/// either take the auth log out or leave it in place.
///
/// With this, we avoid using a flat bool which is confusing at the call site.
pub(crate) enum AuthLogAction {
    /// Leave it in place.
    Leave,
    /// Take it out.
    Take,
}

impl AuthLogAction {
    /// Return true iff this value is [`AuthLogAction::Take`]
    fn is_take(&self) -> bool {
        matches!(self, Self::Take)
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
    /// As an initiator, we are expecting the responder's cells which are:
    /// - [msg::Certs]
    /// - [msg::AuthChallenge]
    /// - [msg::Netinfo]
    ///
    /// Any duplicate, missing cell or unexpected results in a protocol level error.
    ///
    /// This returns the:
    /// - [msg::AuthChallenge] cell
    /// - [msg::Certs] cell
    /// - [msg::Netinfo] cell
    /// - the instant when the netinfo cell was received (needed for the clock skew calculation)
    /// - the SLOG digest if `auth_log_action` is [`AuthLogAction::Take`] (needed if we send an
    ///   [msg::Authenticate] cell in the future)
    async fn recv_cells_from_responder(
        &mut self,
        auth_log_action: AuthLogAction,
    ) -> Result<(
        msg::AuthChallenge,
        msg::Certs,
        (msg::Netinfo, coarsetime::Instant),
        Option<AuthLogDigest>,
    )> {
        // IMPORTANT: Protocol wise, we MUST only allow one single cell of each type for a valid
        // handshake. Any duplicates lead to a failure.
        // They must arrive in a specific order in order for the SLOG calculation to be valid.

        /// Read a message from the stream.
        ///
        /// The `expecting` parameter is used for logging purposes, not filtering.
        async fn read_msg<T>(
            stream_id: UniqId,
            mut stream: impl Stream<Item = Result<AnyChanCell>> + Unpin,
        ) -> Result<T>
        where
            T: RestrictedMsg + TryFrom<AnyChanMsg, Error = AnyChanMsg>,
        {
            let Some(cell) = stream.next().await.transpose()? else {
                // The entire channel has ended, so nothing else to be done.
                return Err(Error::HandshakeProto("Stream ended unexpectedly".into()));
            };

            let (id, m) = cell.into_circid_and_msg();
            trace!(%stream_id, "received a {} cell", m.cmd());

            // TODO: Maybe also check this in the channel handshake codec?
            if let Some(id) = id {
                return Err(Error::HandshakeProto(format!(
                    "Expected no circ ID for {} cell, but received circ ID of {id} instead",
                    m.cmd(),
                )));
            }

            let m = m.try_into().map_err(|m: AnyChanMsg| {
                Error::HandshakeProto(format!(
                    "Expected [{}] cell, but received {} cell instead",
                    tor_basic_utils::iter_join(", ", T::cmds_for_logging().iter()),
                    m.cmd(),
                ))
            })?;

            Ok(m)
        }

        // Note that the `ChannelFrame` already restricts the messages due to its handshake cell
        // handler.

        let certs = loop {
            restricted_msg! {
                enum CertsMsg : ChanMsg {
                    // VPADDING cells (but not PADDING) can be sent during handshaking.
                    Vpadding,
                    Certs,
               }
            }

            break match read_msg(*self.unique_id(), self.framed_tls()).await? {
                CertsMsg::Vpadding(_) => continue,
                CertsMsg::Certs(msg) => msg,
            };
        };

        // Clients don't care about AuthChallenge,
        // but the responder always sends it anyways so we require it here.
        let auth_challenge = loop {
            restricted_msg! {
                enum AuthChallengeMsg : ChanMsg {
                    // VPADDING cells (but not PADDING) can be sent during handshaking.
                    Vpadding,
                    AuthChallenge,
               }
            }

            break match read_msg(*self.unique_id(), self.framed_tls()).await? {
                AuthChallengeMsg::Vpadding(_) => continue,
                AuthChallengeMsg::AuthChallenge(msg) => msg,
            };
        };

        let slog_digest = if auth_log_action.is_take() {
            // We're the initiator, which means that the recv log is the SLOG.
            Some(self.framed_tls().codec_mut().take_recv_log_digest()?)
        } else {
            None
        };

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

        Ok((
            auth_challenge,
            certs,
            (netinfo, netinfo_rcvd_at),
            slog_digest,
        ))
    }
}

/// A base channel on which versions have been negotiated and the relay's handshake has been read,
/// but where the certs have not been checked.
///
/// Both relay and client have specialized objects for an unverified channel which include this one
/// as the base in order to share functionalities.
pub(crate) struct UnverifiedChannel<
    T: AsyncRead + AsyncWrite + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
> {
    /// Runtime handle (insofar as we need it)
    pub(crate) sleep_prov: S,
    /// Memory quota account
    pub(crate) memquota: ChannelAccount,
    /// The negotiated link protocol.  Must be a member of LINK_PROTOCOLS
    pub(crate) link_protocol: u16,
    /// The Source+Sink on which we're reading and writing cells.
    pub(crate) framed_tls: ChannelFrame<T>,
    /// Declared target method for this channel, if any.
    pub(crate) target_method: Option<ChannelMethod>,
    /// How much clock skew did we detect in this handshake?
    ///
    /// This value is _unauthenticated_, since we have not yet checked whether
    /// the keys in the handshake are the ones we expected.
    pub(crate) clock_skew: ClockSkew,
    /// Logging identifier for this stream.  (Used for logging only.)
    pub(crate) unique_id: UniqId,
}

/// A base initiator channel on which versions have been negotiated and the relay's handshake has
/// been read, but where the [`msg::Certs`] has not been checked.
///
/// Both relay and client have specialized objects for an unverified channel which include this one
/// as the base in order to share functionnalities.
///
/// We need this intermediary object between the specialized one (client/relay) and the
/// [`UnverifiedChannel`] because certs validation is quite different from a respodner channel.
/// This avoid code duplication.
pub(crate) struct UnverifiedInitiatorChannel<
    T: AsyncRead + AsyncWrite + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
> {
    /// Base unverified channel.
    pub(crate) inner: UnverifiedChannel<T, S>,
    /// The [`msg::Certs`] received during the handshake.
    pub(crate) certs_cell: msg::Certs,
}

/// A base channel on which versions have been negotiated, relay's handshake has been read, but the
/// client has not yet finished the handshake.
///
/// This type is separate from UnverifiedChannel, since finishing the handshake requires a bunch of
/// CPU, and you might want to do it as a separate task or after a yield.
///
/// Both relay and client have specialized objects for an unverified channel which include this one
/// as the base in order to share functionalities.
pub(crate) struct VerifiedChannel<
    T: AsyncRead + AsyncWrite + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
> {
    /// Runtime handle (insofar as we need it)
    pub(crate) sleep_prov: S,
    /// Memory quota account
    pub(crate) memquota: ChannelAccount,
    /// The negotiated link protocol.
    pub(crate) link_protocol: u16,
    /// The Source+Sink on which we're reading and writing cells.
    pub(crate) framed_tls: ChannelFrame<T>,
    /// Declared target method for this stream, if any.
    pub(crate) target_method: Option<ChannelMethod>,
    /// Logging identifier for this stream.  (Used for logging only.)
    pub(crate) unique_id: UniqId,
    /// Verified peer identities
    pub(crate) relay_ids: RelayIds,
    /// Validated RSA identity digest of the DER format for this peer.
    pub(crate) rsa_id_digest: [u8; 32],
    /// Authenticated clock skew for this peer.
    pub(crate) clock_skew: ClockSkew,
}

impl<
    T: AsyncRead + AsyncWrite + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
> UnverifiedChannel<T, S>
{
    /// Return a newly constructed [`VerifiedChannel`].
    pub(crate) fn into_verified(
        self,
        relay_ids: RelayIds,
        rsa_id_digest: [u8; 32],
    ) -> VerifiedChannel<T, S> {
        VerifiedChannel {
            link_protocol: self.link_protocol,
            framed_tls: self.framed_tls,
            unique_id: self.unique_id,
            target_method: self.target_method,
            relay_ids,
            rsa_id_digest,
            clock_skew: self.clock_skew,
            sleep_prov: self.sleep_prov,
            memquota: self.memquota,
        }
    }

    /// This validates the relay identities (Ed25519 and RSA) and signing key cert (Ed25519).
    /// Successful validation returns the relay ed25519 identitiy key, the ed25519 signing key and
    /// the RSA public key.
    ///
    /// Reason for the RSA public key is because the caller needs to the SHA256 digest for the
    /// [`msg::Authenticate`] cell.
    pub(crate) fn check_relay_identities<U: ChanTarget + ?Sized>(
        &self,
        peer: &U,
        certs: &msg::Certs,
        now: SystemTime,
    ) -> Result<(RelayIds, Ed25519Identity, [u8; 32])> {
        use tor_checkable::*;

        // Get the identity signing cert (CertType 4).
        let id_sk = get_cert(certs, CertType::IDENTITY_V_SIGNING)?;

        // Check the identity->signing cert
        let (id_sk, id_sk_sig) = id_sk
            .should_have_signing_key()
            .map_err(Error::HandshakeCertErr)?
            .dangerously_split()
            .map_err(Error::HandshakeCertErr)?;
        let (id_sk_timeliness, id_sk) = check_cert_timeliness(id_sk, now, self.clock_skew);

        // Make sure the ed25519 identity cert is well signed before parsing more data.
        if !id_sk_sig.is_valid() {
            return Err(Error::HandshakeProto(
                "Invalid ed25519 identity cert signature in handshake".into(),
            ));
        }

        // Take the identity key from the identity->signing cert
        let identity_key = id_sk.signing_key().ok_or_else(|| {
            Error::HandshakeProto("Missing identity key in identity->signing cert".into())
        })?;

        // Take the signing key from the identity->signing cert
        let signing_key = id_sk.subject_key().as_ed25519().ok_or_else(|| {
            Error::HandshakeProto("Bad key type in identity->signing cert".into())
        })?;

        // What is the RSA identity key, according to the X.509 certificate
        // in which it is self-signed?
        //
        // (We don't actually check this self-signed certificate, and we use
        // a kludge to extract the RSA key)
        let rsa_id_cert_bytes = certs
            .cert_body(CertType::RSA_ID_X509)
            .ok_or_else(|| Error::HandshakeProto("Couldn't find RSA identity cert".into()))?;
        let pkrsa =
            ll::util::x509_extract_rsa_subject_kludge(rsa_id_cert_bytes).ok_or_else(|| {
                Error::HandshakeProto(
                    "Couldn't find RSA SubjectPublicKey from RSA identity cert".into(),
                )
            })?;

        // Now verify the RSA identity -> Ed Identity crosscert.
        //
        // This proves that the RSA key vouches for the Ed key.  Note that
        // the Ed key does not vouch for the RSA key: The RSA key is too
        // weak.
        let rsa_cert = certs
            .cert_body(CertType::RSA_ID_V_IDENTITY)
            .ok_or_else(|| Error::HandshakeProto("No RSA->Ed crosscert".into()))?;
        let rsa_cert = tor_cert::rsa::RsaCrosscert::decode(rsa_cert)
            .map_err(|e| Error::from_bytes_err(e, "RSA identity cross-certificate"))?
            .check_signature(&pkrsa)
            .map_err(|_| Error::HandshakeProto("Bad RSA->Ed crosscert signature".into()))?;
        let (rsa_cert_timeliness, rsa_cert) = check_cert_timeliness(rsa_cert, now, self.clock_skew);

        if !rsa_cert.subject_key_matches(identity_key) {
            return Err(Error::HandshakeProto(
                "RSA->Ed crosscert certifies incorrect key".into(),
            ));
        }

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
        rsa_cert_timeliness?;

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
            .rsa_identity(pkrsa.to_rsa_identity())
            .build()
            .expect("Unable to build RelayIds");

        // We enforce that the relay proved that it has every ID that we wanted:
        // it may also have additional IDs that we didn't ask for.
        match super::check_id_match_helper(&actual_identity, peer) {
            Err(Error::ChanMismatch(msg)) => Err(Error::HandshakeProto(msg)),
            other => other,
        }?;

        let rsa_id_digest: [u8; 32] = ll::d::Sha256::digest(pkrsa.to_der()).into();

        Ok((actual_identity, *signing_key, rsa_id_digest))
    }

    /// Finalize this channel into an actual channel and its reactor.
    ///
    /// An unverified channel can be finalized as it skipped the cert verification and
    /// authentication because simply the other side is not authenticating.
    ///
    /// Two cases for this:
    ///     - Client <-> Relay channel
    ///     - Bridge <-> Relay channel
    ///
    // NOTE: Unfortunately, this function has duplicated code with the VerifiedChannel::finish()
    // so make sure any changes here is reflected there. A proper refactoring is welcome!
    #[instrument(skip_all, level = "trace")]
    pub(crate) fn finish(
        mut self,
        netinfo: &msg::Netinfo,
        my_addrs: &[IpAddr],
        peer_info: MaybeSensitive<PeerInfo>,
    ) -> Result<(Arc<super::Channel>, super::reactor::Reactor<S>)> {
        // We treat a completed channel as incoming traffic since all cells were exchanged.
        //
        // TODO: conceivably we should remember the time when we _got_ the
        // final cell on the handshake, and update the channel completion
        // time to be no earlier than _that_ timestamp.
        //
        // TODO: This shouldn't be here. This should be called in the trait functions that actually
        // receives the data (recv_*). We'll move it at a later commit.
        crate::note_incoming_traffic();

        // We have finalized the handshake, move our codec to Open.
        self.framed_tls.codec_mut().set_open()?;

        // Grab the channel type from our underlying frame as we are about to consume the
        // framed_tls and we need the channel type to be set into the resulting Channel.
        let channel_type = self.framed_tls.codec().channel_type();

        // Grab a new handle on which we can apply StreamOps (needed for KIST).
        // On Unix platforms, this handle is a wrapper over the fd of the socket.
        //
        // Note: this is necessary because after `StreamExit::split()`,
        // we no longer have access to the underlying stream
        // or its StreamOps implementation.
        let stream_ops = self.framed_tls.new_handle();
        let (tls_sink, tls_stream) = self.framed_tls.split();

        let canonicity =
            Canonicity::from_netinfo(netinfo, my_addrs, peer_info.addr().netinfo_addr());

        let peer_id = build_filtered_chan_target(self.target_method.take(), &peer_info);

        debug!(
            stream_id = %self.unique_id,
            "Completed handshake without authentication to {}", Redacted::new(&peer_id)
        );

        super::Channel::new(
            channel_type,
            self.link_protocol,
            Box::new(tls_sink),
            Box::new(tls_stream),
            stream_ops,
            self.unique_id,
            peer_id,
            peer_info,
            self.clock_skew,
            self.sleep_prov,
            self.memquota,
            canonicity,
        )
    }
}

impl<
    T: AsyncRead + AsyncWrite + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
> VerifiedChannel<T, S>
{
    /// Mark this channel as authenticated.
    pub(crate) fn set_authenticated(&mut self) -> Result<()> {
        self.framed_tls.codec_mut().set_authenticated()?;
        Ok(())
    }

    /// Return our [`RelayIds`] corresponding to this channel identities.
    pub(crate) fn relay_ids(&self) -> &RelayIds {
        &self.relay_ids
    }

    /// The channel is used to send cells, and to create outgoing circuits.
    /// The reactor is used to route incoming messages to their appropriate
    /// circuit.
    #[instrument(skip_all, level = "trace")]
    pub(crate) async fn finish(
        mut self,
        netinfo: &msg::Netinfo,
        my_addrs: &[IpAddr],
        peer_info: MaybeSensitive<PeerInfo>,
    ) -> Result<(Arc<super::Channel>, super::reactor::Reactor<S>)> {
        // We treat a completed channel -- that is to say, one where the
        // authentication is finished -- as incoming traffic.
        //
        // TODO: conceivably we should remember the time when we _got_ the
        // final cell on the handshake, and update the channel completion
        // time to be no earlier than _that_ timestamp.
        //
        // TODO: This shouldn't be here. This should be called in the trait functions that actually
        // receives the data (recv_*). We'll move it at a later commit.
        crate::note_incoming_traffic();

        // We have finalized the handshake, move our codec to Open.
        self.framed_tls.codec_mut().set_open()?;

        // Grab the channel type from our underlying frame as we are about to consume the
        // framed_tls and we need the channel type to be set into the resulting Channel.
        let channel_type = self.framed_tls.codec().channel_type();

        debug!(
            stream_id = %self.unique_id,
            "Completed handshake with peer: {}", peer_info
        );

        // Grab a new handle on which we can apply StreamOps (needed for KIST).
        // On Unix platforms, this handle is a wrapper over the fd of the socket.
        //
        // Note: this is necessary because after `StreamExit::split()`,
        // we no longer have access to the underlying stream
        // or its StreamOps implementation.
        let stream_ops = self.framed_tls.new_handle();
        let (tls_sink, tls_stream) = self.framed_tls.split();

        let canonicity =
            Canonicity::from_netinfo(netinfo, my_addrs, peer_info.addr().netinfo_addr());

        let peer_id = build_filtered_chan_target(self.target_method.take(), &peer_info);

        super::Channel::new(
            channel_type,
            self.link_protocol,
            Box::new(tls_sink),
            Box::new(tls_stream),
            stream_ops,
            self.unique_id,
            peer_id,
            peer_info,
            self.clock_skew,
            self.sleep_prov,
            self.memquota,
            canonicity,
        )
    }
}

impl<
    T: AsyncRead + AsyncWrite + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
> UnverifiedInitiatorChannel<T, S>
{
    /// Validate the TLS cert (CertType 5) located in our `certs_cell`.
    ///
    /// `peer` is the relay we want to connect to.
    ///
    /// 'peer_cert_digest' is the digest of the x.509 certificate that the peer presented during
    /// its TLS handshake (ServerHello).
    ///
    /// `kp_relaysign_ed` is the relay signing key taken from the signing cert (CertType 4). It is used
    /// to sign the TLS cert and so we use it to validate.
    ///
    /// 'now' is the time at which to check that certificates are valid.  `None` means to use the
    /// current time. It can be used for testing to override the current view of the time.
    ///
    /// The `clock_skew` is the time skew detected during the handshake.
    pub(crate) fn verify<U: ChanTarget + ?Sized>(
        self,
        peer: &U,
        peer_cert_digest: [u8; 32],
        now: Option<std::time::SystemTime>,
    ) -> Result<VerifiedChannel<T, S>> {
        use tor_cert::CertType;

        // Replace 'now' with the real time to use.
        let now = now.unwrap_or_else(SystemTime::get);

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
                .check_relay_identities(peer, &self.certs_cell, now)?;

        // Now look at the signing->TLS cert and check it against the
        // peer certificate.
        let sk_tls = get_cert(&self.certs_cell, CertType::SIGNING_V_TLS_CERT)?;
        let (sk_tls, sk_tls_sig) = sk_tls
            .should_be_signed_with(&kp_relaysign_ed)
            .map_err(Error::HandshakeCertErr)?
            .dangerously_split()
            .map_err(Error::HandshakeCertErr)?;
        let (sk_tls_timeliness, sk_tls) = check_cert_timeliness(sk_tls, now, self.inner.clock_skew);

        if peer_cert_digest != sk_tls.subject_key().as_bytes() {
            return Err(Error::HandshakeProto(
                "Peer cert did not authenticate TLS cert".into(),
            ));
        }

        // Make sure the TLS cert is well signed.
        if !sk_tls_sig.is_valid() {
            return Err(Error::HandshakeProto(
                "Invalid ed25519 TLS cert signature in handshake".into(),
            ));
        }

        // Check TLS cert timeliness.
        sk_tls_timeliness?;

        Ok(self.inner.into_verified(relay_ids, rsa_id_digest))
    }
}

/// Validate the LINK_AUTH cert (CertType 6).
///
/// `certs` is the [`msg::Certs`] cell received during the handshake.
///
/// `kp_relaysign_ed` is the relay signing ed25519 key taken from the signing cert (CertType 4). It
/// is used to sign the LINK_AUTH cert.
///
/// 'now' is the time at which to check that certificates are valid.  `None` means to use the
/// current time. It can be used for testing to override the current view of the time.
///
/// The `clock_skew` is the time skew detected during the handshake.
///
/// If verification is successful, return the peer KP_link_ed.
pub(crate) fn verify_link_auth_cert(
    certs: &msg::Certs,
    kp_relaysign_ed: &Ed25519Identity,
    now: Option<std::time::SystemTime>,
    clock_skew: ClockSkew,
) -> Result<Ed25519Identity> {
    use tor_cert::CertType;

    // Replace 'now' with the real time to use.
    let now = now.unwrap_or_else(SystemTime::get);

    // Now look at the signing->TLS cert and check it against the
    // peer certificate.
    let cert = get_cert(certs, CertType::SIGNING_V_LINK_AUTH)?;
    let (cert, cert_sig) = cert
        .should_be_signed_with(kp_relaysign_ed)
        .map_err(Error::HandshakeCertErr)?
        .dangerously_split()
        .map_err(Error::HandshakeCertErr)?;
    let (cert_timeliness, cert) = check_cert_timeliness(cert, now, clock_skew);

    // Make sure the cert is well signed.
    if cert_sig.is_valid() {
        return Err(Error::HandshakeProto(
            "Invalid ed25519 LINK_AUTH signature in handshake".into(),
        ));
    }

    // Check TLS cert timeliness.
    cert_timeliness?;

    // We are all verified, extract the subject key and return it.
    let peer_kp_link_ed = *cert
        .subject_key()
        .as_ed25519()
        .ok_or(Error::HandshakeProto(
            "Missing kp_link_ed in LINK_AUTH cert subject key".into(),
        ))?;

    Ok(peer_kp_link_ed)
}

/// Helper: given a time-bound input, give a result reflecting its
/// validity at `now`, and the inner object.
///
/// We use this here because we want to validate the whole handshake
/// regardless of whether the certs are expired, so we can determine
/// whether we got a plausible handshake with a skewed partner, or
/// whether the handshake is definitely bad.
pub(crate) fn check_cert_timeliness<C, CERT>(
    checkable: C,
    now: SystemTime,
    clock_skew: ClockSkew,
) -> (Result<()>, CERT)
where
    C: Timebound<CERT, Error = TimeValidityError>,
{
    let status = checkable
        .is_valid_at(&now)
        .map_err(|e| match (e, clock_skew) {
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

/// Helper: get a cert from our Certs cell, and convert errors appropriately.
pub(crate) fn get_cert(certs: &msg::Certs, tp: CertType) -> Result<tor_cert::KeyUnknownCert> {
    match certs.parse_ed_cert(tp) {
        Ok(c) => Ok(c),
        Err(tor_cell::Error::ChanProto(e)) => Err(Error::HandshakeProto(e)),
        Err(e) => Err(Error::HandshakeProto(e.to_string())),
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

/// Helper: Build a OwnedChanTarget that retains only the address that was actually used.
fn build_filtered_chan_target(
    target_method: Option<ChannelMethod>,
    peer_info: &MaybeSensitive<PeerInfo>,
) -> OwnedChanTarget {
    let mut peer_builder = OwnedChanTargetBuilder::default();
    if let Some(mut method) = target_method {
        // Retain only the address that was actually used to connect.
        if let Some(addr) = peer_info.addr().socket_addr() {
            let _ = method.retain_addrs(|socket_addr| socket_addr == &addr);
            peer_builder.addrs(vec![addr]);
        }
        peer_builder.method(method);
    }
    *peer_builder.ids() = RelayIdsBuilder::from_relay_ids(peer_info.ids());

    peer_builder
        .build()
        .expect("OwnedChanTarget builder failed")
}

#[cfg(test)]
pub(super) mod test {
    #![allow(clippy::unwrap_used)]
    use hex_literal::hex;
    use regex::Regex;
    use std::time::{Duration, SystemTime};
    use tor_llcrypto::pk::rsa::RsaIdentity;

    use super::*;
    use crate::channel::handler::test::MsgBuf;
    use crate::channel::{ChannelType, new_frame};
    use crate::util::fake_mq;
    use crate::{Result, channel::ClientInitiatorHandshake};
    use tor_cell::chancell::msg::{self, Netinfo};
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
            // auth_challenge cell
            buf.extend_from_slice(AUTHCHALLENGE);
            // netinfo cell -- quite minimal.
            add_padded(&mut buf, NETINFO_PREFIX);
            let mb = MsgBuf::new(&buf[..]);
            let handshake = ClientInitiatorHandshake::new(mb, None, rt.clone(), fake_mq());
            let unverified = handshake.connect(|| now).await?;

            assert_eq!(unverified.link_protocol(), 5);
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
        handshake.connect(SystemTime::get).await.err().unwrap()
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
                "Handshake protocol violation: Expected [VPADDING, AUTH_CHALLENGE] cell, but received CERTS cell instead"
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
                "Handshake protocol violation: Expected [VPADDING, NETINFO] cell, but received AUTH_CHALLENGE cell instead"
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
                "Handshake protocol violation: Expected [VPADDING, CERTS] cell, but received NETINFO cell instead"
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
                "Handshake protocol violation: Stream ended unexpectedly"
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

    fn make_unverified<R>(runtime: R) -> UnverifiedChannel<MsgBuf, R>
    where
        R: Runtime,
    {
        let mut framed_tls = new_frame(MsgBuf::new(&b""[..]), ChannelType::ClientInitiator);
        let _ = framed_tls.codec_mut().set_link_version(4);
        let _ = framed_tls.codec_mut().set_open();
        let clock_skew = ClockSkew::None;
        UnverifiedChannel {
            link_protocol: 4,
            framed_tls,
            clock_skew,
            target_method: None,
            unique_id: UniqId::new(),
            sleep_prov: runtime,
            memquota: fake_mq(),
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
        peer_cert_sha256: [u8; 32],
        runtime: &R,
    ) -> Result<VerifiedChannel<MsgBuf, R>>
    where
        R: Runtime,
    {
        let relay_ids = RelayIdsBuilder::default()
            .ed_identity(Ed25519Identity::from_bytes(peer_ed).unwrap())
            .rsa_identity(RsaIdentity::from_bytes(peer_rsa).unwrap())
            .build()
            .unwrap();
        let mut peer_builder = OwnedChanTargetBuilder::default();
        *peer_builder.ids() = RelayIdsBuilder::from_relay_ids(&relay_ids);
        let peer = peer_builder.build().unwrap();

        let unverified = UnverifiedInitiatorChannel {
            inner: make_unverified(runtime.clone()),
            certs_cell: certs,
        };
        unverified.verify(&peer, peer_cert_sha256, when)
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
            [0_u8; 32],
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
            *certs::PEER_CERT_DIGEST,
            &rt,
        );
        let _ = res.unwrap();
    }

    #[test]
    fn certs_missing() {
        let rt = PreferredRuntime::create().unwrap();
        let all_certs = [
            (2, certs::CERT_T2, "Couldn't find RSA identity cert"),
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
                *certs::PEER_CERT_DIGEST,
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
            *certs::PEER_CERT_DIGEST,
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
            *certs::PEER_CERT_DIGEST,
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
            [0; 32],
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
            *certs::PEER_CERT_DIGEST,
            &rt,
        )
        .err()
        .unwrap();

        assert_eq!(
            format!("{}", res),
            "Handshake protocol violation: Invalid ed25519 TLS cert signature in handshake"
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
            *certs::PEER_CERT_DIGEST,
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

        pub(crate) const PEER_CERT_DIGEST: &[u8; 32] =
            &hex!("b4fd606b64e4cbd466b8d76cb131069bae6f3aa1878857c9f624e31d77a799b8");

        pub(crate) const PEER_ED: &[u8] =
            &hex!("dcb604db2034b00fd16986d4adb9d16b21cb4e4457a33dec0f538903683e96e9");
        pub(crate) const PEER_RSA: &[u8] = &hex!("2f1fb49bb332a9eec617e41e911c33fb3890aef3");
    }

    #[test]
    fn test_finish() {
        tor_rtcompat::test_with_one_runtime!(|rt| async move {
            let peer_addr = "127.1.1.2:443".parse().unwrap();
            let mut framed_tls = new_frame(MsgBuf::new(&b""[..]), ChannelType::ClientInitiator);
            let _ = framed_tls.codec_mut().set_link_version(4);
            let ver = VerifiedChannel {
                link_protocol: 4,
                framed_tls,
                unique_id: UniqId::new(),
                target_method: Some(ChannelMethod::Direct(vec![peer_addr])),
                relay_ids: RelayIds::empty(),
                rsa_id_digest: [0; 32],
                clock_skew: ClockSkew::None,
                sleep_prov: rt,
                memquota: fake_mq(),
            };

            let peer_ip = peer_addr.ip();
            let netinfo = Netinfo::from_client(Some(peer_ip));

            let (_chan, _reactor) = ver
                .finish(
                    &netinfo,
                    &[],
                    MaybeSensitive::not_sensitive(PeerInfo::EMPTY),
                )
                .await
                .unwrap();

            // TODO: check contents of netinfo cell
        });
    }
}
