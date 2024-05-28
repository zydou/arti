//! Implementations for the channel handshake

use asynchronous_codec as futures_codec;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use futures::sink::SinkExt;
use futures::stream::StreamExt;
use tor_cell::restricted_msg;
use tor_error::internal;

use crate::channel::codec::{self, ChannelCodec, CodecError};
use crate::channel::UniqId;
use crate::util::skew::ClockSkew;
use crate::{Error, Result};
use tor_cell::chancell::{msg, ChanCmd, ChanMsg};
use tor_rtcompat::SleepProvider;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;

use tor_bytes::Reader;
use tor_linkspec::{ChanTarget, ChannelMethod, OwnedChanTargetBuilder, RelayIds};
use tor_llcrypto as ll;
use tor_llcrypto::pk::ed25519::Ed25519Identity;
use tor_llcrypto::pk::rsa::RsaIdentity;

use digest::Digest;

use super::CellFrame;

use tracing::{debug, trace};

/// A list of the link protocols that we support.
static LINK_PROTOCOLS: &[u16] = &[4, 5];

/// A raw client channel on which nothing has been done.
pub struct OutboundClientHandshake<
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    S: SleepProvider,
> {
    /// Runtime handle (insofar as we need it)
    sleep_prov: S,

    /// Underlying TLS stream.
    ///
    /// (We don't enforce that this is actually TLS, but if it isn't, the
    /// connection won't be secure.)
    tls: T,

    /// Declared target method for this channel, if any.
    target_method: Option<ChannelMethod>,

    /// Logging identifier for this stream.  (Used for logging only.)
    unique_id: UniqId,
}

/// A client channel on which versions have been negotiated and the
/// relay's handshake has been read, but where the certs have not
/// been checked.
pub struct UnverifiedChannel<T: AsyncRead + AsyncWrite + Send + Unpin + 'static, S: SleepProvider> {
    /// Runtime handle (insofar as we need it)
    sleep_prov: S,
    /// The negotiated link protocol.  Must be a member of LINK_PROTOCOLS
    link_protocol: u16,
    /// The Source+Sink on which we're reading and writing cells.
    tls: CellFrame<T>,
    /// The certs cell that we got from the relay.
    certs_cell: msg::Certs,
    /// Declared target method for this channel, if any.
    target_method: Option<ChannelMethod>,
    /// The netinfo cell that we got from the relay.
    #[allow(dead_code)] // Relays will need this.
    netinfo_cell: msg::Netinfo,
    /// How much clock skew did we detect in this handshake?
    ///
    /// This value is _unauthenticated_, since we have not yet checked whether
    /// the keys in the handshake are the ones we expected.
    clock_skew: ClockSkew,
    /// Logging identifier for this stream.  (Used for logging only.)
    unique_id: UniqId,
}

/// A client channel on which versions have been negotiated,
/// relay's handshake has been read, but the client has not yet
/// finished the handshake.
///
/// This type is separate from UnverifiedChannel, since finishing the
/// handshake requires a bunch of CPU, and you might want to do it as
/// a separate task or after a yield.
pub struct VerifiedChannel<T: AsyncRead + AsyncWrite + Send + Unpin + 'static, S: SleepProvider> {
    /// Runtime handle (insofar as we need it)
    sleep_prov: S,
    /// The negotiated link protocol.
    link_protocol: u16,
    /// The Source+Sink on which we're reading and writing cells.
    tls: CellFrame<T>,
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
}

restricted_msg! {
    /// A restricted subset of ChanMsg that can arrive during a handshake.
    ///
    /// (These are messages that come after the VERSIONS cell, up to and
    /// including the NETINFO.)
    ///
    /// Note that unrecognized message types (ones not yet implemented in Arti)
    /// cause an error, rather than getting ignored.  That's intentional: if we
    /// start to allow them in the future, we should negotiate a new Channel
    /// protocol for the VERSIONS cell.
    #[derive(Clone,Debug)]
    enum HandshakeMsg : ChanMsg {
        Padding,
        Vpadding,
        AuthChallenge,
        Certs,
        Netinfo
    }
}

/// Convert a CodecError to an Error, under the context that it occurs while
/// doing a channel handshake.
fn codec_err_to_handshake(err: CodecError) -> Error {
    match err {
        CodecError::Io(e) => Error::HandshakeIoErr(Arc::new(e)),
        CodecError::DecCell(e) => {
            Error::HandshakeProto(format!("Invalid cell on handshake: {}", e))
        }
        CodecError::EncCell(e) => Error::from_cell_enc(e, "cell on handshake"),
    }
}

impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static, S: SleepProvider>
    OutboundClientHandshake<T, S>
{
    /// Construct a new OutboundClientHandshake.
    pub(crate) fn new(tls: T, target_method: Option<ChannelMethod>, sleep_prov: S) -> Self {
        Self {
            tls,
            target_method,
            unique_id: UniqId::new(),
            sleep_prov,
        }
    }

    /// Negotiate a link protocol version with the relay, and read
    /// the relay's handshake information.
    ///
    /// Takes a function that reports the current time.  In theory, this can just be
    /// `SystemTime::now()`.
    pub async fn connect<F>(mut self, now_fn: F) -> Result<UnverifiedChannel<T, S>>
    where
        F: FnOnce() -> SystemTime,
    {
        /// Helper: wrap an IoError as a HandshakeIoErr.
        fn io_err_to_handshake(err: std::io::Error) -> Error {
            Error::HandshakeIoErr(Arc::new(err))
        }

        match &self.target_method {
            Some(method) => debug!(
                "{}: starting Tor handshake with {:?}",
                self.unique_id, method
            ),
            None => debug!("{}: starting Tor handshake", self.unique_id),
        }
        trace!("{}: sending versions", self.unique_id);
        // Send versions cell
        {
            let my_versions = msg::Versions::new(LINK_PROTOCOLS)
                .map_err(|e| Error::from_cell_enc(e, "versions message"))?;
            self.tls
                .write_all(
                    &my_versions
                        .encode_for_handshake()
                        .map_err(|e| Error::from_cell_enc(e.into(), "versions message"))?,
                )
                .await
                .map_err(io_err_to_handshake)?;
            self.tls.flush().await.map_err(io_err_to_handshake)?;
        }
        let versions_flushed_at = coarsetime::Instant::now();
        let versions_flushed_wallclock = now_fn();

        // Get versions cell.
        trace!("{}: waiting for versions", self.unique_id);
        let their_versions: msg::Versions = {
            // TODO: this could be turned into another function, I suppose.
            let mut hdr = [0_u8; 5];
            let not_relay = || {
                Err(Error::HandshakeProto(
                    "Doesn't seem to be a tor relay".into(),
                ))
            };
            match self.tls.read_exact(&mut hdr).await {
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return not_relay(),
                otherwise => otherwise,
            }
            .map_err(io_err_to_handshake)?;
            if hdr[0..3] != [0, 0, ChanCmd::VERSIONS.into()] {
                return not_relay();
            }
            let msglen = u16::from_be_bytes(
                hdr[3..5]
                    .try_into()
                    .expect("Two-byte field was not two bytes!?"),
            );
            let mut msg = vec![0; msglen as usize];
            self.tls
                .read_exact(&mut msg)
                .await
                .map_err(io_err_to_handshake)?;
            let mut reader = Reader::from_slice(&msg);
            reader
                .extract()
                .map_err(|e| Error::from_bytes_err(e, "versions cell"))?
        };
        trace!("{}: received {:?}", self.unique_id, their_versions);

        // Determine which link protocol we negotiated.
        let link_protocol = their_versions
            .best_shared_link_protocol(LINK_PROTOCOLS)
            .ok_or_else(|| Error::HandshakeProto("No shared link protocols".into()))?;
        trace!("{}: negotiated version {}", self.unique_id, link_protocol);

        // Now we can switch to using a "Framed". We can ignore the
        // AsyncRead/AsyncWrite aspects of the tls, and just treat it
        // as a stream and a sink for cells.
        let codec = ChannelCodec::<HandshakeMsg, HandshakeMsg>::new(link_protocol);
        let mut tls = futures_codec::Framed::new(self.tls, codec);

        // Read until we have the netinfo cells.
        let mut certs: Option<msg::Certs> = None;
        let mut netinfo: Option<(msg::Netinfo, coarsetime::Instant)> = None;
        let mut seen_authchallenge = false;

        // Loop: reject duplicate and unexpected cells
        trace!("{}: waiting for rest of handshake.", self.unique_id);
        while let Some(m) = tls.next().await {
            use HandshakeMsg::*;
            let (_, m) = m.map_err(codec_err_to_handshake)?.into_circid_and_msg();
            trace!("{}: received a {} cell.", self.unique_id, m.cmd());
            match m {
                // Are these technically allowed?
                Padding(_) | Vpadding(_) => (),
                // Clients don't care about AuthChallenge
                AuthChallenge(_) => {
                    if seen_authchallenge {
                        return Err(Error::HandshakeProto("Duplicate authchallenge cell".into()));
                    }
                    seen_authchallenge = true;
                }
                Certs(c) => {
                    if certs.is_some() {
                        return Err(Error::HandshakeProto("Duplicate certs cell".into()));
                    }
                    certs = Some(c);
                }
                Netinfo(n) => {
                    if netinfo.is_some() {
                        // This should be impossible, since we would
                        // exit this loop on the first netinfo cell.
                        return Err(Error::from(internal!(
                            "Somehow tried to record a duplicate NETINFO cell"
                        )));
                    }
                    netinfo = Some((n, coarsetime::Instant::now()));
                    break;
                }
            }
        }

        // If we have certs and netinfo, we can finish authenticating.
        match (certs, netinfo) {
            (Some(_), None) => Err(Error::HandshakeProto(
                "Missing netinfo or closed stream".into(),
            )),
            (None, _) => Err(Error::HandshakeProto("Missing certs cell".into())),
            (Some(certs_cell), Some((netinfo_cell, netinfo_rcvd_at))) => {
                trace!("{}: received handshake, ready to verify.", self.unique_id);
                // Try to compute our clock skew.  It won't be authenticated
                // yet, since we haven't checked the certificates.
                let clock_skew = if let Some(netinfo_timestamp) = netinfo_cell.timestamp() {
                    let delay = netinfo_rcvd_at - versions_flushed_at;
                    ClockSkew::from_handshake_timestamps(
                        versions_flushed_wallclock,
                        netinfo_timestamp,
                        delay.into(),
                    )
                } else {
                    ClockSkew::None
                };
                Ok(UnverifiedChannel {
                    link_protocol,
                    tls: codec::change_message_types(tls),
                    certs_cell,
                    netinfo_cell,
                    clock_skew,
                    target_method: self.target_method.take(),
                    unique_id: self.unique_id,
                    sleep_prov: self.sleep_prov.clone(),
                })
            }
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static, S: SleepProvider> UnverifiedChannel<T, S> {
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
    /// its handshake.
    ///
    /// 'now' is the time at which to check that certificates are
    /// valid.  `None` means to use the current time. It can be used
    /// for testing to override the current view of the time.
    ///
    /// This is a separate function because it's likely to be somewhat
    /// CPU-intensive.
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
        self,
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
            "{}: Validated identity as {} [{}]",
            self.unique_id,
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

        Ok(VerifiedChannel {
            link_protocol: self.link_protocol,
            tls: self.tls,
            unique_id: self.unique_id,
            target_method: self.target_method,
            ed25519_id: *identity_key,
            rsa_id,
            clock_skew: self.clock_skew,
            sleep_prov: self.sleep_prov,
        })
    }
}

impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static, S: SleepProvider> VerifiedChannel<T, S> {
    /// Send a 'Netinfo' message to the relay to finish the handshake,
    /// and create an open channel and reactor.
    ///
    /// The channel is used to send cells, and to create outgoing circuits.
    /// The reactor is used to route incoming messages to their appropriate
    /// circuit.
    pub async fn finish(mut self) -> Result<(Arc<super::Channel>, super::reactor::Reactor<S>)> {
        // We treat a completed channel -- that is to say, one where the
        // authentication is finished -- as incoming traffic.
        //
        // TODO: conceivably we should remember the time when we _got_ the
        // final cell on the handshake, and update the channel completion
        // time to be no earlier than _that_ timestamp.
        crate::note_incoming_traffic();
        trace!("{}: Sending netinfo cell.", self.unique_id);

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
        self.tls
            .send(netinfo.into())
            .await
            .map_err(codec_err_to_handshake)?;

        debug!(
            "{}: Completed handshake with {} [{}]",
            self.unique_id, self.ed25519_id, self.rsa_id
        );

        let (tls_sink, tls_stream) = self.tls.split();

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

        Ok(super::Channel::new(
            self.link_protocol,
            Box::new(tls_sink),
            Box::new(tls_stream),
            self.unique_id,
            peer_id,
            self.clock_skew,
            self.sleep_prov,
        ))
    }
}

#[cfg(test)]
pub(super) mod test {
    #![allow(clippy::unwrap_used)]
    use hex_literal::hex;
    use regex::Regex;
    use std::time::{Duration, SystemTime};

    use super::*;
    use crate::channel::codec::test::MsgBuf;
    use crate::Result;
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
            let handshake = OutboundClientHandshake::new(mb, None, rt.clone());
            let unverified = handshake.connect(|| now).await?;

            assert_eq!(unverified.link_protocol, 5);
            // No timestamp in the NETINFO, so no skew.
            assert_eq!(unverified.clock_skew(), ClockSkew::None);

            // Try again with an authchallenge cell and some padding.
            let mut buf = Vec::new();
            buf.extend_from_slice(VERSIONS);
            buf.extend_from_slice(NOCERTS);
            buf.extend_from_slice(VPADDING);
            buf.extend_from_slice(AUTHCHALLENGE);
            buf.extend_from_slice(VPADDING);
            add_padded(&mut buf, NETINFO_PREFIX_WITH_TIME);
            let mb = MsgBuf::new(&buf[..]);
            let handshake = OutboundClientHandshake::new(mb, None, rt.clone());
            let unverified = handshake.connect(|| now).await?;
            // Correct timestamp in the NETINFO, so no skew.
            assert_eq!(unverified.clock_skew(), ClockSkew::None);

            // Now pretend our clock is fast.
            let now2 = now + Duration::from_secs(3600);
            let mb = MsgBuf::new(&buf[..]);
            let handshake = OutboundClientHandshake::new(mb, None, rt.clone());
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
        S: SleepProvider,
    {
        let mb = MsgBuf::new(input);
        let handshake = OutboundClientHandshake::new(mb, None, sleep_prov);
        handshake.connect(SystemTime::now).await.err().unwrap()
    }

    #[test]
    fn connect_badver() {
        tor_rtcompat::test_with_one_runtime!(|rt| async move {
            let err = connect_err(&b"HTTP://"[..], rt.clone()).await;
            assert!(matches!(err, Error::HandshakeProto(_)));
            assert_eq!(
                format!("{}", err),
                "Handshake protocol violation: Doesn't seem to be a tor relay"
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
            assert!(matches!(err, Error::HandshakeProto(_)));
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
                "Handshake protocol violation: Duplicate certs cell"
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
                "Handshake protocol violation: Duplicate authchallenge cell"
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
                "Handshake protocol violation: Missing certs cell"
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
                "Handshake protocol violation: Missing netinfo or closed stream"
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
                "Handshake protocol violation: Invalid cell on handshake: Error while parsing channel cell"
            );
        });
    }

    fn make_unverified<R>(certs: msg::Certs, runtime: R) -> UnverifiedChannel<MsgBuf, R>
    where
        R: Runtime,
    {
        let localhost = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let netinfo_cell = msg::Netinfo::from_client(Some(localhost));
        let clock_skew = ClockSkew::None;
        UnverifiedChannel {
            link_protocol: 4,
            tls: futures_codec::Framed::new(MsgBuf::new(&b""[..]), ChannelCodec::new(4)),
            certs_cell: certs,
            netinfo_cell,
            clock_skew,
            target_method: None,
            unique_id: UniqId::new(),
            sleep_prov: runtime,
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

        pub(crate) const CERT_T2: &[u8] = &hex!("308201B930820122A0030201020208607C28BE6C390943300D06092A864886F70D01010B0500301F311D301B06035504030C147777772E74636A76356B766A646472322E636F6D301E170D3230303831303030303030305A170D3231303831303030303030305A301F311D301B06035504030C147777772E74636A76356B766A646472322E636F6D30819F300D06092A864886F70D010101050003818D0030818902818100D38B1E6CEB946E0DB0751F4CBACE3DCB9688B6C25304227B4710C35AFB73627E50500F5913E158B621802612D1C75827003703338375237552EB3CD3C12F6AB3604E60C1A2D26BB1FBAD206FF023969A90909D6A65A5458A5312C26EBD3A3DAD30302D4515CDCD264146AC18E6FC60A04BD3EC327F04294D96BA5AA25B464C3F0203010001300D06092A864886F70D01010B0500038181003BCE561EA7F95CC00B78AAB5D69573FF301C282A751D4A651921D042F1BECDBA24D918A6D8A5E138DC07BBA0B335478AE37ABD2C93A93932442AE9084329E846170FE0FC4A50AAFC804F311CC3CA4F41D845A7BA5901CBBC3E021E9794AAC70CE1F37B0A951592DB1B64F2B4AFB81AE52DBD9B6FEDE96A5FB8125EB6251EE50A");

        pub(crate) const CERT_T4: &[u8] = &hex!("01040006CC2A01F82294B866A31F01FC5D0DA8572850A9B929545C3266558D7D2316E3B74172B00100200400DCB604DB2034B00FD16986D4ADB9D16B21CB4E4457A33DEC0F538903683E96E9FF1A5203FA27F86EF7528D89A0845D2520166E340754FFEA2AAE0F612B7CE5DA094A0236CDAC45034B0B6842C18E7F6B51B93A3CF7E60663B8AD061C30A62602");
        pub(crate) const CERT_T5: &[u8] = &hex!("01050006C98A03B4FD606B64E4CBD466B8D76CB131069BAE6F3AA1878857C9F624E31D77A799B8007173E5F8068431D0D3F5EE16B4C9FFD59DF373E152A87281BAE744AA5FCF72171BF4B27C4E8FC1C6A9FC5CA11058BC49647063D7903CFD9F512F89099B27BC0C");

        pub(crate) const CERT_T7: &[u8] = &hex!("DCB604DB2034B00FD16986D4ADB9D16B21CB4E4457A33DEC0F538903683E96E90006DA3A805CF6006F9179066534DE6B45AD47A5C469063EE462762723396DC9F25452A0A52DA3F5087DD239F2A311F6B0D4DFEFF4ABD089DC3D0237A0ABAB19EB2045B91CDCAF04BE0A72D548A27BF2E77BD876ECFE5E1BE622350DA6BF31F6E306ED896488DD5B39409B23FC3EB7B2C9F7328EB18DA36D54D80575899EA6507CCBFCDF1F");

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
            let ver = VerifiedChannel {
                link_protocol: 4,
                tls: futures_codec::Framed::new(MsgBuf::new(&b""[..]), ChannelCodec::new(4)),
                unique_id: UniqId::new(),
                target_method: Some(ChannelMethod::Direct(vec![peer_addr])),
                ed25519_id,
                rsa_id,
                clock_skew: ClockSkew::None,
                sleep_prov: rt,
            };

            let (_chan, _reactor) = ver.finish().await.unwrap();

            // TODO: check contents of netinfo cell
        });
    }
}
