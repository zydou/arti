//! Implementations for the channel handshake

use arrayref::array_ref;
use asynchronous_codec as futures_codec;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use futures::sink::SinkExt;
use futures::stream::{self, StreamExt};

use crate::channel::codec::ChannelCodec;
use crate::channel::UniqId;
use crate::{Error, Result};
use tor_cell::chancell::{msg, ChanCmd};

use std::net::SocketAddr;
use std::sync::Arc;
use tor_bytes::Reader;
use tor_linkspec::ChanTarget;
use tor_llcrypto as ll;
use tor_llcrypto::pk::ed25519::Ed25519Identity;
use tor_llcrypto::pk::rsa::RsaIdentity;

use digest::Digest;

use super::CellFrame;

use tracing::{debug, trace};

/// A list of the link protocols that we support.
// We only support version 4 for now, since we don't do padding right.
static LINK_PROTOCOLS: &[u16] = &[4];

/// A raw client channel on which nothing has been done.
pub struct OutboundClientHandshake<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> {
    /// Underlying TLS stream.
    ///
    /// (We don't enforce that this is actually TLS, but if it isn't, the
    /// connection won't be secure.)
    tls: T,

    /// Declared target for this stream, if any.
    target_addr: Option<SocketAddr>,

    /// Logging identifier for this stream.  (Used for logging only.)
    unique_id: UniqId,
}

/// A client channel on which versions have been negotiated and the
/// relay's handshake has been read, but where the certs have not
/// been checked.
pub struct UnverifiedChannel<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> {
    /// The negotiated link protocol.  Must be a member of LINK_PROTOCOLS
    link_protocol: u16,
    /// The Source+Sink on which we're reading and writing cells.
    tls: CellFrame<T>,
    /// The certs cell that we got from the relay.
    certs_cell: msg::Certs,
    /// Declared target for this stream, if any.
    target_addr: Option<SocketAddr>,
    /// The netinfo cell that we got from the relay.
    #[allow(dead_code)] // Relays will need this.
    netinfo_cell: msg::Netinfo,
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
pub struct VerifiedChannel<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> {
    /// The negotiated link protocol.
    link_protocol: u16,
    /// The Source+Sink on which we're reading and writing cells.
    tls: CellFrame<T>,
    /// Declared target for this stream, if any.
    target_addr: Option<SocketAddr>,
    /// Logging identifier for this stream.  (Used for logging only.)
    unique_id: UniqId,
    /// Validated Ed25519 identity for this peer.
    ed25519_id: Ed25519Identity,
    /// Validated RSA identity for this peer.
    rsa_id: RsaIdentity,
}

impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> OutboundClientHandshake<T> {
    /// Construct a new OutboundClientHandshake.
    pub(crate) fn new(tls: T, target_addr: Option<SocketAddr>) -> Self {
        Self {
            tls,
            target_addr,
            unique_id: UniqId::new(),
        }
    }

    /// Negotiate a link protocol version with the relay, and read
    /// the relay's handshake information.
    pub async fn connect(mut self) -> Result<UnverifiedChannel<T>> {
        match self.target_addr {
            Some(addr) => debug!("{}: starting Tor handshake with {}", self.unique_id, addr),
            None => debug!("{}: starting Tor handshake", self.unique_id),
        }
        trace!("{}: sending versions", self.unique_id);
        // Send versions cell
        {
            let my_versions = msg::Versions::new(LINK_PROTOCOLS)?;
            self.tls.write(&my_versions.encode_for_handshake()).await?;
            self.tls.flush().await?;
        }

        // Get versions cell.
        trace!("{}: waiting for versions", self.unique_id);
        let their_versions: msg::Versions = {
            // TODO: this could be turned into another function, I suppose.
            let mut hdr = [0_u8; 5];
            self.tls.read(&mut hdr).await?;
            if hdr[0..3] != [0, 0, ChanCmd::VERSIONS.into()] {
                return Err(Error::ChanProto("Doesn't seem to be a tor relay".into()));
            }
            let msglen = u16::from_be_bytes(*array_ref![hdr, 3, 2]);
            let mut msg = vec![0; msglen as usize];
            self.tls.read_exact(&mut msg).await?;
            let mut reader = Reader::from_slice(&msg);
            reader.extract()?
        };
        trace!("{}: received {:?}", self.unique_id, their_versions);

        // Determine which link protocol we negotiated.
        let link_protocol = their_versions
            .best_shared_link_protocol(LINK_PROTOCOLS)
            .ok_or_else(|| Error::ChanProto("No shared link protocols".into()))?;
        trace!("{}: negotiated version {}", self.unique_id, link_protocol);

        // Now we can switch to using a "Framed". We can ignore the
        // AsyncRead/AsyncWrite aspects of the tls, and just treat it
        // as a stream and a sink for cells.
        let codec = ChannelCodec::new(link_protocol);
        let mut tls = futures_codec::Framed::new(self.tls, codec);

        // Read until we have the netinfo cells.
        let mut certs: Option<msg::Certs> = None;
        let mut netinfo: Option<msg::Netinfo> = None;
        let mut seen_authchallenge = false;

        // Loop: reject duplicate and unexpected cells
        trace!("{}: waiting for rest of handshake.", self.unique_id);
        while let Some(m) = tls.next().await {
            use msg::ChanMsg::*;
            let (_, m) = m?.into_circid_and_msg();
            trace!("{}: received a {} cell.", self.unique_id, m.cmd());
            match m {
                // Are these technically allowed?
                Padding(_) | VPadding(_) => (),
                // Unrecognized cells get ignored.
                Unrecognized(_) => (),
                // Clients don't care about AuthChallenge
                AuthChallenge(_) => {
                    if seen_authchallenge {
                        return Err(Error::ChanProto("Duplicate authchallenge cell".into()));
                    }
                    seen_authchallenge = true;
                }
                Certs(c) => {
                    if certs.is_some() {
                        return Err(Error::ChanProto("Duplicate certs cell".into()));
                    }
                    certs = Some(c);
                }
                Netinfo(n) => {
                    if netinfo.is_some() {
                        // This should be impossible, since we would
                        // exit this loop on the first netinfo cell.
                        return Err(Error::InternalError(
                            "Somehow tried to record a duplicate NETINFO cell".into(),
                        ));
                    }
                    netinfo = Some(n);
                    break;
                }
                // No other cell types are allowed.
                m => {
                    return Err(Error::ChanProto(format!(
                        "Unexpected cell type {}",
                        m.cmd()
                    )))
                }
            }
        }

        // If we have certs and netinfo, we can finish authenticating.
        match (certs, netinfo) {
            (Some(_), None) => Err(Error::ChanProto("Missing netinfo or closed stream".into())),
            (None, _) => Err(Error::ChanProto("Missing certs cell".into())),
            (Some(certs_cell), Some(netinfo_cell)) => {
                trace!("{}: received handshake, ready to verify.", self.unique_id);
                Ok(UnverifiedChannel {
                    link_protocol,
                    tls,
                    certs_cell,
                    netinfo_cell,
                    target_addr: self.target_addr,
                    unique_id: self.unique_id,
                })
            }
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> UnverifiedChannel<T> {
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
    ) -> Result<VerifiedChannel<T>> {
        let peer_cert_sha256 = ll::d::Sha256::digest(peer_cert);
        self.check_internal(peer, &peer_cert_sha256[..], now)
    }

    /// Same as `check`, but takes the SHA256 hash of the peer certificate,
    /// since that is all we use.
    fn check_internal<U: ChanTarget + ?Sized>(
        self,
        peer: &U,
        peer_cert_sha256: &[u8],
        now: Option<std::time::SystemTime>,
    ) -> Result<VerifiedChannel<T>> {
        use tor_cert::CertType;
        use tor_checkable::*;
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
        let id_sk = c.parse_ed_cert(CertType::IDENTITY_V_SIGNING)?;
        let sk_tls = c.parse_ed_cert(CertType::SIGNING_V_TLS_CERT)?;

        let mut sigs = Vec::new();

        // Part 1: validate ed25519 stuff.

        // Check the identity->signing cert
        let (id_sk, id_sk_sig) = id_sk.check_key(&None)?.dangerously_split()?;
        sigs.push(&id_sk_sig);
        let id_sk = id_sk
            .check_valid_at_opt(now)
            .map_err(|_| Error::ChanProto("Certificate expired or not yet valid".into()))?;

        // Take the identity key from the identity->signing cert
        let identity_key = id_sk.signing_key().ok_or_else(|| {
            Error::ChanProto("Missing identity key in identity->signing cert".into())
        })?;

        // Take the signing key from the identity->signing cert
        let signing_key = id_sk
            .subject_key()
            .as_ed25519()
            .ok_or_else(|| Error::ChanProto("Bad key type in identity->signing cert".into()))?;

        // Now look at the signing->TLS cert and check it against the
        // peer certificate.
        let (sk_tls, sk_tls_sig) = sk_tls
            .check_key(&Some(*signing_key))? // this is a bad interface XXXX
            .dangerously_split()?;
        sigs.push(&sk_tls_sig);
        let sk_tls = sk_tls
            .check_valid_at_opt(now)
            .map_err(|_| Error::ChanProto("Certificate expired or not yet valid".into()))?;

        if peer_cert_sha256 != sk_tls.subject_key().as_bytes() {
            return Err(Error::ChanProto(
                "Peer cert did not authenticate TLS cert".into(),
            ));
        }

        // Batch-verify the ed25519 certificates in this handshake.
        //
        // In theory we could build a list of _all_ the certificates here
        // and call pk::validate_all_sigs() instead, but that doesn't gain
        // any performance.
        if !ll::pk::ed25519::validate_batch(&sigs[..]) {
            return Err(Error::ChanProto(
                "Invalid ed25519 signature in handshake".into(),
            ));
        }

        let ed25519_id: Ed25519Identity = identity_key.into();

        // Part 2: validate rsa stuff.

        // What is the RSA identity key, according to the X.509 certificate
        // in which it is self-signed?
        //
        // (We don't actually check this self-signed certificate, and we use
        // a kludge to extract the RSA key)
        let pkrsa = c
            .cert_body(CertType::RSA_ID_X509)
            .map(ll::util::x509_extract_rsa_subject_kludge)
            .flatten()
            .ok_or_else(|| Error::ChanProto("Couldn't find RSA identity key".into()))?;

        // Now verify the RSA identity -> Ed Identity crosscert.
        //
        // This proves that the RSA key vouches for the Ed key.  Note that
        // the Ed key does not vouch for the RSA key: The RSA key is too
        // weak.
        let rsa_cert = c
            .cert_body(CertType::RSA_ID_V_IDENTITY)
            .ok_or_else(|| Error::ChanProto("No RSA->Ed crosscert".into()))?;
        let rsa_cert = tor_cert::rsa::RsaCrosscert::decode(rsa_cert)?
            .check_signature(&pkrsa)
            .map_err(|_| Error::ChanProto("Bad RSA->Ed crosscert signature".into()))?
            .check_valid_at_opt(now)
            .map_err(|_| Error::ChanProto("RSA->Ed crosscert expired or invalid".into()))?;

        if !rsa_cert.subject_key_matches(identity_key) {
            return Err(Error::ChanProto(
                "RSA->Ed crosscert certifies incorrect key".into(),
            ));
        }

        let rsa_id = pkrsa.to_rsa_identity();

        trace!(
            "{}: Validated identity as {} [{}]",
            self.unique_id,
            ed25519_id,
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
        if *peer.ed_identity() != ed25519_id {
            return Err(Error::ChanProto("Peer ed25519 id not as expected".into()));
        }

        if *peer.rsa_identity() != rsa_id {
            return Err(Error::ChanProto("Peer RSA id not as expected".into()));
        }

        Ok(VerifiedChannel {
            link_protocol: self.link_protocol,
            tls: self.tls,
            unique_id: self.unique_id,
            target_addr: self.target_addr,
            ed25519_id,
            rsa_id,
        })
    }
}

impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> VerifiedChannel<T> {
    /// Send a 'Netinfo' message to the relay to finish the handshake,
    /// and create an open channel and reactor.
    ///
    /// The channel is used to send cells, and to create outgoing circuits.
    /// The reactor is used to route incoming messages to their appropriate
    /// circuit.
    pub async fn finish(
        mut self,
    ) -> Result<(
        Arc<super::Channel>,
        super::reactor::Reactor<stream::SplitStream<CellFrame<T>>>,
    )> {
        trace!("{}: Sending netinfo cell.", self.unique_id);
        let netinfo = msg::Netinfo::for_client(self.target_addr.as_ref().map(SocketAddr::ip));
        self.tls.send(netinfo.into()).await?;

        debug!(
            "{}: Completed handshake with {} [{}]",
            self.unique_id, self.ed25519_id, self.rsa_id
        );

        let (tls_sink, tls_stream) = self.tls.split();

        Ok(super::Channel::new(
            self.link_protocol,
            Box::new(tls_sink),
            tls_stream,
            self.unique_id,
            self.ed25519_id,
            self.rsa_id,
        ))
    }
}

#[cfg(test)]
pub(super) mod test {
    #![allow(clippy::unwrap_used)]
    use futures_await_test::async_test;
    use hex_literal::hex;
    use std::time::{Duration, SystemTime};

    use super::*;
    use crate::channel::codec::test::MsgBuf;
    use crate::Result;
    use tor_cell::chancell::msg;

    const VERSIONS: &[u8] = &hex!("0000 07 0006 0003 0004 0005");
    // no certificates in this cell, but connect() doesn't care.
    const NOCERTS: &[u8] = &hex!("00000000 81 0001 00");
    const NETINFO_PREFIX: &[u8] = &hex!(
        "00000000 08 085F9067F7
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

    #[async_test]
    async fn connect_ok() -> Result<()> {
        let mut buf = Vec::new();
        // versions cell
        buf.extend_from_slice(VERSIONS);
        // certs cell -- no certs in it, but this function doesn't care.
        buf.extend_from_slice(NOCERTS);
        // netinfo cell -- quite minimal.
        add_netinfo(&mut buf);
        let mb = MsgBuf::new(&buf[..]);
        let handshake = OutboundClientHandshake::new(mb, None);
        let unverified = handshake.connect().await?;

        assert_eq!(unverified.link_protocol, 4);

        // Try again with an authchallenge cell and some padding.
        let mut buf = Vec::new();
        buf.extend_from_slice(VERSIONS);
        buf.extend_from_slice(NOCERTS);
        buf.extend_from_slice(VPADDING);
        buf.extend_from_slice(AUTHCHALLENGE);
        buf.extend_from_slice(VPADDING);
        add_netinfo(&mut buf);
        let mb = MsgBuf::new(&buf[..]);
        let handshake = OutboundClientHandshake::new(mb, None);
        let _unverified = handshake.connect().await?;

        Ok(())
    }

    async fn connect_err<T: Into<Vec<u8>>>(input: T) -> Error {
        let mb = MsgBuf::new(input);
        let handshake = OutboundClientHandshake::new(mb, None);
        handshake.connect().await.err().unwrap()
    }

    #[async_test]
    async fn connect_badver() {
        let err = connect_err(&b"HTTP://"[..]).await;
        assert!(matches!(err, Error::ChanProto(_)));
        assert_eq!(
            format!("{}", err),
            "channel protocol violation: Doesn't seem to be a tor relay"
        );

        let err = connect_err(&hex!("0000 07 0004 1234 ffff")[..]).await;
        assert!(matches!(err, Error::ChanProto(_)));
        assert_eq!(
            format!("{}", err),
            "channel protocol violation: No shared link protocols"
        );
    }

    #[async_test]
    async fn connect_cellparse() {
        let mut buf = Vec::new();
        buf.extend_from_slice(VERSIONS);
        // Here's a certs cell that will fail.
        buf.extend_from_slice(&hex!("00000000 81 0001 01")[..]);
        let err = connect_err(buf).await;
        assert!(matches!(
            err,
            Error::CellErr(tor_cell::Error::BytesErr(tor_bytes::Error::Truncated))
        ));
    }

    #[async_test]
    async fn connect_duplicates() {
        let mut buf = Vec::new();
        buf.extend_from_slice(VERSIONS);
        buf.extend_from_slice(NOCERTS);
        buf.extend_from_slice(NOCERTS);
        add_netinfo(&mut buf);
        let err = connect_err(buf).await;
        assert!(matches!(err, Error::ChanProto(_)));
        assert_eq!(
            format!("{}", err),
            "channel protocol violation: Duplicate certs cell"
        );

        let mut buf = Vec::new();
        buf.extend_from_slice(VERSIONS);
        buf.extend_from_slice(NOCERTS);
        buf.extend_from_slice(AUTHCHALLENGE);
        buf.extend_from_slice(AUTHCHALLENGE);
        add_netinfo(&mut buf);
        let err = connect_err(buf).await;
        assert!(matches!(err, Error::ChanProto(_)));
        assert_eq!(
            format!("{}", err),
            "channel protocol violation: Duplicate authchallenge cell"
        );
    }

    #[async_test]
    async fn connect_missing_certs() {
        let mut buf = Vec::new();
        buf.extend_from_slice(VERSIONS);
        add_netinfo(&mut buf);
        let err = connect_err(buf).await;
        assert!(matches!(err, Error::ChanProto(_)));
        assert_eq!(
            format!("{}", err),
            "channel protocol violation: Missing certs cell"
        );
    }

    #[async_test]
    async fn connect_misplaced_cell() {
        let mut buf = Vec::new();
        buf.extend_from_slice(VERSIONS);
        // here's a create cell.
        add_padded(&mut buf, &hex!("00000001 01")[..]);
        let err = connect_err(buf).await;
        assert!(matches!(err, Error::ChanProto(_)));
        assert_eq!(
            format!("{}", err),
            "channel protocol violation: Unexpected cell type CREATE"
        );
    }

    fn make_unverified(certs: msg::Certs) -> UnverifiedChannel<MsgBuf> {
        let localhost = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let netinfo_cell = msg::Netinfo::for_client(Some(localhost));
        UnverifiedChannel {
            link_protocol: 4,
            tls: futures_codec::Framed::new(MsgBuf::new(&b""[..]), ChannelCodec::new(4)),
            certs_cell: certs,
            netinfo_cell,
            target_addr: None,
            unique_id: UniqId::new(),
        }
    }

    struct DummyChanTarget {
        ed: Ed25519Identity,
        rsa: RsaIdentity,
    }
    impl ChanTarget for DummyChanTarget {
        fn addrs(&self) -> &[SocketAddr] {
            &[]
        }
        fn ed_identity(&self) -> &Ed25519Identity {
            &self.ed
        }
        fn rsa_identity(&self) -> &RsaIdentity {
            &self.rsa
        }
    }

    // Timestamp when the example certificates were all valid.
    fn cert_timestamp() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::new(1601143280, 0)
    }

    fn certs_test(
        certs: msg::Certs,
        when: Option<SystemTime>,
        peer_ed: &[u8],
        peer_rsa: &[u8],
        peer_cert_sha256: &[u8],
    ) -> Result<VerifiedChannel<MsgBuf>> {
        let unver = make_unverified(certs);
        let ed = Ed25519Identity::from_bytes(peer_ed).unwrap();
        let rsa = RsaIdentity::from_bytes(peer_rsa).unwrap();
        let chan = DummyChanTarget { ed, rsa };
        unver.check_internal(&chan, peer_cert_sha256, when)
    }

    // no certs at all!
    #[test]
    fn certs_none() {
        let err = certs_test(
            msg::Certs::new_empty(),
            None,
            &[0_u8; 32],
            &[0_u8; 20],
            &[0_u8; 128],
        )
        .err()
        .unwrap();
        assert_eq!(
            format!("{}", err),
            "channel protocol violation: Missing IDENTITY_V_SIGNING certificate"
        );
    }

    #[test]
    fn certs_good() {
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
        );
        let _ = res.unwrap();
    }

    #[test]
    fn certs_missing() {
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
            )
            .err()
            .unwrap();

            assert_eq!(
                format!("{}", res),
                format!("channel protocol violation: {}", expect_err.unwrap())
            );
        }
    }

    #[test]
    fn certs_wrongtarget() {
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
        )
        .err()
        .unwrap();

        assert_eq!(
            format!("{}", err),
            "channel protocol violation: Peer ed25519 id not as expected"
        );

        let err = certs_test(
            certs.clone(),
            Some(cert_timestamp()),
            certs::PEER_ED,
            &[0x99; 20],
            certs::PEER_CERT_DIGEST,
        )
        .err()
        .unwrap();

        assert_eq!(
            format!("{}", err),
            "channel protocol violation: Peer RSA id not as expected"
        );

        let err = certs_test(
            certs,
            Some(cert_timestamp()),
            certs::PEER_ED,
            certs::PEER_RSA,
            &[0; 32],
        )
        .err()
        .unwrap();

        assert_eq!(
            format!("{}", err),
            "channel protocol violation: Peer cert did not authenticate TLS cert"
        );
    }

    #[test]
    fn certs_badsig() {
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
        )
        .err()
        .unwrap();

        assert_eq!(
            format!("{}", res),
            "channel protocol violation: Invalid ed25519 signature in handshake"
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
        )
        .err()
        .unwrap();

        assert_eq!(
            format!("{}", res),
            "channel protocol violation: Bad RSA->Ed crosscert signature"
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

    #[async_test]
    async fn test_finish() {
        let ed25519_id = [3_u8; 32].into();
        let rsa_id = [4_u8; 20].into();
        let peer_addr = "127.1.1.2:443".parse().unwrap();
        let ver = VerifiedChannel {
            link_protocol: 4,
            tls: futures_codec::Framed::new(MsgBuf::new(&b""[..]), ChannelCodec::new(4)),
            unique_id: UniqId::new(),
            target_addr: Some(peer_addr),
            ed25519_id,
            rsa_id,
        };

        let (_chan, _reactor) = ver.finish().await.unwrap();

        // TODO: check contents of netinfo cell
    }
}
