//! Implementations for the client channel handshake

use digest::Digest;
use futures::SinkExt;
use futures::io::{AsyncRead, AsyncWrite};
use std::sync::Arc;
use std::time::SystemTime;
use tracing::{debug, instrument, trace};

use safelog::MaybeSensitive;
use tor_cell::chancell::msg;
use tor_linkspec::{ChannelMethod, OwnedChanTarget};
use tor_rtcompat::{CoarseTimeProvider, Runtime, SleepProvider, StreamOps};

use crate::ClockSkew;
use crate::Result;
use crate::channel::handshake::{
    AuthLogAction, ChannelBaseHandshake, ChannelInitiatorHandshake, UnverifiedChannel,
    UnverifiedInitiatorChannel, VerifiedChannel, unauthenticated_clock_skew,
};
use crate::channel::{Channel, ChannelFrame, ChannelMode, ChannelType, Reactor, UniqId, new_frame};
use crate::memquota::ChannelAccount;
use crate::peer::{PeerAddr, PeerInfo};

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
}

impl<
    T: AsyncRead + AsyncWrite + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
> ClientInitiatorHandshake<T, S>
{
    /// Construct a new ClientInitiatorHandshake.
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
    /// `SystemTime::get()`.
    #[instrument(skip_all, level = "trace")]
    pub async fn connect<F>(mut self, now_fn: F) -> Result<UnverifiedClientChannel<T, S>>
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

        // VERSIONS cell have been exchanged, set the link protocol into our channel frame.
        self.set_link_protocol(link_protocol)?;

        // Receive the relay responder cells. Ignore the AUTH_CHALLENGE cell and SLOG; we don't need
        // them as we are not authenticating with our responder because we are a client.
        let (_auth_chal_cell, certs_cell, (netinfo_cell, netinfo_rcvd_at), _slog) =
            self.recv_cells_from_responder(AuthLogAction::Leave).await?;

        // Get the clock skew.
        let clock_skew = unauthenticated_clock_skew(
            &netinfo_cell,
            netinfo_rcvd_at,
            versions_flushed_at,
            versions_flushed_wallclock,
        );

        trace!(stream_id = %self.unique_id, "received handshake, ready to verify.");

        Ok(UnverifiedClientChannel {
            inner: UnverifiedInitiatorChannel {
                inner: UnverifiedChannel {
                    link_protocol,
                    framed_tls: self.framed_tls,
                    clock_skew,
                    target_method: self.target_method.take(),
                    unique_id: self.unique_id,
                    sleep_prov: self.sleep_prov.clone(),
                    memquota: self.memquota.clone(),
                },
                certs_cell,
            },
            netinfo_cell,
        })
    }
}

/// A client channel on which versions have been negotiated and the relay's handshake has been
/// read, but where the certs have not been checked.
pub struct UnverifiedClientChannel<
    T: AsyncRead + AsyncWrite + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
> {
    /// Inner generic unverified initiator channel.
    inner: UnverifiedInitiatorChannel<T, S>,
    /// Received [`msg::Netinfo`] cell during the handshake.
    netinfo_cell: msg::Netinfo,
}

impl<
    T: AsyncRead + AsyncWrite + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
> UnverifiedClientChannel<T, S>
{
    /// Validate the certificates and keys in the relay's handshake. As a client, we always verify
    /// but we don't authenticate.
    ///
    /// 'peer_target' is the peer that we want to make sure we're connecting to.
    ///
    /// 'peer_tls_cert' is the x.509 certificate that the peer presented during
    /// its TLS handshake (ServerHello).
    ///
    /// 'now' is the time at which to check that certificates are
    /// valid.  `None` means to use the current time. It can be used
    /// for testing to override the current view of the time.
    ///
    /// This is a separate function because it's likely to be somewhat
    /// CPU-intensive.
    #[instrument(skip_all, level = "trace")]
    pub fn verify(
        self,
        peer_target: &OwnedChanTarget,
        peer_tls_cert: &[u8],
        now: Option<std::time::SystemTime>,
    ) -> Result<VerifiedClientChannel<T, S>> {
        let peer_cert_digest = tor_llcrypto::d::Sha256::digest(peer_tls_cert).into();
        let inner = self.inner.verify(peer_target, peer_cert_digest, now)?;

        Ok(VerifiedClientChannel {
            inner,
            netinfo_cell: self.netinfo_cell,
        })
    }

    /// Return the clock skew of this channel.
    pub fn clock_skew(&self) -> ClockSkew {
        self.inner.inner.clock_skew
    }

    /// Return the link protocol version of this channel.
    #[cfg(test)]
    pub(crate) fn link_protocol(&self) -> u16 {
        self.inner.inner.link_protocol
    }
}

/// A client channel on which versions have been negotiated, relay's handshake has been read, but
/// the client has not yet finished the handshake.
///
/// This type is separate from UnverifiedClientChannel, since finishing the handshake requires a
/// bunch of CPU, and you might want to do it as a separate task or after a yield.
pub struct VerifiedClientChannel<
    T: AsyncRead + AsyncWrite + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
> {
    /// Inner generic verified channel.
    inner: VerifiedChannel<T, S>,
    /// Received [`msg::Netinfo`] cell during the handshake.
    netinfo_cell: msg::Netinfo,
}

impl<
    T: AsyncRead + AsyncWrite + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
> VerifiedClientChannel<T, S>
{
    /// Send a NETINFO message to the relay to finish the handshake, and create an open channel and
    /// reactor.
    ///
    /// The `peer_addr` is sensitive because it can be a secret bridge or guard.
    ///
    /// The channel is used to send cells, and to create outgoing circuits. The reactor is used to
    /// route incoming messages to their appropriate circuit.
    #[instrument(skip_all, level = "trace")]
    pub async fn finish(
        mut self,
        peer_addr: MaybeSensitive<PeerAddr>,
    ) -> Result<(Arc<Channel>, Reactor<S>)>
    where
        S: Runtime,
    {
        // Send the NETINFO message.
        let netinfo = msg::Netinfo::from_client(peer_addr.netinfo_addr());
        trace!(stream_id = %self.inner.unique_id, "Sending netinfo cell.");
        self.inner.framed_tls.send(netinfo.into()).await?;

        // This could be a client Guard so it is sensitive.
        let peer_info = MaybeSensitive::sensitive(PeerInfo::new(
            peer_addr.inner(),
            self.inner.relay_ids().clone(),
        ));

        // Finish the channel to get a reactor.
        self.inner
            .finish(&self.netinfo_cell, &[], peer_info, ChannelMode::Client)
            .await
    }
}

#[cfg(test)]
pub(crate) mod test {
    #![allow(clippy::unwrap_used)]
    use hex_literal::hex;
    use std::time::{Duration, SystemTime};
    use tor_linkspec::RelayIds;

    use super::*;
    use crate::channel::handshake::test::*;
    use crate::channel::test::MsgBuf;
    use crate::channel::{ChannelType, new_frame};
    use crate::util::fake_mq;
    use crate::{Error, Result, channel::ClientInitiatorHandshake};
    use tor_cell::chancell::msg::Netinfo;

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
                peer_relay_ids: RelayIds::empty(),
                peer_rsa_id_digest: [0; 32],
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
                    ChannelMode::Client,
                )
                .await
                .unwrap();

            // TODO: check contents of netinfo cell
        });
    }
}
