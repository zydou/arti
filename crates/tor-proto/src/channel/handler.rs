//! Wrap [tor_cell::chancell::codec::ChannelCodec] for use with the futures_codec
//! crate.

use digest::Digest;
use tor_bytes::Reader;
use tor_cell::chancell::{
    AnyChanCell, ChanCell, ChanCmd, ChanMsg, codec,
    msg::{self, AnyChanMsg},
};
use tor_error::internal;
use tor_llcrypto as ll;

use asynchronous_codec as futures_codec;
use bytes::BytesMut;

use crate::{channel::msg::LinkVersion, util::err::Error as ChanError};

use super::{ChannelType, msg::MessageFilter};

/// Channel cell handler which is always in three state.
///
/// This ALWAYS starts the handler at New. This can only be constructed from a [ChannelType] which
/// forces it to start at New.
///
/// From the New state, it will automatically transition to the right state as information is
/// attached to it (ex: link protocol version).
#[allow(unused)] // TODO: Remove once used.
pub(crate) enum ChannelCellHandler {
    /// When a network connection opens to another endpoint, the channel is considered "New" and
    /// so we use this handler to start the handshake.
    New(NewChannelHandler),
    /// We opened and negotiated a VERSIONS cell. If successful, we transition to this cell handler
    /// with sole purpose to handle the handshake phase.
    Handshake(HandshakeChannelHandler),
    /// Once the handshake is successful, the channel is Open and we use this handler.
    Open(OpenChannelHandler),
}

/// This is the only way to construct a ChannelCellHandler, from the channel type which will always
/// start the handler at the New state.
impl From<super::ChannelType> for ChannelCellHandler {
    fn from(ty: ChannelType) -> Self {
        Self::New(ty.into())
    }
}

#[allow(unused)] // TODO: Remove once used.
impl ChannelCellHandler {
    /// Set link protocol for this channel cell handler. This transition the handler into the
    /// handshake handler state.
    ///
    /// An error is returned if the current handler is NOT the New one or if the link version is
    /// unknown.
    pub(crate) fn set_link_version(&mut self, link_version: u16) -> Result<(), ChanError> {
        let Self::New(new_handler) = self else {
            return Err(ChanError::Bug(internal!(
                "Setting link protocol without a new handler",
            )));
        };
        *self = Self::Handshake(new_handler.next_handler(link_version.try_into()?));
        Ok(())
    }

    /// This transition into the open handler state.
    ///
    /// An error is returned if the current handler is NOT the Handshake one.
    pub(crate) fn set_open(&mut self) -> Result<(), ChanError> {
        let Self::Handshake(handler) = self else {
            return Err(ChanError::Bug(internal!(
                "Setting authenticated without a handshake handler"
            )));
        };
        *self = Self::Open(handler.next_handler());
        Ok(())
    }

    /// Return the CLOG digest.
    ///
    /// An error is returned if we are trying to get the CLOG digest without a handshake handler.
    #[allow(unused)] // Remove is when used
    pub(crate) fn get_clog_digest(&mut self) -> Result<[u8; 32], ChanError> {
        if let Self::Handshake(handler) = self {
            handler
                .take_clog()
                .ok_or(ChanError::Bug(internal!("No clog digest on channel")))
        } else {
            Err(ChanError::Bug(internal!(
                "Getting CLOG without a handshake handler"
            )))
        }
    }

    /// Return the SLOG digest.
    ///
    /// An error is returned if we are trying to get the SLOG digest without a handshake handler.
    #[allow(unused)] // Remove is when used
    pub(crate) fn get_slog_digest(&mut self) -> Result<[u8; 32], ChanError> {
        if let Self::Handshake(handler) = self {
            handler
                .take_slog()
                .ok_or(ChanError::Bug(internal!("No slog digest on channel")))
        } else {
            Err(ChanError::Bug(internal!(
                "Getting SLOG without a handshake handler"
            )))
        }
    }
}

// Security Consideration.
//
// Here is an explanation on why AnyChanCell is used as Item in the Handshake and Open handler and
// thus the higher level ChannelCellHandler.
//
// Technically, we could use a restricted message set and so the decoding and encoding wouldn't do
// anything if the cell/data was not part of that set.
//
// However, with relay and client, we have multiple channel types which means we have now a lot
// more sets of restricted message (see msg.rs) and each of them are per link protocol version, per
// stage of the channel opening process and per direction (inbound or outbound).
//
// To go around this, we use [MessageFilter] in order to decode on the specific restricted message
// set but still return a [AnyChanCell].
//
// If someone wants to contribute a more elegant solution that wouldn't require us to duplicate
// code for each restricted message set, by all means, go for it :).

impl futures_codec::Decoder for ChannelCellHandler {
    type Item = AnyChanCell;
    type Error = ChanError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self {
            Self::New(c) => c
                .decode(src)
                .map(|opt| opt.map(|msg| ChanCell::new(None, msg.into()))),
            Self::Handshake(c) => c.decode(src),
            Self::Open(c) => c.decode(src),
        }
    }
}

impl futures_codec::Encoder for ChannelCellHandler {
    type Item<'a> = AnyChanCell;
    type Error = ChanError;

    fn encode(&mut self, item: Self::Item<'_>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match self {
            Self::New(c) => {
                // The new handler pins the only possible message to be a Versions. That is why we
                // extract it here and validate before else we can't pass Item to encode().
                let AnyChanMsg::Versions(versions) = item.into_circid_and_msg().1 else {
                    return Err(Self::Error::HandshakeProto(
                        "Non VERSIONS cell for new handler".into(),
                    ));
                };
                c.encode(versions, dst)
            }
            Self::Handshake(c) => c.encode(item, dst),
            Self::Open(c) => c.encode(item, dst),
        }
    }
}

/// A new channel handler used when a channel is created but before the handshake meaning there is no
/// link protocol version yet associated with it.
///
/// This handler only handles the VERSIONS cell.
pub(crate) struct NewChannelHandler {
    /// The channel type for this handler.
    channel_type: ChannelType,
    /// The CLOG digest needed for authenticated channels.
    clog: Option<ll::d::Sha256>,
    /// The SLOG digest needed for authenticated channels.
    slog: Option<ll::d::Sha256>,
}

impl NewChannelHandler {
    /// Return a handshake handler ready for the given link protocol.
    fn next_handler(&mut self, link_version: LinkVersion) -> HandshakeChannelHandler {
        HandshakeChannelHandler::new(self, link_version)
    }
}

impl From<ChannelType> for NewChannelHandler {
    fn from(channel_type: ChannelType) -> Self {
        match channel_type {
            ChannelType::ClientInitiator => Self {
                channel_type,
                clog: None,
                slog: None,
            },
            // Relay responder might not need clog/slog but that is fine. We don't know until the
            // end of the handshake.
            ChannelType::RelayInitiator | ChannelType::RelayResponder { .. } => Self {
                channel_type,
                clog: Some(ll::d::Sha256::new()),
                slog: Some(ll::d::Sha256::new()),
            },
        }
    }
}

impl futures_codec::Decoder for NewChannelHandler {
    type Item = msg::Versions;
    type Error = ChanError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // See tor-spec, VERSIONS are considered a variable length cell and thus the first 5 bytes
        // are: CircId as u16, Command as u8, Length as u16.
        const HEADER_SIZE: usize = 5;

        // Below this amount, this is not a valid cell we can decode. This is important because we
        // can get an empty buffer in normal circumstances (see how Framed work) and so we have to
        // return that we weren't able to decode and thus no Item.
        if src.len() < HEADER_SIZE {
            return Ok(None);
        }

        // Get the CircID and Command from the header. This is safe due to the header size check
        // above.
        let circ_id = u16::from_be_bytes([src[0], src[1]]);
        if circ_id != 0 {
            return Err(Self::Error::HandshakeProto(
                "Invalid CircID in variable cell".into(),
            ));
        }

        // We are only expecting these specific commands. We have to do this by hand here as after
        // that we can use a proper codec.
        let cmd = ChanCmd::from(src[2]);
        match cmd {
            // We accept those.
            ChanCmd::AUTHORIZE | ChanCmd::VERSIONS | ChanCmd::VPADDING => (),
            _ => {
                return Err(Self::Error::HandshakeProto(format!(
                    "Invalid command {cmd} variable cell"
                )));
            }
        }

        // Get the body length now from the next two bytes. This is still safe due to the first
        // header size check at the start.
        let body_len = u16::from_be_bytes([src[3], src[4]]) as usize;

        // See https://gitlab.torproject.org/tpo/core/tor/-/issues/10365. The gist is that because
        // version numbers are u16, an odd payload would mean we have a trailing byte that is
        // unused which shouldn't be and because we don't expect not controlled that byte, as maxi
        // precaution, we don't allow.
        if matches!(cmd, ChanCmd::VERSIONS) && (body_len % 2) == 1 {
            return Err(Self::Error::HandshakeProto(
                "VERSIONS cell body length is odd. Rejecting.".into(),
            ));
        }

        // Make sure we have enough bytes in our payload.
        let wanted_bytes = HEADER_SIZE + body_len;
        if src.len() < wanted_bytes {
            // We don't haven't received enough data to decode the expected length from the header
            // so return no Item.
            //
            // IMPORTANT: The src buffer here can't be advanced before reaching this check.
            return Ok(None);
        }
        // Extract the exact data we will be looking at.
        let mut data = src.split_to(wanted_bytes);
        let mut versions = None;

        // Update the SLOG digest with the entire cell up to the end of the payload hence the data
        // we are looking at (and not the whole source). Even on error, this doesn't matter because
        // if decoding fails, the channel is closed.
        if let Some(slog) = self.slog.as_mut() {
            slog.update(&data);
        }

        // Handle the VERSIONS.
        if cmd == ChanCmd::VERSIONS {
            let body = data.split_off(HEADER_SIZE).freeze();
            let mut reader = Reader::from_bytes(&body);
            versions = Some(
                msg::Versions::decode_from_reader(ChanCmd::VERSIONS, &mut reader)
                    .map_err(|e| Self::Error::from_bytes_err(e, "new cell handler"))?,
            );
        }

        Ok(versions)
    }
}

impl futures_codec::Encoder for NewChannelHandler {
    type Item<'a> = msg::Versions;
    type Error = ChanError;

    fn encode(&mut self, item: Self::Item<'_>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let encoded_bytes = item
            .encode_for_handshake()
            .map_err(|e| Self::Error::from_bytes_enc(e, "new cell handler"))?;
        // Update the CLOG digest.
        if let Some(clog) = self.clog.as_mut() {
            clog.update(&encoded_bytes);
        }
        // Special encoding for the VERSIONS cell.
        dst.extend_from_slice(&encoded_bytes);
        Ok(())
    }
}

/// The handshake channel handler which is used to decode and encode cells onto a channel that is
/// handshaking with an endpoint.
pub(crate) struct HandshakeChannelHandler {
    /// The channel type for this handler.
    channel_type: ChannelType,
    /// Message filter used to allow or not a certain message.
    filter: MessageFilter,
    /// The cell codec that we'll use to encode and decode our cells.
    inner: codec::ChannelCodec,
    /// The CLOG digest needed for authenticated channels.
    clog: Option<ll::d::Sha256>,
    /// The SLOG digest needed for authenticated channels.
    slog: Option<ll::d::Sha256>,
}

impl HandshakeChannelHandler {
    /// Constructor
    fn new(new_handler: &mut NewChannelHandler, link_version: LinkVersion) -> Self {
        Self {
            channel_type: new_handler.channel_type,
            filter: MessageFilter::new(
                link_version,
                new_handler.channel_type,
                super::msg::MessageStage::Handshake,
            ),
            clog: new_handler.clog.take(),
            slog: new_handler.slog.take(),
            inner: codec::ChannelCodec::new(link_version.value()),
        }
    }

    /// Internal helper: Take a SHA256 digest and finalize it if any. None is returned if no log
    /// digest is given.
    fn finalize_log(log: Option<ll::d::Sha256>) -> Option<[u8; 32]> {
        log.map(|sha256| sha256.finalize().into())
    }

    /// Return an open handshake handler.
    fn next_handler(&mut self) -> OpenChannelHandler {
        OpenChannelHandler::new(
            self.inner
                .link_version()
                .try_into()
                .expect("Channel Codec with unknown link version"),
            self.channel_type,
        )
    }

    /// Return the digest of the CLOG consuming it.
    pub(crate) fn take_clog(&mut self) -> Option<[u8; 32]> {
        Self::finalize_log(self.clog.take())
    }

    /// Return the digest of the SLOG consuming it.
    pub(crate) fn take_slog(&mut self) -> Option<[u8; 32]> {
        Self::finalize_log(self.slog.take())
    }
}

impl futures_codec::Encoder for HandshakeChannelHandler {
    type Item<'a> = AnyChanCell;
    type Error = ChanError;

    fn encode(
        &mut self,
        item: Self::Item<'_>,
        dst: &mut BytesMut,
    ) -> std::result::Result<(), Self::Error> {
        let before_dst_len = dst.len();
        self.filter.encode_cell(item, &mut self.inner, dst)?;
        let after_dst_len = dst.len();
        if let Some(clog) = self.clog.as_mut() {
            // Only use what we actually wrote. Variable length cell are not padded and thus this
            // won't catch a bunch of padding.
            clog.update(&dst[before_dst_len..after_dst_len]);
        }
        Ok(())
    }
}

impl futures_codec::Decoder for HandshakeChannelHandler {
    type Item = AnyChanCell;
    type Error = ChanError;

    fn decode(
        &mut self,
        src: &mut BytesMut,
    ) -> std::result::Result<Option<Self::Item>, Self::Error> {
        let orig = src.clone(); // NOTE: Not fun. But This is only done during handshake.
        let cell = self.filter.decode_cell(&mut self.inner, src)?;
        if let Some(slog) = self.slog.as_mut() {
            let n_used = orig.len() - src.len();
            slog.update(&orig[..n_used]);
        }
        Ok(cell)
    }
}

/// The open channel handler which is used to decode and encode cells onto an open Channel.
pub(crate) struct OpenChannelHandler {
    /// Message filter used to allow or not a certain message.
    filter: MessageFilter,
    /// The cell codec that we'll use to encode and decode our cells.
    inner: codec::ChannelCodec,
}

impl OpenChannelHandler {
    /// Constructor
    fn new(link_version: LinkVersion, channel_type: ChannelType) -> Self {
        Self {
            inner: codec::ChannelCodec::new(link_version.value()),
            filter: MessageFilter::new(link_version, channel_type, super::msg::MessageStage::Open),
        }
    }
}

impl futures_codec::Encoder for OpenChannelHandler {
    type Item<'a> = AnyChanCell;
    type Error = ChanError;

    fn encode(&mut self, item: Self::Item<'_>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        self.filter.encode_cell(item, &mut self.inner, dst)
    }
}

impl futures_codec::Decoder for OpenChannelHandler {
    type Item = AnyChanCell;
    type Error = ChanError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        self.filter.decode_cell(&mut self.inner, src)
    }
}

#[cfg(test)]
pub(crate) mod test {
    #![allow(clippy::unwrap_used)]
    use futures::io::{AsyncRead, AsyncWrite, Cursor, Result};
    use futures::sink::SinkExt;
    use futures::stream::StreamExt;
    use futures::task::{Context, Poll};
    use hex_literal::hex;
    use std::pin::Pin;
    use tor_rtcompat::StreamOps;

    use crate::channel::ChannelType;
    use crate::channel::msg::LinkVersion;

    use super::{ChannelCellHandler, OpenChannelHandler, futures_codec};
    use tor_cell::chancell::{AnyChanCell, ChanCmd, ChanMsg, CircId, msg};

    /// Helper type for reading and writing bytes to/from buffers.
    pub(crate) struct MsgBuf {
        /// Data we have received as a reader.
        inbuf: futures::io::Cursor<Vec<u8>>,
        /// Data we write as a writer.
        outbuf: futures::io::Cursor<Vec<u8>>,
    }

    impl AsyncRead for MsgBuf {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<Result<usize>> {
            Pin::new(&mut self.inbuf).poll_read(cx, buf)
        }
    }
    impl AsyncWrite for MsgBuf {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize>> {
            Pin::new(&mut self.outbuf).poll_write(cx, buf)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
            Pin::new(&mut self.outbuf).poll_flush(cx)
        }
        fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
            Pin::new(&mut self.outbuf).poll_close(cx)
        }
    }

    impl StreamOps for MsgBuf {}

    impl MsgBuf {
        pub(crate) fn new<T: Into<Vec<u8>>>(output: T) -> Self {
            let inbuf = Cursor::new(output.into());
            let outbuf = Cursor::new(Vec::new());
            MsgBuf { inbuf, outbuf }
        }

        pub(crate) fn consumed(&self) -> usize {
            self.inbuf.position() as usize
        }

        pub(crate) fn all_consumed(&self) -> bool {
            self.inbuf.get_ref().len() == self.consumed()
        }

        pub(crate) fn into_response(self) -> Vec<u8> {
            self.outbuf.into_inner()
        }
    }

    fn new_client_open_frame(mbuf: MsgBuf) -> futures_codec::Framed<MsgBuf, ChannelCellHandler> {
        let open_handler = ChannelCellHandler::Open(OpenChannelHandler::new(
            LinkVersion::V5,
            ChannelType::ClientInitiator,
        ));
        futures_codec::Framed::new(mbuf, open_handler)
    }

    #[test]
    fn check_client_encoding() {
        tor_rtcompat::test_with_all_runtimes!(|_rt| async move {
            let mb = MsgBuf::new(&b""[..]);
            let mut framed = new_client_open_frame(mb);

            let destroycell = msg::Destroy::new(2.into());
            framed
                .send(AnyChanCell::new(CircId::new(7), destroycell.into()))
                .await
                .unwrap();

            framed.flush().await.unwrap();

            let data = framed.into_inner().into_response();

            assert_eq!(&data[0..10], &hex!("00000007 04 0200000000")[..]);
        });
    }

    #[test]
    fn check_client_decoding() {
        tor_rtcompat::test_with_all_runtimes!(|_rt| async move {
            let mut dat = Vec::new();
            // DESTROY cell.
            dat.extend_from_slice(&hex!("00000007 04 0200000000")[..]);
            dat.resize(514, 0);
            let mb = MsgBuf::new(&dat[..]);
            let mut framed = new_client_open_frame(mb);

            let destroy = framed.next().await.unwrap().unwrap();

            let circ_id = CircId::new(7);
            assert_eq!(destroy.circid(), circ_id);
            assert_eq!(destroy.msg().cmd(), ChanCmd::DESTROY);

            assert!(framed.into_inner().all_consumed());
        });
    }
}
