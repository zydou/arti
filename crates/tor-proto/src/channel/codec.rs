//! Wrap tor_cell::...:::ChannelCodec for use with the futures_codec
//! crate.
use std::io::Error as IoError;

use tor_cell::chancell::{codec, ChanCell};

use asynchronous_codec as futures_codec;
use bytes::BytesMut;

/// An error from a ChannelCodec.
///
/// This is a separate error type for now because I suspect that we'll want to
/// handle these differently in the rest of our channel code.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CodecError {
    /// An error from the underlying IO stream underneath a codec.
    ///
    /// (This isn't wrapped in an Arc, because we don't need this type to be
    /// clone; it's crate-internal.)
    #[error("Io error reading or writing a channel cell")]
    Io(#[from] IoError),
    /// An error from the cell decoding logic.
    #[error("Error decoding an incoming channel cell")]
    DecCell(#[source] tor_cell::Error),
    /// An error from the cell encoding logic.
    #[error("Error encoding an outgoing channel cell")]
    EncCell(#[source] tor_cell::Error),
}

/// Asynchronous wrapper around ChannelCodec in tor_cell, with implementation
/// for use with futures_codec.
///
/// This type lets us wrap a TLS channel (or some other secure
/// AsyncRead+AsyncWrite type) as a Sink and a Stream of ChanCell, so we
/// can forget about byte-oriented communication.
pub(crate) struct ChannelCodec(codec::ChannelCodec);

impl ChannelCodec {
    /// Create a new ChannelCodec with a given link protocol.
    pub(crate) fn new(link_proto: u16) -> Self {
        ChannelCodec(codec::ChannelCodec::new(link_proto))
    }
}

impl futures_codec::Encoder for ChannelCodec {
    type Item = ChanCell;
    type Error = CodecError;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        self.0.write_cell(item, dst).map_err(CodecError::EncCell)?;
        Ok(())
    }
}

impl futures_codec::Decoder for ChannelCodec {
    type Item = ChanCell;
    type Error = CodecError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        self.0.decode_cell(src).map_err(CodecError::DecCell)
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

    use super::{futures_codec, ChannelCodec};
    use tor_cell::chancell::{msg, ChanCell, ChanCmd, ChanMsgClass, CircId};

    /// Helper type for reading and writing bytes to/from buffers.
    // TODO: We might want to move this
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

    fn frame_buf(mbuf: MsgBuf) -> futures_codec::Framed<MsgBuf, ChannelCodec> {
        futures_codec::Framed::new(mbuf, ChannelCodec::new(4))
    }

    #[test]
    fn check_encoding() {
        tor_rtcompat::test_with_all_runtimes!(|_rt| async move {
            let mb = MsgBuf::new(&b""[..]);
            let mut framed = frame_buf(mb);

            let destroycell = msg::Destroy::new(2.into());
            framed
                .send(ChanCell::new(7.into(), destroycell.into()))
                .await
                .unwrap();

            let nocerts = msg::Certs::new_empty();
            framed
                .send(ChanCell::new(0.into(), nocerts.into()))
                .await
                .unwrap();

            framed.flush().await.unwrap();

            let data = framed.into_inner().into_response();

            assert_eq!(&data[0..10], &hex!("00000007 04 0200000000")[..]);

            assert_eq!(&data[514..], &hex!("00000000 81 0001 00")[..]);
        });
    }

    #[test]
    fn check_decoding() {
        tor_rtcompat::test_with_all_runtimes!(|_rt| async move {
            let mut dat = Vec::new();
            dat.extend_from_slice(&hex!("00000007 04 0200000000")[..]);
            dat.resize(514, 0);
            dat.extend_from_slice(&hex!("00000000 81 0001 00")[..]);
            let mb = MsgBuf::new(&dat[..]);
            let mut framed = frame_buf(mb);

            let destroy = framed.next().await.unwrap().unwrap();
            let nocerts = framed.next().await.unwrap().unwrap();

            assert_eq!(destroy.circid(), CircId::from(7));
            assert_eq!(destroy.msg().cmd(), ChanCmd::DESTROY);
            assert_eq!(nocerts.circid(), CircId::from(0));
            assert_eq!(nocerts.msg().cmd(), ChanCmd::CERTS);

            assert!(framed.into_inner().all_consumed());
        });
    }
}
