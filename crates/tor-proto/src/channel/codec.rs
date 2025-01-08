//! Wrap tor_cell::...:::ChannelCodec for use with the futures_codec
//! crate.
use std::{io::Error as IoError, marker::PhantomData};

use futures::{AsyncRead, AsyncWrite};
use tor_cell::chancell::{codec, ChanCell, ChanMsg};

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
/// AsyncRead+AsyncWrite type) as a Sink and a Stream of ChanCell, so we can
/// forget about byte-oriented communication.
///
/// It's parameterized on two message types: one that we're allowed to receive
/// (`IN`), and one that we're allowed to send (`OUT`).
pub(crate) struct ChannelCodec<IN, OUT> {
    /// The cell codec that we'll use to encode and decode our cells.
    inner: codec::ChannelCodec,
    /// Tells the compiler that we're using IN, and we might
    /// consume values of type IN.
    _phantom_in: PhantomData<fn(IN)>,
    /// Tells the compiler that we're using OUT, and we might
    /// produce values of type OUT.
    _phantom_out: PhantomData<fn() -> OUT>,
}

impl<IN, OUT> ChannelCodec<IN, OUT> {
    /// Create a new ChannelCodec with a given link protocol.
    pub(crate) fn new(link_proto: u16) -> Self {
        ChannelCodec {
            inner: codec::ChannelCodec::new(link_proto),
            _phantom_in: PhantomData,
            _phantom_out: PhantomData,
        }
    }

    /// Consume this codec, and return a new one that sends and receives
    /// different message types.
    pub(crate) fn change_message_types<IN2, OUT2>(self) -> ChannelCodec<IN2, OUT2> {
        ChannelCodec {
            inner: self.inner,
            _phantom_in: PhantomData,
            _phantom_out: PhantomData,
        }
    }
}

impl<IN, OUT> futures_codec::Encoder for ChannelCodec<IN, OUT>
where
    OUT: ChanMsg,
{
    type Item<'a> = ChanCell<OUT>;
    type Error = CodecError;

    fn encode(&mut self, item: Self::Item<'_>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        self.inner
            .write_cell(item, dst)
            .map_err(CodecError::EncCell)?;
        Ok(())
    }
}

impl<IN, OUT> futures_codec::Decoder for ChannelCodec<IN, OUT>
where
    IN: ChanMsg,
{
    type Item = ChanCell<IN>;
    type Error = CodecError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        self.inner.decode_cell(src).map_err(CodecError::DecCell)
    }
}

/// Consume a [`Framed`](futures_codec::Framed) codec user, and produce one that
/// sends and receives different message types.
pub(crate) fn change_message_types<T, IN, OUT, IN2, OUT2>(
    framed: futures_codec::Framed<T, ChannelCodec<IN, OUT>>,
) -> futures_codec::Framed<T, ChannelCodec<IN2, OUT2>>
where
    T: AsyncRead + AsyncWrite,
    IN: ChanMsg,
    OUT: ChanMsg,
    IN2: ChanMsg,
    OUT2: ChanMsg,
{
    futures_codec::Framed::from_parts(
        framed
            .into_parts()
            .map_codec(ChannelCodec::change_message_types),
    )
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
    use tor_cell::chancell::msg::AnyChanMsg;
    use tor_rtcompat::StreamOps;

    use super::{futures_codec, ChannelCodec};
    use tor_cell::chancell::{msg, AnyChanCell, ChanCmd, ChanMsg, CircId};

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

    fn frame_buf(
        mbuf: MsgBuf,
    ) -> futures_codec::Framed<MsgBuf, ChannelCodec<AnyChanMsg, AnyChanMsg>> {
        futures_codec::Framed::new(mbuf, ChannelCodec::new(4))
    }

    #[test]
    fn check_encoding() {
        tor_rtcompat::test_with_all_runtimes!(|_rt| async move {
            let mb = MsgBuf::new(&b""[..]);
            let mut framed = frame_buf(mb);

            let destroycell = msg::Destroy::new(2.into());
            framed
                .send(AnyChanCell::new(CircId::new(7), destroycell.into()))
                .await
                .unwrap();

            let nocerts = msg::Certs::new_empty();
            framed
                .send(AnyChanCell::new(None, nocerts.into()))
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

            assert_eq!(destroy.circid(), CircId::new(7));
            assert_eq!(destroy.msg().cmd(), ChanCmd::DESTROY);
            assert_eq!(nocerts.circid(), None);
            assert_eq!(nocerts.msg().cmd(), ChanCmd::CERTS);

            assert!(framed.into_inner().all_consumed());
        });
    }
}
