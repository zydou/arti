//! Declare DataStream, a type that wraps RawCellStream so as to be useful
//! for byte-oriented communication.

use crate::{Error, Result};
use static_assertions::assert_impl_all;
use tor_cell::relaycell::msg::EndReason;
use tor_cell::relaycell::{RelayCellFormat, RelayCmd};

use futures::io::{AsyncRead, AsyncWrite};
use futures::stream::StreamExt;
use futures::task::{Context, Poll};
use futures::{Future, Stream};
use pin_project::pin_project;
use postage::watch;

#[cfg(feature = "tokio")]
use tokio_crate::io::ReadBuf;
#[cfg(feature = "tokio")]
use tokio_crate::io::{AsyncRead as TokioAsyncRead, AsyncWrite as TokioAsyncWrite};
#[cfg(feature = "tokio")]
use tokio_util::compat::{FuturesAsyncReadCompatExt, FuturesAsyncWriteCompatExt};
use tor_cell::restricted_msg;

use std::fmt::Debug;
use std::io::Result as IoResult;
use std::num::NonZero;
use std::pin::Pin;
#[cfg(any(feature = "stream-ctrl", feature = "experimental-api"))]
use std::sync::Arc;
#[cfg(feature = "stream-ctrl")]
use std::sync::{Mutex, Weak};

use educe::Educe;

use crate::client::ClientTunnel;
use crate::client::stream::StreamReceiver;
use crate::memquota::StreamAccount;
use crate::stream::StreamTarget;
use crate::stream::cmdcheck::{AnyCmdChecker, CmdChecker, StreamStatus};
use crate::stream::flow_ctrl::state::StreamRateLimit;
use crate::stream::flow_ctrl::xon_xoff::reader::{BufferIsEmpty, XonXoffReader, XonXoffReaderCtrl};
use crate::util::token_bucket::dynamic_writer::DynamicRateLimitedWriter;
use crate::util::token_bucket::writer::{RateLimitedWriter, RateLimitedWriterConfig};
use tor_basic_utils::skip_fmt;
use tor_cell::relaycell::msg::Data;
use tor_error::internal;
use tor_rtcompat::{CoarseTimeProvider, DynTimeProvider, SleepProvider};

/// A stream of [`RateLimitedWriterConfig`] used to update a [`DynamicRateLimitedWriter`].
///
/// Unfortunately we need to store the result of a [`StreamExt::map`] and [`StreamExt::fuse`] in
/// [`DataWriter`], which leaves us with this ugly type.
/// We use a type alias to make `DataWriter` a little nicer.
type RateConfigStream = futures::stream::Map<
    futures::stream::Fuse<watch::Receiver<StreamRateLimit>>,
    fn(StreamRateLimit) -> RateLimitedWriterConfig,
>;

/// An anonymized stream over the Tor network.
///
/// For most purposes, you can think of this type as an anonymized
/// TCP stream: it can read and write data, and get closed when it's done.
///
/// [`DataStream`] implements [`futures::io::AsyncRead`] and
/// [`futures::io::AsyncWrite`], so you can use it anywhere that those
/// traits are expected.
///
/// # Examples
///
/// Connecting to an HTTP server and sending a request, using
/// [`AsyncWriteExt::write_all`](futures::io::AsyncWriteExt::write_all):
///
/// ```ignore
/// let mut stream = tor_client.connect(("icanhazip.com", 80), None).await?;
///
/// use futures::io::AsyncWriteExt;
///
/// stream
///     .write_all(b"GET / HTTP/1.1\r\nHost: icanhazip.com\r\nConnection: close\r\n\r\n")
///     .await?;
///
/// // Flushing the stream is important; see below!
/// stream.flush().await?;
/// ```
///
/// Reading the result, using [`AsyncReadExt::read_to_end`](futures::io::AsyncReadExt::read_to_end):
///
/// ```ignore
/// use futures::io::AsyncReadExt;
///
/// let mut buf = Vec::new();
/// stream.read_to_end(&mut buf).await?;
///
/// println!("{}", String::from_utf8_lossy(&buf));
/// ```
///
/// # Usage with Tokio
///
/// If the `tokio` crate feature is enabled, this type also implements
/// [`tokio::io::AsyncRead`](tokio_crate::io::AsyncRead) and
/// [`tokio::io::AsyncWrite`](tokio_crate::io::AsyncWrite) for easier integration
/// with code that expects those traits.
///
/// # Remember to call `flush`!
///
/// DataStream buffers data internally, in order to write as few cells
/// as possible onto the network.  In order to make sure that your
/// data has actually been sent, you need to make sure that
/// [`AsyncWrite::poll_flush`] runs to completion: probably via
/// [`AsyncWriteExt::flush`](futures::io::AsyncWriteExt::flush).
///
/// # Splitting the type
///
/// This type is internally composed of a [`DataReader`] and a [`DataWriter`]; the
/// `DataStream::split` method can be used to split it into those two parts, for more
/// convenient usage with e.g. stream combinators.
///
/// # How long does a stream live?
///
/// A `DataStream` will live until all references to it are dropped,
/// or until it is closed explicitly.
///
/// If you split the stream into a `DataReader` and a `DataWriter`, it
/// will survive until _both_ are dropped, or until it is closed
/// explicitly.
///
/// A stream can also close because of a network error,
/// or because the other side of the stream decided to close it.
///
// # Semver note
//
// Note that this type is re-exported as a part of the public API of
// the `arti-client` crate.  Any changes to its API here in
// `tor-proto` need to be reflected above.
#[derive(Debug)]
pub struct DataStream {
    /// Underlying writer for this stream
    w: DataWriter,
    /// Underlying reader for this stream
    r: DataReader,
    /// A control object that can be used to monitor and control this stream
    /// without needing to own it.
    #[cfg(feature = "stream-ctrl")]
    ctrl: Arc<ClientDataStreamCtrl>,
}
assert_impl_all! { DataStream: Send, Sync }

/// An object used to control and monitor a data stream.
///
/// # Notes
///
/// This is a separate type from [`DataStream`] because it's useful to have
/// multiple references to this object, whereas a [`DataReader`] and [`DataWriter`]
/// need to have a single owner for the `AsyncRead` and `AsyncWrite` APIs to
/// work correctly.
#[cfg(feature = "stream-ctrl")]
#[derive(Debug)]
pub struct ClientDataStreamCtrl {
    /// The circuit to which this stream is attached.
    ///
    /// Note that the stream's reader and writer halves each contain a `StreamTarget`,
    /// which in turn has a strong reference to the `ClientCirc`.  So as long as any
    /// one of those is alive, this reference will be present.
    ///
    /// We make this a Weak reference so that once the stream itself is closed,
    /// we can't leak circuits.
    tunnel: Weak<ClientTunnel>,

    /// Shared user-visible information about the state of this stream.
    ///
    /// TODO RPC: This will probably want to be a `postage::Watch` or something
    /// similar, if and when it stops moving around.
    #[cfg(feature = "stream-ctrl")]
    status: Arc<Mutex<DataStreamStatus>>,

    /// The memory quota account that should be used for this stream's data
    ///
    /// Exists to keep the account alive
    _memquota: StreamAccount,
}

/// The inner writer for [`DataWriter`].
///
/// This type is responsible for taking bytes and packaging them into cells.
/// Rate limiting is implemented in [`DataWriter`] to avoid making this type more complex.
#[derive(Debug)]
struct DataWriterInner {
    /// Internal state for this writer
    ///
    /// This is stored in an Option so that we can mutate it in the
    /// AsyncWrite functions.  It might be possible to do better here,
    /// and we should refactor if so.
    state: Option<DataWriterState>,

    /// The memory quota account that should be used for this stream's data
    ///
    /// Exists to keep the account alive
    // If we liked, we could make this conditional; see DataReaderInner.memquota
    _memquota: StreamAccount,

    /// A control object that can be used to monitor and control this stream
    /// without needing to own it.
    #[cfg(feature = "stream-ctrl")]
    ctrl: Arc<ClientDataStreamCtrl>,
}

/// The write half of a [`DataStream`], implementing [`futures::io::AsyncWrite`].
///
/// See the [`DataStream`] docs for more information. In particular, note
/// that this writer requires `poll_flush` to complete in order to guarantee that
/// all data has been written.
///
/// # Usage with Tokio
///
/// If the `tokio` crate feature is enabled, this type also implements
/// [`tokio::io::AsyncWrite`](tokio_crate::io::AsyncWrite) for easier integration
/// with code that expects that trait.
///
/// # Drop and close
///
/// Note that dropping a `DataWriter` has no special effect on its own:
/// if the `DataWriter` is dropped, the underlying stream will still remain open
/// until the `DataReader` is also dropped.
///
/// If you want the stream to close earlier, use [`close`](futures::io::AsyncWriteExt::close)
/// (or [`shutdown`](tokio_crate::io::AsyncWriteExt::shutdown) with `tokio`).
///
/// Remember that Tor does not support half-open streams:
/// If you `close` or `shutdown` a stream,
/// the other side will not see the stream as half-open,
/// and so will (probably) not finish sending you any in-progress data.
/// Do not use `close`/`shutdown` to communicate anything besides
/// "I am done using this stream."
///
// # Semver note
//
// Note that this type is re-exported as a part of the public API of
// the `arti-client` crate.  Any changes to its API here in
// `tor-proto` need to be reflected above.
#[derive(Debug)]
pub struct DataWriter {
    /// A wrapper around [`DataWriterInner`] that adds rate limiting.
    writer: DynamicRateLimitedWriter<DataWriterInner, RateConfigStream, DynTimeProvider>,
}

impl DataWriter {
    /// Create a new rate-limited [`DataWriter`] from a [`DataWriterInner`].
    fn new(
        inner: DataWriterInner,
        rate_limit_updates: watch::Receiver<StreamRateLimit>,
        time_provider: DynTimeProvider,
    ) -> Self {
        /// Converts a `rate` into a `RateLimitedWriterConfig`.
        fn rate_to_config(rate: StreamRateLimit) -> RateLimitedWriterConfig {
            let rate = rate.bytes_per_sec();
            RateLimitedWriterConfig {
                rate,        // bytes per second
                burst: rate, // bytes
                // This number is chosen arbitrarily, but the idea is that we want to balance
                // between throughput and latency. Assume the user tries to write a large buffer
                // (~600 bytes). If we set this too small (for example 1), we'll be waking up
                // frequently and writing a small number of bytes each time to the
                // `DataWriterInner`, even if this isn't enough bytes to send a cell. If we set this
                // too large (for example 510), we'll be waking up infrequently to write a larger
                // number of bytes each time. So even if the `DataWriterInner` has almost a full
                // cell's worth of data queued (for example 490) and only needs 509-490=19 more
                // bytes before a cell can be sent, it will block until the rate limiter allows 510
                // more bytes.
                //
                // TODO(arti#2028): Is there an optimal value here?
                wake_when_bytes_available: NonZero::new(200).expect("200 != 0"), // bytes
            }
        }

        // get the current rate from the `watch::Receiver`, which we'll use as the initial rate
        let initial_rate: StreamRateLimit = *rate_limit_updates.borrow();

        // map the rate update stream to the type required by `DynamicRateLimitedWriter`
        let rate_limit_updates = rate_limit_updates.fuse().map(rate_to_config as fn(_) -> _);

        // build the rate limiter
        let writer = RateLimitedWriter::new(inner, &rate_to_config(initial_rate), time_provider);
        let writer = DynamicRateLimitedWriter::new(writer, rate_limit_updates);

        Self { writer }
    }

    /// Return a [`ClientDataStreamCtrl`] object that can be used to monitor and
    /// interact with this stream without holding the stream itself.
    #[cfg(feature = "stream-ctrl")]
    pub fn client_stream_ctrl(&self) -> Option<&Arc<ClientDataStreamCtrl>> {
        Some(self.writer.inner().client_stream_ctrl())
    }
}

impl AsyncWrite for DataWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<IoResult<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.writer), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.writer), cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        AsyncWrite::poll_close(Pin::new(&mut self.writer), cx)
    }
}

#[cfg(feature = "tokio")]
impl TokioAsyncWrite for DataWriter {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<IoResult<usize>> {
        TokioAsyncWrite::poll_write(Pin::new(&mut self.compat_write()), cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        TokioAsyncWrite::poll_flush(Pin::new(&mut self.compat_write()), cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        TokioAsyncWrite::poll_shutdown(Pin::new(&mut self.compat_write()), cx)
    }
}

/// The read half of a [`DataStream`], implementing [`futures::io::AsyncRead`].
///
/// See the [`DataStream`] docs for more information.
///
/// # Usage with Tokio
///
/// If the `tokio` crate feature is enabled, this type also implements
/// [`tokio::io::AsyncRead`](tokio_crate::io::AsyncRead) for easier integration
/// with code that expects that trait.
//
// # Semver note
//
// Note that this type is re-exported as a part of the public API of
// the `arti-client` crate.  Any changes to its API here in
// `tor-proto` need to be reflected above.
#[derive(Debug)]
pub struct DataReader {
    /// The [`DataReaderInner`] with a wrapper to support XON/XOFF flow control.
    reader: XonXoffReader<DataReaderInner>,
}

impl DataReader {
    /// Create a new [`DataReader`].
    fn new(reader: DataReaderInner, xon_xoff_reader_ctrl: XonXoffReaderCtrl) -> Self {
        Self {
            reader: XonXoffReader::new(xon_xoff_reader_ctrl, reader),
        }
    }

    /// Return a [`ClientDataStreamCtrl`] object that can be used to monitor and
    /// interact with this stream without holding the stream itself.
    #[cfg(feature = "stream-ctrl")]
    pub fn client_stream_ctrl(&self) -> Option<&Arc<ClientDataStreamCtrl>> {
        Some(self.reader.inner().client_stream_ctrl())
    }
}

impl AsyncRead for DataReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        AsyncRead::poll_read(Pin::new(&mut self.reader), cx, buf)
    }

    fn poll_read_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
    ) -> Poll<IoResult<usize>> {
        AsyncRead::poll_read_vectored(Pin::new(&mut self.reader), cx, bufs)
    }
}

#[cfg(feature = "tokio")]
impl TokioAsyncRead for DataReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<IoResult<()>> {
        TokioAsyncRead::poll_read(Pin::new(&mut self.compat()), cx, buf)
    }
}

/// The inner reader for [`DataReader`].
///
/// This type is responsible for taking stream messages and extracting the stream data from them.
/// Flow control logic is implemented in [`DataReader`] to avoid making this type more complex.
#[derive(Debug)]
pub(crate) struct DataReaderInner {
    /// Internal state for this reader.
    ///
    /// This is stored in an Option so that we can mutate it in
    /// poll_read().  It might be possible to do better here, and we
    /// should refactor if so.
    state: Option<DataReaderState>,

    /// The memory quota account that should be used for this stream's data
    ///
    /// Exists to keep the account alive
    // If we liked, we could make this conditional on not(cfg(feature = "stream-ctrl"))
    // since, ClientDataStreamCtrl contains a StreamAccount clone too.  But that seems fragile.
    _memquota: StreamAccount,

    /// A control object that can be used to monitor and control this stream
    /// without needing to own it.
    #[cfg(feature = "stream-ctrl")]
    ctrl: Arc<ClientDataStreamCtrl>,
}

impl BufferIsEmpty for DataReaderInner {
    /// The result will become stale,
    /// so is most accurate immediately after a [`poll_read`](AsyncRead::poll_read).
    fn is_empty(mut self: Pin<&mut Self>) -> bool {
        match self
            .state
            .as_mut()
            .expect("forgot to put `DataReaderState` back")
        {
            DataReaderState::Open(imp) => {
                // check if the partial cell in `pending` is empty,
                // and if the message stream is empty
                imp.pending[imp.offset..].is_empty() && imp.s.is_empty()
            }
            // closed, so any data should have been discarded
            DataReaderState::Closed => true,
        }
    }
}

/// Shared status flags for tracking the status of as `DataStream`.
///
/// We expect to refactor this a bit, so it's not exposed at all.
//
// TODO RPC: Possibly instead of manipulating the fields of DataStreamStatus
// from various points in this module, we should instead construct
// DataStreamStatus as needed from information available elsewhere.  In any
// case, we should really  eliminate as much duplicate state here as we can.
// (See discussions at !1198 for some challenges with this.)
#[cfg(feature = "stream-ctrl")]
#[derive(Clone, Debug, Default)]
struct DataStreamStatus {
    /// True if we've received a CONNECTED message.
    //
    // TODO: This is redundant with `connected` in DataReaderImpl.
    received_connected: bool,
    /// True if we have decided to send an END message.
    //
    // TODO RPC: There is not an easy way to set this from this module!  Really,
    // the decision to send an "end" is made when the StreamTarget object is
    // dropped, but we don't currently have any way to see when that happens.
    // Perhaps we need a different shared StreamStatus object that the
    // StreamTarget holds?
    sent_end: bool,
    /// True if we have received an END message telling us to close the stream.
    received_end: bool,
    /// True if we have received an error.
    ///
    /// (This is not a subset or superset of received_end; some errors are END
    /// messages but some aren't; some END messages are errors but some aren't.)
    received_err: bool,
}

#[cfg(feature = "stream-ctrl")]
impl DataStreamStatus {
    /// Remember that we've received a connected message.
    fn record_connected(&mut self) {
        self.received_connected = true;
    }

    /// Remember that we've received an error of some kind.
    fn record_error(&mut self, e: &Error) {
        // TODO: Probably we should remember the actual error in a box or
        // something.  But that means making a redundant copy of the error
        // even if nobody will want it.  Do we care?
        match e {
            Error::EndReceived(EndReason::DONE) => self.received_end = true,
            Error::EndReceived(_) => {
                self.received_end = true;
                self.received_err = true;
            }
            _ => self.received_err = true,
        }
    }
}

restricted_msg! {
    /// An allowable incoming message on a client data stream.
    enum ClientDataStreamMsg:RelayMsg {
        // SENDME is handled by the reactor.
        Data, End, Connected,
    }
}

// TODO RPC: Should we also implement this trait for everything that holds a
// ClientDataStreamCtrl?
#[cfg(feature = "stream-ctrl")]
impl super::ctrl::ClientStreamCtrl for ClientDataStreamCtrl {
    fn tunnel(&self) -> Option<Arc<ClientTunnel>> {
        self.tunnel.upgrade()
    }
}

#[cfg(feature = "stream-ctrl")]
impl ClientDataStreamCtrl {
    /// Return true if the underlying stream is connected. (That is, if it has
    /// received a `CONNECTED` message, and has not been closed.)
    pub fn is_connected(&self) -> bool {
        let s = self.status.lock().expect("poisoned lock");
        s.received_connected && !(s.sent_end || s.received_end || s.received_err)
    }

    // TODO RPC: Add more functions once we have the desired API more nailed
    // down.
}

impl DataStream {
    /// Wrap raw stream receiver and target parts as a DataStream.
    ///
    /// For non-optimistic stream, function `wait_for_connection`
    /// must be called after to make sure CONNECTED is received.
    pub(crate) fn new<P: SleepProvider + CoarseTimeProvider>(
        time_provider: P,
        receiver: StreamReceiver,
        xon_xoff_reader_ctrl: XonXoffReaderCtrl,
        target: StreamTarget,
        memquota: StreamAccount,
    ) -> Self {
        Self::new_inner(
            time_provider,
            receiver,
            xon_xoff_reader_ctrl,
            target,
            false,
            memquota,
        )
    }

    /// Wrap raw stream receiver and target parts as a connected DataStream.
    ///
    /// Unlike [`DataStream::new`], this creates a `DataStream` that does not expect to receive a
    /// CONNECTED cell.
    ///
    /// This is used by hidden services, exit relays, and directory servers to accept streams.
    #[cfg(any(feature = "hs-service", feature = "relay"))]
    pub(crate) fn new_connected<P: SleepProvider + CoarseTimeProvider>(
        time_provider: P,
        receiver: StreamReceiver,
        xon_xoff_reader_ctrl: XonXoffReaderCtrl,
        target: StreamTarget,
        memquota: StreamAccount,
    ) -> Self {
        Self::new_inner(
            time_provider,
            receiver,
            xon_xoff_reader_ctrl,
            target,
            true,
            memquota,
        )
    }

    /// The shared implementation of the `new*()` functions.
    fn new_inner<P: SleepProvider + CoarseTimeProvider>(
        time_provider: P,
        receiver: StreamReceiver,
        xon_xoff_reader_ctrl: XonXoffReaderCtrl,
        target: StreamTarget,
        connected: bool,
        memquota: StreamAccount,
    ) -> Self {
        let relay_cell_format = target.relay_cell_format();
        let out_buf_len = Data::max_body_len(relay_cell_format);
        let rate_limit_stream = target.rate_limit_stream().clone();

        #[cfg(feature = "stream-ctrl")]
        let status = {
            let mut data_stream_status = DataStreamStatus::default();
            if connected {
                data_stream_status.record_connected();
            }
            Arc::new(Mutex::new(data_stream_status))
        };

        #[cfg(feature = "stream-ctrl")]
        let ctrl = {
            let tunnel = match target.tunnel() {
                crate::stream::Tunnel::Client(t) => Arc::downgrade(t),
                #[cfg(feature = "relay")]
                crate::stream::Tunnel::Relay(_) => panic!("created a relay tunnel in the client?!"),
            };

            Arc::new(ClientDataStreamCtrl {
                tunnel,
                status: status.clone(),
                _memquota: memquota.clone(),
            })
        };
        let r = DataReaderInner {
            state: Some(DataReaderState::Open(DataReaderImpl {
                s: receiver,
                pending: Vec::new(),
                offset: 0,
                connected,
                #[cfg(feature = "stream-ctrl")]
                status: status.clone(),
            })),
            _memquota: memquota.clone(),
            #[cfg(feature = "stream-ctrl")]
            ctrl: ctrl.clone(),
        };
        let w = DataWriterInner {
            state: Some(DataWriterState::Ready(DataWriterImpl {
                s: target,
                buf: vec![0; out_buf_len].into_boxed_slice(),
                n_pending: 0,
                #[cfg(feature = "stream-ctrl")]
                status,
                relay_cell_format,
            })),
            _memquota: memquota,
            #[cfg(feature = "stream-ctrl")]
            ctrl: ctrl.clone(),
        };

        let time_provider = DynTimeProvider::new(time_provider);

        DataStream {
            w: DataWriter::new(w, rate_limit_stream, time_provider),
            r: DataReader::new(r, xon_xoff_reader_ctrl),
            #[cfg(feature = "stream-ctrl")]
            ctrl,
        }
    }

    /// Divide this DataStream into its constituent parts.
    pub fn split(self) -> (DataReader, DataWriter) {
        (self.r, self.w)
    }

    /// Wait until a CONNECTED cell is received, or some other cell
    /// is received to indicate an error.
    ///
    /// Does nothing if this stream is already connected.
    pub async fn wait_for_connection(&mut self) -> Result<()> {
        // We must put state back before returning
        let state = self
            .r
            .reader
            .inner_mut()
            .state
            .take()
            .expect("Missing state in DataReaderInner");

        if let DataReaderState::Open(mut imp) = state {
            let result = if imp.connected {
                Ok(())
            } else {
                // This succeeds if the cell is CONNECTED, and fails otherwise.
                std::future::poll_fn(|cx| Pin::new(&mut imp).read_cell(cx)).await
            };
            self.r.reader.inner_mut().state = Some(match result {
                Err(_) => DataReaderState::Closed,
                Ok(_) => DataReaderState::Open(imp),
            });
            result
        } else {
            Err(Error::from(internal!(
                "Expected ready state, got {:?}",
                state
            )))
        }
    }

    /// Return a [`ClientDataStreamCtrl`] object that can be used to monitor and
    /// interact with this stream without holding the stream itself.
    #[cfg(feature = "stream-ctrl")]
    pub fn client_stream_ctrl(&self) -> Option<&Arc<ClientDataStreamCtrl>> {
        Some(&self.ctrl)
    }
}

impl AsyncRead for DataStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        AsyncRead::poll_read(Pin::new(&mut self.r), cx, buf)
    }
}

#[cfg(feature = "tokio")]
impl TokioAsyncRead for DataStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<IoResult<()>> {
        TokioAsyncRead::poll_read(Pin::new(&mut self.compat()), cx, buf)
    }
}

impl AsyncWrite for DataStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<IoResult<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.w), cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.w), cx)
    }
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        AsyncWrite::poll_close(Pin::new(&mut self.w), cx)
    }
}

#[cfg(feature = "tokio")]
impl TokioAsyncWrite for DataStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<IoResult<usize>> {
        TokioAsyncWrite::poll_write(Pin::new(&mut self.compat()), cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        TokioAsyncWrite::poll_flush(Pin::new(&mut self.compat()), cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        TokioAsyncWrite::poll_shutdown(Pin::new(&mut self.compat()), cx)
    }
}

/// Helper type: Like BoxFuture, but also requires that the future be Sync.
type BoxSyncFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + Sync + 'a>>;

/// An enumeration for the state of a DataWriter.
///
/// We have to use an enum here because, for as long as we're waiting
/// for a flush operation to complete, the future returned by
/// `flush_cell()` owns the DataWriterImpl.
#[derive(Educe)]
#[educe(Debug)]
enum DataWriterState {
    /// The writer has closed or gotten an error: nothing more to do.
    Closed,
    /// The writer is not currently flushing; more data can get queued
    /// immediately.
    Ready(DataWriterImpl),
    /// The writer is flushing a cell.
    Flushing(
        #[educe(Debug(method = "skip_fmt"))] //
        BoxSyncFuture<'static, (DataWriterImpl, Result<()>)>,
    ),
}

/// Internal: the write part of a DataStream
#[derive(Educe)]
#[educe(Debug)]
struct DataWriterImpl {
    /// The underlying StreamTarget object.
    s: StreamTarget,

    /// Buffered data to send over the connection.
    ///
    /// This buffer is currently allocated using a number of bytes
    /// equal to the maximum that we can package at a time.
    //
    // TODO: this buffer is probably smaller than we want, but it's good
    // enough for now.  If we _do_ make it bigger, we'll have to change
    // our use of Data::split_from to handle the case where we can't fit
    // all the data.
    #[educe(Debug(method = "skip_fmt"))]
    buf: Box<[u8]>,

    /// Number of unflushed bytes in buf.
    n_pending: usize,

    /// Relay cell format in use
    relay_cell_format: RelayCellFormat,

    /// Shared user-visible information about the state of this stream.
    #[cfg(feature = "stream-ctrl")]
    status: Arc<Mutex<DataStreamStatus>>,
}

impl DataWriterInner {
    /// See [`DataWriter::client_stream_ctrl`].
    #[cfg(feature = "stream-ctrl")]
    fn client_stream_ctrl(&self) -> &Arc<ClientDataStreamCtrl> {
        &self.ctrl
    }

    /// Helper for poll_flush() and poll_close(): Performs a flush, then
    /// closes the stream if should_close is true.
    fn poll_flush_impl(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        should_close: bool,
    ) -> Poll<IoResult<()>> {
        let state = self.state.take().expect("Missing state in DataWriter");

        // TODO: this whole function is a bit copy-pasted.
        let mut future: BoxSyncFuture<_> = match state {
            DataWriterState::Ready(imp) => {
                if imp.n_pending == 0 {
                    // Nothing to flush!
                    if should_close {
                        // We need to actually continue with this function to do the closing.
                        // Thus, make a future that does nothing and is ready immediately.
                        Box::pin(futures::future::ready((imp, Ok(()))))
                    } else {
                        // There's nothing more to do; we can return.
                        self.state = Some(DataWriterState::Ready(imp));
                        return Poll::Ready(Ok(()));
                    }
                } else {
                    // We need to flush the buffer's contents; Make a future for that.
                    Box::pin(imp.flush_buf())
                }
            }
            DataWriterState::Flushing(fut) => fut,
            DataWriterState::Closed => {
                self.state = Some(DataWriterState::Closed);
                return Poll::Ready(Err(Error::NotConnected.into()));
            }
        };

        match future.as_mut().poll(cx) {
            Poll::Ready((_imp, Err(e))) => {
                self.state = Some(DataWriterState::Closed);
                Poll::Ready(Err(e.into()))
            }
            Poll::Ready((mut imp, Ok(()))) => {
                if should_close {
                    // Tell the StreamTarget to close, so that the reactor
                    // realizes that we are done sending. (Dropping `imp.s` does not
                    // suffice, since there may be other clones of it.  In particular,
                    // the StreamReceiver has one, which it uses to keep the stream
                    // open, among other things.)
                    imp.s.close();

                    #[cfg(feature = "stream-ctrl")]
                    {
                        // TODO RPC:  This is not sufficient to track every case
                        // where we might have sent an End.  See note on the
                        // `sent_end` field.
                        imp.status.lock().expect("lock poisoned").sent_end = true;
                    }
                    self.state = Some(DataWriterState::Closed);
                } else {
                    self.state = Some(DataWriterState::Ready(imp));
                }
                Poll::Ready(Ok(()))
            }
            Poll::Pending => {
                self.state = Some(DataWriterState::Flushing(future));
                Poll::Pending
            }
        }
    }
}

impl AsyncWrite for DataWriterInner {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<IoResult<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let state = self.state.take().expect("Missing state in DataWriter");

        let mut future = match state {
            DataWriterState::Ready(mut imp) => {
                let n_queued = imp.queue_bytes(buf);
                if n_queued != 0 {
                    self.state = Some(DataWriterState::Ready(imp));
                    return Poll::Ready(Ok(n_queued));
                }
                // we couldn't queue anything, so the current cell must be full.
                Box::pin(imp.flush_buf())
            }
            DataWriterState::Flushing(fut) => fut,
            DataWriterState::Closed => {
                self.state = Some(DataWriterState::Closed);
                return Poll::Ready(Err(Error::NotConnected.into()));
            }
        };

        match future.as_mut().poll(cx) {
            Poll::Ready((_imp, Err(e))) => {
                #[cfg(feature = "stream-ctrl")]
                {
                    _imp.status.lock().expect("lock poisoned").record_error(&e);
                }
                self.state = Some(DataWriterState::Closed);
                Poll::Ready(Err(e.into()))
            }
            Poll::Ready((mut imp, Ok(()))) => {
                // Great!  We're done flushing.  Queue as much as we can of this
                // cell.
                let n_queued = imp.queue_bytes(buf);
                self.state = Some(DataWriterState::Ready(imp));
                Poll::Ready(Ok(n_queued))
            }
            Poll::Pending => {
                self.state = Some(DataWriterState::Flushing(future));
                Poll::Pending
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        self.poll_flush_impl(cx, false)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        self.poll_flush_impl(cx, true)
    }
}

#[cfg(feature = "tokio")]
impl TokioAsyncWrite for DataWriterInner {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<IoResult<usize>> {
        TokioAsyncWrite::poll_write(Pin::new(&mut self.compat_write()), cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        TokioAsyncWrite::poll_flush(Pin::new(&mut self.compat_write()), cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        TokioAsyncWrite::poll_shutdown(Pin::new(&mut self.compat_write()), cx)
    }
}

impl DataWriterImpl {
    /// Try to flush the current buffer contents as a data cell.
    async fn flush_buf(mut self) -> (Self, Result<()>) {
        let result = if let Some((cell, remainder)) =
            Data::try_split_from(self.relay_cell_format, &self.buf[..self.n_pending])
        {
            // TODO: Eventually we may want a larger buffer; if we do,
            // this invariant will become false.
            assert!(remainder.is_empty());
            self.n_pending = 0;
            self.s.send(cell.into()).await
        } else {
            Ok(())
        };

        (self, result)
    }

    /// Add as many bytes as possible from `b` to our internal buffer;
    /// return the number we were able to add.
    fn queue_bytes(&mut self, b: &[u8]) -> usize {
        let empty_space = &mut self.buf[self.n_pending..];
        if empty_space.is_empty() {
            // that is, len == 0
            return 0;
        }

        let n_to_copy = std::cmp::min(b.len(), empty_space.len());
        empty_space[..n_to_copy].copy_from_slice(&b[..n_to_copy]);
        self.n_pending += n_to_copy;
        n_to_copy
    }
}

impl DataReaderInner {
    /// Return a [`ClientDataStreamCtrl`] object that can be used to monitor and
    /// interact with this stream without holding the stream itself.
    #[cfg(feature = "stream-ctrl")]
    pub(crate) fn client_stream_ctrl(&self) -> &Arc<ClientDataStreamCtrl> {
        &self.ctrl
    }
}

/// An enumeration for the state of a [`DataReaderInner`].
// TODO: We don't need to implement the state in this way anymore now that we've removed the saved
// future. There are a few ways we could simplify this. See:
// https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/3076#note_3218210
#[derive(Educe)]
#[educe(Debug)]
// We allow this since it's expected that streams will spend most of their time in the `Open` state,
// and will be cleaned up shortly after closing.
#[allow(clippy::large_enum_variant)]
enum DataReaderState {
    /// In this state we have received an end cell or an error.
    Closed,
    /// In this state the reader is open.
    Open(DataReaderImpl),
}

/// Wrapper for the read part of a [`DataStream`].
#[derive(Educe)]
#[educe(Debug)]
#[pin_project]
struct DataReaderImpl {
    /// The underlying StreamReceiver object.
    #[educe(Debug(method = "skip_fmt"))]
    #[pin]
    s: StreamReceiver,

    /// If present, data that we received on this stream but have not
    /// been able to send to the caller yet.
    // TODO: This data structure is probably not what we want, but
    // it's good enough for now.
    #[educe(Debug(method = "skip_fmt"))]
    pending: Vec<u8>,

    /// Index into pending to show what we've already read.
    offset: usize,

    /// If true, we have received a CONNECTED cell on this stream.
    connected: bool,

    /// Shared user-visible information about the state of this stream.
    #[cfg(feature = "stream-ctrl")]
    status: Arc<Mutex<DataStreamStatus>>,
}

impl AsyncRead for DataReaderInner {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        // We're pulling the state object out of the reader.  We MUST
        // put it back before this function returns.
        let mut state = self.state.take().expect("Missing state in DataReaderInner");

        loop {
            let mut imp = match state {
                DataReaderState::Open(mut imp) => {
                    // There may be data to read already.
                    let n_copied = imp.extract_bytes(buf);
                    if n_copied != 0 || buf.is_empty() {
                        // We read data into the buffer, or the buffer was 0-len to begin with.
                        // Tell the caller.
                        self.state = Some(DataReaderState::Open(imp));
                        return Poll::Ready(Ok(n_copied));
                    }

                    // No data available!  We have to try reading.
                    imp
                }
                DataReaderState::Closed => {
                    // TODO: Why are we returning an error rather than continuing to return EOF?
                    self.state = Some(DataReaderState::Closed);
                    return Poll::Ready(Err(Error::NotConnected.into()));
                }
            };

            // See if a cell is ready.
            match Pin::new(&mut imp).read_cell(cx) {
                Poll::Ready(Err(e)) => {
                    // There aren't any survivable errors in the current
                    // design.
                    self.state = Some(DataReaderState::Closed);
                    #[cfg(feature = "stream-ctrl")]
                    {
                        imp.status.lock().expect("lock poisoned").record_error(&e);
                    }
                    let result = if matches!(e, Error::EndReceived(EndReason::DONE)) {
                        Ok(0)
                    } else {
                        Err(e.into())
                    };
                    return Poll::Ready(result);
                }
                Poll::Ready(Ok(())) => {
                    // It read a cell!  Continue the loop.
                    state = DataReaderState::Open(imp);
                }
                Poll::Pending => {
                    // No cells ready, so tell the
                    // caller to get back to us later.
                    self.state = Some(DataReaderState::Open(imp));
                    return Poll::Pending;
                }
            }
        }
    }
}

#[cfg(feature = "tokio")]
impl TokioAsyncRead for DataReaderInner {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<IoResult<()>> {
        TokioAsyncRead::poll_read(Pin::new(&mut self.compat()), cx, buf)
    }
}

impl DataReaderImpl {
    /// Pull as many bytes as we can off of self.pending, and return that
    /// number of bytes.
    fn extract_bytes(&mut self, buf: &mut [u8]) -> usize {
        let remainder = &self.pending[self.offset..];
        let n_to_copy = std::cmp::min(buf.len(), remainder.len());
        buf[..n_to_copy].copy_from_slice(&remainder[..n_to_copy]);
        self.offset += n_to_copy;

        n_to_copy
    }

    /// Return true iff there are no buffered bytes here to yield
    fn buf_is_empty(&self) -> bool {
        self.pending.len() == self.offset
    }

    /// Load self.pending with the contents of a new data cell.
    fn read_cell(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        use ClientDataStreamMsg::*;
        let msg = match self.as_mut().project().s.poll_next(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Some(Ok(unparsed))) => match unparsed.decode::<ClientDataStreamMsg>() {
                Ok(cell) => cell.into_msg(),
                Err(e) => {
                    self.s.protocol_error();
                    return Poll::Ready(Err(Error::from_bytes_err(e, "message on a data stream")));
                }
            },
            Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(e)),
            // TODO: This doesn't seem right to me, but seems to be the behaviour of the code before
            // the refactoring, so I've kept the same behaviour. I think if the cell stream is
            // terminated, we should be returning `None` here and not considering it as an error.
            // The `StreamReceiver` will have already returned an error if the cell stream was
            // terminated without an END message.
            Poll::Ready(None) => return Poll::Ready(Err(Error::NotConnected)),
        };

        let result = match msg {
            Connected(_) if !self.connected => {
                self.connected = true;
                #[cfg(feature = "stream-ctrl")]
                {
                    self.status
                        .lock()
                        .expect("poisoned lock")
                        .record_connected();
                }
                Ok(())
            }
            Connected(_) => {
                self.s.protocol_error();
                Err(Error::StreamProto(
                    "Received a second connect cell on a data stream".to_string(),
                ))
            }
            Data(d) if self.connected => {
                self.add_data(d.into());
                Ok(())
            }
            Data(_) => {
                self.s.protocol_error();
                Err(Error::StreamProto(
                    "Received a data cell an unconnected stream".to_string(),
                ))
            }
            End(e) => Err(Error::EndReceived(e.reason())),
        };

        Poll::Ready(result)
    }

    /// Add the data from `d` to the end of our pending bytes.
    fn add_data(&mut self, mut d: Vec<u8>) {
        if self.buf_is_empty() {
            // No data pending?  Just take d as the new pending.
            self.pending = d;
            self.offset = 0;
        } else {
            // TODO(nickm) This has potential to grow `pending` without bound.
            // Fortunately, we don't currently read cells or call this
            // `add_data` method when pending is nonempty—but if we do in the
            // future, we'll have to be careful here.
            self.pending.append(&mut d);
        }
    }
}

/// A `CmdChecker` that enforces invariants for outbound data streams.
#[derive(Debug)]
pub(crate) struct OutboundDataCmdChecker {
    /// True if we are expecting to receive a CONNECTED message on this stream.
    expecting_connected: bool,
}

impl Default for OutboundDataCmdChecker {
    fn default() -> Self {
        Self {
            expecting_connected: true,
        }
    }
}

impl CmdChecker for OutboundDataCmdChecker {
    fn check_msg(&mut self, msg: &tor_cell::relaycell::UnparsedRelayMsg) -> Result<StreamStatus> {
        use StreamStatus::*;
        match msg.cmd() {
            RelayCmd::CONNECTED => {
                if !self.expecting_connected {
                    Err(Error::StreamProto(
                        "Received CONNECTED twice on a stream.".into(),
                    ))
                } else {
                    self.expecting_connected = false;
                    Ok(Open)
                }
            }
            RelayCmd::DATA => {
                if !self.expecting_connected {
                    Ok(Open)
                } else {
                    Err(Error::StreamProto(
                        "Received DATA before CONNECTED on a stream".into(),
                    ))
                }
            }
            RelayCmd::END => Ok(Closed),
            _ => Err(Error::StreamProto(format!(
                "Unexpected {} on a data stream!",
                msg.cmd()
            ))),
        }
    }

    fn consume_checked_msg(&mut self, msg: tor_cell::relaycell::UnparsedRelayMsg) -> Result<()> {
        let _ = msg
            .decode::<ClientDataStreamMsg>()
            .map_err(|err| Error::from_bytes_err(err, "cell on half-closed stream"))?;
        Ok(())
    }
}

impl OutboundDataCmdChecker {
    /// Return a new boxed `DataCmdChecker` in a state suitable for a newly
    /// constructed connection.
    pub(crate) fn new_any() -> AnyCmdChecker {
        Box::<Self>::default()
    }
}
