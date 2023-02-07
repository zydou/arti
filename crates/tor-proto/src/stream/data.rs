//! Declare DataStream, a type that wraps RawCellStream so as to be useful
//! for byte-oriented communication.

use crate::{Error, Result};
use tor_cell::relaycell::msg::EndReason;
use tor_cell::relaycell::RelayMsgClass;

use futures::io::{AsyncRead, AsyncWrite};
use futures::task::{Context, Poll};
use futures::Future;

#[cfg(feature = "tokio")]
use tokio_crate::io::ReadBuf;
#[cfg(feature = "tokio")]
use tokio_crate::io::{AsyncRead as TokioAsyncRead, AsyncWrite as TokioAsyncWrite};
#[cfg(feature = "tokio")]
use tokio_util::compat::{FuturesAsyncReadCompatExt, FuturesAsyncWriteCompatExt};

use std::fmt::Debug;
use std::io::Result as IoResult;
use std::pin::Pin;

use educe::Educe;

use crate::circuit::StreamTarget;
use crate::stream::StreamReader;
use tor_basic_utils::skip_fmt;
use tor_cell::relaycell::msg::{Data, RelayMsg};
use tor_error::internal;

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
// # Semver note
//
// Note that this type is re-exported as a part of the public API of
// the `arti-client` crate.  Any changes to its API here in
// `tor-proto` need to be reflected above.
#[derive(Debug)]
pub struct DataWriter {
    /// Internal state for this writer
    ///
    /// This is stored in an Option so that we can mutate it in the
    /// AsyncWrite functions.  It might be possible to do better here,
    /// and we should refactor if so.
    state: Option<DataWriterState>,
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
    /// Internal state for this reader.
    ///
    /// This is stored in an Option so that we can mutate it in
    /// poll_read().  It might be possible to do better here, and we
    /// should refactor if so.
    state: Option<DataReaderState>,
}

impl DataStream {
    /// Wrap raw stream reader and target parts as a DataStream.
    ///
    /// For non-optimistic stream, function `wait_for_connection`
    /// must be called after to make sure CONNECTED is received.
    pub(crate) fn new(reader: StreamReader, target: StreamTarget) -> Self {
        let r = DataReader {
            state: Some(DataReaderState::Ready(DataReaderImpl {
                s: reader,
                pending: Vec::new(),
                offset: 0,
                connected: false,
            })),
        };
        let w = DataWriter {
            state: Some(DataWriterState::Ready(DataWriterImpl {
                s: target,
                buf: Box::new([0; Data::MAXLEN]),
                n_pending: 0,
            })),
        };
        DataStream { w, r }
    }

    /// Divide this DataStream into its constituent parts.
    pub fn split(self) -> (DataReader, DataWriter) {
        (self.r, self.w)
    }

    /// Wait until a CONNECTED cell is received, or some other cell
    /// is received to indicate an error.
    ///
    /// Does nothing if this stream is already connected.
    pub(crate) async fn wait_for_connection(&mut self) -> Result<()> {
        // We must put state back before returning
        let state = self.r.state.take().expect("Missing state in DataReader");

        if let DataReaderState::Ready(imp) = state {
            let (imp, result) = if imp.connected {
                (imp, Ok(()))
            } else {
                // This succeeds if the cell is CONNECTED, and fails otherwise.
                imp.read_cell().await
            };
            self.r.state = Some(match result {
                Err(_) => DataReaderState::Closed,
                Ok(_) => DataReaderState::Ready(imp),
            });
            result
        } else {
            Err(Error::from(internal!(
                "Expected ready state, got {:?}",
                state
            )))
        }
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
        #[educe(Debug(method = "skip_fmt"))]
        Pin<Box<dyn Future<Output = (DataWriterImpl, Result<()>)> + Send>>,
    ),
}

/// Internal: the write part of a DataStream
#[derive(Educe)]
#[educe(Debug)]
struct DataWriterImpl {
    /// The underlying StreamTarget object.
    s: StreamTarget,

    /// Buffered data to send over the connection.
    // TODO: this buffer is probably smaller than we want, but it's good
    // enough for now.  If we _do_ make it bigger, we'll have to change
    // our use of Data::split_from to handle the case where we can't fit
    // all the data.
    #[educe(Debug(method = "skip_fmt"))]
    buf: Box<[u8; Data::MAXLEN]>,

    /// Number of unflushed bytes in buf.
    n_pending: usize,
}

impl DataWriter {
    /// Helper for poll_flush() and poll_close(): Performs a flush, then
    /// closes the stream if should_close is true.
    fn poll_flush_impl(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        should_close: bool,
    ) -> Poll<IoResult<()>> {
        let state = self.state.take().expect("Missing state in DataWriter");

        // TODO: this whole function is a bit copy-pasted.

        let mut future = match state {
            DataWriterState::Ready(imp) => {
                if imp.n_pending == 0 {
                    // Nothing to flush!
                    self.state = Some(DataWriterState::Ready(imp));
                    return Poll::Ready(Ok(()));
                }

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
                self.state = Some(DataWriterState::Closed);
                Poll::Ready(Err(e.into()))
            }
            Poll::Ready((imp, Ok(()))) => {
                if should_close {
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

impl AsyncWrite for DataWriter {
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

impl DataWriterImpl {
    /// Try to flush the current buffer contents as a data cell.
    async fn flush_buf(mut self) -> (Self, Result<()>) {
        let result = if self.n_pending != 0 {
            let (cell, remainder) = Data::split_from(&self.buf[..self.n_pending]);
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

/// An enumeration for the state of a DataReader.
///
/// We have to use an enum here because, when we're waiting for
/// ReadingCell to complete, the future returned by `read_cell()` owns the
/// DataCellImpl.  If we wanted to store the future and the cell at the
/// same time, we'd need to make a self-referential structure, which isn't
/// possible in safe Rust AIUI.
#[derive(Educe)]
#[educe(Debug)]
enum DataReaderState {
    /// In this state we have received an end cell or an error.
    Closed,
    /// In this state the reader is not currently fetching a cell; it
    /// either has data or not.
    Ready(DataReaderImpl),
    /// The reader is currently fetching a cell: this future is the
    /// progress it is making.
    ReadingCell(
        #[educe(Debug(method = "skip_fmt"))]
        Pin<Box<dyn Future<Output = (DataReaderImpl, Result<()>)> + Send>>,
    ),
}

/// Wrapper for the read part of a DataStream
#[derive(Educe)]
#[educe(Debug)]
struct DataReaderImpl {
    /// The underlying StreamReader object.
    #[educe(Debug(method = "skip_fmt"))]
    s: StreamReader,

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
}

impl AsyncRead for DataReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        // We're pulling the state object out of the reader.  We MUST
        // put it back before this function returns.
        let mut state = self.state.take().expect("Missing state in DataReader");

        loop {
            let mut future = match state {
                DataReaderState::Ready(mut imp) => {
                    // There may be data to read already.
                    let n_copied = imp.extract_bytes(buf);
                    if n_copied != 0 {
                        // We read data into the buffer.  Tell the caller.
                        self.state = Some(DataReaderState::Ready(imp));
                        return Poll::Ready(Ok(n_copied));
                    }

                    // No data available!  We have to launch a read.
                    Box::pin(imp.read_cell())
                }
                DataReaderState::ReadingCell(fut) => fut,
                DataReaderState::Closed => {
                    self.state = Some(DataReaderState::Closed);
                    return Poll::Ready(Err(Error::NotConnected.into()));
                }
            };

            // We have a future that represents an in-progress read.
            // See if it can make progress.
            match future.as_mut().poll(cx) {
                Poll::Ready((_imp, Err(e))) => {
                    // There aren't any survivable errors in the current
                    // design.
                    self.state = Some(DataReaderState::Closed);
                    let result = if matches!(e, Error::EndReceived(EndReason::DONE)) {
                        Ok(0)
                    } else {
                        Err(e.into())
                    };
                    return Poll::Ready(result);
                }
                Poll::Ready((imp, Ok(()))) => {
                    // It read a cell!  Continue the loop.
                    state = DataReaderState::Ready(imp);
                }
                Poll::Pending => {
                    // The future is pending; store it and tell the
                    // caller to get back to us later.
                    self.state = Some(DataReaderState::ReadingCell(future));
                    return Poll::Pending;
                }
            }
        }
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
    ///
    /// This function takes ownership of self so that we can avoid
    /// self-referential lifetimes.
    async fn read_cell(mut self) -> (Self, Result<()>) {
        let cell = self.s.recv().await;

        let result = match cell {
            Ok(RelayMsg::Connected(_)) if !self.connected => {
                self.connected = true;
                Ok(())
            }
            Ok(RelayMsg::Data(d)) if self.connected => {
                self.add_data(d.into());
                Ok(())
            }
            Ok(RelayMsg::End(e)) => Err(Error::EndReceived(e.reason())),
            Err(e) => Err(e),
            Ok(m) => {
                self.s.protocol_error();
                Err(Error::StreamProto(format!(
                    "Unexpected {} cell on stream",
                    m.cmd()
                )))
            }
        };

        (self, result)
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
