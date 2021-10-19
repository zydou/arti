//! Declare DataStream, a type that wraps RawCellStream so as to be useful
//! for byte-oriented communication.

use super::RawCellStream;
use crate::{Error, Result};
use tor_cell::relaycell::msg::EndReason;

use futures::io::{AsyncRead, AsyncWrite};
use futures::task::{Context, Poll};
use futures::Future;

#[cfg(feature = "tokio")]
use tokio_crate::io::ReadBuf;
#[cfg(feature = "tokio")]
use tokio_crate::io::{AsyncRead as TokioAsyncRead, AsyncWrite as TokioAsyncWrite};
#[cfg(feature = "tokio")]
use tokio_util::compat::FuturesAsyncReadCompatExt;

use std::io::Result as IoResult;
use std::pin::Pin;
use std::sync::Arc;

use tor_cell::relaycell::msg::{Data, RelayMsg};

/// A DataStream is a Tor stream packaged so as to be useful for
/// byte-oriented IO.
///
/// It's suitable for use with BEGIN or BEGIN_DIR streams.
///
/// # Semver note:
///
/// Note that this type is re-exported as a part of the public API of
/// the `tor-client` crate.  Any changes to its API here in
/// `tor-proto` need to be reflected above.
pub struct DataStream {
    /// Underlying writer for this stream
    w: DataWriter,
    /// Underlying reader for this stream
    r: DataReader,
}

/// Wrapper for the Write part of a DataStream.
///
/// Note that this implementation writes Tor cells lazily, so it is essential to
/// flush the stream when you need the data to do out right away.
pub struct DataWriter {
    /// Internal state for this writer
    ///
    /// This is stored in an Option so that we can mutate it in the
    /// AsyncWrite functions.  It might be possible to do better here,
    /// and we should refactor if so.
    state: Option<DataWriterState>,
}

/// Wrapper for the Read part of a DataStream
pub struct DataReader {
    /// Internal state for this reader.
    ///
    /// This is stored in an Option so that we can mutate it in
    /// poll_read().  It might be possible to do better here, and we
    /// should refactor if so.
    state: Option<DataReaderState>,
}

impl DataStream {
    /// Wrap a RawCellStream as a DataStream.
    ///
    /// Call only after a CONNECTED cell has been received.
    pub(crate) fn new(s: RawCellStream) -> Self {
        let s = Arc::new(s);
        let r = DataReader {
            state: Some(DataReaderState::Ready(DataReaderImpl {
                s: Arc::clone(&s),
                pending: Vec::new(),
                offset: 0,
            })),
        };
        let w = DataWriter {
            state: Some(DataWriterState::Ready(DataWriterImpl {
                s,
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
}

impl AsyncRead for DataStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        Pin::new(&mut self.r).poll_read(cx, buf)
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
        Pin::new(&mut self.w).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        Pin::new(&mut self.w).poll_flush(cx)
    }
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        Pin::new(&mut self.w).poll_close(cx)
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
enum DataWriterState {
    /// The writer has closed or gotten an error: nothing more to do.
    Closed,
    /// The writer is not currently flushing; more data can get queued
    /// immediately.
    Ready(DataWriterImpl),
    /// The writer is flushing a cell.
    Flushing(Pin<Box<dyn Future<Output = (DataWriterImpl, Result<()>)> + Send>>),
}

/// Internal: the write part of a DataStream
struct DataWriterImpl {
    /// The underlying RawCellStream object.
    s: Arc<RawCellStream>,

    /// Buffered data to send over the connection.
    // TODO: this buffer is probably smaller than we want, but it's good
    // enough for now.  If we _do_ make it bigger, we'll have to change
    // our use of Data::split_from to handle the case where we can't fit
    // all the data.
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
enum DataReaderState {
    /// In this state we have received an end cell or an error.
    Closed,
    /// In this state the reader is not currently fetching a cell; it
    /// either has data or not.
    Ready(DataReaderImpl),
    /// The reader is currently fetching a cell: this future is the
    /// progress it is making.
    ReadingCell(Pin<Box<dyn Future<Output = (DataReaderImpl, Result<()>)> + Send>>),
}

/// Wrapper for the read part of a DataStream
struct DataReaderImpl {
    /// The underlying RawCellStream object.
    s: Arc<RawCellStream>,

    /// If present, data that we received on this stream but have not
    /// been able to send to the caller yet.
    // TODO: This data structure is probably not what we want, but
    // it's good enough for now.
    pending: Vec<u8>,

    /// Index into pending to show what we've already read.
    offset: usize,
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
            Ok(RelayMsg::Data(d)) => {
                self.add_data(d.into());
                Ok(())
            }
            Ok(RelayMsg::End(e)) => Err(Error::EndReceived(e.reason())),
            Err(e) => Err(e),
            Ok(m) => {
                self.s.protocol_error().await;
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
            // XXXX This has potential to grow `pending` without
            // bound.  Fortunately, we don't read data in this
            // (non-empty) case right now.
            self.pending.append(&mut d);
        }
    }
}
