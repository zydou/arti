//! A wrapper for an [`AsyncRead`] to support XON/XOFF flow control.
//!
//! This allows any `AsyncRead` that implements [`BufferIsEmpty`] to be used with XON/XOFF flow
//! control.

use std::io::Error;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::{AsyncRead, Stream};
use pin_project::pin_project;
use tor_basic_utils::assert_val_impl_trait;
use tor_cell::relaycell::flow_ctrl::XonKBpsEwma;

use crate::stream::StreamTarget;
use crate::util::notify::NotifyReceiver;

/// A wrapper for an [`AsyncRead`] to support XON/XOFF flow control.
///
/// This reader will take care of communicating with the circuit reactor to handle XON/XOFF-related
/// events.
#[derive(Debug)]
#[pin_project]
pub(crate) struct XonXoffReader<R, T: DrainRateNotifier = StreamTarget> {
    /// How we communicate with the circuit reactor.
    #[pin]
    ctrl: XonXoffReaderCtrl<T>,
    /// The inner reader.
    #[pin]
    reader: R,
    /// Have we received a drain rate request notification from the reactor,
    /// but haven't yet sent a drain rate update back to the reactor?
    pending_drain_rate_update: bool,
}

impl<R, T: DrainRateNotifier> XonXoffReader<R, T> {
    /// Create a new [`XonXoffReader`].
    ///
    /// The reader must implement [`BufferIsEmpty`], which allows the `XonXoffReader` to check if
    /// the incoming stream buffer is empty or not.
    pub(crate) fn new(ctrl: XonXoffReaderCtrl<T>, reader: R) -> Self {
        Self {
            ctrl,
            reader,
            pending_drain_rate_update: false,
        }
    }

    /// Get a reference to the inner [`AsyncRead`].
    ///
    /// NOTE: This will bypass the [`XonXoffReader`] and may cause incorrect behaviour depending on
    /// how you use the returned reader (for example if it uses interior mutability).
    pub(crate) fn inner(&self) -> &R {
        &self.reader
    }

    /// Get a mutable reference to the inner [`AsyncRead`].
    ///
    /// NOTE: This will bypass the [`XonXoffReader`] and may cause incorrect behaviour depending on
    /// how you use the returned reader (for example if you read bytes directly).
    pub(crate) fn inner_mut(&mut self) -> &mut R {
        &mut self.reader
    }
}

impl<R: AsyncRead + BufferIsEmpty, T: DrainRateNotifier> AsyncRead for XonXoffReader<R, T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, Error>> {
        let mut self_ = self.project();

        // ensure that `drain_rate_request_stream` is a `FusedStream`,
        // which means that we don't need to worry about calling `poll_next()` repeatedly
        assert_val_impl_trait!(
            self_.ctrl.drain_rate_request_stream,
            futures::stream::FusedStream,
        );

        // check if the circuit reactor has requested a drain rate update
        if let Poll::Ready(Some(())) = self_
            .ctrl
            .as_mut()
            .project()
            .drain_rate_request_stream
            .poll_next(cx)
        {
            // a drain rate update was requested, so we need to send a drain rate update once we
            // have no more bytes buffered
            *self_.pending_drain_rate_update = true;
        }

        // try reading from the inner reader
        let res = self_.reader.as_mut().poll_read(cx, buf);

        // if we need to send a drain rate update and the stream buffer is empty, inform the reactor
        if *self_.pending_drain_rate_update && self_.reader.is_empty() {
            // TODO(arti#534): in the future we want to do rate estimation, but for now we'll just
            // send an "unlimited" drain rate
            self_
                .ctrl
                .drain_rate_notifier
                .notify(XonKBpsEwma::Unlimited)?;
            *self_.pending_drain_rate_update = false;
        }

        res
    }
}

/// Something that sends drain rate updates to the flow control logic (the `XonXoffFlowCtrl`).
pub(crate) trait DrainRateNotifier {
    /// Send the drain rate update.
    fn notify(&mut self, rate: XonKBpsEwma) -> Result<(), Error>;
}

impl DrainRateNotifier for StreamTarget {
    fn notify(&mut self, rate: XonKBpsEwma) -> Result<(), Error> {
        self.drain_rate_update(rate).map_err(Into::into)
    }
}

/// The control structure for a stream that partakes in XON/XOFF flow control.
///
/// Used to construct an [`XonXoffReader`].
///
/// This contains a mechanism for us to be asked for our drain rate,
/// and a mechanism of sending the drain rate in response.
///
/// The `DrainRateNotifier` is typically a `StreamTarget`,
/// which sends the drain rate to the circuit reactor so that it can be sent in an XON message.
/// We make this a trait to make unit testing possible.
#[derive(Debug)]
#[pin_project]
pub(crate) struct XonXoffReaderCtrl<T: DrainRateNotifier = StreamTarget> {
    /// Receive notifications when the reactor requests a new drain rate.
    /// When we do, we should begin waiting for the receive buffer to clear.
    /// Then when the buffer clears, we should send a new drain rate update to the reactor.
    #[pin]
    drain_rate_request_stream: NotifyReceiver<DrainRateRequest>,
    /// An abstract handle to the reactor for this stream.
    /// This allows us to send drain rate updates to the circuit reactor.
    drain_rate_notifier: T,
}

impl<T: DrainRateNotifier> XonXoffReaderCtrl<T> {
    /// Create a new [`XonXoffReaderCtrl`].
    ///
    /// The `drain_rate_request_stream` informs us when we need to send our drain rate,
    /// and `drain_rate_notifier` allows us to send that drain rate.
    pub(crate) fn new(
        drain_rate_request_stream: NotifyReceiver<DrainRateRequest>,
        drain_rate_notifier: T,
    ) -> Self {
        Self {
            drain_rate_request_stream,
            drain_rate_notifier,
        }
    }
}

/// Used by the [`XonXoffReader`] to decide when to send a drain rate update
/// (typically resulting in an XON message).
pub(crate) trait BufferIsEmpty {
    /// Returns `true` if there are no incoming bytes buffered on this stream.
    ///
    /// This takes a `&mut` so that implementers can
    /// [`unobtrusive_peek()`](tor_async_utils::peekable_stream::UnobtrusivePeekableStream::unobtrusive_peek)
    /// a stream if necessary.
    fn is_empty(self: Pin<&mut Self>) -> bool;
}

/// A marker type for a [`NotifySender`](crate::util::notify::NotifySender)
/// indicating that notifications are for new drain rate requests.
#[derive(Debug)]
pub(crate) struct DrainRateRequest;

#[cfg(test)]
// This module (and `XonXoffReader`) are always available,
// but the flow control code logic that it uses requires the "flowctl-cc" feature.
#[cfg(feature = "flowctl-cc")]
// We use some tokio-specific types here to make the test easier to write.
#[cfg(feature = "tokio")]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    #![allow(clippy::string_slice)] // See arti#2571
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;

    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::stream::flow_ctrl::params::FlowCtrlParameters;
    use crate::stream::flow_ctrl::state::{FlowCtrlHooks, StreamRateLimit};
    use crate::stream::flow_ctrl::xon_xoff::state::XonXoffFlowCtrl;
    use crate::util::notify::NotifySender;

    use futures::channel::mpsc::{self, TryRecvError};
    use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio_crate::io::{DuplexStream, duplex};
    use tokio_util::compat::{Compat, TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

    /// The type that will be stored by the [`XonXoffReader`] and used to send drain rate updates.
    ///
    /// This essentially mocks what the [`StreamTarget`] would do.
    struct TestingDrainRateUpdates(mpsc::UnboundedSender<XonKBpsEwma>);

    impl TestingDrainRateUpdates {
        pub(crate) fn new(sender: mpsc::UnboundedSender<XonKBpsEwma>) -> Self {
            Self(sender)
        }
    }

    impl DrainRateNotifier for TestingDrainRateUpdates {
        fn notify(&mut self, rate: XonKBpsEwma) -> Result<(), Error> {
            self.0.unbounded_send(rate).unwrap();
            Ok(())
        }
    }

    /// The writer for a data stream that tracks the length.
    #[pin_project::pin_project]
    struct WriterWithLength<W> {
        #[pin]
        writer: W,
        length: Arc<AtomicU64>,
    }

    /// The reader for a data stream that tracks the length.
    #[pin_project::pin_project]
    struct ReaderWithLength<R> {
        #[pin]
        reader: R,
        length: Arc<AtomicU64>,
    }

    /// Wraps a writer and reader to track the queue length.
    fn with_length<W, R>(writer: W, reader: R) -> (WriterWithLength<W>, ReaderWithLength<R>) {
        let length = Arc::new(AtomicU64::new(0));

        let writer = WriterWithLength {
            writer,
            length: Arc::clone(&length),
        };
        let reader = ReaderWithLength { reader, length };

        (writer, reader)
    }

    impl<W> WriterWithLength<W> {
        /// Amount of bytes queued.
        pub(crate) fn len(&self) -> u64 {
            self.length.load(Ordering::Acquire)
        }
    }

    impl<R> BufferIsEmpty for ReaderWithLength<R> {
        fn is_empty(self: Pin<&mut Self>) -> bool {
            self.length.load(Ordering::Acquire) == 0
        }
    }

    impl<W: AsyncWrite> AsyncWrite for WriterWithLength<W> {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let self_ = self.project();

            let rv = self_.writer.poll_write(cx, buf);

            // NOTE: There's a race condition here since we don't write to the writer and update the
            // length as one atomic operation.
            // But this is good enough for our test where the mock runtime is deterministic and
            // single-threaded.
            //
            // We ignore the possibility of overflowing the 64-bit integer here.
            if let Poll::Ready(Ok(len)) = rv {
                let len: u64 = len.try_into().expect("usize should fit into u64");
                // The effect of `poll_write()` above will be visible after another thread checks
                // the length with `load(Acquire)`.
                self_.length.fetch_add(len, Ordering::Release);
            }

            rv
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            self.project().writer.poll_flush(cx)
        }

        fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            self.project().writer.poll_close(cx)
        }
    }

    impl<R: AsyncRead> AsyncRead for ReaderWithLength<R> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<std::io::Result<usize>> {
            let self_ = self.project();

            let rv = self_.reader.poll_read(cx, buf);

            // NOTE: There's a race condition here since we don't read from the reader and update
            // the length as one atomic operation.
            // But this is good enough for our test where the mock runtime is deterministic and
            // single-threaded.
            //
            // We ignore the possibility of underflowing the integer here.
            if let Poll::Ready(Ok(len)) = rv {
                let len: u64 = len.try_into().expect("usize should fit into u64");
                // The effect of `poll_read()` above will be visible after another thread checks
                // the length with `load(Acquire)`.
                self_.length.fetch_sub(len, Ordering::Release);
            }

            rv
        }
    }

    /// Set up all of the flow control stuff needed to test the [`XonXoffReader`].
    ///
    /// Returns:
    ///
    /// 1. The stream writer (as would be held by the circuit/stream reactor).
    /// 2. The stream reader (as would be held in a user-facing `DataStream`).
    /// 3. An MPSC receiver of drain rate updates.
    /// 4. The flow control logic.
    #[allow(clippy::type_complexity)]
    fn init_flow_ctrl(
        use_sidechannel_mitigations: bool,
    ) -> (
        WriterWithLength<Compat<DuplexStream>>,
        XonXoffReader<ReaderWithLength<Compat<DuplexStream>>, TestingDrainRateUpdates>,
        mpsc::UnboundedReceiver<XonKBpsEwma>,
        XonXoffFlowCtrl,
    ) {
        let params = FlowCtrlParameters::defaults_for_tests();

        // For the flow control logic to send rate limit changes to the stream writer.
        // We don't use this in this test, but the `XonXoffFlowCtrl` needs the tx side.
        let (rate_limit_tx, _rate_limit_rx) = postage::watch::channel_with(StreamRateLimit::MAX);

        // For the flow control logic to request a new drain rate update from the stream reader.
        let mut drain_rate_request_tx = NotifySender::new_typed();
        let drain_rate_request_rx = drain_rate_request_tx.subscribe();

        // The flow control logic.
        let flow_ctrl = XonXoffFlowCtrl::new(
            Arc::new(params),
            use_sidechannel_mitigations,
            rate_limit_tx,
            drain_rate_request_tx,
        );

        // For the `XonXoffReader` to send a drain rate update.
        let (drain_rate_sender, drain_rate_receiver) = mpsc::unbounded();
        let drain_rate_updates = TestingDrainRateUpdates::new(drain_rate_sender);

        // All of the information needed to build a `XonXoffReader`.
        let reader_ctrl = XonXoffReaderCtrl::new(drain_rate_request_rx, drain_rate_updates);

        // This is the stream queue for incoming data.
        // So the `reader` is the stream reader and the `writer` would be within the reactor.
        //
        // In arti this stream should be unbounded, so here we use a max size of `usize::MAX`.
        let (writer, reader) = duplex(/* max_buf_size= */ usize::MAX);
        let writer = writer.compat_write();
        let reader = reader.compat();

        // Make the reader+writer pair track the length of the buffer so that it can support
        // `BufferIsEmpty`.
        let (writer, reader) = with_length(writer, reader);

        // The reader for incoming stream data, with XON/XOFF support.
        let reader = XonXoffReader::new(reader_ctrl, reader);

        (writer, reader, drain_rate_receiver, flow_ctrl)
    }

    /// Buffer `num_bytes` as if the bytes arrived on the stream.
    ///
    /// Returns whether the flow control logic wanted to send an XOFF.
    async fn buffer_incoming_data(
        writer: &mut WriterWithLength<impl AsyncWrite + Unpin>,
        mut num_bytes: usize,
        flow_ctrl: &mut XonXoffFlowCtrl,
    ) -> bool {
        let mut wants_to_send_xoff = false;

        // Write the requested number of bytes.
        while num_bytes > 0 {
            // Write 100_000 bytes at a time.
            let buf_size = num_bytes.min(100_000);
            writer.write_all(&vec![0; buf_size]).await.unwrap();
            num_bytes -= buf_size;

            // Inform the flow control logic.
            let xoff = flow_ctrl.maybe_send_xoff(writer.len() as usize).unwrap();
            wants_to_send_xoff |= xoff.is_some();
        }

        wants_to_send_xoff
    }

    /// Read `num_bytes` from the stream.
    async fn read_incoming_data(mut reader: impl AsyncRead + Unpin, mut num_bytes: usize) {
        // Read the requested number of bytes.
        while num_bytes > 0 {
            // Read 100_000 bytes at a time.
            let buf_size = num_bytes.min(100_000);
            reader.read_exact(&mut vec![0; buf_size]).await.unwrap();
            num_bytes -= buf_size;
        }
    }

    /// This test is meant to test the drain rate update.
    /// It adds a lot of data to the stream queue so that it triggers sending an XOFF
    /// and sends a drain rate request to the [`XonXoffReader`],
    /// then it reads from the stream until it's empty
    /// and the `XonXoffReader` sends a drain rate update.
    /// The flow control logic receives the drain rate update and sends an XON.
    #[test]
    fn drain_rate_update() {
        tor_rtmock::MockRuntime::test_with_various(|_rt| async move {
            // This is the stream queue for incoming data.
            // So the `reader` is the stream reader and the `writer` would be within the reactor.
            let (mut writer, mut reader, mut drain_rate_receiver, mut flow_ctrl) =
                init_flow_ctrl(/* use_sidechannel_mitigations= */ true);

            // Data has arrived on the stream.
            // We always consider sending an XOFF when a stream has received data.
            // The amount of incoming data wasn't very large,
            // so we don't expect that it would actually want to send an XOFF.
            let wants_to_send_xoff =
                buffer_incoming_data(&mut writer, 10_000, &mut flow_ctrl).await;
            assert!(!wants_to_send_xoff);

            // We didn't want to send an XOFF,
            // so the stream reader will never have been asked for a drain rate update.
            assert!(!reader.pending_drain_rate_update);

            // The stream reader reads all of the incoming data.
            read_incoming_data(&mut reader, 10_000).await;

            // Check `pending_drain_rate_update` again,
            // and also ensure that we didn't send a drain rate update.
            assert!(!reader.pending_drain_rate_update);
            assert_eq!(drain_rate_receiver.try_recv(), Err(TryRecvError::Empty));

            // Data has arrived on the stream.
            // We always consider sending an XOFF when a stream has received data.
            // The amount of incoming data was large,
            // so we expect that it would want to send an XOFF.
            let wants_to_send_xoff =
                buffer_incoming_data(&mut writer, 800_000, &mut flow_ctrl).await;
            assert!(wants_to_send_xoff);

            // The above code should have sent an XOFF and asked the reader for a drain rate update,
            // but the reader hasn't realized this yet.
            assert!(!reader.pending_drain_rate_update);
            assert_eq!(drain_rate_receiver.try_recv(), Err(TryRecvError::Empty));

            // The reader won't realize it was asked for a drain rate update until after it's tried
            // reading once.
            let _ = reader.read(&mut [0; 0]).await.unwrap();
            assert!(reader.pending_drain_rate_update);

            // The drain rate update is only sent once we've drained the buffer,
            // so an update should not have been sent yet.
            assert_eq!(drain_rate_receiver.try_recv(), Err(TryRecvError::Empty));

            // Read most (but not all) of the data on the stream.
            read_incoming_data(&mut reader, 700_000).await;

            // We haven't read *all* of the data,
            // so should still not have sent a drain rate update.
            assert!(!Pin::new(reader.inner_mut()).is_empty());
            assert!(reader.pending_drain_rate_update);
            assert_eq!(drain_rate_receiver.try_recv(), Err(TryRecvError::Empty));

            // Read the last of the data on the stream.
            read_incoming_data(&mut reader, 100_000).await;

            // Now that the buffer is empty,
            // we should have sent a drain rate update.
            assert!(Pin::new(reader.inner_mut()).is_empty());
            assert!(!reader.pending_drain_rate_update);
            let xon_rate = drain_rate_receiver.try_recv().unwrap();
            assert_eq!(xon_rate, XonKBpsEwma::Unlimited);

            // The buffer is still empty,
            // so the flow control logic should want to send an XON.
            let xon = flow_ctrl
                .maybe_send_xon(xon_rate, writer.len() as usize)
                .unwrap()
                .unwrap();
            assert_eq!(xon.kbytes_per_sec_ewma(), xon_rate);
        });
    }

    /// Like the `drain_rate_update()` test,
    /// this test causes the `XonXoffReader` to send a drain rate update.
    /// But in this case the buffer refills again past the high-water mark
    /// before the drain rate update can be processed by the flow control logic,
    /// so it *does not* send an XON.
    /// Instead it re-requests a drain rate from the `XonXoffReader`.
    #[test]
    fn drain_rate_update_then_buffer_refill() {
        tor_rtmock::MockRuntime::test_with_various(|_rt| async move {
            // This is the stream queue for incoming data.
            // So the `reader` is the stream reader and the `writer` would be within the reactor.
            let (mut writer, mut reader, mut drain_rate_receiver, mut flow_ctrl) =
                init_flow_ctrl(/* use_sidechannel_mitigations= */ true);

            // Data has arrived on the stream.
            // We always consider sending an XOFF when a stream has received data.
            // The amount of incoming data was large,
            // so we expect that it would want to send an XOFF.
            let wants_to_send_xoff =
                buffer_incoming_data(&mut writer, 800_000, &mut flow_ctrl).await;
            assert!(wants_to_send_xoff);

            // Read all of the data on the stream.
            read_incoming_data(&mut reader, 700_000).await;
            assert!(reader.pending_drain_rate_update);
            read_incoming_data(&mut reader, 100_000).await;

            // Now that the buffer is empty,
            // we should have sent a drain rate update.
            assert!(Pin::new(reader.inner_mut()).is_empty());
            assert!(!reader.pending_drain_rate_update);

            // Before this drain rate update can make it to the
            // flow control logic with `maybe_send_xon()`,
            // the buffer fills again past the high-water mark.
            let wants_to_send_xoff =
                buffer_incoming_data(&mut writer, 800_000, &mut flow_ctrl).await;
            assert!(!wants_to_send_xoff);

            // Now the drain rate update makes it to the flow control logic.
            // Since the buffer is past the high-water mark,
            // we won't want to send an XON.
            let xon_rate = drain_rate_receiver.try_recv().unwrap();
            assert_eq!(xon_rate, XonKBpsEwma::Unlimited);
            let xon = flow_ctrl
                .maybe_send_xon(xon_rate, writer.len() as usize)
                .unwrap();
            assert!(xon.is_none());

            // Instead the reader will have been asked for a drain rate update again,
            // which restarts the entire process.
            assert!(!reader.pending_drain_rate_update);
            let _ = reader.read(&mut [0; 0]).await.unwrap();
            assert!(reader.pending_drain_rate_update);
        });
    }
}
