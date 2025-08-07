//! Queues for stream messages.
//!
//! While these are technically "channels", we call them "queues" to indicate that they're mostly
//! just dumb pipes. They do some tracking (memquota and size), but nothing else. The higher-level
//! object is [`StreamReceiver`](crate::stream::raw::StreamReceiver) which tracks SENDME and END
//! messages. So the idea is that the "queue" (ex: [`StreamQueueReceiver`]) just holds data and the
//! "channel" (ex: `StreamReceiver`) adds the Tor logic.
//!
//! The main purpose of these types are so that we can count how many bytes of stream data are
//! stored for the stream. Ideally we'd use a channel type that tracks and reports this as part of
//! its implementation, but popular channel implementations don't seem to do that.

use std::fmt::Debug;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use futures::{Sink, SinkExt, Stream};
use tor_async_utils::SinkTrySend;
use tor_async_utils::peekable_stream::UnobtrusivePeekableStream;
use tor_async_utils::stream_peek::StreamUnobtrusivePeeker;
use tor_cell::relaycell::UnparsedRelayMsg;
use tor_memquota::mq_queue::{self, ChannelSpec, MpscSpec, MpscUnboundedSpec};
use tor_rtcompat::DynTimeProvider;

use crate::memquota::{SpecificAccount, StreamAccount};

// TODO(arti#534): remove these type aliases when we remove the "flowctl-cc" feature,
// and just use `MpscUnboundedSpec` everywhere
#[cfg(feature = "flowctl-cc")]
/// Alias for the memquota mpsc spec.
type Spec = MpscUnboundedSpec;
#[cfg(not(feature = "flowctl-cc"))]
/// Alias for the memquota mpsc spec.
type Spec = MpscSpec;

/// Create a new stream queue for incoming messages.
pub(crate) fn stream_queue(
    #[cfg(not(feature = "flowctl-cc"))] size: usize,
    memquota: &StreamAccount,
    time_prov: &DynTimeProvider,
) -> Result<(StreamQueueSender, StreamQueueReceiver), tor_memquota::Error> {
    let (sender, receiver) = {
        cfg_if::cfg_if! {
            if #[cfg(not(feature = "flowctl-cc"))] {
                MpscSpec::new(size).new_mq(time_prov.clone(), memquota.as_raw_account())?
            } else {
                MpscUnboundedSpec::new().new_mq(time_prov.clone(), memquota.as_raw_account())?
            }
        }
    };

    let receiver = StreamUnobtrusivePeeker::new(receiver);
    let counter = Arc::new(Mutex::new(0));
    Ok((
        StreamQueueSender {
            sender,
            counter: Arc::clone(&counter),
        },
        StreamQueueReceiver { receiver, counter },
    ))
}

/// For testing purposes, create a stream queue wth a no-op memquota account and a fake time
/// provider.
#[cfg(test)]
pub(crate) fn fake_stream_queue(
    #[cfg(not(feature = "flowctl-cc"))] size: usize,
) -> (StreamQueueSender, StreamQueueReceiver) {
    // The fake Account doesn't care about the data ages, so this will do.
    //
    // This would be wrong to use generally in tests, where we might want to mock time,
    // since we end up, here with totally *different* mocked time.
    // But it's OK here, and saves passing a runtime parameter into this function.
    stream_queue(
        #[cfg(not(feature = "flowctl-cc"))]
        size,
        &StreamAccount::new_noop(),
        &DynTimeProvider::new(tor_rtmock::MockRuntime::default()),
    )
    .expect("create fake stream queue")
}

/// The sending end of a channel of incoming stream messages.
#[derive(Debug)]
#[pin_project::pin_project]
pub(crate) struct StreamQueueSender {
    /// The inner sender.
    #[pin]
    sender: mq_queue::Sender<UnparsedRelayMsg, Spec>,
    /// Number of bytes within the queue.
    counter: Arc<Mutex<usize>>,
}

/// The receiving end of a channel of incoming stream messages.
#[derive(Debug)]
#[pin_project::pin_project]
pub(crate) struct StreamQueueReceiver {
    /// The inner receiver.
    ///
    /// We add the [`StreamUnobtrusivePeeker`] here so that peeked messages are included in
    /// `counter`.
    // TODO(arti#534): the possible extra msg held by the `StreamUnobtrusivePeeker` isn't tracked by
    // memquota
    #[pin]
    receiver: StreamUnobtrusivePeeker<mq_queue::Receiver<UnparsedRelayMsg, Spec>>,
    /// Number of bytes within the queue.
    counter: Arc<Mutex<usize>>,
}

impl StreamQueueSender {
    /// Get the approximate number of data bytes queued for this stream.
    ///
    /// As messages can be dequeued at any time, the return value may be larger than the actual
    /// number of bytes queued for this stream.
    pub(crate) fn approx_stream_bytes(&self) -> usize {
        *self.counter.lock().expect("poisoned")
    }
}

impl StreamQueueReceiver {
    /// Get the approximate number of data bytes queued for this stream.
    ///
    /// As messages can be enqueued at any time, the return value may be smaller than the actual
    /// number of bytes queued for this stream.
    pub(crate) fn approx_stream_bytes(&self) -> usize {
        *self.counter.lock().expect("poisoned")
    }
}

impl Sink<UnparsedRelayMsg> for StreamQueueSender {
    type Error = <mq_queue::Sender<UnparsedRelayMsg, MpscSpec> as Sink<UnparsedRelayMsg>>::Error;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), Self::Error>> {
        self.sender.poll_ready_unpin(cx)
    }

    fn start_send(
        mut self: Pin<&mut Self>,
        item: UnparsedRelayMsg,
    ) -> std::result::Result<(), Self::Error> {
        let mut self_ = self.as_mut().project();

        let stream_data_len = data_len(&item);

        // This lock ensures that us sending the item and the counter increase are done
        // "atomically", so that the receiver doesn't see the item and try to decrement the
        // counter before we've incremented the counter, which could cause an underflow.
        let mut counter = self_.counter.lock().expect("poisoned");

        self_.sender.start_send_unpin(item)?;

        *counter = counter
            .checked_add(stream_data_len.into())
            .expect("queue has more than `usize::MAX` bytes?!");

        Ok(())
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), Self::Error>> {
        self.sender.poll_flush_unpin(cx)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), Self::Error>> {
        self.sender.poll_close_unpin(cx)
    }
}

impl SinkTrySend<UnparsedRelayMsg> for StreamQueueSender {
    type Error =
        <mq_queue::Sender<UnparsedRelayMsg, MpscSpec> as SinkTrySend<UnparsedRelayMsg>>::Error;

    fn try_send_or_return(
        mut self: Pin<&mut Self>,
        item: UnparsedRelayMsg,
    ) -> Result<
        (),
        (
            <Self as SinkTrySend<UnparsedRelayMsg>>::Error,
            UnparsedRelayMsg,
        ),
    > {
        let self_ = self.as_mut().project();

        let stream_data_len = data_len(&item);

        // See comments in `StreamQueueSender::start_send`.
        let mut counter = self_.counter.lock().expect("poisoned");

        self_.sender.try_send_or_return(item)?;

        *counter = counter
            .checked_add(stream_data_len.into())
            .expect("queue has more than `usize::MAX` bytes?!");

        Ok(())
    }
}

impl Stream for StreamQueueReceiver {
    type Item = UnparsedRelayMsg;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let self_ = self.as_mut().project();

        // This lock ensures that us receiving the item and the counter decrease are done
        // "atomically", so that the sender doesn't send a new item and try to increase the
        // counter before we've decreased the counter, which could cause an overflow.
        let mut counter = self_.counter.lock().expect("poisoned");

        let item = match self_.receiver.poll_next(cx) {
            Poll::Ready(Some(x)) => x,
            Poll::Ready(None) => return Poll::Ready(None),
            Poll::Pending => return Poll::Pending,
        };

        let stream_data_len = data_len(&item);

        if stream_data_len != 0 {
            *counter = counter
                .checked_sub(stream_data_len.into())
                .expect("we've removed more bytes than we've added?!");
        }

        Poll::Ready(Some(item))
    }
}

impl UnobtrusivePeekableStream for StreamQueueReceiver {
    fn unobtrusive_peek_mut<'s>(
        self: Pin<&'s mut Self>,
    ) -> Option<&'s mut <Self as futures::Stream>::Item> {
        self.project().receiver.unobtrusive_peek_mut()
    }
}

/// The `length` field of the message, or 0 if not a data message.
///
/// If the RELAY_DATA message had an invalid length field, we just ignore the message.
/// The receiver will find out eventually when it tries to parse the message.
/// We could return an error here, but for now I think it's best not to behave as if this
/// queue is performing any validation.
///
/// This is its own function so that all parts of the code use the same logic.
fn data_len(item: &UnparsedRelayMsg) -> u16 {
    item.data_len().unwrap_or(0)
}
