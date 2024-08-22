//! Types and code for mapping StreamIDs to streams on a circuit.

use crate::circuit::halfstream::HalfStream;
use crate::circuit::sendme;
use crate::stream::{AnyCmdChecker, StreamSendFlowControl};
use crate::util::stream_poll_set::{KeyAlreadyInsertedError, StreamPollSet};
use crate::{Error, Result};
use pin_project::pin_project;
use tor_async_utils::peekable_stream::{PeekableStream, UnobtrusivePeekableStream};
use tor_cell::relaycell::{msg::AnyRelayMsg, StreamId};
use tor_cell::relaycell::{RelayMsg, UnparsedRelayMsg};

use futures::channel::mpsc;
use std::collections::hash_map;
use std::collections::HashMap;
use std::num::NonZeroU16;
use std::pin::Pin;
use std::task::{Poll, Waker};
use tor_error::{bad_api_usage, internal};
use tor_memquota::stream_peek::StreamUnobtrusivePeeker;

use rand::Rng;

use crate::circuit::reactor::RECV_WINDOW_INIT;
use crate::circuit::sendme::StreamRecvWindow;
use tracing::debug;

/// Entry for an open stream
///
/// (For the purposes of this module, an open stream is one where we have not
/// sent or received any message indicating that the stream is ended.)
#[derive(Debug)]
#[pin_project]
pub(super) struct OpenStreamEnt {
    /// Sink to send relay cells tagged for this stream into.
    pub(super) sink: mpsc::Sender<UnparsedRelayMsg>,
    /// Number of cells dropped due to the stream disappearing before we can
    /// transform this into an `EndSent`.
    pub(super) dropped: u16,
    /// A `CmdChecker` used to tell whether cells on this stream are valid.
    pub(super) cmd_checker: AnyCmdChecker,
    /// Flow control for this stream.
    // Non-pub because we need to proxy `put_for_incoming_sendme` to ensure
    // `flow_ctrl_waker` is woken.
    flow_ctrl: StreamSendFlowControl,
    /// Stream for cells that should be sent down this stream.
    // Not directly exposed. This should only be polled via
    // `OpenStreamEntStream`s implementation of `Stream`, which in turn should
    // only be used through `StreamPollSet`.
    #[pin]
    rx: tor_memquota::stream_peek::StreamUnobtrusivePeeker<mpsc::Receiver<AnyRelayMsg>>,
    /// Waker to be woken when more sending capacity becomes available (e.g.
    /// receiving a SENDME).
    flow_ctrl_waker: Option<Waker>,
}

impl OpenStreamEnt {
    /// Whether this stream is ready to send `msg`.
    pub(crate) fn can_send<M: RelayMsg>(&self, msg: &M) -> bool {
        self.flow_ctrl.can_send(msg)
    }

    /// Handle an incoming sendme.
    ///
    /// On success, return the number of cells left in the window.
    ///
    /// On failure, return an error: the caller should close the stream or
    /// circuit with a protocol error.
    pub(crate) fn put_for_incoming_sendme(&mut self) -> Result<u16> {
        let res = self.flow_ctrl.put_for_incoming_sendme()?;
        // Wake the stream if it was blocked on flow control.
        if let Some(waker) = self.flow_ctrl_waker.take() {
            waker.wake();
        }
        Ok(res)
    }

    /// Take capacity to send `msg`. If there's insufficient capacity, returns
    /// an error. Should be called at the point we've fullyh committed to
    /// sending the message.
    //
    // TODO: Consider not exposing this, and instead taking the capacity in
    // `StreamMap::take_ready_msg`.
    pub(crate) fn take_capacity_to_send<M: RelayMsg>(&mut self, msg: &M) -> Result<()> {
        self.flow_ctrl.take_capacity_to_send(msg)
    }
}

/// Private wrapper over `OpenStreamEnt`. We implement `futures::Stream` for
/// this wrapper, and not directly for `OpenStreamEnt`, so that client code
/// can't directly access the stream.
#[derive(Debug)]
#[pin_project]
struct OpenStreamEntStream {
    /// Inner value.
    #[pin]
    inner: OpenStreamEnt,
}

impl futures::Stream for OpenStreamEntStream {
    type Item = AnyRelayMsg;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        if !self.as_mut().poll_peek_mut(cx).is_ready() {
            return Poll::Pending;
        };
        let res = self.project().inner.project().rx.poll_next(cx);
        debug_assert!(res.is_ready());
        // TODO: consider calling `inner.flow_ctrl.take_capacity_to_send` here;
        // particularly if we change it to return a wrapper type that proves
        // we've taken the capacity. Otherwise it'd make it tricky in the reactor
        // to be sure we've correctly taken the capacity, since messages can originate
        // in other parts of the code (currently none of those should be of types that
        // count towards flow control, but that may change).
        res
    }
}

impl PeekableStream for OpenStreamEntStream {
    fn poll_peek_mut(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<&mut <Self as futures::Stream>::Item>> {
        let s = self.project();
        let inner = s.inner.project();
        let m = match inner.rx.poll_peek_mut(cx) {
            Poll::Ready(Some(m)) => m,
            Poll::Ready(None) => return Poll::Ready(None),
            Poll::Pending => return Poll::Pending,
        };
        if !inner.flow_ctrl.can_send(m) {
            inner.flow_ctrl_waker.replace(cx.waker().clone());
            return Poll::Pending;
        }
        Poll::Ready(Some(m))
    }
}

impl UnobtrusivePeekableStream for OpenStreamEntStream {
    fn unobtrusive_peek_mut(
        self: std::pin::Pin<&mut Self>,
    ) -> Option<&mut <Self as futures::Stream>::Item> {
        let s = self.project();
        let inner = s.inner.project();
        let m = inner.rx.unobtrusive_peek_mut()?;
        if inner.flow_ctrl.can_send(m) {
            Some(m)
        } else {
            None
        }
    }
}

/// Entry for a stream where we have sent an END, or other message
/// indicating that the stream is terminated.
#[derive(Debug)]
pub(super) struct EndSentStreamEnt {
    /// A "half-stream" that we use to check the validity of incoming
    /// messages on this stream.
    pub(super) half_stream: HalfStream,
    /// True if the sender on this stream has been explicitly dropped;
    /// false if we got an explicit close from `close_pending`
    explicitly_dropped: bool,
}

/// The entry for a stream.
#[derive(Debug)]
enum ClosedStreamEnt {
    /// A stream for which we have received an END cell, but not yet
    /// had the stream object get dropped.
    EndReceived,
    /// A stream for which we have sent an END cell but not yet received an END
    /// cell.
    ///
    /// TODO(arti#264) Can we ever throw this out? Do we really get END cells for
    /// these?
    EndSent(EndSentStreamEnt),
}

/// Mutable reference to a stream entry.
pub(super) enum StreamEntMut<'a> {
    /// An open stream.
    Open(&'a mut OpenStreamEnt),
    /// A stream for which we have received an END cell, but not yet
    /// had the stream object get dropped.
    EndReceived,
    /// A stream for which we have sent an END cell but not yet received an END
    /// cell.
    EndSent(&'a mut EndSentStreamEnt),
}

impl<'a> From<&'a mut ClosedStreamEnt> for StreamEntMut<'a> {
    fn from(value: &'a mut ClosedStreamEnt) -> Self {
        match value {
            ClosedStreamEnt::EndReceived => Self::EndReceived,
            ClosedStreamEnt::EndSent(e) => Self::EndSent(e),
        }
    }
}

impl<'a> From<&'a mut OpenStreamEntStream> for StreamEntMut<'a> {
    fn from(value: &'a mut OpenStreamEntStream) -> Self {
        Self::Open(&mut value.inner)
    }
}

/// Return value to indicate whether or not we send an END cell upon
/// terminating a given stream.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(super) enum ShouldSendEnd {
    /// An END cell should be sent.
    Send,
    /// An END cell should not be sent.
    DontSend,
}

/// A priority for use with [`StreamPollSet`].
#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord)]
struct Priority(u64);

/// A map from stream IDs to stream entries. Each circuit has one for each
/// hop.
pub(super) struct StreamMap {
    /// Open streams.
    // Invariants:
    // * Keys are disjoint with `closed_streams`.
    open_streams: StreamPollSet<StreamId, Priority, OpenStreamEntStream>,
    /// Closed streams.
    // Invariants:
    // * Keys are disjoint with `open_streams`.
    closed_streams: HashMap<StreamId, ClosedStreamEnt>,
    /// The next StreamId that we should use for a newly allocated
    /// circuit.
    next_stream_id: StreamId,
    /// Next priority to use in `rxs`. We implement round-robin scheduling of
    /// handling outgoing messages from streams by assigning a stream the next
    /// priority whenever an outgoing message is processed from that stream,
    /// putting it last in line.
    next_priority: Priority,
}

impl StreamMap {
    /// Make a new empty StreamMap.
    pub(super) fn new() -> Self {
        let mut rng = rand::thread_rng();
        let next_stream_id: NonZeroU16 = rng.gen();
        StreamMap {
            open_streams: StreamPollSet::new(),
            closed_streams: HashMap::new(),
            next_stream_id: next_stream_id.into(),
            next_priority: Priority(0),
        }
    }

    /// Return the number of open streams in this map.
    pub(super) fn n_open_streams(&self) -> usize {
        self.open_streams.len()
    }

    /// Return the next available priority.
    fn take_next_priority(&mut self) -> Priority {
        let rv = self.next_priority;
        self.next_priority = Priority(rv.0 + 1);
        rv
    }

    /// Add an entry to this map; return the newly allocated StreamId.
    pub(super) fn add_ent(
        &mut self,
        sink: mpsc::Sender<UnparsedRelayMsg>,
        rx: mpsc::Receiver<AnyRelayMsg>,
        send_window: sendme::StreamSendWindow,
        cmd_checker: AnyCmdChecker,
    ) -> Result<StreamId> {
        let mut stream_ent = OpenStreamEntStream {
            inner: OpenStreamEnt {
                sink,
                flow_ctrl: StreamSendFlowControl::new_window_based(send_window),
                dropped: 0,
                cmd_checker,
                rx: StreamUnobtrusivePeeker::new(rx),
                flow_ctrl_waker: None,
            },
        };
        let priority = self.take_next_priority();
        // This "65536" seems too aggressive, but it's what tor does.
        //
        // Also, going around in a loop here is (sadly) needed in order
        // to look like Tor clients.
        for _ in 1..=65536 {
            let id: StreamId = self.next_stream_id;
            self.next_stream_id = wrapping_next_stream_id(self.next_stream_id);
            stream_ent = match self.open_streams.try_insert(id, priority, stream_ent) {
                Ok(_) => return Ok(id),
                Err(KeyAlreadyInsertedError {
                    key: _,
                    priority: _,
                    stream,
                }) => stream,
            };
        }

        Err(Error::IdRangeFull)
    }

    /// Add an entry to this map using the specified StreamId.
    #[cfg(feature = "hs-service")]
    pub(super) fn add_ent_with_id(
        &mut self,
        sink: mpsc::Sender<UnparsedRelayMsg>,
        rx: mpsc::Receiver<AnyRelayMsg>,
        send_window: sendme::StreamSendWindow,
        id: StreamId,
        cmd_checker: AnyCmdChecker,
    ) -> Result<()> {
        let stream_ent = OpenStreamEntStream {
            inner: OpenStreamEnt {
                sink,
                flow_ctrl: StreamSendFlowControl::new_window_based(send_window),
                dropped: 0,
                cmd_checker,
                rx: StreamUnobtrusivePeeker::new(rx),
                flow_ctrl_waker: None,
            },
        };
        let priority = self.take_next_priority();
        self.open_streams
            .try_insert(id, priority, stream_ent)
            .map_err(|_| Error::IdUnavailable(id))
    }

    /// Return the entry for `id` in this map, if any.
    pub(super) fn get_mut(&mut self, id: StreamId) -> Option<StreamEntMut<'_>> {
        if let Some(e) = self.open_streams.stream_mut(&id) {
            return Some(e.into());
        }
        if let Some(e) = self.closed_streams.get_mut(&id) {
            return Some(e.into());
        }
        None
    }

    /// Note that we received an END message (or other message indicating the end of
    /// the stream) on the stream with `id`.
    ///
    /// Returns true if there was really a stream there.
    pub(super) fn ending_msg_received(&mut self, id: StreamId) -> Result<()> {
        if self.open_streams.remove(&id).is_some() {
            let prev = self.closed_streams.insert(id, ClosedStreamEnt::EndReceived);
            debug_assert!(prev.is_none(), "Unexpected duplicate entry for {id}");
            return Ok(());
        }
        let hash_map::Entry::Occupied(closed_entry) = self.closed_streams.entry(id) else {
            return Err(Error::CircProto(
                "Received END cell on nonexistent stream".into(),
            ));
        };
        // Progress the stream's state machine accordingly
        match closed_entry.get() {
            ClosedStreamEnt::EndReceived => Err(Error::CircProto(
                "Received two END cells on same stream".into(),
            )),
            ClosedStreamEnt::EndSent { .. } => {
                debug!("Actually got an end cell on a half-closed stream!");
                // We got an END, and we already sent an END. Great!
                // we can forget about this stream.
                closed_entry.remove_entry();
                Ok(())
            }
        }
    }

    /// Handle a termination of the stream with `id` from this side of
    /// the circuit. Return true if the stream was open and an END
    /// ought to be sent.
    pub(super) fn terminate(
        &mut self,
        id: StreamId,
        why: TerminateReason,
    ) -> Result<ShouldSendEnd> {
        use TerminateReason as TR;

        if let Some((_id, _priority, ent)) = self.open_streams.remove(&id) {
            let OpenStreamEntStream {
                inner:
                    OpenStreamEnt {
                        flow_ctrl,
                        dropped,
                        cmd_checker,
                        // notably absent: the channels for sink and stream, which will get dropped and
                        // closed (meaning reads/writes from/to this stream will now fail)
                        ..
                    },
            } = ent;
            // FIXME(eta): we don't copy the receive window, instead just creating a new one,
            //             so a malicious peer can send us slightly more data than they should
            //             be able to; see arti#230.
            let mut recv_window = StreamRecvWindow::new(RECV_WINDOW_INIT);
            recv_window.decrement_n(dropped)?;
            // TODO: would be nice to avoid new_ref.
            let half_stream = HalfStream::new(flow_ctrl, recv_window, cmd_checker);
            let explicitly_dropped = why == TR::StreamTargetClosed;
            let prev = self.closed_streams.insert(
                id,
                ClosedStreamEnt::EndSent(EndSentStreamEnt {
                    half_stream,
                    explicitly_dropped,
                }),
            );
            debug_assert!(prev.is_none(), "Unexpected duplicate entry for {id}");
            return Ok(ShouldSendEnd::Send);
        }

        // Progress the stream's state machine accordingly
        match self
            .closed_streams
            .remove(&id)
            .ok_or_else(|| Error::from(internal!("Somehow we terminated a nonexistent stream?")))?
        {
            ClosedStreamEnt::EndReceived => Ok(ShouldSendEnd::DontSend),
            ClosedStreamEnt::EndSent(EndSentStreamEnt {
                ref mut explicitly_dropped,
                ..
            }) => match (*explicitly_dropped, why) {
                (false, TR::StreamTargetClosed) => {
                    *explicitly_dropped = true;
                    Ok(ShouldSendEnd::DontSend)
                }
                (true, TR::StreamTargetClosed) => {
                    Err(bad_api_usage!("Tried to close an already closed stream.").into())
                }
                (_, TR::ExplicitEnd) => Err(bad_api_usage!(
                    "Tried to end an already closed stream. (explicitly_dropped={:?})",
                    *explicitly_dropped
                )
                .into()),
            },
        }
    }

    /// Get an up-to-date iterator of streams with ready items. `Option<AnyRelayMsg>::None`
    /// indicates that the local sender has been dropped.
    ///
    /// Conceptually all streams are in a queue; new streams are added to the
    /// back of the queue, and a stream is sent to the back of the queue
    /// whenever a ready message is taken from it (via
    /// [`Self::take_ready_msg`]). The returned iterator is an ordered view of
    /// this queue, showing the subset of streams that have a message ready to
    /// send, or whose sender has been dropped.
    pub(super) fn poll_ready_streams_iter<'a>(
        &'a mut self,
        cx: &mut std::task::Context,
    ) -> impl Iterator<Item = (StreamId, Option<&'a AnyRelayMsg>)> + 'a {
        self.open_streams
            .poll_ready_iter_mut(cx)
            .map(|(sid, _priority, ent)| {
                let ent = Pin::new(ent);
                let msg = ent.unobtrusive_peek();
                (*sid, msg)
            })
    }

    /// If the stream `sid` has a message ready, take it, and reprioritize `sid`
    /// to the "back of the line" with respect to
    /// [`Self::poll_ready_streams_iter`].
    pub(super) fn take_ready_msg(&mut self, sid: StreamId) -> Option<AnyRelayMsg> {
        let new_priority = self.take_next_priority();
        let (_prev_priority, val) = self
            .open_streams
            .take_ready_value_and_reprioritize(&sid, new_priority)?;
        Some(val)
    }

    // TODO: Eventually if we want relay support, we'll need to support
    // stream IDs chosen by somebody else. But for now, we don't need those.
}

/// A reason for terminating a stream.
///
/// We use this type in order to ensure that we obey the API restrictions of [`StreamMap::terminate`]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(super) enum TerminateReason {
    /// Closing a stream because the receiver got `Ok(None)`, indicating that the
    /// corresponding senders were all dropped.
    StreamTargetClosed,
    /// Closing a stream because we were explicitly told to end it via
    /// [`StreamTarget::close_pending`](crate::circuit::StreamTarget::close_pending).
    ExplicitEnd,
}

/// Convenience function for doing a wrapping increment of a `StreamId`.
fn wrapping_next_stream_id(id: StreamId) -> StreamId {
    let next_val = NonZeroU16::from(id)
        .checked_add(1)
        .unwrap_or_else(|| NonZeroU16::new(1).expect("Impossibly got 0 value"));
    next_val.into()
}

#[cfg(test)]
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
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    use crate::{circuit::sendme::StreamSendWindow, stream::DataCmdChecker};

    #[test]
    fn test_wrapping_next_stream_id() {
        let one = StreamId::new(1).unwrap();
        let two = StreamId::new(2).unwrap();
        let max = StreamId::new(0xffff).unwrap();
        assert_eq!(wrapping_next_stream_id(one), two);
        assert_eq!(wrapping_next_stream_id(max), one);
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn streammap_basics() -> Result<()> {
        let mut map = StreamMap::new();
        let mut next_id = map.next_stream_id;
        let mut ids = Vec::new();

        assert_eq!(map.n_open_streams(), 0);

        // Try add_ent
        for n in 1..=128 {
            let (sink, _) = mpsc::channel(128);
            let (_, rx) = mpsc::channel(2);
            let id = map.add_ent(
                sink,
                rx,
                StreamSendWindow::new(500),
                DataCmdChecker::new_any(),
            )?;
            let expect_id: StreamId = next_id;
            assert_eq!(expect_id, id);
            next_id = wrapping_next_stream_id(next_id);
            ids.push(id);
            assert_eq!(map.n_open_streams(), n);
        }

        // Test get_mut.
        let nonesuch_id = next_id;
        assert!(matches!(
            map.get_mut(ids[0]),
            Some(StreamEntMut::Open { .. })
        ));
        assert!(map.get_mut(nonesuch_id).is_none());

        // Test end_received
        assert!(map.ending_msg_received(nonesuch_id).is_err());
        assert_eq!(map.n_open_streams(), 128);
        assert!(map.ending_msg_received(ids[1]).is_ok());
        assert_eq!(map.n_open_streams(), 127);
        assert!(matches!(
            map.get_mut(ids[1]),
            Some(StreamEntMut::EndReceived)
        ));
        assert!(map.ending_msg_received(ids[1]).is_err());

        // Test terminate
        use TerminateReason as TR;
        assert!(map.terminate(nonesuch_id, TR::ExplicitEnd).is_err());
        assert_eq!(map.n_open_streams(), 127);
        assert_eq!(
            map.terminate(ids[2], TR::ExplicitEnd).unwrap(),
            ShouldSendEnd::Send
        );
        assert_eq!(map.n_open_streams(), 126);
        assert!(matches!(
            map.get_mut(ids[2]),
            Some(StreamEntMut::EndSent { .. })
        ));
        assert_eq!(
            map.terminate(ids[1], TR::ExplicitEnd).unwrap(),
            ShouldSendEnd::DontSend
        );
        // This stream was already closed when we called `ending_msg_received`
        // above.
        assert_eq!(map.n_open_streams(), 126);
        assert!(map.get_mut(ids[1]).is_none());

        // Try receiving an end after a terminate.
        assert!(map.ending_msg_received(ids[2]).is_ok());
        assert!(map.get_mut(ids[2]).is_none());
        assert_eq!(map.n_open_streams(), 126);

        Ok(())
    }
}
