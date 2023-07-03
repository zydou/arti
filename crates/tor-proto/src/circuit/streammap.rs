//! Types and code for mapping StreamIDs to streams on a circuit.

use crate::circuit::halfstream::HalfStream;
use crate::circuit::sendme;
use crate::stream::AnyCmdChecker;
use crate::{Error, Result};
use tor_cell::relaycell::UnparsedRelayCell;
/// Mapping from stream ID to streams.
// NOTE: This is a work in progress and I bet I'll refactor it a lot;
// it needs to stay opaque!
use tor_cell::relaycell::{msg::AnyRelayMsg, StreamId};

use futures::channel::mpsc;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use tor_error::internal;

use rand::Rng;

use crate::circuit::reactor::RECV_WINDOW_INIT;
use crate::circuit::sendme::StreamRecvWindow;
use tracing::debug;

/// The entry for a stream.
pub(super) enum StreamEnt {
    /// An open stream.
    Open {
        /// Sink to send relay cells tagged for this stream into.
        sink: mpsc::Sender<UnparsedRelayCell>,
        /// Stream for cells that should be sent down this stream.
        rx: mpsc::Receiver<AnyRelayMsg>,
        /// Send window, for congestion control purposes.
        send_window: sendme::StreamSendWindow,
        /// Number of cells dropped due to the stream disappearing before we can
        /// transform this into an `EndSent`.
        dropped: u16,
        /// A `CmdChecker` used to tell whether cells on this stream are valid.
        cmd_checker: AnyCmdChecker,
    },
    /// A stream for which we have received an END cell, but not yet
    /// had the stream object get dropped.
    EndReceived,
    /// A stream for which we have sent an END cell but not yet received an END
    /// cell.
    ///
    /// TODO(arti#264) Can we ever throw this out? Do we really get END cells for
    /// these?
    EndSent(HalfStream),
}

impl StreamEnt {
    /// Retrieve the send window for this stream, if it is open.
    pub(super) fn send_window(&mut self) -> Option<&mut sendme::StreamSendWindow> {
        match self {
            StreamEnt::Open {
                ref mut send_window,
                ..
            } => Some(send_window),
            _ => None,
        }
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

/// A map from stream IDs to stream entries. Each circuit has one for each
/// hop.
pub(super) struct StreamMap {
    /// Map from StreamId to StreamEnt.  If there is no entry for a
    /// StreamId, that stream doesn't exist.
    m: HashMap<StreamId, StreamEnt>,
    /// The next StreamId that we should use for a newly allocated
    /// circuit.  (0 is not a valid streamID).
    next_stream_id: u16,
}

impl StreamMap {
    /// Make a new empty StreamMap.
    pub(super) fn new() -> Self {
        let mut rng = rand::thread_rng();
        let next_stream_id: u16 = loop {
            let v: u16 = rng.gen();
            if v != 0 {
                break v;
            }
        };
        StreamMap {
            m: HashMap::new(),
            next_stream_id,
        }
    }

    /// Get the `HashMap` inside this stream map.
    pub(super) fn inner(&mut self) -> &mut HashMap<StreamId, StreamEnt> {
        &mut self.m
    }

    /// Add an entry to this map; return the newly allocated StreamId.
    pub(super) fn add_ent(
        &mut self,
        sink: mpsc::Sender<UnparsedRelayCell>,
        rx: mpsc::Receiver<AnyRelayMsg>,
        send_window: sendme::StreamSendWindow,
        cmd_checker: AnyCmdChecker,
    ) -> Result<StreamId> {
        let stream_ent = StreamEnt::Open {
            sink,
            rx,
            send_window,
            dropped: 0,
            cmd_checker,
        };
        // This "65536" seems too aggressive, but it's what tor does.
        //
        // Also, going around in a loop here is (sadly) needed in order
        // to look like Tor clients.
        for _ in 1..=65536 {
            let id: StreamId = self.next_stream_id.into();
            self.next_stream_id = self.next_stream_id.wrapping_add(1);
            if id.is_zero() {
                continue;
            }
            let ent = self.m.entry(id);
            if let Entry::Vacant(_) = ent {
                ent.or_insert(stream_ent);
                return Ok(id);
            }
        }

        Err(Error::IdRangeFull)
    }

    /// Return the entry for `id` in this map, if any.
    pub(super) fn get_mut(&mut self, id: StreamId) -> Option<&mut StreamEnt> {
        self.m.get_mut(&id)
    }

    /// Note that we received an END message (or other message indicating the end of
    /// the stream) on the stream with `id`.
    ///
    /// Returns true if there was really a stream there.
    pub(super) fn ending_msg_received(&mut self, id: StreamId) -> Result<()> {
        // Check the hashmap for the right stream. Bail if not found.
        // Also keep the hashmap handle so that we can do more efficient inserts/removals
        let mut stream_entry = match self.m.entry(id) {
            Entry::Vacant(_) => {
                return Err(Error::CircProto(
                    "Received END cell on nonexistent stream".into(),
                ))
            }
            Entry::Occupied(o) => o,
        };

        // Progress the stream's state machine accordingly
        match stream_entry.get() {
            StreamEnt::EndReceived => Err(Error::CircProto(
                "Received two END cells on same stream".into(),
            )),
            StreamEnt::EndSent(_) => {
                debug!("Actually got an end cell on a half-closed stream!");
                // We got an END, and we already sent an END. Great!
                // we can forget about this stream.
                stream_entry.remove_entry();
                Ok(())
            }
            StreamEnt::Open { .. } => {
                stream_entry.insert(StreamEnt::EndReceived);
                Ok(())
            }
        }
    }

    /// Handle a termination of the stream with `id` from this side of
    /// the circuit. Return true if the stream was open and an END
    /// ought to be sent.
    pub(super) fn terminate(&mut self, id: StreamId) -> Result<ShouldSendEnd> {
        // Progress the stream's state machine accordingly
        match self
            .m
            .remove(&id)
            .ok_or_else(|| Error::from(internal!("Somehow we terminated a nonexistent stream?")))?
        {
            StreamEnt::EndReceived => Ok(ShouldSendEnd::DontSend),
            StreamEnt::Open {
                send_window,
                dropped,
                cmd_checker,
                // notably absent: the channels for sink and stream, which will get dropped and
                // closed (meaning reads/writes from/to this stream will now fail)
                ..
            } => {
                // FIXME(eta): we don't copy the receive window, instead just creating a new one,
                //             so a malicious peer can send us slightly more data than they should
                //             be able to; see arti#230.
                let mut recv_window = StreamRecvWindow::new(RECV_WINDOW_INIT);
                recv_window.decrement_n(dropped)?;
                // TODO: would be nice to avoid new_ref.
                let halfstream = HalfStream::new(send_window, recv_window, cmd_checker);
                self.m.insert(id, StreamEnt::EndSent(halfstream));
                Ok(ShouldSendEnd::Send)
            }
            StreamEnt::EndSent(_) => {
                panic!("Hang on! We're sending an END on a stream where we already sent an END‽");
            }
        }
    }

    // TODO: Eventually if we want relay support, we'll need to support
    // stream IDs chosen by somebody else. But for now, we don't need those.
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    use crate::{circuit::sendme::StreamSendWindow, stream::DataCmdChecker};

    #[test]
    fn streammap_basics() -> Result<()> {
        let mut map = StreamMap::new();
        let mut next_id = map.next_stream_id;
        let mut ids = Vec::new();

        // Try add_ent
        for _ in 0..128 {
            let (sink, _) = mpsc::channel(128);
            let (_, rx) = mpsc::channel(2);
            let id = map.add_ent(
                sink,
                rx,
                StreamSendWindow::new(500),
                DataCmdChecker::new_any(),
            )?;
            let expect_id: StreamId = next_id.into();
            assert_eq!(expect_id, id);
            next_id = next_id.wrapping_add(1);
            if next_id == 0 {
                next_id = 1;
            }
            ids.push(id);
        }

        // Test get_mut.
        let nonesuch_id = next_id.into();
        assert!(matches!(map.get_mut(ids[0]), Some(StreamEnt::Open { .. })));
        assert!(map.get_mut(nonesuch_id).is_none());

        // Test end_received
        assert!(map.ending_msg_received(nonesuch_id).is_err());
        assert!(map.ending_msg_received(ids[1]).is_ok());
        assert!(matches!(map.get_mut(ids[1]), Some(StreamEnt::EndReceived)));
        assert!(map.ending_msg_received(ids[1]).is_err());

        // Test terminate
        assert!(map.terminate(nonesuch_id).is_err());
        assert_eq!(map.terminate(ids[2]).unwrap(), ShouldSendEnd::Send);
        assert!(matches!(map.get_mut(ids[2]), Some(StreamEnt::EndSent(_))));
        assert_eq!(map.terminate(ids[1]).unwrap(), ShouldSendEnd::DontSend);
        assert!(map.get_mut(ids[1]).is_none());

        // Try receiving an end after a terminate.
        assert!(map.ending_msg_received(ids[2]).is_ok());
        assert!(map.get_mut(ids[2]).is_none());

        Ok(())
    }
}
