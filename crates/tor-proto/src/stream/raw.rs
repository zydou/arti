//! Declare the lowest level of stream: a stream that operates on raw
//! cells.

use crate::circuit::StreamTarget;
use crate::{Error, Result};
use tor_cell::relaycell::msg::RelayMsg;

use futures::channel::mpsc;
use futures::lock::Mutex;
use futures::stream::StreamExt;

use std::sync::atomic::{AtomicBool, Ordering};

/// A RawCellStream is a client's cell-oriented view of a stream over the
/// Tor network.
pub struct RawCellStream {
    /// Wrapped view of the circuit, hop, and streamid that we're using.
    ///
    /// TODO: do something similar with circuits?
    target: Mutex<StreamTarget>,
    /// A Stream over which we receive relay messages.  Only relay messages
    /// that can be associated with a stream ID will be received.
    ///
    /// FIXME(eta): ideally, this shouldn't be wrapped in a mutex / shared
    receiver: Mutex<mpsc::UnboundedReceiver<RelayMsg>>,
    /// Have we been informed that this stream is closed, or received a fatal
    /// error?
    stream_ended: AtomicBool,
}

impl RawCellStream {
    /// Internal: build a new RawCellStream.
    pub(crate) fn new(target: StreamTarget, receiver: mpsc::UnboundedReceiver<RelayMsg>) -> Self {
        RawCellStream {
            target: Mutex::new(target),
            receiver: Mutex::new(receiver),
            stream_ended: AtomicBool::new(false),
        }
    }

    /// Try to read the next relay message from this stream.
    async fn recv_raw(&self) -> Result<RelayMsg> {
        let msg = self
            .receiver
            .lock()
            .await
            .next()
            .await
            // This probably means that the other side closed the
            // mpsc channel.  I'm not sure the error type is correct though?
            .ok_or_else(|| {
                Error::StreamProto("stream channel disappeared without END cell?".into())
            })?;

        Ok(msg)
    }

    /// As recv_raw, but if there is an error or an end cell, note that this
    /// stream has ended.
    pub async fn recv(&self) -> Result<RelayMsg> {
        let val = self.recv_raw().await;
        match val {
            Err(_) | Ok(RelayMsg::End(_)) => {
                self.note_ended();
            }
            _ => {}
        }
        val
    }

    /// Send a relay message along this stream
    pub async fn send(&self, msg: RelayMsg) -> Result<()> {
        self.target.lock().await.send(msg).await
    }

    /// Return true if this stream is marked as having ended.
    pub fn has_ended(&self) -> bool {
        self.stream_ended.load(Ordering::SeqCst)
    }

    /// Mark this stream as having ended because of an incoming cell.
    fn note_ended(&self) {
        self.stream_ended.store(true, Ordering::SeqCst);
    }

    /// Inform the circuit-side of this stream about a protocol error
    pub async fn protocol_error(&self) {
        // TODO: Should this call note_ended?
        self.target.lock().await.protocol_error()
    }

    /// Ensure that all the data in this stream has been flushed in to
    /// the circuit, and close it.
    pub async fn close(self) -> Result<()> {
        // Not much to do here right now.
        drop(self);
        Ok(())
    }
}
