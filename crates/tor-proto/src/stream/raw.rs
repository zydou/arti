//! Declare the lowest level of stream: a stream that operates on raw
//! cells.

use crate::circuit::{sendme, StreamTarget};
use crate::{Error, Result};
use tor_cell::relaycell::msg::AnyRelayMsg;

use crate::circuit::sendme::StreamRecvWindow;
use futures::channel::mpsc;
use futures::stream::StreamExt;

/// The read part of a stream on a particular circuit.
#[derive(Debug)]
pub struct StreamReader {
    /// The underlying `StreamTarget` for this stream.
    pub(crate) target: StreamTarget,
    /// Channel to receive stream messages from the reactor.
    pub(crate) receiver: mpsc::Receiver<AnyRelayMsg>,
    /// Congestion control receive window for this stream.
    ///
    /// Having this here means we're only going to update it when the end consumer of this stream
    /// actually reads things, meaning we don't ask for more data until it's actually needed (as
    /// opposed to having the reactor assume we're always reading, and potentially overwhelm itself
    /// with having to buffer data).
    pub(crate) recv_window: StreamRecvWindow,
    /// Whether or not this stream has ended.
    pub(crate) ended: bool,
}

impl StreamReader {
    /// Try to read the next relay message from this stream.
    async fn recv_raw(&mut self) -> Result<AnyRelayMsg> {
        if self.ended {
            // Prevent reading from streams after they've ended.
            return Err(Error::NotConnected);
        }
        let msg = self
            .receiver
            .next()
            .await
            // This probably means that the other side closed the
            // mpsc channel.  I'm not sure the error type is correct though?
            .ok_or_else(|| {
                Error::StreamProto("stream channel disappeared without END cell?".into())
            })?;

        if sendme::msg_counts_towards_windows(&msg) && self.recv_window.take()? {
            self.target.send_sendme()?;
            self.recv_window.put();
        }

        Ok(msg)
    }

    /// As recv_raw, but if there is an error or an end cell, note that this
    /// stream has ended.
    pub async fn recv(&mut self) -> Result<AnyRelayMsg> {
        let val = self.recv_raw().await;
        match val {
            Err(_) | Ok(AnyRelayMsg::End(_)) => {
                self.ended = true;
            }
            _ => {}
        }
        val
    }

    /// Shut down this stream.
    pub fn protocol_error(&mut self) {
        self.target.protocol_error();
    }
}
