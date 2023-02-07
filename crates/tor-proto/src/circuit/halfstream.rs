//! Type and code for handling a "half-closed" stream.
//!
//! A half-closed stream is one that we've sent an END on, but where
//! we might still receive some cells.

use crate::circuit::sendme::{StreamRecvWindow, StreamSendWindow};
use crate::{Error, Result};
use tor_cell::relaycell::{msg::AnyRelayMsg, RelayMsg};
use tor_error::internal;

/// Type to track state of half-closed streams.
///
/// A half-closed stream is one where we've sent an END cell, but where
/// the other side might still send us data.
///
/// We need to track these streams instead of forgetting about them entirely,
/// since otherwise we'd be vulnerable to a class of "DropMark" attacks;
/// see <https://gitlab.torproject.org/tpo/core/tor/-/issues/25573>.
pub(super) struct HalfStream {
    /// Send window for this stream. Used to detect whether we get too many
    /// SENDME cells.
    sendw: StreamSendWindow,
    /// Receive window for this stream. Used to detect whether we get too
    /// many data cells.
    recvw: StreamRecvWindow,
    /// If true, accept a connected cell on this stream.
    connected_ok: bool,
}

impl HalfStream {
    /// Create a new half-closed stream.
    pub(super) fn new(
        sendw: StreamSendWindow,
        recvw: StreamRecvWindow,
        connected_ok: bool,
    ) -> Self {
        HalfStream {
            sendw,
            recvw,
            connected_ok,
        }
    }

    /// Process an incoming message and adjust this HalfStream accordingly.
    /// Give an error if the protocol has been violated.
    ///
    /// The caller must handle END cells; it is an internal error to pass
    /// END cells to this method.
    /// no ends here.
    pub(super) fn handle_msg(&mut self, msg: &AnyRelayMsg) -> Result<()> {
        match msg {
            AnyRelayMsg::Sendme(_) => {
                self.sendw.put(Some(()))?;
                Ok(())
            }
            AnyRelayMsg::Data(_) => {
                self.recvw.take()?;
                Ok(())
            }
            AnyRelayMsg::Connected(_) => {
                if self.connected_ok {
                    self.connected_ok = false;
                    Ok(())
                } else {
                    Err(Error::CircProto(
                        "Bad CONNECTED cell on a closed stream!".into(),
                    ))
                }
            }
            AnyRelayMsg::End(_) => Err(Error::from(internal!(
                "END cell in HalfStream::handle_msg()"
            ))),
            _ => Err(Error::CircProto(format!(
                "Bad {} cell on a closed stream!",
                msg.cmd()
            ))),
        }
    }
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
    use crate::circuit::sendme::{StreamRecvWindow, StreamSendWindow};
    use tor_cell::relaycell::msg;

    #[test]
    fn halfstream_sendme() -> Result<()> {
        let mut sendw = StreamSendWindow::new(101);
        sendw.take(&())?; // Make sure that it will accept one sendme.

        let mut hs = HalfStream::new(sendw, StreamRecvWindow::new(20), true);

        // one sendme is fine
        let m = msg::Sendme::new_empty().into();
        assert!(hs.handle_msg(&m).is_ok());
        // but no more were expected!
        let e = hs.handle_msg(&m).err().unwrap();
        assert_eq!(
            format!("{}", e),
            "Circuit protocol violation: Received a SENDME when none was expected"
        );
        Ok(())
    }

    fn hs_new() -> HalfStream {
        HalfStream::new(StreamSendWindow::new(20), StreamRecvWindow::new(20), true)
    }

    #[test]
    fn halfstream_data() {
        let mut hs = hs_new();

        // 20 data cells are okay.
        let m = msg::Data::new(&b"this offer is unrepeatable"[..])
            .unwrap()
            .into();
        for _ in 0_u8..20 {
            assert!(hs.handle_msg(&m).is_ok());
        }

        // But one more is a protocol violation.
        let e = hs.handle_msg(&m).err().unwrap();
        assert_eq!(
            format!("{}", e),
            "Circuit protocol violation: Received a data cell in violation of a window"
        );
    }

    #[test]
    fn halfstream_connected() {
        let mut hs = hs_new();
        // We were told to accept a connected, so we'll accept one
        // and no more.
        let m = msg::Connected::new_empty().into();
        assert!(hs.handle_msg(&m).is_ok());
        assert!(hs.handle_msg(&m).is_err());

        // If we try that again with connected_ok == false, we won't
        // accept any.
        let mut hs = HalfStream::new(StreamSendWindow::new(20), StreamRecvWindow::new(20), false);
        let e = hs.handle_msg(&m).err().unwrap();
        assert_eq!(
            format!("{}", e),
            "Circuit protocol violation: Bad CONNECTED cell on a closed stream!"
        );
    }

    #[test]
    fn halfstream_other() {
        let mut hs = hs_new();
        let m = msg::Extended2::new(Vec::new()).into();
        let e = hs.handle_msg(&m).err().unwrap();
        assert_eq!(
            format!("{}", e),
            "Circuit protocol violation: Bad EXTENDED2 cell on a closed stream!"
        );
    }
}
