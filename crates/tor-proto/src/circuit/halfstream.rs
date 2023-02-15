//! Type and code for handling a "half-closed" stream.
//!
//! A half-closed stream is one that we've sent an END on, but where
//! we might still receive some cells.

use crate::circuit::sendme::{StreamRecvWindow, StreamSendWindow};
use crate::{Error, Result};
use tor_cell::relaycell::UnparsedRelayCell;
use tor_cell::restricted_msg;

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

restricted_msg! {
    enum HalfStreamMsg : RelayMsg {
        Sendme, Data, Connected, End, Resolved
    }
}

/// A status value returned by [`HalfStream::handle_msg`].
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum HalfStreamStatus {
    /// The stream has been closed successfully and can now be dropped.
    Closed,
    /// The stream is still half,open, and must still be tracked.
    Open,
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
    pub(super) fn handle_msg(&mut self, msg: UnparsedRelayCell) -> Result<HalfStreamStatus> {
        use HalfStreamMsg::*;
        use HalfStreamStatus::*;
        let msg = msg
            .decode::<HalfStreamMsg>()
            .map_err(|e| Error::from_bytes_err(e, "message on half-closed stream"))?
            .into_msg();
        match msg {
            Sendme(_) => {
                self.sendw.put(Some(()))?;
                Ok(Open)
            }
            Data(_) => {
                self.recvw.take()?;
                Ok(Open)
            }
            Connected(_) => {
                if self.connected_ok {
                    self.connected_ok = false;
                    Ok(Open)
                } else {
                    Err(Error::CircProto(
                        "Bad CONNECTED cell on a closed stream!".into(),
                    ))
                }
            }
            End(_) => Ok(Closed),
            // TODO XXXX: We should only allow a Resolved() on streams where we sent
            // Resolve. My intended solution for #774 will fix this too.
            Resolved(_) => Ok(Closed),
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
    use rand::{CryptoRng, Rng};
    use tor_basic_utils::test_rng::testing_rng;
    use tor_cell::relaycell::{
        msg::{self, AnyRelayMsg},
        AnyRelayCell,
    };

    fn to_unparsed<R: Rng + CryptoRng>(rng: &mut R, val: AnyRelayMsg) -> UnparsedRelayCell {
        UnparsedRelayCell::from_body(
            AnyRelayCell::new(77.into(), val)
                .encode(rng)
                .expect("encoding failed"),
        )
    }

    #[test]
    fn halfstream_sendme() -> Result<()> {
        let mut rng = testing_rng();

        let mut sendw = StreamSendWindow::new(101);
        sendw.take(&())?; // Make sure that it will accept one sendme.

        let mut hs = HalfStream::new(sendw, StreamRecvWindow::new(20), true);

        // one sendme is fine
        let m = msg::Sendme::new_empty();
        assert!(hs
            .handle_msg(to_unparsed(&mut rng, m.clone().into()))
            .is_ok());
        // but no more were expected!
        let e = hs
            .handle_msg(to_unparsed(&mut rng, m.into()))
            .err()
            .unwrap();
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
        let mut rng = testing_rng();

        // 20 data cells are okay.
        let m = msg::Data::new(&b"this offer is unrepeatable"[..]).unwrap();
        for _ in 0_u8..20 {
            assert!(hs
                .handle_msg(to_unparsed(&mut rng, m.clone().into()))
                .is_ok());
        }

        // But one more is a protocol violation.
        let e = hs
            .handle_msg(to_unparsed(&mut rng, m.into()))
            .err()
            .unwrap();
        assert_eq!(
            format!("{}", e),
            "Circuit protocol violation: Received a data cell in violation of a window"
        );
    }

    #[test]
    fn halfstream_connected() {
        let mut hs = hs_new();
        let mut rng = testing_rng();
        // We were told to accept a connected, so we'll accept one
        // and no more.
        let m = msg::Connected::new_empty();
        assert!(hs
            .handle_msg(to_unparsed(&mut rng, m.clone().into()))
            .is_ok());
        assert!(hs
            .handle_msg(to_unparsed(&mut rng, m.clone().into()))
            .is_err());

        // If we try that again with connected_ok == false, we won't
        // accept any.
        let mut hs = HalfStream::new(StreamSendWindow::new(20), StreamRecvWindow::new(20), false);
        let e = hs
            .handle_msg(to_unparsed(&mut rng, m.into()))
            .err()
            .unwrap();
        assert_eq!(
            format!("{}", e),
            "Circuit protocol violation: Bad CONNECTED cell on a closed stream!"
        );
    }

    #[test]
    fn halfstream_other() {
        let mut hs = hs_new();
        let mut rng = testing_rng();
        let m = msg::Extended2::new(Vec::new());
        let e = hs
            .handle_msg(to_unparsed(&mut rng, m.into()))
            .err()
            .unwrap();
        assert_eq!(
            format!("{}", e),
            "Unable to parse message on half-closed stream"
        );
    }
}
