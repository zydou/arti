//! Type and code for handling a "half-closed" stream.
//!
//! A half-closed stream is one that we've sent an END on, but where
//! we might still receive some cells.

use crate::circuit::sendme::{cmd_counts_towards_windows, StreamRecvWindow, StreamSendWindow};
use crate::stream::{AnyCmdChecker, StreamStatus};
use crate::{Error, Result};
use tor_cell::relaycell::{RelayCmd, UnparsedRelayMsg};

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
    /// Object to tell us which cells to accept on this stream.
    cmd_checker: AnyCmdChecker,
}

impl HalfStream {
    /// Create a new half-closed stream.
    pub(super) fn new(
        sendw: StreamSendWindow,
        recvw: StreamRecvWindow,
        cmd_checker: AnyCmdChecker,
    ) -> Self {
        HalfStream {
            sendw,
            recvw,
            cmd_checker,
        }
    }

    /// Process an incoming message and adjust this HalfStream accordingly.
    /// Give an error if the protocol has been violated.
    ///
    /// The caller must handle END cells; it is an internal error to pass
    /// END cells to this method.
    /// no ends here.
    pub(super) fn handle_msg(&mut self, msg: UnparsedRelayMsg) -> Result<StreamStatus> {
        use tor_cell::relaycell::msg::Sendme;
        use StreamStatus::*;
        if msg.cmd() == RelayCmd::SENDME {
            // We handle SENDME separately, and don't give it to the checker.
            let _ = msg
                .decode::<Sendme>()
                .map_err(|e| Error::from_bytes_err(e, "SENDME on half-closed stream"))?;
            self.sendw.put(Some(()))?;
            return Ok(Open);
        }

        if cmd_counts_towards_windows(msg.cmd()) {
            self.recvw.take()?;
        }

        let status = self.cmd_checker.check_msg(&msg)?;
        self.cmd_checker.consume_checked_msg(msg)?;
        Ok(status)
    }
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
    use crate::{
        circuit::sendme::{StreamRecvWindow, StreamSendWindow},
        stream::DataCmdChecker,
    };
    use rand::{CryptoRng, Rng};
    use tor_basic_utils::test_rng::testing_rng;
    use tor_cell::relaycell::{
        msg::{self, AnyRelayMsg},
        AnyRelayMsgOuter, RelayCellFormat, StreamId,
    };

    fn to_unparsed<R: Rng + CryptoRng>(rng: &mut R, val: AnyRelayMsg) -> UnparsedRelayMsg {
        UnparsedRelayMsg::from_singleton_body(
            RelayCellFormat::V0,
            AnyRelayMsgOuter::new(StreamId::new(77), val)
                .encode(rng)
                .expect("encoding failed"),
        )
        .unwrap()
    }

    #[test]
    fn halfstream_sendme() -> Result<()> {
        let mut rng = testing_rng();

        let mut sendw = StreamSendWindow::new(101);
        sendw.take(&())?; // Make sure that it will accept one sendme.

        let mut hs = HalfStream::new(sendw, StreamRecvWindow::new(20), DataCmdChecker::new_any());

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
        HalfStream::new(
            StreamSendWindow::new(20),
            StreamRecvWindow::new(20),
            DataCmdChecker::new_any(),
        )
    }

    #[test]
    fn halfstream_data() {
        let mut hs = hs_new();
        let mut rng = testing_rng();

        // we didn't give a connected cell during setup, so do it now.
        hs.handle_msg(to_unparsed(&mut rng, msg::Connected::new_empty().into()))
            .unwrap();

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

        // If we try that again _after getting a connected_,
        // accept any.
        let mut cmd_checker = DataCmdChecker::new_any();
        {
            cmd_checker
                .check_msg(&to_unparsed(&mut rng, msg::Connected::new_empty().into()))
                .unwrap();
        }
        let mut hs = HalfStream::new(
            StreamSendWindow::new(20),
            StreamRecvWindow::new(20),
            cmd_checker,
        );
        let e = hs
            .handle_msg(to_unparsed(&mut rng, m.into()))
            .err()
            .unwrap();
        assert_eq!(
            format!("{}", e),
            "Stream protocol violation: Received CONNECTED twice on a stream."
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
            "Stream protocol violation: Unexpected EXTENDED2 on a data stream!"
        );
    }
}
