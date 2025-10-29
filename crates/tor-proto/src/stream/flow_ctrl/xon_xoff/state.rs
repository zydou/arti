//! Circuit reactor's stream XON/XOFF flow control.
//!
//! ## Notes on consensus parameters
//!
//! ### `cc_xoff_client`
//!
//! This is the number of bytes that we buffer within a [`DataStream`]. The actual total number of
//! bytes buffered can be *much* larger. For example there will be additional buffering:
//!
//! - Within the arti socks/http proxy: Arti's proxy code needs to read some bytes from the stream, store
//!   it in a temporary buffer, then write the buffer to the socket. If the socket would block, the
//!   data would remain in that temporary buffer. In practice arti uses only a small byte buffer (APP_STREAM_BUF_LEN) at
//!   the time of writing, which is hopefully negligible. See `arti::socks::copy_interactive()`.
//! - Within the kernel: There are two additional buffers that will store stream data before the
//!   application connected over socks will see the data: Arti's socket send buffer and the
//!   application's socket receive buffer. If the application were to stop reading from its socket,
//!   stream data would accumulate first in the socket's receive buffer. Once full, stream data
//!   would accumulate in arti's socket's send buffer. This can become relatively large, especially
//!   with buffer autotuning enabled. On a Linux 6.15 system with curl downloading a large file and
//!   stopping mid-download, the receive buffer was 6,116,738 bytes and the send buffer was
//!   2,631,062 bytes. This sums to around 8.7 MB of stream data buffered in the kernel, which is
//!   significantly higher than the current consensus value of `cc_xoff_client`.
//!
//! This means that the total number of bytes buffered before an XOFF is sent can be much larger
//! than `cc_xoff_client`.
//!
//! While we should take into account the kernel and arti socks buffering above, we also need to
//! keep in mind that arti-client is a library that can be used by others. These library users might
//! not do any kernel or socks buffering, for example if they write a rust program that handles the
//! stream data entirely within their program. We don't want to set `cc_xoff_client` too low that it
//! harms the performance for these users, even if it's fine for the arti socks proxy case.

use std::num::Saturating;
use std::sync::Arc;

use postage::watch;
use tor_cell::relaycell::flow_ctrl::{FlowCtrlVersion, Xoff, Xon, XonKbpsEwma};
use tor_cell::relaycell::msg::AnyRelayMsg;
use tor_cell::relaycell::{RelayMsg, UnparsedRelayMsg};
use tracing::trace;

use super::reader::DrainRateRequest;

use crate::stream::flow_ctrl::params::{CellCount, FlowCtrlParameters};
use crate::stream::flow_ctrl::state::{FlowCtrlHooks, StreamRateLimit};
use crate::util::notify::NotifySender;
use crate::{Error, Result};

#[cfg(doc)]
use {crate::client::stream::DataStream, crate::stream::flow_ctrl::state::StreamFlowCtrl};

/// State for XON/XOFF flow control.
#[derive(Debug)]
pub(crate) struct XonXoffFlowCtrl {
    /// Consensus parameters.
    params: Arc<FlowCtrlParameters>,
    /// How we communicate rate limit updates to the
    /// [`DataWriter`](crate::client::stream::DataWriter).
    rate_limit_updater: watch::Sender<StreamRateLimit>,
    /// How we communicate requests for new drain rate updates to the
    /// [`XonXoffReader`](crate::stream::flow_ctrl::xon_xoff::reader::XonXoffReader).
    drain_rate_requester: NotifySender<DrainRateRequest>,
    /// The last rate limit we sent.
    last_sent_xon_xoff: Option<XonXoffMsg>,
    /// The buffer limit at which we should send an XOFF.
    ///
    /// In prop324 it says that this will be either `cc_xoff_client` or `cc_xoff_exit` depending on
    /// whether we're a client/hs or exit, but we deviate from the spec here (see how it is set
    /// below).
    xoff_limit: CellCount<{ tor_cell::relaycell::PAYLOAD_MAX_SIZE_ALL as u32 }>,
    /// DropMark sidechannel mitigations.
    ///
    /// This is only enabled if we are a client (including an onion service).
    //
    // We could use a `Box` here so that this only takes up space if sidechannel mitigations are
    // enabled. But `SidechannelMitigation` is (at the time of writing) only 16 bytes. We could
    // reconsider in the future if we add more functionality to `SidechannelMitigation`.
    sidechannel_mitigation: Option<SidechannelMitigation>,
}

impl XonXoffFlowCtrl {
    /// Returns a new xon/xoff-based state.
    pub(crate) fn new(
        params: Arc<FlowCtrlParameters>,
        use_sidechannel_mitigations: bool,
        rate_limit_updater: watch::Sender<StreamRateLimit>,
        drain_rate_requester: NotifySender<DrainRateRequest>,
    ) -> Self {
        let sidechannel_mitigation =
            use_sidechannel_mitigations.then_some(SidechannelMitigation::new());

        // We use the same XOFF limit regardless of if we're a client or exit.
        // See https://gitlab.torproject.org/tpo/core/torspec/-/issues/371#note_3260658
        let xoff_limit = std::cmp::max(params.cc_xoff_client, params.cc_xoff_exit);

        Self {
            params,
            rate_limit_updater,
            drain_rate_requester,
            last_sent_xon_xoff: None,
            xoff_limit,
            sidechannel_mitigation,
        }
    }
}

impl FlowCtrlHooks for XonXoffFlowCtrl {
    fn can_send<M: RelayMsg>(&self, _msg: &M) -> bool {
        // we perform rate-limiting in the `DataWriter`,
        // so we send any messages that made it past the `DataWriter`
        true
    }

    fn about_to_send(&mut self, msg: &AnyRelayMsg) -> Result<()> {
        // if sidechannel mitigations are enabled and this is a RELAY_DATA message,
        // notify that we sent a data message
        if let Some(ref mut sidechannel_mitigation) = self.sidechannel_mitigation {
            if let AnyRelayMsg::Data(data_msg) = msg {
                sidechannel_mitigation.sent_stream_data(data_msg.as_ref().len());
            }
        }

        Ok(())
    }

    fn put_for_incoming_sendme(&mut self, _msg: UnparsedRelayMsg) -> Result<()> {
        let msg = "Stream level SENDME not allowed due to congestion control";
        Err(Error::CircProto(msg.into()))
    }

    fn handle_incoming_xon(&mut self, msg: UnparsedRelayMsg) -> Result<()> {
        let xon = msg
            .decode::<Xon>()
            .map_err(|e| Error::from_bytes_err(e, "failed to decode XON message"))?
            .into_msg();

        // > Parties SHOULD treat XON or XOFF cells with unrecognized versions as a protocol
        // > violation.
        if *xon.version() != 0 {
            return Err(Error::CircProto("Unrecognized XON version".into()));
        }

        // if sidechannel mitigations are enabled, notify that an XON was received
        if let Some(ref mut sidechannel_mitigation) = self.sidechannel_mitigation {
            sidechannel_mitigation.received_xon(&self.params)?;
        }

        trace!("Received an XON with rate {}", xon.kbps_ewma());

        let rate = match xon.kbps_ewma() {
            XonKbpsEwma::Limited(rate_kbps) => {
                let rate_kbps = u64::from(rate_kbps.get());
                // convert from kbps to bytes/s
                StreamRateLimit::new_bytes_per_sec(rate_kbps * 1000 / 8)
            }
            XonKbpsEwma::Unlimited => StreamRateLimit::MAX,
        };

        *self.rate_limit_updater.borrow_mut() = rate;
        Ok(())
    }

    fn handle_incoming_xoff(&mut self, msg: UnparsedRelayMsg) -> Result<()> {
        let xoff = msg
            .decode::<Xoff>()
            .map_err(|e| Error::from_bytes_err(e, "failed to decode XOFF message"))?
            .into_msg();

        // > Parties SHOULD treat XON or XOFF cells with unrecognized versions as a protocol
        // > violation.
        if *xoff.version() != 0 {
            return Err(Error::CircProto("Unrecognized XOFF version".into()));
        }

        // if sidechannel mitigations are enabled, notify that an XOFF was received
        if let Some(ref mut sidechannel_mitigation) = self.sidechannel_mitigation {
            sidechannel_mitigation.received_xoff(&self.params)?;
        }

        trace!("Received an XOFF");

        // update the rate limit and notify the `DataWriter`
        *self.rate_limit_updater.borrow_mut() = StreamRateLimit::ZERO;

        Ok(())
    }

    fn maybe_send_xon(&mut self, rate: XonKbpsEwma, buffer_len: usize) -> Result<Option<Xon>> {
        if buffer_len as u64 > self.xoff_limit.as_bytes() {
            // we can't send an XON, and we should have already sent an XOFF when the queue first
            // exceeded the limit (see `maybe_send_xoff()`)
            debug_assert!(matches!(self.last_sent_xon_xoff, Some(XonXoffMsg::Xoff)));

            // inform the stream reader that we need a new drain rate
            self.drain_rate_requester.notify();
            return Ok(None);
        }

        self.last_sent_xon_xoff = Some(XonXoffMsg::Xon(rate));

        trace!("Want to send an XON with rate {rate}");

        Ok(Some(Xon::new(FlowCtrlVersion::V0, rate)))
    }

    fn maybe_send_xoff(&mut self, buffer_len: usize) -> Result<Option<Xoff>> {
        // if the last XON/XOFF we sent was an XOFF, no need to send another
        if matches!(self.last_sent_xon_xoff, Some(XonXoffMsg::Xoff)) {
            return Ok(None);
        }

        if buffer_len as u64 <= self.xoff_limit.as_bytes() {
            return Ok(None);
        }

        // either we have never sent an XOFF or XON, or we last sent an XON

        // remember that we last sent an XOFF
        self.last_sent_xon_xoff = Some(XonXoffMsg::Xoff);

        // inform the stream reader that we need a new drain rate
        self.drain_rate_requester.notify();

        trace!("Want to send an XOFF");

        Ok(Some(Xoff::new(FlowCtrlVersion::V0)))
    }
}

/// An XON or XOFF message with no associated data.
#[derive(Debug, PartialEq, Eq)]
enum XonXoff {
    /// XON message.
    Xon,
    /// XOFF message.
    Xoff,
}

/// An XON or XOFF message with associated data.
#[derive(Debug)]
enum XonXoffMsg {
    /// XON message with a rate.
    // TODO: I'm expecting that we'll want the `XonKbpsEwma` in the future.
    // If that doesn't end up being the case, then we should remove it.
    #[expect(dead_code)]
    Xon(XonKbpsEwma),
    /// XOFF message.
    Xoff,
}

/// Sidechannel mitigations for DropMark attacks.
///
/// > In order to mitigate DropMark attacks, both XOFF and advisory XON transmission must be
/// > restricted.
///
/// These restrictions should be implemented for clients (OPs and onion services).
#[derive(Debug)]
struct SidechannelMitigation {
    /// The last rate limit update we received.
    last_recvd_xon_xoff: Option<XonXoff>,
    /// Number of sent stream bytes.
    ///
    /// We only use this for bytes that are sent early on the stream,
    /// checking if it's less than `cc_xon_rate` and/or `cc_xoff_{client,exit}`.
    /// Once this value is sufficiently large, we don't care about the exact value.
    /// So a saturating u32 should be more than enough bits for what we need.
    bytes_sent_total: Saturating<u32>,
    /// Number of sent stream bytes since the last advisory XON was received.
    bytes_sent_since_recvd_last_advisory_xon: Saturating<u32>,
    /// Number of sent stream bytes since the last XOFF was received.
    bytes_sent_since_recvd_last_xoff: Saturating<u32>,
}

impl SidechannelMitigation {
    /// A new [`SidechannelMitigation`].
    fn new() -> Self {
        Self {
            last_recvd_xon_xoff: None,
            bytes_sent_total: Saturating(0),
            // We set these to 0 even though we haven't yet received an XON or XOFF. We could use an
            // `Option` instead, but it makes the code more complicated and increases their size
            // from 32 bits to 64 bits.
            bytes_sent_since_recvd_last_advisory_xon: Saturating(0),
            bytes_sent_since_recvd_last_xoff: Saturating(0),
        }
    }

    /// A (likely underestimated) guess of the XOFF limit that the other endpoint is using.
    fn peer_xoff_limit_bytes(params: &FlowCtrlParameters) -> u64 {
        // We need to consider that `xoff_client` and `xoff_exit` may be different, we don't know
        // here exactly what kind of peer we're connected to, and that we may have a different view
        // of the consensus than the peer.
        // We deviate from prop324 here and use a more relaxed threshold.
        // See https://gitlab.torproject.org/tpo/core/torspec/-/issues/371#note_3260658
        let min = std::cmp::min(
            params.cc_xoff_client.as_bytes(),
            params.cc_xoff_exit.as_bytes(),
        );
        min / 2
    }

    /// A (likely underestimated) guess of the advisory XON limit that the other endpoint is using.
    fn peer_xon_limit_bytes(params: &FlowCtrlParameters) -> u64 {
        // We need to consider that we may have a different view of the consensus than the peer.
        // We deviate from prop324 here and use a more relaxed threshold.
        // See https://gitlab.torproject.org/tpo/core/torspec/-/issues/371#note_3260658
        params.cc_xon_rate.as_bytes() / 2
    }

    /// Notify that we have sent stream data.
    fn sent_stream_data(&mut self, stream_bytes: usize) {
        // perform a saturating conversion to u32
        let stream_bytes: u32 = stream_bytes.try_into().unwrap_or(u32::MAX);

        self.bytes_sent_total += stream_bytes;

        // when we receive an XON or XOFF, we set the corresponding variable back to 0
        self.bytes_sent_since_recvd_last_advisory_xon += stream_bytes;
        self.bytes_sent_since_recvd_last_xoff += stream_bytes;
    }

    /// Notify that we have received an XON message.
    fn received_xon(&mut self, params: &FlowCtrlParameters) -> Result<()> {
        // Check to make sure that XON is not sent too early, for dropmark attacks. The main
        // sidechannel risk is early cells, but we also check to see that we did not get more XONs
        // than make sense for the number of bytes we sent.
        //
        // The ordering is important here. For example we first want to check if we received an
        // advisory XON that was too early, before we check if we received the advisory XON too
        // frequently.

        // Ensure that we have sent some bytes. This might be covered by other checks below, but this
        // is the most important check so we do it explicitly here first.
        if self.bytes_sent_total.0 == 0 {
            const MSG: &str = "Received XON before sending any data";
            return Err(Error::CircProto(MSG.into()));
        }

        // is this an advisory XON?
        let is_advisory = match self.last_recvd_xon_xoff {
            // if we last received an XON, then this is advisory since we are already sending data
            Some(XonXoff::Xon) => true,
            // if we last received an XOFF, then this isn't advisory since we're being asked to
            // resume sending data
            Some(XonXoff::Xoff) => false,
            // if we never received an XON nor XOFF, then this is advisory since we are already
            // sending data
            None => true,
        };

        // set this before we possibly return early below, since this must be set regardless of if
        // it's an advisory XON or not
        self.last_recvd_xon_xoff = Some(XonXoff::Xon);

        // we only restrict advisory XON messages
        if !is_advisory {
            return Ok(());
        }

        // > Clients also SHOULD ensure that advisory XONs do not arrive before the minimum of the
        // > XOFF limit and 'cc_xon_rate' full cells worth of bytes have been transmitted.
        //
        // NOTE: We use a more relaxed threshold for the XON and XOFF limits than in prop324.
        let advisory_not_expected_before = std::cmp::min(
            Self::peer_xoff_limit_bytes(params),
            Self::peer_xon_limit_bytes(params),
        );
        if u64::from(self.bytes_sent_total.0) < advisory_not_expected_before {
            const MSG: &str = "Received advisory XON too early";
            return Err(Error::CircProto(MSG.into()));
        }

        // > Clients SHOULD ensure that advisory XONs do not arrive more frequently than every
        // > 'cc_xon_rate' cells worth of sent data.
        //
        // NOTE: We implement this a bit different than C-tor. In C-tor it checks that:
        //   conn->total_bytes_xmit < MIN(xoff_{client/exit}, xon_rate_bytes)*conn->num_xon_recv
        // which effectively checks that the average XON frequency over the lifetime of the stream
        // does not exceed a frequency of `MIN(xoff_{client/exit}, xon_rate_bytes)`. Instead here we
        // check that two XON messages never arrive at an interval that would exceed a frequency of
        // `cc_xon_rate`.
        //
        // NOTE: We use a more relaxed threshold for the XON limit than in prop324.
        if u64::from(self.bytes_sent_since_recvd_last_advisory_xon.0)
            < Self::peer_xon_limit_bytes(params)
        {
            const MSG: &str = "Received advisory XON too frequently";
            return Err(Error::CircProto(MSG.into()));
        }

        self.bytes_sent_since_recvd_last_advisory_xon = Saturating(0);

        Ok(())
    }

    /// Notify that we have received an XOFF message.
    fn received_xoff(&mut self, params: &FlowCtrlParameters) -> Result<()> {
        // Check to make sure that XOFF is not sent too early, for dropmark attacks. The
        // main sidechannel risk is early cells, but we also check to make sure that we have not
        // received more XOFFs than could have been generated by the bytes we sent.
        //
        // The ordering is important here. For example we first want to disallow consecutive XOFFs,
        // then check if we received an XOFF that was too early, and finally check if we received
        // the XOFF too frequently.

        // Ensure that we have sent some bytes. This might be covered by other checks below, but this
        // is the most important check so we do it explicitly here first.
        if self.bytes_sent_total.0 == 0 {
            const MSG: &str = "Received XOFF before sending any data";
            return Err(Error::CircProto(MSG.into()));
        }

        // disallow consecutive XOFF messages
        if self.last_recvd_xon_xoff == Some(XonXoff::Xoff) {
            const MSG: &str = "Received consecutive XOFF messages";
            return Err(Error::CircProto(MSG.into()));
        }

        // > clients MUST ensure that an XOFF does not arrive before it has sent the appropriate
        // > XOFF limit of bytes on a stream ('cc_xoff_exit' for exits, 'cc_xoff_client' for
        // > onions).
        //
        // NOTE: We use a more relaxed threshold for the XOFF limit than in prop324.
        if u64::from(self.bytes_sent_total.0) < Self::peer_xoff_limit_bytes(params) {
            const MSG: &str = "Received XOFF too early";
            return Err(Error::CircProto(MSG.into()));
        }

        // > Clients also SHOULD ensure than XOFFs do not arrive more frequently than every XOFF
        // > limit worth of sent data.
        //
        // NOTE: We implement this a bit different than C-tor. In C-tor it checks that:
        //   conn->total_bytes_xmit < xoff_{client/exit}*conn->num_xoff_recv
        // which effectively checks that the average XOFF frequency over the lifetime of the stream
        // does not exceed a frequency of `xoff_{client/exit}`. Instead here we check that two XOFF
        // messages never arrive at an interval that would exceed a frequency of
        // `xoff_{client/exit}`.
        //
        // NOTE: We use a more relaxed threshold for the XOFF limit than in prop324.
        if u64::from(self.bytes_sent_since_recvd_last_xoff.0) < Self::peer_xoff_limit_bytes(params)
        {
            return Err(Error::CircProto("Received XOFF too frequently".into()));
        }

        self.bytes_sent_since_recvd_last_xoff = Saturating(0);
        self.last_recvd_xon_xoff = Some(XonXoff::Xoff);

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::stream::flow_ctrl::params::CellCount;

    #[test]
    fn sidechannel_mitigation() {
        let params = [
            FlowCtrlParameters {
                cc_xoff_client: CellCount::new(2),
                cc_xoff_exit: CellCount::new(4),
                cc_xon_rate: CellCount::new(8),
                cc_xon_change_pct: 1,
                cc_xon_ewma_cnt: 1,
            },
            FlowCtrlParameters {
                cc_xoff_client: CellCount::new(8),
                cc_xoff_exit: CellCount::new(4),
                cc_xon_rate: CellCount::new(2),
                cc_xon_change_pct: 1,
                cc_xon_ewma_cnt: 1,
            },
        ];

        for params in params {
            let xon_limit = SidechannelMitigation::peer_xon_limit_bytes(&params);
            let xoff_limit = SidechannelMitigation::peer_xoff_limit_bytes(&params);

            let mut x = SidechannelMitigation::new();
            // cannot receive XON as first message
            assert!(x.received_xon(&params).is_err());

            let mut x = SidechannelMitigation::new();
            // cannot receive XOFF as first message
            assert!(x.received_xoff(&params).is_err());

            let mut x = SidechannelMitigation::new();
            // cannot receive XOFF after sending fewer than `xoff_limit` bytes
            x.sent_stream_data(xoff_limit as usize - 1);
            assert!(x.received_xoff(&params).is_err());

            let mut x = SidechannelMitigation::new();
            // can receive XOFF after sending `xoff_limit` bytes
            x.sent_stream_data(xoff_limit as usize);
            assert!(x.received_xoff(&params).is_ok());
            // but cannot receive another XOFF immediately after
            assert!(x.received_xoff(&params).is_err());

            let mut x = SidechannelMitigation::new();
            // can receive XOFF after sending `xoff_limit` bytes
            x.sent_stream_data(xoff_limit as usize);
            assert!(x.received_xoff(&params).is_ok());
            // but cannot receive another XOFF even after sending another `xoff_limit` bytes
            x.sent_stream_data(xoff_limit as usize);
            assert!(x.received_xoff(&params).is_err());

            let mut x = SidechannelMitigation::new();
            // can receive XOFF after sending `xoff_limit` bytes
            x.sent_stream_data(xoff_limit as usize);
            assert!(x.received_xoff(&params).is_ok());
            // and can immediately receive an XON
            assert!(x.received_xon(&params).is_ok());
            // and can receive another XOFF after sending another `xoff_limit` bytes
            x.sent_stream_data(xoff_limit as usize);
            assert!(x.received_xoff(&params).is_ok());

            let mut x = SidechannelMitigation::new();
            // cannot receive XON after sending fewer than `xon_limit` bytes
            x.sent_stream_data(xon_limit as usize - 1);
            assert!(x.received_xon(&params).is_err());
        }
    }
}
