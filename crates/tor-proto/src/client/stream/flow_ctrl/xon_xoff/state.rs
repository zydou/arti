//! Circuit reactor's stream XON/XOFF flow control.
//!
//! ## Notes on consensus parameters
//!
//! ### `cc_xoff_client`
//!
//! This is the number of bytes that we buffer within a [`DataStream`]. The actual total number of
//! bytes buffered can be *much* larger. For example there will be additional buffering:
//!
//! - Within the arti socks proxy: Arti's socks code needs to read some bytes from the stream, store
//!   it in a temporary buffer, then write the buffer to the socket. If the socket would block, the
//!   data would remain in that temporary buffer. In practice arti uses only a 1024 byte buffer at
//!   the time of writing, which is negligible. See `arti::socks::copy_interactive()`.
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

use postage::watch;
use tor_cell::relaycell::flow_ctrl::{FlowCtrlVersion, Xoff, Xon, XonKbpsEwma};
use tor_cell::relaycell::msg::AnyRelayMsg;
use tor_cell::relaycell::{RelayMsg, UnparsedRelayMsg};

use super::reader::DrainRateRequest;

use crate::client::stream::flow_ctrl::params::FlowCtrlParameters;
use crate::client::stream::flow_ctrl::state::{FlowCtrlMethods, StreamRateLimit};
use crate::util::notify::NotifySender;
use crate::{Error, Result};

#[cfg(doc)]
use crate::client::stream::{data::DataStream, flow_ctrl::state::StreamFlowCtrl};

/// State for XON/XOFF flow control.
#[derive(Debug)]
pub(crate) struct XonXoffFlowCtrl {
    /// Consensus parameters.
    // TODO: This is a lot of wasted space since each stream needs to store this,
    // and it's very likely that all will be using the same values.
    // TODO: Use these values.
    params: FlowCtrlParameters,
    /// How we communicate rate limit updates to the
    /// [`DataWriter`](crate::client::stream::data::DataWriter).
    rate_limit_updater: watch::Sender<StreamRateLimit>,
    /// How we communicate requests for new drain rate updates to the
    /// [`XonXoffReader`](crate::client::stream::flow_ctrl::xon_xoff::reader::XonXoffReader).
    drain_rate_requester: NotifySender<DrainRateRequest>,
    /// The last rate limit we sent.
    last_sent_xon_xoff: Option<XonXoffMsg>,
}

impl XonXoffFlowCtrl {
    /// Returns a new xon/xoff-based state.
    pub(crate) fn new(
        params: &FlowCtrlParameters,
        rate_limit_updater: watch::Sender<StreamRateLimit>,
        drain_rate_requester: NotifySender<DrainRateRequest>,
    ) -> Self {
        Self {
            params: params.clone(),
            rate_limit_updater,
            drain_rate_requester,
            last_sent_xon_xoff: None,
        }
    }
}

impl FlowCtrlMethods for XonXoffFlowCtrl {
    fn can_send<M: RelayMsg>(&self, _msg: &M) -> bool {
        // we perform rate-limiting in the `DataWriter`,
        // so we send any messages that made it past the `DataWriter`
        true
    }

    fn take_capacity_to_send(&mut self, _msg: &AnyRelayMsg) -> Result<()> {
        // xon/xoff flow control doesn't have "capacity";
        // the capacity is effectively controlled by the congestion control
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

        // update the rate limit and notify the `DataWriter`
        let old_rate_limit = std::mem::replace(
            &mut *self.rate_limit_updater.borrow_mut(),
            StreamRateLimit::ZERO,
        );

        // if the old rate limit is zero,
        // then the last XON or XOFF message we received was an XOFF
        if old_rate_limit == StreamRateLimit::ZERO {
            // we don't expect to receive consecutive XOFFs, so we want to close the circuit
            // as a sidechannel mitigation
            return Err(Error::CircProto("Consecutive XOFF messages".into()));
        }

        Ok(())
    }

    fn maybe_send_xon(&mut self, rate: XonKbpsEwma, buffer_len: usize) -> Result<Option<Xon>> {
        if buffer_len as u64 > self.params.cc_xoff_client.as_bytes() {
            // we can't send an XON, and we should have already sent an XOFF when the queue first
            // exceeded the limit (see `maybe_send_xoff()`)
            debug_assert!(matches!(self.last_sent_xon_xoff, Some(XonXoffMsg::Xoff)));

            // inform the stream reader that we need a new drain rate
            self.drain_rate_requester.notify();
            return Ok(None);
        }

        self.last_sent_xon_xoff = Some(XonXoffMsg::Xon(rate));

        Ok(Some(Xon::new(FlowCtrlVersion::V0, rate)))
    }

    fn maybe_send_xoff(&mut self, buffer_len: usize) -> Result<Option<Xoff>> {
        // if the last XON/XOFF we sent was an XOFF, no need to send another
        if matches!(self.last_sent_xon_xoff, Some(XonXoffMsg::Xoff)) {
            return Ok(None);
        }

        if buffer_len as u64 <= self.params.cc_xoff_client.as_bytes() {
            return Ok(None);
        }

        // either we have never sent an XOFF or XON, or we last sent an XON

        // remember that we last sent an XOFF
        self.last_sent_xon_xoff = Some(XonXoffMsg::Xoff);

        // inform the stream reader that we need a new drain rate
        self.drain_rate_requester.notify();

        Ok(Some(Xoff::new(FlowCtrlVersion::V0)))
    }
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
