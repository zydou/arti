//! Module exposing the [`ChannelProvider`] trait.
//!
//! Relay circuit reactors use a [`ChannelProvider`] to open outgoing channels.

use crate::Result;
use crate::channel::Channel;
use crate::circuit::UniqId;

use futures::channel::mpsc;

use std::sync::Arc;

use tor_linkspec::HasRelayIds;

/// A channel result returned by a [`ChannelProvider`].
pub type ChannelResult = Result<Arc<Channel>>;

/// A sender for returning an outgoing relay channel
/// requested via [`ChannelProvider::get_or_launch_relay`].
//
// Note: this channel is unbounded, because the limit should be imposed
// by the [`ChannelProvider`].
#[allow(unreachable_pub)] // TODO(#1447)
#[allow(unused)]
pub struct OutboundChanSender(mpsc::UnboundedSender<ChannelResult>);

impl OutboundChanSender {
    /// Create a new [`OutboundChanSender`] from an [`mpsc`] sender.
    ///
    /// This should remain crate-private, as these senders
    /// should only ever be created by the relay circuit reactor
    /// to request a new outbound channel.
    #[allow(dead_code)] // TODO(relay)
    pub(crate) fn new(tx: mpsc::UnboundedSender<ChannelResult>) -> Self {
        Self(tx)
    }

    /// Send the specified channel result to the requester.
    ///
    /// See [`ChannelProvider::get_or_launch_relay`].
    #[allow(dead_code)] // TODO(relay)
    pub fn send(self, result: ChannelResult) {
        // Don't care if the receiver goes away
        let _ = self.0.unbounded_send(result);
    }
}

/// An object that can fulfill outbound channel requests
/// issued by the relay circuit reactor.
///
/// The implementor is responsible for imposing a limit on the
/// number of outbound channels that can be opened on a given circuit.
#[allow(unreachable_pub)] // TODO(#1447): impl this for ChanMgr
#[allow(unused)]
pub trait ChannelProvider {
    /// Type that explains how to build an outgoing channel.
    type BuildSpec: HasRelayIds;

    /// Get a channel corresponding to the identities of `target`,
    /// for the circuit with the specified `circ_id`.
    ///
    /// Returns the requested channel via the specified [`OutboundChanSender`].
    fn get_or_launch_relay(
        &self,
        circ_id: UniqId,
        target: &Self::BuildSpec,
        tx: OutboundChanSender,
    ) -> Result<()>;
}
