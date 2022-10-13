//! Implement a registry for different kinds of transports.

use async_trait::async_trait;
use tor_linkspec::{HasChanMethod, OwnedChanTarget, TransportId};
use tor_proto::channel::Channel;

use crate::Error;

use super::ChannelFactory;

/// An object that knows about one or more ChannelFactories.
pub trait TransportRegistry {
    /// Return a ChannelFactory that can make connections via a chosen
    /// transport, if we know one.
    //
    // TODO pt-client: This might need to return an Arc instead of a reference
    fn get_factory(&self, transport: &TransportId) -> Option<&(dyn ChannelFactory + Sync)>;
}

/// Helper type: Wrap a `TransportRegistry` so that it can be used as a
/// `ChannelFactory`.
///
/// (This has to be a new type, or else the blanket implementation of
/// `ChannelFactory` for `TransportHelper` would conflict.)
#[derive(Clone, Debug)]
pub(crate) struct RegistryAsFactory<R: TransportRegistry>(R);

#[async_trait]
impl<R: TransportRegistry + Sync> ChannelFactory for RegistryAsFactory<R> {
    async fn connect_via_transport(&self, target: &OwnedChanTarget) -> crate::Result<Channel> {
        let method = target.chan_method();
        let id = method.transport_id();
        let factory = self.0.get_factory(&id).ok_or(Error::NoSuchTransport(id))?;

        factory.connect_via_transport(target).await
    }
}
