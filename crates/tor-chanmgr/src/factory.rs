//! Traits and code to define different mechanisms for building Channels to
//! different kinds of targets.

pub(crate) mod registry;

use std::sync::Arc;

use async_trait::async_trait;
use tor_linkspec::OwnedChanTarget;
use tor_proto::channel::Channel;

pub use registry::TransportRegistry;
use tracing::debug;

/// An object that knows how to build `Channels` to `ChanTarget`s.
///
/// This trait must be object-safe.
///
/// Every [`ChanMgr`](crate::ChanMgr) has a `ChannelFactory` that it uses to
/// construct all of its channels.
///
/// A `ChannelFactory` can be implemented in terms of a
/// [`TransportHelper`](crate::transport::TransportHelper), by wrapping it in a
/// `ChanBuilder`.
#[async_trait]
pub trait ChannelFactory {
    /// Open an authenticated channel to `target`.
    ///
    /// This method does does not necessarily handle retries or timeouts,
    /// although some of its implementations may.
    ///
    /// This method does not necessarily handle every kind of transport. If the
    /// caller provides a target with an unsupported
    /// [`TransportId`](tor_linkspec::TransportId), this method should return
    /// [`Error::NoSuchTransport`](crate::Error::NoSuchTransport).
    async fn connect_via_transport(&self, target: &OwnedChanTarget) -> crate::Result<Channel>;
}

#[async_trait]
impl<'a> ChannelFactory for Arc<(dyn ChannelFactory + Send + Sync + 'a)> {
    async fn connect_via_transport(&self, target: &OwnedChanTarget) -> crate::Result<Channel> {
        self.as_ref().connect_via_transport(target).await
    }
}

#[async_trait]
impl<'a> ChannelFactory for Box<(dyn ChannelFactory + Send + Sync + 'a)> {
    async fn connect_via_transport(&self, target: &OwnedChanTarget) -> crate::Result<Channel> {
        self.as_ref().connect_via_transport(target).await
    }
}

#[async_trait]
impl<CF> crate::mgr::AbstractChannelFactory for CF
where
    CF: ChannelFactory + Sync,
{
    type Channel = tor_proto::channel::Channel;
    type BuildSpec = OwnedChanTarget;

    async fn build_channel(&self, target: &Self::BuildSpec) -> crate::Result<Self::Channel> {
        debug!("Attempting to open a new channel to {target}");
        self.connect_via_transport(target).await
    }
}
