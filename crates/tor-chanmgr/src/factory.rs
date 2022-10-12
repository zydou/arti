//! Traits and code to define different mechanisms for building Channels to
//! different kinds of targets.

use std::sync::Arc;

use crate::Error;

use async_trait::async_trait;
use futures::{AsyncRead, AsyncWrite};
use tor_linkspec::{HasChanMethod, OwnedChanTarget, TransportId};
use tor_proto::channel::Channel;

/// An object that knows how to build Channels to ChanTargets.
///
/// This trait must be object-safe.
#[async_trait]
pub trait ChannelFactory {
    /// Open an authenticated channel to `target`.
    ///
    /// This method does does not necessarily handle retries or timeouts,
    /// although some of its implementations may.
    ///
    /// This method does not necessarily handle every kind of transport.
    /// If the caller provides a target with the wrong [`TransportId`], this
    /// method should return [`Error::NoSuchTransport`].
    async fn connect_via_transport(&self, target: &OwnedChanTarget) -> crate::Result<Channel>;
}

/// A more convenient API for defining transports.  This type's role is to let
/// the implementor just define a replacement way to pass bytes around, and
/// return something that we can use in place of a TcpStream.
///
/// This is the trait you should probably implement if you want to define a new
/// [`ChannelFactory`] that performs Tor over TLS over some stream-like type,
/// and you only want to define the stream-like type.
///
/// To convert a [`TransportHelper`] into a [`ChannelFactory`], wrap it in a ChannelBuilder.
#[async_trait]
pub trait TransportHelper {
    /// The type of the resulting stream.
    type Stream: AsyncRead + AsyncWrite + Send + Sync + 'static;

    /// Implements the transport: makes a TCP connection (possibly
    /// tunneled over whatever protocol) if possible.
    ///
    /// This method does does not necessarily handle retries or timeouts,
    /// although some of its implementations may.
    ///
    /// This method does not necessarily handle every kind of transport.
    /// If the caller provides a target with the wrong [`TransportId`], this
    /// method should return [`Error::NoSuchTransport`].
    async fn connect(
        &self,
        target: &OwnedChanTarget,
    ) -> crate::Result<(OwnedChanTarget, Self::Stream)>;
}

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
