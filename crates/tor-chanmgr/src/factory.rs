//! Traits and code to define different mechanisms for building Channels to
//! different kinds of targets.

use async_trait::async_trait;
use futures::{AsyncRead, AsyncWrite};
use tor_linkspec::{ChanTarget, OwnedChanTarget, TransportId};
use tor_proto::channel::Channel;
use tor_rtcompat::Runtime;

/// An object that knows how to build Channels to ChanTargets.
///
/// This trait must be object-safe.
#[async_trait]
pub trait ChannelFactory {
    /// Open an authenticated channel to `target`.
    ///
    /// We need this method to take a dyn ChanTarget so it is
    /// object-safe.
    //
    // TODO pt-client: How does this handle multiple addresses? Do we
    // parallelize here, or at a higher level?
    fn connect_via_transport(&self, target: &OwnedChanTarget) -> crate::Result<Channel>;
}

/// A more convenient API for defining transports.  This type's role is to let
/// the implementor just define a replacement way to pass bytes around, and
/// return something that we can use in place of a TcpStream.
///
/// This is the trait you should probably implement if you want to define a new
/// [`ChannelFactory`] that performs Tor over TLS over some stream-like type,
/// and you only want to define the stream-like type.
//
// TODO pt-client: I originally had this parameterized on a Runtime.  But I
// think instead we should have individual TransportHelper implementations be
// parameterized on a Runtime.
pub trait TransportHelper {
    /// The type of the resulting stream.
    type Stream: AsyncRead + AsyncWrite + Send + Sync + 'static;

    /// Implements the transport: makes a TCP connection (possibly
    /// tunneled over whatever protocol) if possible.
    //
    // TODO pt-client: How does this handle multiple addresses? Do we
    // parallelize here, or at a higher level?
    //
    // TODO pt-client: We could make the address an associated type: would that
    // help anything?
    fn connect(&self, target: &impl ChanTarget) -> crate::Result<(OwnedChanTarget, Self::Stream)>;
}

// We define an implementation so that every TransportHelper
// can be wrapped as a ChannelFactory...
impl<H> ChannelFactory for H
where
    H: TransportHelper,
{
    fn connect_via_transport(&self, target: &OwnedChanTarget) -> crate::Result<Channel> {
        let _stream = self.connect(target)?;

        // Now do the logic from
        // `tor_chanmgr::builder::ChanBuilder::build_channel_no_timeout`:
        // Negotiate TLS, call tor_proto::ChannelBuilder::build, ...

        // TODO: Hang on, where do we get a pre-built TlsConnector in
        // this method?  We may need a different signature, or some
        // kind of wrapper type.
        //
        // TODO: We may also need access to other stuff, like the contents
        // of `ChanBuilder`.

        todo!("TODO pt-client: implement this")
    }
}

/// A ChannelFactory implementing Tor's default channel protocol.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct DefaultChannelFactory<R: Runtime> {
    /// The runtime that we use to make connections.
    #[allow(dead_code)] // TODO pt-client: this will be removed.
    runtime: R,
}
impl<R: Runtime> TransportHelper for DefaultChannelFactory<R> {
    type Stream = R::TcpStream;
    fn connect(&self, _target: &impl ChanTarget) -> crate::Result<(OwnedChanTarget, Self::Stream)> {
        // Call connect_one() as in `build_channel_no_timeout`.

        // TODO pt-client: This is another place where we need to figure out
        // multiple addresses and "happy eyeballs".

        // Call restrict_addr() as in `build_channel_no_timeout`.

        todo!("TODO pt-client: implement this")
    }
}

/// An object that knows about one or more ChannelFactories.
#[async_trait]
pub trait TransportRegistry {
    /// Return a ChannelFactory that can make connections via a chosen
    /// transport, if we know one.
    //
    // TODO pt-client: This might need to return an Arc instead of a reference
    async fn get_factory(&self, transport: &TransportId) -> Option<&dyn ChannelFactory>;
}

// TODO pt-client: implement a DefaultTransportRegistry that returns a
// DefaultChannelFactory for TransportId::Builtin, and nothing otherwise.
