//! Traits and code to define different mechanisms for building Channels to
//! different kinds of targets.

use std::sync::Arc;

use async_trait::async_trait;
use tor_error::{HasKind, HasRetryTime};
use tor_linkspec::{HasChanMethod, OwnedChanTarget, PtTransportName};
use tor_proto::channel::Channel;
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
pub trait ChannelFactory: Send + Sync {
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

/// The error type returned by a pluggable transport manager.
pub trait AbstractPtError: std::error::Error + HasKind + HasRetryTime + Send + Sync {}

/// A pluggable transport manager.
///
/// We can't directly reference the `PtMgr` type from `tor-ptmgr`, because of dependency resolution
/// constraints, so this defines the interface for what one should look like.
#[async_trait]
pub trait AbstractPtMgr: Send + Sync {
    /// Get a `ChannelFactory` for the provided `PtTransportName`.
    async fn factory_for_transport(
        &self,
        transport: &PtTransportName,
    ) -> Result<Option<Arc<dyn ChannelFactory + Send + Sync>>, Arc<dyn AbstractPtError>>;
}

/// Alias for an Arc ChannelFactory with all of the traits that we require.
pub(crate) type ArcFactory = Arc<dyn ChannelFactory + 'static>;

/// Alias for an Arc PtMgr with all of the traits that we require.
pub(crate) type ArcPtMgr = Arc<dyn AbstractPtMgr + 'static>;

#[async_trait]
impl<P> AbstractPtMgr for Option<P>
where
    P: AbstractPtMgr,
{
    async fn factory_for_transport(
        &self,
        transport: &PtTransportName,
    ) -> Result<Option<Arc<dyn ChannelFactory + Send + Sync>>, Arc<dyn AbstractPtError>> {
        match self {
            Some(mgr) => mgr.factory_for_transport(transport).await,
            None => Ok(None),
        }
    }
}

/// A ChannelFactory built from an optional PtMgr to use for pluggable transports, and a
/// ChannelFactory to use for everything else.
#[derive(Clone)]
pub(crate) struct Factory {
    #[cfg(feature = "pt-client")]
    /// The PtMgr to use for pluggable transports
    ptmgr: Option<ArcPtMgr>,
    /// The factory to use for everything else
    default_factory: ArcFactory,
}

#[async_trait]
impl ChannelFactory for Factory {
    async fn connect_via_transport(&self, target: &OwnedChanTarget) -> crate::Result<Channel> {
        use tor_linkspec::ChannelMethod::*;
        let factory = match target.chan_method() {
            Direct(_) => self.default_factory.clone(),
            #[cfg(feature = "pt-client")]
            Pluggable(a) => match self.ptmgr.as_ref() {
                Some(mgr) => mgr
                    .factory_for_transport(a.transport())
                    .await
                    .expect("TODO pt-client")
                    .ok_or_else(|| crate::Error::NoSuchTransport(a.transport().clone().into()))?,
                None => return Err(crate::Error::NoSuchTransport(a.transport().clone().into())),
            },
        };

        factory.connect_via_transport(target).await
    }
}

impl Factory {
    /// Create a new `Factory` that will try to use `ptmgr` to handle pluggable
    /// transports requests, and `default_factory` to handle everything else.
    pub(crate) fn new(
        default_factory: ArcFactory,
        #[cfg(feature = "pt-client")] ptmgr: Option<ArcPtMgr>,
    ) -> Self {
        Self {
            default_factory,
            #[cfg(feature = "pt-client")]
            ptmgr,
        }
    }

    /// Replace the default factory in this object.
    pub(crate) fn replace_default_factory(&mut self, factory: ArcFactory) {
        self.default_factory = factory;
    }

    #[cfg(feature = "pt-client")]
    /// Replace the PtMgr in this object.
    pub(crate) fn replace_ptmgr(&mut self, ptmgr: ArcPtMgr) {
        self.ptmgr = Some(ptmgr);
    }
}
