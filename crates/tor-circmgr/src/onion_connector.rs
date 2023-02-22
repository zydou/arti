//! Declare the `OnionServiceConnector` trait.

use async_trait::async_trait;
use thiserror::Error;
use tor_proto::circuit::ClientCirc;

/// A trait representing the ability to make a connection to an onion service.
///
/// This is defined in `tor-circmgr`, since `tor-circmgr` uses an instance of
/// this object to connect to onion services.
//
// TODO HS API: The only reason this needs to exist is so that the circmgr can divert
// requests for an exit circuit to a .onion domain name, to the HS code.
// This seems to be an acceptable layering violation, to serve the purpose.
// But maybe that diversion function should be done higher up (in arti-client maybe).
// See the comment on `get_or_launch_exit`.
//
// TODO HS: If we retain this, this module and its types should be renamed "hs".
#[async_trait]
pub trait OnionServiceConnector {
    /// Try to launch a connection to a given onion service.
    async fn create_connection(
        &self,
        service_id: tor_hscrypto::pk::HsId,
        // TODO hs: If we want to support cache isolation, we may need to pass
        // an additional argument here.
    ) -> Result<ClientCirc, OnionConnectError>;
}

/// An error returned when constructing an onion service.
#[derive(Debug, Clone, Error)]
#[non_exhaustive]
pub enum OnionConnectError {
    // TODO hs add variants.
}
