//! Declare the `OnionServiceConnector` trait.

use async_trait::async_trait;
use thiserror::Error;
use tor_proto::circuit::ClientCirc;

/// A trait representing the ability to make a connection to an onion service.
///
/// This is defined in `tor-circmgr`, since `tor-circmgr` uses an instance of
/// this object to connect to onion services.
#[async_trait]
pub trait OnionServiceConnector {
    /// Try to launch a connection to a given onion service.
    async fn create_connection(
        &self,
        service_id: tor_hscrypto::pk::HsId,
        using_keys: Option<tor_hscrypto::pk::ClientSecretKeys>,
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
