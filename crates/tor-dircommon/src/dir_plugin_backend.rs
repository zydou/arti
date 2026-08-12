//! TEMPORARY, EXPERIMENTAL traits for using tor-dirmgr as a dirserver backend.
//!
//! This module will be removed in the future.  It only exists for now so that
//! we can test Arti relays as guards before tor-dirserver is finished.
//
// NOTE: Some aspects of this module are marked with "LIMITATION".
// Don't just run in and fix these: remember, this is throw-away code.

pub use http;

/// An object that knows how to handle one or more kinds of directory requests.
pub trait DirBackendPlugin: Send + Sync + 'static {
    /// Handle a GET request.
    ///
    /// Returns an http Response if the request is recognized,
    /// _whether it succeeds or fails_.
    ///
    /// Returns an error if the request type is not recognized,
    /// or if an internal error occurs.
    fn get(
        &self,
        request: &http::Request<()>,
    ) -> Result<http::Response<Box<[u8]>>, DirBackendPluginError>;
}

/// An error that occurred while trying to handle a request.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum DirBackendPluginError {
    /// The request was one which this plugin doesn't know how to handle.
    #[error("URI not handled by plugin.")]
    UriNotHandledByPlugin,

    /// An internal error occurred while trying to handle the request.
    #[error("Internal error")]
    Bug(tor_error::Bug),
}
