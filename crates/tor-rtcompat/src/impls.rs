//! Different implementations of a common async API for use in arti
//!
//! Currently only async_std and tokio are provided.

#[cfg(all(feature = "async-std"))]
pub(crate) mod async_std;

#[cfg(all(feature = "tokio"))]
pub(crate) mod tokio;

#[cfg(all(feature = "rustls"))]
pub(crate) mod rustls;

pub(crate) mod native_tls;
