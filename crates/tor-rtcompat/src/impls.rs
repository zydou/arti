//! Different implementations of a common async API for use in arti
//!
//! Currently only async_std and tokio are provided.

#[cfg(feature = "async-std")]
pub(crate) mod async_std;

#[cfg(feature = "tokio")]
pub(crate) mod tokio;

#[cfg(feature = "rustls")]
pub(crate) mod rustls;

#[cfg(feature = "native-tls")]
pub(crate) mod native_tls;
