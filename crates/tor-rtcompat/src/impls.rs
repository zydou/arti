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

/// Helper: Implement an unreachable NetProvider<unix::SocketAddr> for a given runtime.
#[cfg(not(unix))]
macro_rules! impl_unix_non_provider {
    { $for_type:ty } => {

        #[async_trait]
        impl crate::traits::NetStreamProvider<crate::unix::SocketAddr> for $for_type {
            type Stream = crate::unimpl::FakeStream;
            type Listener = crate::unimpl::FakeListener<crate::unix::SocketAddr>;
            async fn connect(&self, _a: &crate::unix::SocketAddr) -> IoResult<Self::Stream> {
                Err(crate::unix::NoUnixAddressSupport.into())

            }
            async fn listen(&self, _a: &crate::unix::SocketAddr) -> IoResult<Self::Listener> {
                Err(crate::unix::NoUnixAddressSupport.into())
            }
        }
    }
}
#[cfg(not(unix))]
pub(crate) use impl_unix_non_provider;
