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

pub(crate) mod streamops;

/// Helper: Implement an unreachable NetProvider<unix::SocketAddr> for a given runtime.
#[cfg(not(unix))]
macro_rules! impl_unix_non_provider {
    { $for_type:ty } => {

        #[async_trait]
        impl crate::traits::NetStreamProvider<tor_general_addr::unix::SocketAddr> for $for_type {
            type Stream = crate::unimpl::FakeStream;
            type Listener = crate::unimpl::FakeListener<tor_general_addr::unix::SocketAddr>;
            async fn connect(&self, _a: &tor_general_addr::unix::SocketAddr) -> IoResult<Self::Stream> {
                Err(tor_general_addr::unix::NoUnixAddressSupport::default().into())

            }
            async fn listen(&self, _a: &tor_general_addr::unix::SocketAddr) -> IoResult<Self::Listener> {
                Err(tor_general_addr::unix::NoUnixAddressSupport::default().into())
            }
        }
    }
}
#[cfg(not(unix))]
pub(crate) use impl_unix_non_provider;
