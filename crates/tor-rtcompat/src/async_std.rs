//! Entry points for use with async_std runtimes.
pub use crate::impls::async_std::create_runtime as create_runtime_impl;
use crate::{compound::CompoundRuntime, SpawnBlocking};
use std::io::Result as IoResult;

use crate::impls::native_tls::NativeTlsProvider;

#[cfg(feature = "rustls")]
use crate::impls::rustls::RustlsProvider;
use async_std_crate::net::TcpStream;

use async_executors::AsyncStd;

/// A [`Runtime`](crate::Runtime) powered by `async_std` and `native_tls`.
#[derive(Clone)]
pub struct AsyncStdNativeTlsRuntime {
    /// The actual runtime object.
    inner: NativeTlsInner,
}

/// Implementation type for AsyncStdRuntime.
type NativeTlsInner = CompoundRuntime<AsyncStd, AsyncStd, AsyncStd, NativeTlsProvider<TcpStream>>;

crate::opaque::implement_opaque_runtime! {
    AsyncStdNativeTlsRuntime { inner : NativeTlsInner }
}

#[cfg(feature = "rustls")]
/// A [`Runtime`](crate::Runtime) powered by `async_std` and `rustls`.
#[derive(Clone)]
pub struct AsyncStdRustlsRuntime {
    /// The actual runtime object.
    inner: RustlsInner,
}

/// Implementation type for AsyncStdRustlsRuntime.
#[cfg(feature = "rustls")]
type RustlsInner = CompoundRuntime<AsyncStd, AsyncStd, AsyncStd, RustlsProvider<TcpStream>>;

#[cfg(feature = "rustls")]
crate::opaque::implement_opaque_runtime! {
    AsyncStdRustlsRuntime { inner: RustlsInner }
}

impl AsyncStdNativeTlsRuntime {
    /// Return a new [`AsyncStdNativeTlsRuntime`]
    ///
    /// Generally you should call this function only once, and then use
    /// [`Clone::clone()`] to create additional references to that
    /// runtime.
    pub fn create() -> IoResult<Self> {
        let rt = create_runtime_impl();
        Ok(AsyncStdNativeTlsRuntime {
            inner: CompoundRuntime::new(rt, rt, rt, NativeTlsProvider::default()),
        })
    }

    /// Return an [`AsyncStdNativeTlsRuntime`] for the currently running
    /// `async_std` executor.
    ///
    /// Note that since async_std executors are global, there is no distinction
    /// between this method and [`AsyncStdNativeTlsRuntime::create()`]: it is
    /// provided only for API consistency with the Tokio runtimes.
    pub fn current() -> IoResult<Self> {
        Self::create()
    }
}

#[cfg(feature = "rustls")]
impl AsyncStdRustlsRuntime {
    /// Return a new [`AsyncStdRustlsRuntime`]
    ///
    /// Generally you should call this function only once, and then use
    /// [`Clone::clone()`] to create additional references to that
    /// runtime.
    pub fn create() -> IoResult<Self> {
        let rt = create_runtime_impl();
        Ok(AsyncStdRustlsRuntime {
            inner: CompoundRuntime::new(rt, rt, rt, RustlsProvider::default()),
        })
    }

    /// Return an [`AsyncStdRustlsRuntime`] for the currently running
    /// `async_std` executor.
    ///
    /// Note that since async_std executors are global, there is no distinction
    /// between this method and [`AsyncStdNativeTlsRuntime::create()`]: it is
    /// provided only for API consistency with the Tokio runtimes.
    pub fn current() -> IoResult<Self> {
        Self::create()
    }
}

/// Run a test function using a freshly created async_std runtime.
pub fn test_with_runtime<P, F, O>(func: P) -> O
where
    P: FnOnce(AsyncStdNativeTlsRuntime) -> F,
    F: futures::Future<Output = O>,
{
    let runtime =
        AsyncStdNativeTlsRuntime::create().expect("Couldn't get global async_std runtime?");
    runtime.clone().block_on(func(runtime))
}
