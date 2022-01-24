//! Entry points for use with async_std runtimes.
pub use crate::impls::async_std::create_runtime as create_runtime_impl;
use crate::{compound::CompoundRuntime, SpawnBlocking};

use crate::impls::native_tls::NativeTlsProvider;

#[cfg(feature = "rustls")]
use crate::impls::rustls::RustlsProvider;
use async_std_crate::net::TcpStream;

use async_executors::AsyncStd;

/// A [`Runtime`](crate::Runtime) powered by `async_std` and `native_tls`.
#[derive(Clone)]
pub struct AsyncStdRuntime {
    /// The actual runtime object.
    inner: NativeTlsInner,
}

/// Implementation type for AsyncStdRuntime.
type NativeTlsInner = CompoundRuntime<AsyncStd, AsyncStd, AsyncStd, NativeTlsProvider<TcpStream>>;

crate::opaque::implement_opaque_runtime! {
    AsyncStdRuntime { inner : NativeTlsInner }
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

/// Return a new async-std-based [`Runtime`](crate::Runtime).
///
/// Generally you should call this function only once, and then use
/// [`Clone::clone()`] to create additional references to that
/// runtime.
pub fn create_runtime() -> std::io::Result<AsyncStdRuntime> {
    let rt = create_runtime_impl();
    Ok(AsyncStdRuntime {
        inner: CompoundRuntime::new(rt, rt, rt, NativeTlsProvider::default()),
    })
}

/// Return a new [`Runtime`](crate::Runtime) based on `async_std` and `rustls`.
#[cfg(feature = "rustls")]
pub fn create_rustls_runtime() -> std::io::Result<AsyncStdRustlsRuntime> {
    let rt = create_runtime_impl();
    Ok(AsyncStdRustlsRuntime {
        inner: CompoundRuntime::new(rt, rt, rt, RustlsProvider::default()),
    })
}

/// Try to return an instance of the currently running async_std
/// [`Runtime`](crate::Runtime).
pub fn current_runtime() -> std::io::Result<AsyncStdRuntime> {
    // In async_std, the runtime is a global singleton.
    create_runtime()
}

/// Run a test function using a freshly created async_std runtime.
pub fn test_with_runtime<P, F, O>(func: P) -> O
where
    P: FnOnce(AsyncStdRuntime) -> F,
    F: futures::Future<Output = O>,
{
    let runtime = current_runtime().expect("Couldn't get global async_std runtime?");
    runtime.clone().block_on(func(runtime))
}
