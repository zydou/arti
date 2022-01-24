//! Entry points for use with Tokio runtimes.
use crate::impls::tokio::{NativeTlsTokio, TokioRuntimeHandle as Handle};
use async_executors::TokioTp;

use crate::{CompoundRuntime, Runtime, SpawnBlocking};
use std::io::{Error as IoError, ErrorKind, Result as IoResult};

/// A [`Runtime`] built around a Handle to a tokio runtime, and `native_tls`.
///
/// # Limitations
///
/// Note that Arti requires that the runtime should have working
/// implementations for Tokio's time, net, and io facilities, but we have
/// no good way to check that when creating this object.
#[derive(Clone)]
pub struct TokioRuntimeHandle {
    /// The actual [`CompoundRuntime`] that implements this.
    inner: HandleInner,
}

/// Implementation type for a TokioRuntimeHandle.
type HandleInner = CompoundRuntime<Handle, Handle, Handle, NativeTlsTokio>;

/// A [`Runtime`] built around an owned `TokioTp` executor, and `native_tls`.
#[derive(Clone)]
pub struct TokioRuntime {
    /// The actual [`CompoundRuntime`] that implements this.
    inner: TokioRuntimeInner,
}

/// Implementation type for TokioRuntime.
type TokioRuntimeInner = CompoundRuntime<TokioTp, TokioTp, TokioTp, NativeTlsTokio>;

crate::opaque::implement_opaque_runtime! {
    TokioRuntimeHandle { inner : HandleInner }
}

crate::opaque::implement_opaque_runtime! {
    TokioRuntime { inner : TokioRuntimeInner }
}

impl From<tokio_crate::runtime::Handle> for TokioRuntimeHandle {
    fn from(h: tokio_crate::runtime::Handle) -> Self {
        let h = Handle::new(h);
        TokioRuntimeHandle {
            inner: CompoundRuntime::new(h.clone(), h.clone(), h, NativeTlsTokio::default()),
        }
    }
}

/// Create and return a new Tokio multithreaded runtime.
fn create_tokio_runtime() -> IoResult<TokioRuntime> {
    crate::impls::tokio::create_runtime().map(|r| TokioRuntime {
        inner: CompoundRuntime::new(r.clone(), r.clone(), r, NativeTlsTokio::default()),
    })
}

/// Create a new Tokio-based [`Runtime`].
///
/// Generally you should call this function only once, and then use
/// [`Clone::clone()`] to create additional references to that
/// runtime.
///
/// Tokio users may want to avoid this function and instead make a
/// runtime using [`current_runtime()`]: this function always _builds_ a
/// runtime, and if you already have a runtime, that isn't what you
/// want with Tokio.
pub fn create_runtime() -> std::io::Result<impl Runtime> {
    create_tokio_runtime()
}

/// Try to return an instance of the currently running tokio [`Runtime`].
///
/// # Usage note
///
/// We should never call this from inside other Arti crates, or from
/// library crates that want to support multiple runtimes!  This
/// function is for Arti _users_ who want to wrap some existing Tokio
/// runtime as a [`Runtime`].  It is not for library
/// crates that want to work with multiple runtimes.
///
/// Once you have a runtime returned by this function, you should
/// just create more handles to it via [`Clone`].
pub fn current_runtime() -> std::io::Result<TokioRuntimeHandle> {
    let handle = tokio_crate::runtime::Handle::try_current()
        .map_err(|e| IoError::new(ErrorKind::Other, e))?;
    let h = Handle::new(handle);
    Ok(TokioRuntimeHandle {
        inner: CompoundRuntime::new(h.clone(), h.clone(), h, NativeTlsTokio::default()),
    })
}

/// Run a test function using a freshly created tokio runtime.
///
/// # Panics
///
/// Panics if we can't create a tokio runtime.
pub fn test_with_runtime<P, F, O>(func: P) -> O
where
    P: FnOnce(TokioRuntime) -> F,
    F: futures::Future<Output = O>,
{
    let runtime = create_tokio_runtime().expect("Failed to create a tokio runtime");
    runtime.clone().block_on(func(runtime))
}
