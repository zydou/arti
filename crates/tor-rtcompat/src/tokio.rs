//! Entry points for use with Tokio runtimes.
pub use crate::impls::tokio::create_runtime as create_tokio_runtime;
pub use crate::impls::tokio::TokioRuntimeHandle;

use crate::Runtime;
use std::io::{Error as IoError, ErrorKind};

/// Create a new Tokio-based [`Runtime`].
///
/// Generally you should call this function only once, and then use
/// [`Clone::clone()`] to create additional references to that
/// runtime.
///
/// Tokio users may want to avoid this function and instead make a
/// runtime using [`current_runtime()`] or
/// [`TokioRuntimeHandle::new()`]: this function always _builds_ a
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
    Ok(TokioRuntimeHandle::new(handle))
}

/// Run a test function using a freshly created tokio runtime.
///
/// # Panics
///
/// Panics if we can't create a tokio runtime.
pub fn test_with_runtime<P, F, O>(func: P) -> O
where
    P: FnOnce(async_executors::TokioTp) -> F,
    F: futures::Future<Output = O>,
{
    let runtime = create_tokio_runtime().expect("Failed to create a tokio runtime");
    runtime.block_on(func(runtime.clone()))
}
