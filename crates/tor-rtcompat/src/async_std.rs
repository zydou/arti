//! Entry points for use with async_std runtimes.
pub use crate::impls::async_std::create_runtime as create_async_std_runtime;
use crate::SpawnBlocking;

/// A [`Runtime`](crate::Runtime) powered by async-std.
pub use async_executors::AsyncStd as AsyncStdRuntime;

/// Return a new async-std-based [`Runtime`](crate::Runtime).
///
/// Generally you should call this function only once, and then use
/// [`Clone::clone()`] to create additional references to that
/// runtime.

pub fn create_runtime() -> std::io::Result<AsyncStdRuntime> {
    Ok(create_async_std_runtime())
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
    let runtime = create_async_std_runtime();
    runtime.block_on(func(runtime))
}
