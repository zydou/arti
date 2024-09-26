//! Entry points for use with async_std runtimes.
pub use crate::impls::async_std::create_runtime as create_runtime_impl;
use crate::{compound::CompoundRuntime, BlockOn, RealCoarseTimeProvider};
use std::io::Result as IoResult;

#[cfg(feature = "native-tls")]
use crate::impls::native_tls::NativeTlsProvider;
#[cfg(feature = "rustls")]
use crate::impls::rustls::RustlsProvider;

use async_executors::AsyncStd;

/// An alias for the async_std runtime that we prefer to use, based on whatever TLS
/// implementation has been enabled.
///
/// If only one of `native_tls` and `rustls` bas been enabled within the
/// `tor-rtcompat` crate, that will be the TLS backend that this uses.
///
/// Currently, `native_tls` is preferred over `rustls` when both are available,
/// because of its maturity within Arti.  However, this might change in the
/// future.
#[cfg(feature = "native-tls")]
pub use AsyncStdNativeTlsRuntime as PreferredRuntime;

#[cfg(all(feature = "rustls", not(feature = "native-tls")))]
pub use AsyncStdRustlsRuntime as PreferredRuntime;

/// A [`Runtime`](crate::Runtime) powered by `async_std` and `native_tls`.
#[derive(Clone)]
#[cfg(feature = "native-tls")]
pub struct AsyncStdNativeTlsRuntime {
    /// The actual runtime object.
    inner: NativeTlsInner,
}

/// Implementation type for AsyncStdRuntime.
#[cfg(feature = "native-tls")]
type NativeTlsInner = CompoundRuntime<
    AsyncStd,
    AsyncStd,
    RealCoarseTimeProvider,
    AsyncStd,
    AsyncStd,
    NativeTlsProvider,
    AsyncStd,
>;

#[cfg(feature = "native-tls")]
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
type RustlsInner = CompoundRuntime<
    AsyncStd,
    AsyncStd,
    RealCoarseTimeProvider,
    AsyncStd,
    AsyncStd,
    RustlsProvider,
    AsyncStd,
>;

#[cfg(feature = "rustls")]
crate::opaque::implement_opaque_runtime! {
    AsyncStdRustlsRuntime { inner: RustlsInner }
}

#[cfg(feature = "native-tls")]
impl AsyncStdNativeTlsRuntime {
    /// Return a new [`AsyncStdNativeTlsRuntime`]
    ///
    /// Generally you should call this function only once, and then use
    /// [`Clone::clone()`] to create additional references to that
    /// runtime.
    pub fn create() -> IoResult<Self> {
        let rt = create_runtime_impl();
        let ct = RealCoarseTimeProvider::new();
        Ok(AsyncStdNativeTlsRuntime {
            inner: CompoundRuntime::new(rt, rt, ct, rt, rt, NativeTlsProvider::default(), rt),
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

    /// Helper to run a single test function in a freshly created runtime.
    ///
    /// # Panics
    ///
    /// Panics if we can't create this runtime.
    ///
    /// # Warning
    ///
    /// This API is **NOT** for consumption outside Arti. Semver guarantees are not provided.
    #[doc(hidden)]
    pub fn run_test<P, F, O>(func: P) -> O
    where
        P: FnOnce(Self) -> F,
        F: futures::Future<Output = O>,
    {
        let runtime = Self::create().expect("Failed to create runtime");
        runtime.clone().block_on(func(runtime))
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
        let ct = RealCoarseTimeProvider::new();
        Ok(AsyncStdRustlsRuntime {
            inner: CompoundRuntime::new(rt, rt, ct, rt, rt, RustlsProvider::default(), rt),
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

    /// Helper to run a single test function in a freshly created runtime.
    ///
    /// # Panics
    ///
    /// Panics if we can't create this runtime.
    ///
    /// # Warning
    ///
    /// This API is **NOT** for consumption outside Arti. Semver guarantees are not provided.
    #[doc(hidden)]
    pub fn run_test<P, F, O>(func: P) -> O
    where
        P: FnOnce(Self) -> F,
        F: futures::Future<Output = O>,
    {
        let runtime = Self::create().expect("Failed to create runtime");
        runtime.clone().block_on(func(runtime))
    }
}

#[cfg(not(miri))] // async_ztd startup seems to fail under miri
#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;

    #[test]
    fn current() {
        // We should actually have to run this inside a runtime with async_std,
        // but let's do it anyway to make sure that "current" works.
        let runtime = PreferredRuntime::create().unwrap();
        runtime.block_on(async {
            #[cfg(feature = "native-tls")]
            assert!(AsyncStdNativeTlsRuntime::current().is_ok());

            #[cfg(feature = "rustls")]
            assert!(AsyncStdRustlsRuntime::current().is_ok());
        });
    }

    #[test]
    fn debug() {
        #[cfg(feature = "native-tls")]
        assert_eq!(
            format!("{:?}", AsyncStdNativeTlsRuntime::create().unwrap()),
            "AsyncStdNativeTlsRuntime { .. }"
        );
        #[cfg(feature = "rustls")]
        assert_eq!(
            format!("{:?}", AsyncStdRustlsRuntime::create().unwrap()),
            "AsyncStdRustlsRuntime { .. }"
        );
    }
}
