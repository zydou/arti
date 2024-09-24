//! Entry points for use with Tokio runtimes.
use crate::impls::tokio::TokioRuntimeHandle as Handle;

use crate::{BlockOn, CompoundRuntime, RealCoarseTimeProvider};
use std::io::{Error as IoError, ErrorKind, Result as IoResult};

#[cfg(feature = "native-tls")]
use crate::impls::native_tls::NativeTlsProvider;
#[cfg(feature = "rustls")]
use crate::impls::rustls::RustlsProvider;

/// An alias for the Tokio runtime that we prefer to use, based on whatever TLS
/// implementation has been enabled.
///
/// If only one of `native_tls` and `rustls` bas been enabled within the
/// `tor-rtcompat` crate, that will be the TLS backend that this uses.
///
/// Currently, `native_tls` is preferred over `rustls` when both are available,
/// because of its maturity within Arti.  However, this might change in the
/// future.
#[cfg(feature = "native-tls")]
pub use TokioNativeTlsRuntime as PreferredRuntime;
#[cfg(all(feature = "rustls", not(feature = "native-tls")))]
pub use TokioRustlsRuntime as PreferredRuntime;

/// A [`Runtime`](crate::Runtime) built around a Handle to a tokio runtime, and `native_tls`.
///
/// # Limitations
///
/// Note that Arti requires that the runtime should have working
/// implementations for Tokio's time, net, and io facilities, but we have
/// no good way to check that when creating this object.
#[derive(Clone)]
#[cfg(feature = "native-tls")]
pub struct TokioNativeTlsRuntime {
    /// The actual [`CompoundRuntime`] that implements this.
    inner: HandleInner,
}

/// Implementation type for a TokioRuntimeHandle.
#[cfg(feature = "native-tls")]
type HandleInner = CompoundRuntime<
    Handle,
    Handle,
    RealCoarseTimeProvider,
    Handle,
    Handle,
    NativeTlsProvider,
    Handle,
>;

/// A [`Runtime`](crate::Runtime) built around a Handle to a tokio runtime, and `rustls`.
#[derive(Clone)]
#[cfg(feature = "rustls")]
pub struct TokioRustlsRuntime {
    /// The actual [`CompoundRuntime`] that implements this.
    inner: RustlsHandleInner,
}

/// Implementation for a TokioRuntimeRustlsHandle
#[cfg(feature = "rustls")]
type RustlsHandleInner =
    CompoundRuntime<Handle, Handle, RealCoarseTimeProvider, Handle, Handle, RustlsProvider, Handle>;

#[cfg(feature = "native-tls")]
crate::opaque::implement_opaque_runtime! {
    TokioNativeTlsRuntime { inner : HandleInner }
}

#[cfg(feature = "rustls")]
crate::opaque::implement_opaque_runtime! {
    TokioRustlsRuntime { inner : RustlsHandleInner }
}

#[cfg(feature = "native-tls")]
impl From<tokio_crate::runtime::Handle> for TokioNativeTlsRuntime {
    fn from(h: tokio_crate::runtime::Handle) -> Self {
        let h = Handle::new(h);
        TokioNativeTlsRuntime {
            inner: CompoundRuntime::new(
                h.clone(),
                h.clone(),
                RealCoarseTimeProvider::new(),
                h.clone(),
                h.clone(),
                NativeTlsProvider::default(),
                h,
            ),
        }
    }
}

#[cfg(feature = "rustls")]
impl From<tokio_crate::runtime::Handle> for TokioRustlsRuntime {
    fn from(h: tokio_crate::runtime::Handle) -> Self {
        let h = Handle::new(h);
        TokioRustlsRuntime {
            inner: CompoundRuntime::new(
                h.clone(),
                h.clone(),
                RealCoarseTimeProvider::new(),
                h.clone(),
                h.clone(),
                RustlsProvider::default(),
                h,
            ),
        }
    }
}

#[cfg(feature = "native-tls")]
impl TokioNativeTlsRuntime {
    /// Create a new [`TokioNativeTlsRuntime`].
    ///
    /// The return value will own the underlying Tokio runtime object, which
    /// will be dropped when the last copy of this handle is freed.
    ///
    /// If you want to use a currently running runtime instead, call
    /// [`TokioNativeTlsRuntime::current()`].
    pub fn create() -> IoResult<Self> {
        crate::impls::tokio::create_runtime().map(|r| TokioNativeTlsRuntime {
            inner: CompoundRuntime::new(
                r.clone(),
                r.clone(),
                RealCoarseTimeProvider::new(),
                r.clone(),
                r.clone(),
                NativeTlsProvider::default(),
                r,
            ),
        })
    }

    /// Return a [`TokioNativeTlsRuntime`] wrapping the currently running
    /// Tokio runtime.
    ///
    /// # Usage note
    ///
    /// We should never call this from inside other Arti crates, or from library
    /// crates that want to support multiple runtimes!  This function is for
    /// Arti _users_ who want to wrap some existing Tokio runtime as a
    /// [`Runtime`](crate::Runtime).  It is not for library crates that want to work with
    /// multiple runtimes.
    ///
    /// Once you have a runtime returned by this function, you should just
    /// create more handles to it via [`Clone`].
    pub fn current() -> IoResult<Self> {
        Ok(current_handle()?.into())
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
impl TokioRustlsRuntime {
    /// Create a new [`TokioRustlsRuntime`].
    ///
    /// The return value will own the underlying Tokio runtime object, which
    /// will be dropped when the last copy of this handle is freed.
    ///
    /// If you want to use a currently running runtime instead, call
    /// [`TokioRustlsRuntime::current()`].
    pub fn create() -> IoResult<Self> {
        crate::impls::tokio::create_runtime().map(|r| TokioRustlsRuntime {
            inner: CompoundRuntime::new(
                r.clone(),
                r.clone(),
                RealCoarseTimeProvider::new(),
                r.clone(),
                r.clone(),
                RustlsProvider::default(),
                r,
            ),
        })
    }

    /// Return a [`TokioRustlsRuntime`] wrapping the currently running
    /// Tokio runtime.
    ///
    /// # Usage note
    ///
    /// We should never call this from inside other Arti crates, or from library
    /// crates that want to support multiple runtimes!  This function is for
    /// Arti _users_ who want to wrap some existing Tokio runtime as a
    /// [`Runtime`](crate::Runtime).  It is not for library crates that want to work with
    /// multiple runtimes.
    ///
    /// Once you have a runtime returned by this function, you should just
    /// create more handles to it via [`Clone`].
    pub fn current() -> IoResult<Self> {
        Ok(current_handle()?.into())
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

/// As `Handle::try_current()`, but return an IoError on failure.
#[cfg(any(feature = "native-tls", feature = "rustls"))]
fn current_handle() -> std::io::Result<tokio_crate::runtime::Handle> {
    tokio_crate::runtime::Handle::try_current().map_err(|e| IoError::new(ErrorKind::Other, e))
}

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
    fn no_current() {
        // There should be no running tokio runtime in this context.

        #[cfg(feature = "native-tls")]
        assert!(TokioNativeTlsRuntime::current().is_err());

        #[cfg(feature = "rustls")]
        assert!(TokioRustlsRuntime::current().is_err());
    }

    #[test]
    fn current() {
        // Now start a tokio runtime and make sure that the "current" functions do work in that case.
        let runtime = PreferredRuntime::create().unwrap();
        runtime.block_on(async {
            #[cfg(feature = "native-tls")]
            assert!(TokioNativeTlsRuntime::current().is_ok());

            #[cfg(feature = "rustls")]
            assert!(TokioRustlsRuntime::current().is_ok());
        });
    }

    #[test]
    fn debug() {
        #[cfg(feature = "native-tls")]
        assert_eq!(
            format!("{:?}", TokioNativeTlsRuntime::create().unwrap()),
            "TokioNativeTlsRuntime { .. }"
        );
        #[cfg(feature = "rustls")]
        assert_eq!(
            format!("{:?}", TokioRustlsRuntime::create().unwrap()),
            "TokioRustlsRuntime { .. }"
        );

        // Just for fun, let's try the Debug output for the Compound.
        assert_eq!(
            format!("{:?}", PreferredRuntime::create().unwrap().inner),
            "CompoundRuntime { .. }"
        );
    }
}
