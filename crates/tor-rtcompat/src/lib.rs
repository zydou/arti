//! Compatibility between different async runtimes for Arti
//!
//! # Overview
//!
//! Rust's support for asynchronous programming is powerful, but still
//! a bit immature: there are multiple powerful runtimes you can use,
//! but they do not expose a consistent set of interfaces.
//!
//! The [`futures`] API abstracts much of the differences among these
//! runtime libraries, but there are still areas where no standard API
//! yet exists, including:
//!  - Network programming.
//!  - Time and delays.
//!  - Launching new tasks
//!  - Blocking until a task is finished.
//!
//! Additionally, the `AsyncRead` and `AsyncWrite` traits provide by
//! [`futures`] are not the same as those provided by `tokio`, and
//! require compatibility wrappers to use.
//!
//! To solve these problems, the `tor-rtcompat` crate provides a set
//! of traits that represent a runtime's ability to perform these
//! tasks, along with implementations for these traits for the `tokio`
//! and `async-std` runtimes.  In the future we hope to add support
//! for other runtimes as needed.
//!
//! This crate is part of
//! [Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
//! implement [Tor](https://www.torproject.org/) in Rust.
//! As such, it does not currently include (or
//! plan to include) any functionality beyond what Arti needs to
//! implement Tor.
//!
//! We hope that in the future this crate can be replaced (or mostly
//! replaced) with standardized and general-purpose versions of the
//! traits it provides.
//!
//! # Using `tor-rtcompat`
//!
//! The `tor-rtcompat` crate provides several traits that
//! encapsulate different runtime capabilities.
//!
//!  * A runtime is a [`SpawnBlocking`] if it can block on a future.
//!  * A runtime is a [`SleepProvider`] if it can make timer futures that
//!    become Ready after a given interval of time.
//!  * A runtime is a [`TcpProvider`] if it can make and receive TCP
//!    connections
//!  * A runtime is a [`TlsProvider`] if it can make TLS connections.
//!
//! For convenience, the [`Runtime`] trait derives from all the traits
//! above, plus [`futures::task::Spawn`] and [`Send`].
//!
//! You can get a [`Runtime`] in several ways:
//!
//!   * If you already have an asynchronous backend (for example, one
//!     that you built with tokio by running with
//!     `#[tokio::main]`), you can wrap it as a [`Runtime`] with
//!     [`current_user_runtime()`].
//!
//!   * If you want to construct a default runtime that you won't be
//!     using for anything besides Arti, you can use [`create_runtime()`].
//!
//!   * If you want to explicitly construct a runtime with a specific
//!     backend, you can do so with [`async_std::create_async_std_runtime`] or
//!     [`tokio::create_tokio_runtime`].  Or if you have already constructed a
//!     tokio runtime that you want to use, you can wrap it as a
//!     [`Runtime`] explicitly with [`tokio::TokioRuntimeHandle`].
//!
//! # Cargo features
//!
//! `tokio` -- (Default) Build with Tokio support.
//!
//! `async-std` -- Build with async_std support.
//!
//! `static` -- Try to link with a static copy of our native TLS library,
//! if possible.
//!
//! # Design FAQ
//!
//! ## Why support `async_std`?
//!
//! Although Tokio currently a more popular and widely supported
//! asynchronous runtime than `async_std` is, we believe that it's
//! critical to build Arti against multiple runtimes.
//!
//! By supporting multiple runtimes, we avoid making tokio-specific
//! assumptions in our code, which we hope will make it easier to port
//! to other environments (like WASM) in the future.
//!
//! ## Why a `Runtime` trait, and not a set of functions?
//!
//! We could simplify this code significantly by removing most of the
//! traits it exposes, and instead just exposing a single
//! implementation.  For example, instead of exposing a
//! [`SpawnBlocking`] trait to represent blocking until a task is
//! done, we could just provide a single global `block_on` function.
//!
//! That simplification would come at a cost, however.  First of all,
//! it would make it harder for us to use Rust's "feature" system
//! correctly.  Current features are supposed to be _additive only_,
//! but if had a single global runtime, then support for different
//! backends would be _mutually exclusive_.  (That is, you couldn't
//! have both the tokio and async-std features building at the same
//! time.)
//!
//! Secondly, much of our testing in the rest of Arti relies on the
//! ability to replace [`Runtime`]s.  By treating a runtime as an
//! object, we can override a runtime's view of time, or of the
//! network, in order to test asynchronous code effectively.
//! (See the [`tor-rtmock`] crate for examples.)

#![deny(missing_docs)]
#![warn(noop_method_call)]
#![deny(unreachable_pub)]
#![deny(clippy::all)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::checked_conversions)]
#![warn(clippy::clone_on_ref_ptr)]
#![warn(clippy::cognitive_complexity)]
#![deny(clippy::debug_assert_with_mut_call)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::expl_impl_clone_on_copy)]
#![deny(clippy::fallible_impl_from)]
#![deny(clippy::implicit_clone)]
#![deny(clippy::large_stack_arrays)]
#![warn(clippy::manual_ok_or)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(clippy::missing_panics_doc)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]

pub(crate) mod impls;
pub mod task;

mod timer;
mod traits;

#[cfg(all(test, any(feature = "tokio", feature = "async-std")))]
mod test;

pub use traits::{
    CertifiedConn, Runtime, SleepProvider, SpawnBlocking, TcpListener, TcpProvider, TlsProvider,
};

pub use timer::{SleepProviderExt, Timeout, TimeoutError};

/// Traits used to describe TLS connections and objects that can
/// create them.
pub mod tls {
    pub use crate::traits::{CertifiedConn, TlsConnector};
}

#[cfg(feature = "tokio")]
pub mod tokio;

#[cfg(feature = "async-std")]
pub mod async_std;

/// Try to return an instance of the currently running [`Runtime`].
///
/// # Limitations
///
/// If the `tor-rtcompat` crate was compiled with `tokio` support,
/// this function will never return an `async_std` runtime.
///
/// # Usage note
///
/// We should never call this from inside other Arti crates, or from
/// library crates that want to support multiple runtimes!  This
/// function is for Arti _users_ who want to wrap some existing Tokio
/// or Async_std runtime as a [`Runtime`].  It is not for library
/// crates that want to work with multiple runtimes.
///
/// Once you have a runtime returned by this function, you should
/// just create more handles to it via [`Clone`].
#[cfg(any(feature = "async-std", feature = "tokio"))]
pub fn current_user_runtime() -> std::io::Result<impl Runtime> {
    #[cfg(feature = "tokio")]
    {
        crate::tokio::current_runtime()
    }
    #[cfg(all(feature = "async-std", not(feature = "tokio")))]
    {
        crate::async_std::current_runtime()
    }
}

/// Return a new instance of the default [`Runtime`].
///
/// Generally you should call this function at most once, and then use
/// [`Clone::clone()`] to create additional references to that
/// runtime.
///
/// Tokio users may want to avoid this function and instead make a
/// runtime using [`current_user_runtime()`] or
/// [`tokio::TokioRuntimeHandle::new()`]: this function always _builds_ a
/// runtime, and if you already have a runtime, that isn't what you
/// want with Tokio.
///
/// If you need more fine-grained control over a runtime, you can
/// create it using an appropriate builder type or function.
#[cfg(any(feature = "async-std", feature = "tokio"))]
pub fn create_runtime() -> std::io::Result<impl Runtime> {
    #[cfg(feature = "tokio")]
    {
        crate::tokio::create_runtime()
    }
    #[cfg(all(feature = "async-std", not(feature = "tokio")))]
    {
        crate::async_std::create_runtime()
    }
}

/// Helpers for test_with_all_runtimes
pub mod testing__ {
    /// A trait for an object that might represent a test failure.
    pub trait TestOutcome {
        /// Abort if the test has failed.
        fn check_ok(&self);
    }
    impl TestOutcome for () {
        fn check_ok(&self) {}
    }
    impl<T, E> TestOutcome for Result<T, E> {
        fn check_ok(&self) {
            assert!(self.is_ok());
        }
    }
}

/// Run a test closure, passing as argument every supported runtime.
///
/// (This is a macro so that it can repeat the closure as two separate
/// expressions, so it can take on two different types, if needed.)
#[macro_export]
#[cfg(all(feature = "tokio", feature = "async-std"))]
macro_rules! test_with_all_runtimes {
    ( $fn:expr ) => {{
        use $crate::testing__::TestOutcome;
        $crate::tokio::test_with_runtime($fn).check_ok();
        $crate::async_std::test_with_runtime($fn)
    }};
}

/// Run a test closure, passing as argument every supported runtime.
#[macro_export]
#[cfg(all(feature = "tokio", not(feature = "async-std")))]
macro_rules! test_with_all_runtimes {
    ( $fn:expr ) => {{
        $crate::tokio::test_with_runtime($fn)
    }};
}

/// Run a test closure, passing as argument every supported runtime.
#[macro_export]
#[cfg(all(not(feature = "tokio"), feature = "async-std"))]
macro_rules! test_with_all_runtimes {
    ( $fn:expr ) => {{
        $crate::async_std::test_with_runtime($fn)
    }};
}

/// Run a test closure, passing as argument one supported runtime.
///
/// (Always prefers tokio if present.)
#[macro_export]
#[cfg(feature = "tokio")]
macro_rules! test_with_one_runtime {
    ( $fn:expr ) => {{
        $crate::tokio::test_with_runtime($fn)
    }};
}

/// Run a test closure, passing as argument one supported runtime.
///
/// (Always prefers tokio if present.)
#[macro_export]
#[cfg(all(not(feature = "tokio"), feature = "async-std"))]
macro_rules! test_with_one_runtime {
    ( $fn:expr ) => {{
        $crate::async_std::test_with_runtime($fn)
    }};
}
