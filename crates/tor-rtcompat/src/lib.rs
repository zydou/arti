#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
//! Compatibility between different async runtimes for Arti.
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
//!  * A runtime is a [`BlockOn`] if it can block on a future.
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
//!     [`PreferredRuntime::current()`].
//!
//!   * If you want to construct a default runtime that you won't be
//!     using for anything besides Arti, you can use [`PreferredRuntime::create()`].
//!
//! Both of the above methods use the "preferred runtime", which is usually Tokio.
//! However, changing the set of Cargo features available can affect this; see
//! [`PreferredRuntime`] for more.
//!
//!   * If you want to use a runtime with an explicitly chosen backend,
//!     name its type directly as [`async_std::AsyncStdNativeTlsRuntime`],
//!     [`async_std::AsyncStdRustlsRuntime`], [`tokio::TokioNativeTlsRuntime`],
//!     or [`tokio::TokioRustlsRuntime`]. To construct one of these runtimes,
//!     call its `create()` method.  Or if you have already constructed a
//!     Tokio runtime that you want to use, you can wrap it as a
//!     [`Runtime`] explicitly with `current()`.
//!
//! # Advanced usage: implementing runtimes yourself
//!
//! You might want to implement some of the traits above (especially [`TcpProvider`] and
//! [`TlsProvider`]) if you're embedding Arti, and want more control over the resources it uses.
//! For example, you might want to perform actions when TCP connections open and close, replace the
//! TLS stack with your own, or proxy TCP connections over your own custom transport.
//!
//! This can be more easily accomplished using the [`CompoundRuntime`] type, which lets you
//! create a [`Runtime`] from various implementors of the various traits (which don't all need to
//! be the same).
//!
//! See [`arti-client/examples/hook-tcp.rs`](https://gitlab.torproject.org/tpo/core/arti/-/blob/main/crates/arti-client/examples/hook-tcp.rs)
//! for a full example of this.
//!
//! # Cargo features
//!
//! Features supported by this crate:
//!
//! * `tokio` -- build with [Tokio](https://tokio.rs/) support
//! * `async-std` -- build with [async-std](https://async.rs/) support
//! * `native-tls` --  build with the [native-tls](https://github.com/sfackler/rust-native-tls)
//!   crate for TLS support
//! * `static` -- link the native TLS library statically (enables the `vendored` feature of the
//!   `native-tls` crate).
//! * `rustls` -- build with the [rustls](https://github.com/rustls/rustls) crate for TLS support.  Note that `rustls` uses the `ring` crate, which uses
//!    the old (3BSD/SSLEay) OpenSSL license, which may introduce licensing
//!    compatibility issues.
//!
//! By default, *this* crate doesn't enable any features. However, you're almost certainly
//! using this as part of the `arti-client` crate, which will enable `tokio` and `native-tls` in
//! its default configuration.
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
//! [`BlockOn`] trait to represent blocking until a task is
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

// @@ begin lint list maintained by maint/add_warning @@
#![cfg_attr(not(ci_arti_stable), allow(renamed_and_removed_lints))]
#![cfg_attr(not(ci_arti_nightly), allow(unknown_lints))]
#![deny(missing_docs)]
#![warn(noop_method_call)]
#![deny(unreachable_pub)]
#![warn(clippy::all)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::checked_conversions)]
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
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

#[cfg(all(
    any(feature = "native-tls", feature = "rustls"),
    any(feature = "async-std", feature = "tokio")
))]
pub(crate) mod impls;
pub mod task;

mod compound;
mod opaque;
pub mod scheduler;
mod timer;
mod traits;

#[cfg(any(feature = "async-std", feature = "tokio"))]
use std::io;
pub use traits::{
    BlockOn, CertifiedConn, Runtime, SleepProvider, TcpListener, TcpProvider, TlsProvider,
    UdpProvider, UdpSocket,
};

pub use timer::{SleepProviderExt, Timeout, TimeoutError};

/// Traits used to describe TLS connections and objects that can
/// create them.
pub mod tls {
    pub use crate::traits::{CertifiedConn, TlsConnector};

    #[cfg(feature = "native-tls")]
    pub use crate::impls::native_tls::NativeTlsProvider;
    #[cfg(feature = "rustls")]
    pub use crate::impls::rustls::RustlsProvider;
}

#[cfg(all(any(feature = "native-tls", feature = "rustls"), feature = "tokio"))]
pub mod tokio;

#[cfg(all(any(feature = "native-tls", feature = "rustls"), feature = "async-std"))]
pub mod async_std;

pub use compound::CompoundRuntime;

#[cfg(all(
    any(feature = "native-tls", feature = "rustls"),
    feature = "async-std",
    not(feature = "tokio")
))]
use async_std as preferred_backend_mod;
#[cfg(all(any(feature = "native-tls", feature = "rustls"), feature = "tokio"))]
use tokio as preferred_backend_mod;

/// The runtime that we prefer to use, out of all the runtimes compiled into the
/// tor-rtcompat crate.
///
/// If `tokio` and `async-std` are both available, we prefer `tokio` for its
/// performance.
/// If `native_tls` and `rustls` are both available, we prefer `native_tls` since
/// it has been used in Arti for longer.
#[cfg(all(
    any(feature = "native-tls", feature = "rustls"),
    any(feature = "async-std", feature = "tokio")
))]
#[derive(Clone)]
pub struct PreferredRuntime {
    /// The underlying runtime object.
    inner: preferred_backend_mod::PreferredRuntime,
}

#[cfg(all(
    any(feature = "native-tls", feature = "rustls"),
    any(feature = "async-std", feature = "tokio")
))]
crate::opaque::implement_opaque_runtime! {
    PreferredRuntime { inner : preferred_backend_mod::PreferredRuntime }
}

#[cfg(all(
    any(feature = "native-tls", feature = "rustls"),
    any(feature = "async-std", feature = "tokio")
))]
impl PreferredRuntime {
    /// Obtain a [`PreferredRuntime`] from the currently running asynchronous runtime.
    /// Generally, this is what you want.
    ///
    /// This tries to get a handle to a currently running asynchronous runtime, and
    /// wraps it; the returned [`PreferredRuntime`] isn't the same thing as the
    /// asynchronous runtime object itself (e.g. `tokio::runtime::Runtime`).
    ///
    /// # Panics
    ///
    /// When `tor-rtcompat` is compiled with the `tokio` feature enabled
    /// (regardless of whether the `async-std` feature is also enabled),
    /// panics if called outside of Tokio runtime context.
    /// See `tokio::runtime::Handle::current`.
    ///
    /// # Usage notes
    ///
    /// Once you have a runtime returned by this function, you should
    /// just create more handles to it via [`Clone`].
    ///
    /// # Limitations
    ///
    /// If the `tor-rtcompat` crate was compiled with `tokio` support,
    /// this function will never return a runtime based on `async_std`.
    ///
    //
    // ## Note to Arti developers
    //
    // We should never call this from inside other Arti crates, or from
    // library crates that want to support multiple runtimes!  This
    // function is for Arti _users_ who want to wrap some existing Tokio
    // or Async_std runtime as a [`Runtime`].  It is not for library
    // crates that want to work with multiple runtimes.
    pub fn current() -> io::Result<Self> {
        let rt = preferred_backend_mod::PreferredRuntime::current()?;

        Ok(Self { inner: rt })
    }

    /// Create and return a new instance of the default [`Runtime`].
    ///
    /// Generally you should call this function at most once, and then use
    /// [`Clone::clone()`] to create additional references to that runtime.
    ///
    /// Tokio users may want to avoid this function and instead obtain a runtime using
    /// [`PreferredRuntime::current`]: this function always _builds_ a runtime,
    /// and if you already have a runtime, that isn't what you want with Tokio.
    ///
    /// If you need more fine-grained control over a runtime, you can create it
    /// using an appropriate builder type or function.
    //
    // ## Note to Arti developers
    //
    // We should never call this from inside other Arti crates, or from
    // library crates that want to support multiple runtimes!  This
    // function is for Arti _users_ who want to wrap some existing Tokio
    // or Async_std runtime as a [`Runtime`].  It is not for library
    // crates that want to work with multiple runtimes.
    pub fn create() -> io::Result<Self> {
        let rt = preferred_backend_mod::PreferredRuntime::create()?;

        Ok(Self { inner: rt })
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

/// Helpers for test_with_all_runtimes
///
/// # Warning
///
/// This API is **NOT** for consumption outside Arti. Semver guarantees are not provided.
#[doc(hidden)]
pub mod testing__ {
    /// A trait for an object that might represent a test failure, or which
    /// might just be `()`.
    pub trait TestOutcome {
        /// Abort if the test has failed.
        fn check_ok(&self);
    }
    impl TestOutcome for () {
        fn check_ok(&self) {}
    }
    impl<E: std::fmt::Debug> TestOutcome for Result<(), E> {
        fn check_ok(&self) {
            self.as_ref().expect("Test failure");
        }
    }
}

/// Helper: define a macro that expands a token tree iff a pair of features are
/// both present.
macro_rules! declare_conditional_macro {
    ( $(#[$meta:meta])* macro $name:ident = ($f1:expr, $f2:expr) ) => {
        $( #[$meta] )*
        #[cfg(all(feature=$f1, feature=$f2))]
        #[macro_export]
        macro_rules! $name {
            ($tt:tt) => {
                $tt
            };
        }

        $( #[$meta] )*
        #[cfg(not(all(feature=$f1, feature=$f2)))]
        #[macro_export]
        macro_rules! $name {
            ($tt:tt) => {};
        }

        // Needed so that we can access this macro at this path, both within the
        // crate and without.
        pub use $name;
    };
}

/// Defines macros that will expand when certain runtimes are available.
#[doc(hidden)]
pub mod cond {
    declare_conditional_macro! {
        /// Expand a token tree if the TokioNativeTlsRuntime is available.
        #[doc(hidden)]
        macro if_tokio_native_tls_present = ("tokio", "native-tls")
    }
    declare_conditional_macro! {
        /// Expand a token tree if the TokioRustlsRuntime is available.
        #[doc(hidden)]
        macro if_tokio_rustls_present = ("tokio", "rustls")
    }
    declare_conditional_macro! {
        /// Expand a token tree if the TokioNativeTlsRuntime is available.
        #[doc(hidden)]
        macro if_async_std_native_tls_present = ("async-std", "native-tls")
    }
    declare_conditional_macro! {
        /// Expand a token tree if the TokioNativeTlsRuntime is available.
        #[doc(hidden)]
        macro if_async_std_rustls_present = ("async-std", "rustls")
    }
}

/// Run a test closure, passing as argument every supported runtime.
///
/// (This is a macro so that it can repeat the closure as multiple separate
/// expressions, so it can take on two different types, if needed.)
//
// NOTE(eta): changing this #[cfg] can affect tests inside this crate that use
//            this macro, like in scheduler.rs
#[macro_export]
#[cfg(all(
    any(feature = "native-tls", feature = "rustls"),
    any(feature = "tokio", feature = "async-std"),
))]
macro_rules! test_with_all_runtimes {
    ( $fn:expr ) => {{
        use $crate::cond::*;
        use $crate::testing__::TestOutcome;
        // We have to do this outcome-checking business rather than just using
        // the ? operator or calling expect() because some of the closures that
        // we use this macro with return (), and some return Result.

        if_tokio_native_tls_present! {{
           $crate::tokio::TokioNativeTlsRuntime::run_test($fn).check_ok();
        }}
        if_tokio_rustls_present! {{
            $crate::tokio::TokioRustlsRuntime::run_test($fn).check_ok();
        }}
        if_async_std_native_tls_present! {{
            $crate::async_std::AsyncStdNativeTlsRuntime::run_test($fn).check_ok();
        }}
        if_async_std_rustls_present! {{
            $crate::async_std::AsyncStdRustlsRuntime::run_test($fn).check_ok();
        }}
    }};
}

/// Run a test closure, passing as argument one supported runtime.
///
/// (Always prefers tokio if present.)
#[macro_export]
#[cfg(all(
    any(feature = "native-tls", feature = "rustls"),
    any(feature = "tokio", feature = "async-std"),
))]
macro_rules! test_with_one_runtime {
    ( $fn:expr ) => {{
        $crate::PreferredRuntime::run_test($fn)
    }};
}

#[cfg(all(
    test,
    any(feature = "native-tls", feature = "rustls"),
    any(feature = "async-std", feature = "tokio")
))]
mod test {
    #![allow(clippy::unwrap_used, clippy::unnecessary_wraps)]
    use crate::Runtime;
    use crate::SleepProviderExt;

    use crate::traits::*;

    use futures::io::{AsyncReadExt, AsyncWriteExt};
    use futures::stream::StreamExt;
    use native_tls_crate as native_tls;
    use std::io::Result as IoResult;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::time::{Duration, Instant};

    // Test "sleep" with a tiny delay, and make sure that at least that
    // much delay happens.
    fn small_delay<R: Runtime>(runtime: &R) -> IoResult<()> {
        let rt = runtime.clone();
        runtime.block_on(async {
            let i1 = Instant::now();
            let one_msec = Duration::from_millis(1);
            rt.sleep(one_msec).await;
            let i2 = Instant::now();
            assert!(i2 >= i1 + one_msec);
        });
        Ok(())
    }

    // Try a timeout operation that will succeed.
    fn small_timeout_ok<R: Runtime>(runtime: &R) -> IoResult<()> {
        let rt = runtime.clone();
        runtime.block_on(async {
            let one_day = Duration::from_secs(86400);
            let outcome = rt.timeout(one_day, async { 413_u32 }).await;
            assert_eq!(outcome, Ok(413));
        });
        Ok(())
    }

    // Try a timeout operation that will time out.
    fn small_timeout_expire<R: Runtime>(runtime: &R) -> IoResult<()> {
        use futures::future::pending;

        let rt = runtime.clone();
        runtime.block_on(async {
            let one_micros = Duration::from_micros(1);
            let outcome = rt.timeout(one_micros, pending::<()>()).await;
            assert_eq!(outcome, Err(crate::TimeoutError));
            assert_eq!(
                outcome.err().unwrap().to_string(),
                "Timeout expired".to_string()
            );
        });
        Ok(())
    }
    // Try a little wallclock delay.
    //
    // NOTE: This test will fail if the clock jumps a lot while it's
    // running.  We should use simulated time instead.
    fn tiny_wallclock<R: Runtime>(runtime: &R) -> IoResult<()> {
        let rt = runtime.clone();
        runtime.block_on(async {
            let i1 = Instant::now();
            let now = runtime.wallclock();
            let one_millis = Duration::from_millis(1);
            let one_millis_later = now + one_millis;

            rt.sleep_until_wallclock(one_millis_later).await;

            let i2 = Instant::now();
            let newtime = runtime.wallclock();
            assert!(newtime >= one_millis_later);
            assert!(i2 - i1 >= one_millis);
        });
        Ok(())
    }

    // Try connecting to ourself and sending a little data.
    //
    // NOTE: requires Ipv4 localhost.
    fn self_connect_tcp<R: Runtime>(runtime: &R) -> IoResult<()> {
        let localhost = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0);
        let rt1 = runtime.clone();

        let listener = runtime.block_on(rt1.listen(&(localhost.into())))?;
        let addr = listener.local_addr()?;

        runtime.block_on(async {
            let task1 = async {
                let mut buf = vec![0_u8; 11];
                let (mut con, _addr) = listener.accept().await?;
                con.read_exact(&mut buf[..]).await?;
                IoResult::Ok(buf)
            };
            let task2 = async {
                let mut con = rt1.connect(&addr).await?;
                con.write_all(b"Hello world").await?;
                con.flush().await?;
                IoResult::Ok(())
            };

            let (data, send_r) = futures::join!(task1, task2);
            send_r?;

            assert_eq!(&data?[..], b"Hello world");

            Ok(())
        })
    }

    // Try connecting to ourself and sending a little data.
    //
    // NOTE: requires Ipv4 localhost.
    fn self_connect_udp<R: Runtime>(runtime: &R) -> IoResult<()> {
        let localhost = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0);
        let rt1 = runtime.clone();

        let socket1 = runtime.block_on(rt1.bind(&(localhost.into())))?;
        let addr1 = socket1.local_addr()?;

        let socket2 = runtime.block_on(rt1.bind(&(localhost.into())))?;
        let addr2 = socket2.local_addr()?;

        runtime.block_on(async {
            let task1 = async {
                let mut buf = vec![0_u8; 16];
                let (len, addr) = socket1.recv(&mut buf[..]).await?;
                IoResult::Ok((buf[..len].to_vec(), addr))
            };
            let task2 = async {
                socket2.send(b"Hello world", &addr1).await?;
                IoResult::Ok(())
            };

            let (recv_r, send_r) = futures::join!(task1, task2);
            send_r?;
            let (buff, addr) = recv_r?;
            assert_eq!(addr2, addr);
            assert_eq!(&buff, b"Hello world");

            Ok(())
        })
    }

    // Try out our incoming connection stream code.
    //
    // We launch a few connections and make sure that we can read data on
    // them.
    fn listener_stream<R: Runtime>(runtime: &R) -> IoResult<()> {
        let localhost = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0);
        let rt1 = runtime.clone();

        let listener = runtime.block_on(rt1.listen(&(localhost.into()))).unwrap();
        let addr = listener.local_addr().unwrap();
        let mut stream = listener.incoming();

        runtime.block_on(async {
            let task1 = async {
                let mut n = 0_u32;
                loop {
                    let (mut con, _addr) = stream.next().await.unwrap()?;
                    let mut buf = vec![0_u8; 11];
                    con.read_exact(&mut buf[..]).await?;
                    n += 1;
                    if &buf[..] == b"world done!" {
                        break IoResult::Ok(n);
                    }
                }
            };
            let task2 = async {
                for _ in 0_u8..5 {
                    let mut con = rt1.connect(&addr).await?;
                    con.write_all(b"Hello world").await?;
                    con.flush().await?;
                }
                let mut con = rt1.connect(&addr).await?;
                con.write_all(b"world done!").await?;
                con.flush().await?;
                con.close().await?;
                IoResult::Ok(())
            };

            let (n, send_r) = futures::join!(task1, task2);
            send_r?;

            assert_eq!(n?, 6);

            Ok(())
        })
    }

    // Try listening on an address and connecting there, except using TLS.
    //
    // Note that since we don't have async tls server support yet, I'm just
    // going to use a thread.
    fn simple_tls<R: Runtime>(runtime: &R) -> IoResult<()> {
        /*
         A simple expired self-signed rsa-2048 certificate.

         Generated by running the make-cert.c program in tor-rtcompat/test-data-helper,
         and then making a PFX file using

         openssl pkcs12 -export -certpbe PBE-SHA1-3DES -out test.pfx -inkey test.key -in test.crt

         The password is "abc".
        */
        static PFX_ID: &[u8] = include_bytes!("test.pfx");
        // Note that we need to set a password on the pkcs12 file, since apparently
        // OSX doesn't support pkcs12 with empty passwords. (That was arti#111).
        static PFX_PASSWORD: &str = "abc";

        let localhost = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0);
        let listener = std::net::TcpListener::bind(localhost)?;
        let addr = listener.local_addr()?;

        let identity = native_tls::Identity::from_pkcs12(PFX_ID, PFX_PASSWORD).unwrap();

        // See note on function for why we're using a thread here.
        let th = std::thread::spawn(move || {
            // Accept a single TLS connection and run an echo server
            use std::io::{Read, Write};
            let acceptor = native_tls::TlsAcceptor::new(identity).unwrap();
            let (con, _addr) = listener.accept()?;
            let mut con = acceptor.accept(con).unwrap();
            let mut buf = [0_u8; 16];
            loop {
                let n = con.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                con.write_all(&buf[..n])?;
            }
            IoResult::Ok(())
        });

        let connector = runtime.tls_connector();

        runtime.block_on(async {
            let text = b"I Suddenly Dont Understand Anything";
            let mut buf = vec![0_u8; text.len()];
            let conn = runtime.connect(&addr).await?;
            let mut conn = connector.negotiate_unvalidated(conn, "Kan.Aya").await?;
            assert!(conn.peer_certificate()?.is_some());
            conn.write_all(text).await?;
            conn.flush().await?;
            conn.read_exact(&mut buf[..]).await?;
            assert_eq!(&buf[..], text);
            conn.close().await?;
            IoResult::Ok(())
        })?;

        th.join().unwrap()?;
        IoResult::Ok(())
    }

    macro_rules! tests_with_runtime {
        { $runtime:expr  => $($id:ident),* $(,)? } => {
            $(
                #[test]
                fn $id() -> std::io::Result<()> {
                    super::$id($runtime)
                }
            )*
        }
    }

    macro_rules! runtime_tests {
        { $($id:ident),* $(,)? } =>
        {
           #[cfg(feature="tokio")]
            mod tokio_runtime_tests {
                tests_with_runtime! { &crate::tokio::PreferredRuntime::create()? => $($id),* }
            }
            #[cfg(feature="async-std")]
            mod async_std_runtime_tests {
                tests_with_runtime! { &crate::async_std::PreferredRuntime::create()? => $($id),* }
            }
            mod default_runtime_tests {
                tests_with_runtime! { &crate::PreferredRuntime::create()? => $($id),* }
            }
        }
    }

    macro_rules! tls_runtime_tests {
        { $($id:ident),* $(,)? } =>
        {
            #[cfg(all(feature="tokio", feature = "native-tls"))]
            mod tokio_native_tls_tests {
                tests_with_runtime! { &crate::tokio::TokioNativeTlsRuntime::create()? => $($id),* }
            }
            #[cfg(all(feature="async-std", feature = "native-tls"))]
            mod async_std_native_tls_tests {
                tests_with_runtime! { &crate::async_std::AsyncStdNativeTlsRuntime::create()? => $($id),* }
            }
            #[cfg(all(feature="tokio", feature="rustls"))]
            mod tokio_rustls_tests {
                tests_with_runtime! {  &crate::tokio::TokioRustlsRuntime::create()? => $($id),* }
            }
            #[cfg(all(feature="async-std", feature="rustls"))]
            mod async_std_rustls_tests {
                tests_with_runtime! {  &crate::async_std::AsyncStdRustlsRuntime::create()? => $($id),* }
            }
            mod default_runtime_tls_tests {
                tests_with_runtime! { &crate::PreferredRuntime::create()? => $($id),* }
            }
        }
    }

    runtime_tests! {
        small_delay,
        small_timeout_ok,
        small_timeout_expire,
        tiny_wallclock,
        self_connect_tcp,
        self_connect_udp,
        listener_stream,
    }

    tls_runtime_tests! {
        simple_tls,
    }
}
