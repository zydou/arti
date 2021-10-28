//! High-level functionality for accessing the Tor network as a client.
//!
//! # Overview
//!
//! The `arti-client` crate aims to provide a safe, easy-to-use API for
//! applications that want to use Tor network to anonymize their
//! traffic.  It hides most of the underlying detail, letting other
//! crates decide how exactly to use the Tor crate.
//!
//! This crate is part of
//! [Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
//! implement [Tor](https://www.torproject.org/) in Rust.
//! It is the highest-level library crate in
//! Arti, and the one that nearly all client-only programs should use.
//! Most of its functionality is provided by lower-level crates in Arti.
//!
//! ## ⚠ Warnings ⚠
//!
//! Note that Arti is a work in progress; although we've tried to
//! write all the critical security components, you probably shouldn't
//! use Arti in production until it's a bit more mature.
//!
//! Also note that all of the APIs for this crate, and for Arti in
//! general, are not the least bit stable.  If you use this code,
//! please expect your software to break on a regular basis.
//!
//! # Using `arti-client`
//!
//! The main entry point for this crate is the [`TorClient`], an object that lets you make
//! connections over the Tor network.
//!
//! Calling [`TorClient::bootstrap`] establishes a connection to the Tor network, pulling in
//! necessary state about network consensus as required. This state gets persisted to the
//! locations specified in the [`TorClientConfig`].
//!
//! A client can then be used to make connections over Tor with [`TorClient::connect`], which
//! accepts anything implementing [`IntoTorAddr`]. This returns a [`DataStream`], an anonymised
//! TCP stream type that implements [`AsyncRead`](futures::io::AsyncRead) and
//! [`AsyncWrite`](futures::io::AsyncWrite), as well as the Tokio versions of those traits if
//! the `tokio` crate feature is enabled.
//!
//! The [`TorAddr`] type is intended to ensure that DNS lookups are done via the Tor network
//! instead of locally. Doing local DNS resolution can leak information about which hostnames you're
//! connecting to to your local DNS resolver (i.e. your ISP), so it's much better to let Arti
//! do it for you to maintain privacy.
//!
//! If you really want to connect to a raw IP address and know what you're doing, take a look at
//! [`TorAddr::dangerously_from`] -- but be careful!
//!
//! ## Example: making connections over Tor
//!
//! ```no_run
//! # use anyhow::Result;
//! # use arti_client::{TorClient, TorClientConfig};
//! # use tokio_crate as tokio;
//! # #[tokio::main]
//! # async fn main() -> Result<()> {
//! // The client config includes things like where to store persistent Tor network state.
//! let config = TorClientConfig::sane_defaults()?;
//! // Arti needs a handle to an async runtime in order to spawn async tasks.
//! // (See "Multiple runtime support" below.)
//! let rt = tor_rtcompat::tokio::current_runtime()?;
//!
//! // Start the Arti client, and let it bootstrap a connection to the Tor network.
//! // (This takes a while to gather the necessary consensus state, etc.)
//! let tor_client = TorClient::bootstrap(rt, config).await?;
//!
//! // Initiate a connection over Tor to example.com, port 80.
//! let mut stream = tor_client.connect(("example.com", 80), None).await?;
//!
//! use futures::io::{AsyncReadExt, AsyncWriteExt};
//!
//! // Write out an HTTP request.
//! stream
//!     .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
//!     .await?;
//!
//! // IMPORTANT: Make sure the request was written.
//! // Arti buffers data by default due to the design of the Tor protocol, so flushing the
//! // buffer is usually required.
//! stream.flush().await?;
//!
//! // Read and print the result.
//! let mut buf = Vec::new();
//! stream.read_to_end(&mut buf).await?;
//!
//! println!("{}", String::from_utf8_lossy(&buf));
//! #
//! #    Ok(())
//! # }
//! ```
//!
//! ## More advanced usage
//!
//! This version of Arti includes basic support for "stream isolation": the ability to ensure that
//! different TCP connections ('streams') go over different Tor circuits (and thus different exit
//! nodes, making them originate from different IP addresses).
//!
//! This is useful to avoid deanonymising
//! users by correlation: for example, you might want a Tor connection to your bank and a Tor
//! connection to an online forum to use different circuits, to avoid the possibility of the two
//! identities being linked by having the same source IP.
//!
//! Streams can be isolated in two ways:
//!
//! - by calling [`TorClient::isolated_client`], which returns a new [`TorClient`] whose streams
//!   will use a different circuit
//! - by generating [`IsolationToken`]s, and passing them in via [`ConnectPrefs`] to
//!   [`TorClient::connect`].
//!
//! # Multiple runtime support
//!
//! Arti uses the [`tor_rtcompat`] crate to support multiple asynchronous runtimes; currently,
//! both [Tokio](https://tokio.rs) and [async-std](https://async.rs) are supported.
//!
//! Functions in this crate, like [`TorClient::bootstrap`],
//! will expect a type that implements [`tor_rtcompat::Runtime`], which can be obtained:
//!
//! - for Tokio:
//!   - by calling [`tor_rtcompat::tokio::current_runtime`], if a Tokio reactor is already running
//!   - by calling [`tor_rtcompat::tokio::create_runtime`], to start a new reactor if one is not
//!     already running
//!   - by manually creating a [`TokioRuntimeHandle`](tor_rtcompat::tokio::TokioRuntimeHandle) from
//!     an existing Tokio runtime handle
//! - for async-std:
//!   - by calling [`tor_rtcompat::async_std::current_runtime`], which will create a runtime or
//!     retrieve the existing one, if one has already been started
//!
//!
//! # Feature flags
//!
//! `tokio` -- (Default) Build with support for the Tokio backend.
//!
//! `async-std` -- Build with support for the `async_std` backend.
//!
//! `experimental-api` -- Build with experimental, unstable API support.
//! Note that these APIs are NOT covered by semantic versioning guarantees:
//! we might break them or remove them between patch versions.

#![deny(missing_docs)]
#![warn(noop_method_call)]
#![deny(unreachable_pub)]
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
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]

mod address;
mod client;

pub mod config;

pub use address::{DangerouslyIntoTorAddr, IntoTorAddr, TorAddr, TorAddrError};
pub use client::{ConnectPrefs, TorClient};
pub use config::TorClientConfig;

pub use tor_circmgr::IsolationToken;
/// An anonymized stream over the Tor network.
///
/// For most purposes, you can think of this type as an anonymized
/// TCP stream: it can read and write data, and get closed when it's done.
///
/// To get one of these, clients should use [`TorClient::connect()`].
/// [`DataStream`] implements [`futures::io::AsyncRead`] and
/// [`futures::io::AsyncWrite`], so you can use it anywhere that those
/// types are expected.
///
/// This type is a re-export from [`tor_proto::stream::DataStream`];
/// see that crate for its documentation in a more low-level context.
pub use tor_proto::stream::DataStream;

mod err;
pub use err::Error;

/// Result type used by this crate
type Result<T> = std::result::Result<T, Error>;
