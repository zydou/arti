//! High-level functionality for accessing the Tor network as a client.
//!
//! (Note that this crate is called `tor-client` in some other places,
//! since we didn't know about the conflict with `tor_client`. We will
//! clean all of this up somehow before the next release.)
//!
//! # Overview
//!
//! The `arti-tor-client` crate aims to provide a safe, easy-to-use API for
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
//! ## ⚠️️ Warnings ⚠️
//! ️
//! **Do not expect ANY privacy from this code yet.**
//!
//! Arti is a work in progress, and there are currently certain
//! missing features that _will_ make it far less private than the
//! standard Tor implementation.  In fact, the absence of these makes
//! Arti clients vulnerable to certain classes of well known attacks
//! that the standard Tor implementation defends against.
//!
//! At present, do not expect Arti to give you _any privacy at all_.  (We'll
//! remove or soften this warning once we're more confident in our privacy.)
//!
//! **Do not use this code in production yet.**
//!
//! All of the APIs for this crate, and for Arti in general, are not
//! the least bit stable.  If you use this code, please expect your
//! software to break on a regular basis.
//!
//! ## Design considerations, privacy considerations.
//!
//! As we build the APIs for this crate, we've been aiming for
//! simplicity and safety: we want it to be as easy as possible to use
//! `tor-client`, while trying to make certain kinds of privacy or security
//! violation hard to write accidentally.
//!
//! Privacy isn't just a drop-in feature, however.  There are still
//! plenty of ways to accidentally leak information, even if you're
//! anonymizing your connections over Tor.  We'll try to document
//! those in a user's guide at some point as Arti becomes more mature.
//!
//! # Using `tor-client`
//!
//! The `tor-client` crate provides an async Rust API.  It is
//! compatible with the `tokio` and `async_std` asynchronous backends.
//!
//! TODO: Good examples here once the crate setup API is more simple.
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

mod config;

mod client;

pub use client::{ConnectPrefs, TorClient};

pub use config::{ClientConfig, ClientConfigBuilder};

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
