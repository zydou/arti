//! Thin veneer over `futures::channel::oneshot` to fix use with [`select!`](futures::select)
//!
//! A bare [`futures::channel::oneshot::Receiver`] doesn't work properly with
//! `futures::select!`, because it has a broken
//! [`FusedFuture`](futures::future::FusedFuture)
//! implementation.
//! (See [`futures-rs` ticket #2455](https://github.com/rust-lang/futures-rs/issues/2455).)
//!
//! Wrapping it up in a [`future::Fuse`](futures::future::Fuse) works around this,
//! with a minor performance penalty.
//!
//! ### Limitations
//!
//! The API of this [`Receiver`] is rather more limited.
//! For example, it lacks `.try_recv()`.
//
// The veneer is rather thin and the types from `futures-rs` show through.
// If we change this in the future, it will be a breaking change.
#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![doc = include_str!("../README.md")]
// @@ begin lint list maintained by maint/add_warning @@
#![allow(renamed_and_removed_lints)] // @@REMOVE_WHEN(ci_arti_stable)
#![allow(unknown_lints)] // @@REMOVE_WHEN(ci_arti_nightly)
#![warn(missing_docs)]
#![warn(noop_method_call)]
#![warn(unreachable_pub)]
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
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![deny(clippy::print_stderr)]
#![deny(clippy::print_stdout)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unchecked_duration_subtraction)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
#![allow(clippy::result_large_err)] // temporary workaround for arti#587
#![allow(clippy::needless_raw_string_hashes)] // complained-about code is fine, often best
#![allow(clippy::needless_lifetimes)] // See arti#1765
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

use futures::channel::oneshot as fut_oneshot;
use futures::FutureExt as _;

pub use fut_oneshot::Canceled;

/// `oneshot::Sender` type alias
//
// This has to be `pub type` rather than `pub use` so that
// (i) call sites don't trip the "disallowed types" lint
// (ii) we can apply a fine-grained allow, here.
#[allow(clippy::disallowed_types)]
pub type Sender<T> = fut_oneshot::Sender<T>;

/// `oneshot::Receiver` that works properly with [`futures::select!`]
#[allow(clippy::disallowed_types)]
pub type Receiver<T> = futures::future::Fuse<fut_oneshot::Receiver<T>>;

/// Return a fresh oneshot channel
pub fn channel<T>() -> (Sender<T>, Receiver<T>) {
    #[allow(clippy::disallowed_methods)]
    let (tx, rx) = fut_oneshot::channel();
    (tx, rx.fuse())
}
