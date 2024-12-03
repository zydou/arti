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

mod join_read_write;
mod prepare_send;
mod sink_close_channel;
mod sink_try_send;
mod sinkext;
mod watch;

pub mod peekable_stream;
pub mod stream_peek;

pub use join_read_write::*;

pub use prepare_send::{SinkPrepareExt, SinkPrepareSendFuture, SinkSendable};

pub use sinkext::SinkExt;

pub use sink_close_channel::SinkCloseChannel;

pub use sink_try_send::{ErasedSinkTrySendError, MpscOtherSinkTrySendError};
pub use sink_try_send::{SinkTrySend, SinkTrySendError};

pub use watch::{DropNotifyEofSignallable, DropNotifyWatchSender, PostageWatchSenderExt};

pub use oneshot_fused_workaround as oneshot;

use futures::channel::mpsc;

/// Precisely [`futures::channel::mpsc::channel`]
///
/// In `arti.git` we disallow this method, because we want to ensure
/// that all our queues participate in our memory quota system
/// (see `tor-memquota` and `tor_proto::memquota`).y
///
/// Use this method to make an `mpsc::channel` when you know that's not appropriate.
///
/// (`#[allow]` on an expression is unstable Rust, so this is needed to avoid
/// decorating whole functions with the allow.)
#[allow(clippy::disallowed_methods)] // We don't care about mq tracking in this test code
pub fn mpsc_channel_no_memquota<T>(buffer: usize) -> (mpsc::Sender<T>, mpsc::Receiver<T>) {
    mpsc::channel(buffer)
}
