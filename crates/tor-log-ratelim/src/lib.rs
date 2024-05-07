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
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

/// Implementation notes
///
/// We build our logging in a few layers.
///
/// At the lowest level, there is a [`Loggable`] trait, for events which can
/// accumulate and eventually be flushed; this combines with the
/// [`RateLim`](ratelim::RateLim) structure, which is responsible for managing
/// the decision of when to flush these [`Loggable`]s.
///
/// The role of RateLim is to decide
/// when to flush the information in a `Loggable`,
/// and to flush the `Loggable` as needed.
/// The role of a `Loggable` is to
/// accumulate information
/// and to know how to flush that information as a log message
/// when it is told to do so.
///
/// One layer up, there is [`LogState`](logstate::LogState), which is used to to
/// implement `Loggable` as used by [`log_ratelim!`].
/// It can remember the name of an activity, accumulate
/// successes and failures, and remember an error and associated message.
///
/// The highest layer is the [`log_ratelim!`] macro, which uses
/// [`RateLim`](ratelim::RateLim) and [`LogState`](logstate::LogState) to record
/// successes and failures, and launch background tasks as needed.
mod implementation_notes {}

mod logstate;
mod macros;
mod ratelim;

use std::time::Duration;

pub use ratelim::rt::{install_runtime, InstallRuntimeError};

/// Re-exports for macros.
#[doc(hidden)]
pub mod macro_prelude {
    pub use crate::{
        logstate::LogState,
        ratelim::{rt::rt_support, RateLim},
        Activity, Loggable,
    };
    pub use once_cell::sync::Lazy;
    pub use std::sync::{Arc, Mutex, Weak};
    pub use tor_error::ErrorReport;
    pub use tracing;
    pub use weak_table::WeakValueHashMap;
}

/// A group of events that can be logged singly or in a summary over a period of time.
#[doc(hidden)]
pub trait Loggable: 'static + Send {
    /// Log these events immediately, if there is anything to log.
    ///
    /// The `summarizing` argument is the amount of time that this `Loggable``
    /// has been accumulating information.
    ///
    /// Implementations should return `Active` if they have logged that
    /// some activity happened, and `Dormant` if they had nothing to log, or
    /// if they are logging "I didn't see that problem for a while."
    ///
    ///  After a `Loggable` has been dormant for a while, its timer will be reset.
    fn flush(&mut self, summarizing: Duration) -> Activity;
}

/// A description of the whether a `Loggable` had something to say.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(clippy::exhaustive_enums)] // okay, since this is doc(hidden).
pub enum Activity {
    /// There was a failure to report
    Active,
    /// There is nothing to report except perhaps a lack of failures.
    Dormant,
}
