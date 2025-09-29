#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "memquota"), allow(unused))]

//! ## Intended behaviour
//!
//! In normal operation we try to track as little state as possible, cheaply.
//! We do track total memory use in nominal bytes
//! (but a little approximately).
//!
//! When we exceed the quota, we engage a more expensive algorithm:
//! we build a heap to select oldest victims, and
//! we use the heap to keep reducing memory
//! until we go below a low-water mark (hysteresis).
//!
//! ## Key concepts
//!
//!  * **Tracker**:
//!    Instance of the memory quota system
//!    Each tracker has a notion of how much memory its participants
//!    are allowed to use, in aggregate.
//!    Tracks memory usage by all the Accounts and Participants.
//!    Different Trackers are completely independent.
//!
//!  * **Account**:
//!    all memory used within the same Account is treated equally,
//!    and reclamation also happens on an account-by-account basis.
//!    (Each Account is with one Tracker.)
//!
//!    See [the `mq_queue` docs](mq_queue/index.html#use-in-arti)
//!    for we use Accounts in Arti to track memory for the various queues.
//!
//!  * **Participant**:
//!    one data structure that uses memory.
//!    Each Participant is linked to *one* Account.  An account has *one or more* Participants.
//!    (An Account can exist with zero Participants, but can't then claim memory.)
//!    A Participant provides a `dyn IsParticipant` to the memory system;
//!    in turn, the memory system provides the Participant with a `Participation` -
//!    a handle for tracking memory alloc/free.
//!
//!    Actual memory allocation is handled by the participant itself,
//!    using the global heap:
//!    for each allocation, the Participant *both*
//!    calls [`claim`](mtracker::Participation::claim)
//!    *and* allocates the actual object,
//!    and later, *both* frees the actual object *and*
//!    calls [`release`](mtracker::Participation::release).
//!
//!  * **Child Account**/**Parent Account**:
//!    An Account may have a Parent.
//!    When a tracker requests memory reclamation from a Parent,
//!    it will also request it of all that Parent's Children (but not vice versa).
//!
//!    The account structure and reclamation strategy for Arti is defined in
//!    `tor-proto`, and documented in `tor_proto::memquota`.
//!
//!  * **Data age**:
//!    Each Participant must be able to say what the oldest data is, that it is storing.
//!    The reclamation policy is to try to free the oldest data.
//!
//!  * **Reclamation**:
//!    When a Tracker decides that too much memory is being used,
//!    it will select a victim Account based on the data age.
//!    It will then ask *every Participant* in that Account,
//!    and every Participant in every Child of that Account,
//!    to reclaim memory.
//!    A Participant responds by freeing at least some memory,
//!    according to the reclamation request, and tells the Tracker when it has done so.
//!
//!  * **Reclamation strategy**:
//!    To avoid too-frequent reclamation, once reclamation has started,
//!    it will continue until a low-water mark is reached, significantly lower than the quota.
//!    I.e. the system has a hysteresis.
//!
//!    The only currently implemented higher-level Participant is
//!    [`mq_queue`], a queue which responds to a reclamation request
//!    by completely destroying itself, freeing all its data,
//!    and reporting it has been closed.
//!
//!  * <div id="is-approximate">
//!
//!    **Approximate** (both in time and space):
//!    The memory quota system is not completely precise.
//!    Participants need not report their use precisely,
//!    but the errors should be reasonably small, and bounded.
//!    Likewise, the enforcement is not precise:
//!    reclamation may start slightly too early, or too late;
//!    but the memory use will be bounded below by O(number of participants)
//!    and above by O(1) (plus errors from the participants).
//!    Reclamation is not immediate, and is dependent on task scheduling;
//!    during memory pressure the quota may be exceeded;
//!    new allocations are not prevented while attempts at reclamation are ongoing.
//!
//!    </div>
//!
// TODO we haven't implemented the queue wrapper yet
// !  * **Queues**:
// !    We provide a higher-level API that wraps an mpsc queue and turns it into a Participant.
// !
//! ## Ownership and Arc keeping-alive
//!
//!  * Somewhere, someone must keep an `Account` to keep the account open.
//!    Ie, the principal object corresponding to the accountholder should contain an `Account`.
//!
//!  * `Arc<MemoryTracker>` holds `Weak<dyn IsParticipant>`.
//!    If the tracker finds the `IsParticipant` has vanished,
//!    it assumes this means that the Participant is being destroyed and
//!    it can treat all of the memory it claimed as freed.
//!
//!  * Each participant holds a `Participation`.
//!    A `Participation` may be invalidated by collapse of the underlying Account,
//!    which may be triggered in any number of ways.
//!
//!  * A `Participation` does *not* keep its `Account` alive.
//!    Ie, it has only a weak reference to the Account.
//!
//!  * A Participant's implementor of `IsParticipant` may hold a `Participation`.
//!    If the `impl IsParticipant` is also the principal accountholder object,
//!    it must hold an `Account` too.
//!
//!  * Child/parent accounts do not imply any keeping-alive relationship.
//!    It's just that a reclamation request to a parent (if it still exists)
//!    will also be made to its children.
//!
//!
//! ```text
//!     accountholder   =======================================>*  Participant
//!                                                                (impl IsParticipant)
//!           ||
//!           ||                                                     ^     ||
//!           ||                                                     |     ||
//!           ||                 global                     Weak<dyn>|     ||
//!           ||                     ||                              |     ||
//!           \/*                    \/                              |     ||
//!                                                                  |     ||
//!         Account  *===========>  MemoryTracker  ------------------'     ||
//!                                                                        ||
//!            ^                                                           ||
//!            |                                                           \/
//!            |
//!             `-------------------------------------------------*   Participation
//!
//!
//!
//!     accountholder which is also directly the Participant ==============\
//!     (impl IsParticipant)                                              ||
//!                                           ^                           ||
//!           ||                              |                           ||
//!           ||                              |                           ||
//!           ||                 global       |Weak<dyn>                  ||
//!           ||                     ||       |                           ||
//!           \/                     \/       |                           ||
//!                                                                       ||
//!         Account  *===========>  MemoryTracker                         ||
//!                                                                       ||
//!            ^                                                          ||
//!            |                                                          \/
//!            |
//!             `-------------------------------------------------*   Participation
//!
//! ```
//!
//! ## Panics and state corruption
//!
//! This library is intended to be entirely panic-free,
//! even in the case of accounting errors, arithmetic overflow, etc.
//!
//! In the case of sufficiently bad account errors,
//! a Participant, or a whole Account, or the whole MemoryQuotaTracker,
//! may become unusable,
//! in which case methods will return errors with kind [`tor_error::ErrorKind::Internal`].
//
// TODO MEMQUOTA: We ought to account for the fixed overhead of each stream, circuit, and
// channel.  For example, DataWriterImpl holds a substantial fixed-length buffer.  A
// complication is that we want to know the "data age", which is possibly the time this stream
// was last used.

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
#![deny(clippy::mod_module_files)]
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
#![allow(clippy::result_large_err)] // temporary workaround for arti#587
#![allow(clippy::needless_raw_string_hashes)] // complained-about code is fine, often best
#![allow(clippy::needless_lifetimes)] // See arti#1765
#![allow(mismatched_lifetime_syntaxes)] // temporary workaround for arti#2060
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

// TODO #1176
#![allow(clippy::blocks_in_conditions)]
//
// See `Panics` in the crate-level docs, above.
//
// This lint sometimes has bugs, but it seems to DTRT for me as of 1.81.0-beta.6.
// If it breaks, these bug(s) may be relevant:
// https://github.com/rust-lang/rust-clippy/issues/11220
// https://github.com/rust-lang/rust-clippy/issues/11145
// https://github.com/rust-lang/rust-clippy/issues/10209
#![warn(clippy::arithmetic_side_effects)]

// Internal supporting modules
#[macro_use]
mod drop_bomb;
#[macro_use]
mod refcount;
#[macro_use]
mod memory_cost_derive;

mod drop_reentrancy;
mod if_enabled;
mod internal_prelude;
mod utils;

// Modules with public items
mod config;
mod error;
pub mod memory_cost;
pub mod mq_queue;
pub mod mtracker;

/// For trait sealing
mod private {
    /// Inaccessible trait
    pub trait Sealed {}
}

/// Names exported for testing
#[cfg(feature = "testing")]
pub mod testing {
    use super::*;
    pub use config::ConfigInner;
}

//---------- re-exports at the crate root ----------

pub use config::{Config, ConfigBuilder};
pub use error::{Error, MemoryReclaimedError, StartupError};
pub use if_enabled::EnabledToken;
pub use memory_cost::HasMemoryCost;
pub use memory_cost_derive::{HasMemoryCostStructural, assert_copy_static};
pub use mtracker::{Account, MemoryQuotaTracker};
pub use utils::ArcMemoryQuotaTrackerExt;

#[doc(hidden)]
pub use derive_deftly;

/// `Result` whose `Err` is [`tor_memtrack::Error`](Error)
pub type Result<T> = std::result::Result<T, Error>;
