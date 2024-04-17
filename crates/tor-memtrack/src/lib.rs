#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![doc = include_str!("../README.md")]

//! ## Intended behavour
//!
//! In normal operation we track very little cheaply
//! We do track total memory use in nominal bytes
//! (but a little approximately).
//!
//! When we exceed the quota, we engage a more expensive algorithm:
//! we build a heap to select oldest victims.
//! We use the heap to keep reducing memory
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
//!  * **Participant**:
//!    one data structure that uses memory.
//!    Each Participant is linked to *one* Account.  An account has *one or more* Participants.
//!    (An Account can exist with zero Participants, but can't then claim memory.)
//!    A Participant provides a `dyn IsParticipant` to the memory system;
//!    in turn, the memory system provides the Participant with a `Participation` -
//!    a handle for tracking memory alloc/free.
//!
//!  * **Child Account**/**Parent Account**:
//!    An Account may have a Parent.
//!    When a tracker requests memory reclamation from a Parent,
//!    it will also request it of all that Parent's Children (but not vice versa).
//!
//!  * **Data age**:
//!    Each Participant is must be able to say what the oldest data is, that it is storing.
//!    The reclamation policy is to try to free the oldest data.
//!
//!  * **Reclamation**:
//!    When a Tracker decides that too much memory is being used,
//!    it will select a victim Account based on the data age.
//!    It will then ask *every Participant* in that Account,
//!    and every Participant in every Child of that Account,
//!    to reclaim memory.
//!     A Participant responds by freeing at least some memory,
//!    according to the reclamation request, and tells the Tracker when it has done so.
//!
//!  * **Reclamation strategy**:
//!    To avoid too-frequent Reclamation, once Reclamation ha started,
//!    it will continue until a low-water mark is reached, significantly lower than the quota.
//!    I.e. the system has a hysteresis.
// TODO we haven't implemented the queue wrapper yet
// !    The only currently implemented higher-level Participant is
// !    a queue which responds to a reclamation request
// !    by completely destroying itself and freeing all its data.
//!
//!  * **Approximate** (both in time and space):
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

// @@ begin lint list maintained by maint/add_warning @@
#![cfg_attr(not(ci_arti_stable), allow(renamed_and_removed_lints))]
#![cfg_attr(not(ci_arti_nightly), allow(unknown_lints))]
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
#![allow(clippy::blocks_in_conditions)] // TODO #1176

// Internal supporting modules
mod drop_reentrancy;
mod internal_prelude;
#[macro_use]
mod refcount;
mod utils;

// Modules with public items
mod config;
mod error;
pub mod mtracker;

//---------- re-exports at the crate root ----------

pub use config::{Config, ConfigBuilder};
pub use error::{Error, StartupError};
pub use mtracker::MemoryQuotaTracker;

/// `Result` whose `Err` is [`tor_memtrack::Error`](Error)
pub type Result<T> = std::result::Result<T, Error>;
