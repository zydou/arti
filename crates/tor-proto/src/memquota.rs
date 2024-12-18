//! Types to support memory quota tracking
//!
//! We make these newtypes because we otherwise have a confusing a maze of
//! identical-looking, but supposedly semantically different, [`Account`]s.
//!
//! # Memory tracking architecture in Arti
//!
//! ## Queues
//!
//! The following queues in Arti participate in the memory quota system:
//!
//!   * Tor streams ([`StreamAccount`])
//!     - inbound data, on its way from the circuit to the stream's user
//!     - outbound data, on its way from the stream's user to the circuit
//!   * Tor circuits ([`CircuitAccount`])
//!     - inbound stream requests, on their way from the circuit to the handling code
//!     - inbound data, on its way from the channel
//!   * Tor channels ([`ChannelAccount`])
//!     - outbound data, on its way from a circuit to the channel
//!       (this ought to be accounted to the circuit, TODO #1652)
//!
//! The following data buffers do *not* participate:
//!
//!   * Our TLS implementation(s) may have internal buffers.
//!     We hope that these buffers will be kept reasonably small,
//!     and hooking into them would in any case going be quite hard.
//!
//!   * TCP sockets will also buffer data, in the operating system.
//!     Hooking into this is not trivial.
//!     
//!   * Our pluggable transport driver can buffer some data.
//!     This should be kept to a minimum for several reasons,
//!     so we hope that the buffers are small.
//!     
//!   * The actual pluggable transport might buffer data.
//!     Again, this should be kept to a minimum.
//!
//! ## Overview
//!
//! See the [tor_memquota] crate-level docs for an overview of the memquota system.
//! To summarise:
//!
//! When too much memory is in use, the queue with the oldest data is selected for reclaim.
//! The whole Account relating to the victim queue is torn down.
//! When the victim Account collapses, all its queues collapse too:
//! reading ends give EOF, and writing ends give errors.
//! This will tear down the associated Tor protocol association.
//!
//! All the children Accounts of the victim Account are torn down too.
//! This propagates the collapse to dependent Tor protocol associations.
//!
//! ## Accounting
//!
//! Within Arti we maintain a hierarchy of [`Account`]s.
//! These are wrapped in newtypes, here in `tor_proto::memquota`.
//!
//!   * [`ToplevelAccount`]:
//!     In a single Arti instance there will be one of these,
//!     used for all memory tracking.
//!     This is held (shared) by the chanmgr and the circmgr.
//!     Unlike the other layer-specific accounts,
//!     this is just a type alias for [`MemoryQuotaTracker`].
//!     It doesn't support claiming memory directly from it, so it won't be subject to reclaim.
//!
//!   * [`ChannelAccount`].
//!     Contains (via parentage) everything that goes via a particular Channel.
//!     This includes all circuits on the channel, and those circuits' streams.
//!
//!   * [`CircuitAccount`].
//!     Has the `ChannelAccount` as its parent.
//!     So if a queue accounted to a channel is selected for reclaim,
//!     that channel, and all of its circuits, will collapse.
//!     
//!   * [`StreamAccount`].
//!     Has the `CircuitAccount` as its parent.
//!     So if a queue accounted to a circuit is selected for reclaim,
//!     that circuit, and all of its streams, will collapse.
//!     If a stream's queue is selected for reclaim, only that stream will collapse.
//!     (See [#1661](https://gitlab.torproject.org/tpo/core/arti/-/issues/1661)
//!     for discussion of this behaviour.)
//!
//! Thus, killing a single queue will reclaim the memory associated with several other queues.

use derive_deftly::{define_derive_deftly, Deftly};
use std::sync::Arc;
use tor_memquota::{Account, MemoryQuotaTracker};

/// An [`Account`], whose type indicates which layer of the stack it's for
//
// Making this a trait rather than ad-hoc output from the derive macro
// makes things more regular, and the documentation easier.
pub trait SpecificAccount: Sized {
    /// The type that this `Account` can be constructed from.
    ///
    /// The progenitor [`Account`], or, for a standalone account type,
    /// [`Arc<MemoryQuotaTracker>`](tor_memquota::MemoryQuotaTracker).
    type ConstructedFrom;

    /// Create a new Account at this layer, given the progenitor
    fn new(progenitor: &Self::ConstructedFrom) -> Result<Self, tor_memquota::Error>;

    /// Access the underlying raw [`Account`]
    ///
    /// Use this when you need to actually track memory,
    /// for example when constructing a queue with [`tor_memquota::mq_queue`]
    fn as_raw_account(&self) -> &Account;

    /// Wrap an `Account`, blessing it with a layer
    ///
    /// Generally, don't call this function.
    /// Instead, use `new()`(SpecificAccount::new).
    fn from_raw_account(account: Account) -> Self;

    /// Unwrap this into a raw [`Account`]
    fn into_raw_account(self) -> Account;

    /// Create a new dummy account for testing purposes
    fn new_noop() -> Self {
        Self::from_raw_account(Account::new_noop())
    }
}

define_derive_deftly! {
    /// Implements [`SpecificAccount`]
    ///
    /// Exactly one of the following attributes must be supplied:
    ///
    ///  * **`#[deftly(account_newtype(toplevel)]`**:
    ///    Standalone Account, without a parent Account.
    ///    `type ConstructedFrom = Arc<MemoryQuotaTracker>`.
    ///
    ///  * **`#[deftly(account_newtype(parent = "PARENT_ACCOUNT"))]`**:
    ///    `type ConstructedFrom = PARENT_ACCOUNT`
    ///    (and PARENT_ACCOUNT must itself impl `SpecificAccount`).
    ///
    /// Applicable to newtype tuple structs, containing an [`Account`], only.
    export SpecificAccount for struct, expect items:

    ${define ACCOUNT { $crate::tor_memquota::Account }}

    ${defcond HAS_PARENT  tmeta(account_newtype(parent))}
    ${defcond IS_TOPLEVEL tmeta(account_newtype(toplevel))}

    ${define CONSTRUCTED_FROM {
        ${select1
          HAS_PARENT  { ${tmeta(account_newtype(parent)) as ty} }
          IS_TOPLEVEL { std::sync::Arc<$crate::tor_memquota::MemoryQuotaTracker> }
        }
    }}

    impl SpecificAccount for $ttype {
        type ConstructedFrom = $CONSTRUCTED_FROM;

        fn new(src: &Self::ConstructedFrom) -> Result<Self, tor_memquota::Error> {
          ${select1
            HAS_PARENT  { $crate::memquota::SpecificAccount::as_raw_account(src).new_child() }
            IS_TOPLEVEL { src.new_account(None) }
          }
                .map(Self::from_raw_account)
        }

        fn as_raw_account(&self) -> &$ACCOUNT {
            &self.0
        }
        fn from_raw_account(account: $ACCOUNT) -> Self {
            Self(account)
        }
        fn into_raw_account(self) -> $ACCOUNT {
            self.0
        }
    }

}

/// Account for the whole system
///
/// There will typically be only one of these for an entire Arti client or relay.
///
/// This is not really an [`Account`].
/// We don't want anyone to make a Participant from this,
/// because if that Participant were reclaimed, *everything* would be torn down.
///
/// We provide the type alias for consistency/readability at call sites.
///
/// See the [`memquota`](self) module documentation.
pub type ToplevelAccount = Arc<MemoryQuotaTracker>;

/// [`Account`] for a Tor Channel
///
/// Use via the [`SpecificAccount`] impl.
/// See the [`memquota`](self) module documentation.
#[derive(Deftly, Clone, Debug)]
#[derive_deftly(SpecificAccount)]
#[deftly(account_newtype(toplevel))]
pub struct ChannelAccount(Account);

/// [`Account`] for a Tor Circuit
///
/// Use via the [`SpecificAccount`] impl.
/// See the [`memquota`](self) module documentation.
#[derive(Deftly, Clone, Debug)]
#[derive_deftly(SpecificAccount)]
#[deftly(account_newtype(parent = "ChannelAccount"))]
pub struct CircuitAccount(Account);

/// [`Account`] for a Tor Stream
///
/// Use via the [`SpecificAccount`] impl.
/// See the [`memquota`](self) module documentation.
#[derive(Deftly, Clone, Debug)]
#[derive_deftly(SpecificAccount)]
#[deftly(account_newtype(parent = "CircuitAccount"))]
pub struct StreamAccount(Account);
