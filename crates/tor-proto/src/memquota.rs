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
//!   * Tor channels ([`ChannelAccount`])
//!     - outbound data, on its way from a circuit to the upstream
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
//!     We do not claim memory directly from it, so it won't be subject to reclaim.
//      This is silly.  We don't want anyone to make a Participant from this account.
//      TODO #351 make `ToplevelAccount` a type alias or wrapper for `Arc<MemoryQuotaTracker>`.
//      (but doing this before we have merged !2505/!2508 will just generate conflicts.)
//!
//!   * [`ChannelAccount`].
//!     Contains (via parentage) everything that goes via a particular Channel.
//!
//!   * [`CircuitAccount`].
//!     Has the `ChannelAccount` as its parent.
//!     So if a queue accounted to a channel is selected for reclaim,
//!     that channel, and all of its circuits, will collapse.
//!     
//!   * [`StreamAccount`].
//!     Is a *clone* of the `CircuitAccount`.
//!     If a queue associated with any stream of a circuit is selected for reclaim,
//!     the whole circuit, including all of its other streams, will collapse.
//      TODO #351 this is true after #1661/!2505.
//!
//! Thus, killing a single queue will reclaim the memory associated with several other queues.

use derive_deftly::{define_derive_deftly, Deftly};
use tor_memquota::Account;

/// An [`Account`], whose type indicates which layer of the stack it's for
//
// Making this a trait rather than ad-hoc output from the derive macro
// makes things more regular, and the documentation easier.
pub trait SpecificAccount: Sized {
    /// The parent [`Account`], or, for a standalone account type,
    /// [`Arc<MemoryQuotaTracker>`](tor_memquota::MemoryQuotaTracker).
    type Parent;

    /// Create a new Account at this layer, given the parent
    fn new(within: &Self::Parent) -> Result<Self, tor_memquota::Error>;

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
    ///    `type Parent = Arc<MemoryQuotaTracker>`.
    ///
    ///  * **`#[deftly(account_newtype(parent = "PARENT_ACCOUNT"))]`**:
    ///    `type Parent = PARENT_ACCOUNT`
    ///    (and PARENT_ACCOUNT must itself impl `SpecificAccount`.
    ///
    /// Applicable to newtype tuple structs, containing an [`Account`], only.
    export SpecificAccount for struct, expect items:

    ${define ACCOUNT { $crate::tor_memquota::Account }}

    ${defcond HAS_PARENT not(tmeta(account_newtype(toplevel)))}
    ${define PARENT_TY { ${if HAS_PARENT {
        ${tmeta(account_newtype(parent)) as ty}
    } else {
        std::sync::Arc<$crate::tor_memquota::MemoryQuotaTracker>
    }}}}

    impl SpecificAccount for $ttype {
        type Parent = $PARENT_TY;

        fn new(within: &Self::Parent) -> Result<Self, tor_memquota::Error> {
            ${if HAS_PARENT {
                $crate::memquota::SpecificAccount::as_raw_account(within).new_child()
            } else {
                within.new_account(None)
            }}
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

/// [`Account`] for the whole system (eg, for a channel manager from `tor-chanmgr`)
///
/// Use via the [`SpecificAccount`] impl.
/// See the [`memquota`](self) module documentation.
#[derive(Deftly, Clone, Debug)]
#[derive_deftly(SpecificAccount)]
#[deftly(account_newtype(toplevel))]
pub struct ToplevelAccount(Account);

/// [`Account`] for a Tor Channel
///
/// Use via the [`SpecificAccount`] impl.
/// See the [`memquota`](self) module documentation.
#[derive(Deftly, Clone, Debug)]
#[derive_deftly(SpecificAccount)]
#[deftly(account_newtype(parent = "ToplevelAccount"))]
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
