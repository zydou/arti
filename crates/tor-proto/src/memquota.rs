//! Types to support memory quota tracking
//!
//! We make these newtypes because we otherwise have a confusing a maze of
//! identical-looking, but supposedly semantically different, [`Account`]s.

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
#[derive(Deftly, Clone, Debug)]
#[derive_deftly(SpecificAccount)]
#[deftly(account_newtype(toplevel))]
pub struct ToplevelAccount(Account);

/// [`Account`] for a Tor Channel
#[derive(Deftly, Clone, Debug)]
#[derive_deftly(SpecificAccount)]
#[deftly(account_newtype(parent = "ToplevelAccount"))]
pub struct ChannelAccount(Account);

/// [`Account`] for a Tor Circuit
#[derive(Deftly, Clone, Debug)]
#[derive_deftly(SpecificAccount)]
#[deftly(account_newtype(parent = "ChannelAccount"))]
pub struct CircuitAccount(Account);

/// [`Account`] for a Tor Stream
#[derive(Deftly, Clone, Debug)]
#[derive_deftly(SpecificAccount)]
#[deftly(account_newtype(parent = "CircuitAccount"))]
pub struct StreamAccount(Account);
