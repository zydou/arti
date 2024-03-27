//! Functionality for exposing details about a relay that most users should avoid.
//!
//! ## Design notes
//!
//! These types aren't meant to be a dumping grounds
//! for every function in `Relay` or `UncheckedRelay`:
//! instead, they are for methods that are easy to misuse or misunderstand
//! misunderstand if applied out-of-context.
//!
//! For example, it's generally wrong in most contexts
//! to check for a specific relay flag.
//! Instead, we should be checking whether the relay is suitable
//! for some particular _usage_,
//! which will itself depend on a combination of flags.
//!
//! Therefore, this module should be used for checking properties only when:
//! - The property is one that is usually subsumed
//!   in a higher-level check.
//! - Using the lower-level property on its own poses a risk
//!   of accidentally forgetting to check other important properties.
//!
//! If you find that your code is using this module, you should ask yourself
//! - whether the actual thing that you're testing
//!   is something that _any other piece of code_ might want to test
//! - whether the collection of properties that you're testing
//!   creates a risk of leaving out some other properties
//!   that should also be tested.
//!
//! If you answer "yes" to either of these, it's better to define a higher-level property,
//! and have your code use that instead.
#![allow(unused)] //XXXX

/// A view for lower-level details about a [`Relay`](crate::Relay).
///
/// Most callers should avoid using this structure;
/// they should instead call higher-level functions
/// like those in the `tor-relay-selection` crate.
#[derive(Clone)]
pub struct RelayDetails<'a>(pub(crate) &'a super::Relay<'a>);

/// A view for lower-level details about a [`UncheckedRelay`](crate::UncheckedRelay).
///
/// Most callers should avoid using this structure;
/// they should instead call higher-level functions
/// like those in the `tor-relay-selection` crate.
#[derive(Debug, Clone)]
pub struct UncheckedRelayDetails<'a>(pub(crate) &'a super::UncheckedRelay<'a>);
