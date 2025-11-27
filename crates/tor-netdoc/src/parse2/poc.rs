//! Proof-of-concept parser using parse2 for network status documents.
//!
//! # Naming conventions
//!
//!   * `DocumentName`: important types,
//!     including network documents or sub-documents,
//!     eg `NetworkStatsuMd` and `RouterVote`,
//!     and types that are generally useful.
//!   * `NddDoucmnetSection`: sections and sub-documents
//!     that the user won't normally need to name.
//!   * `NdiItemValue`: parsed value for a network document Item.
//!     eg `NdiVoteStatus` representing the whole of the RHS of a `vote-status` Item.
//!     Often not needed since `ItemValueParseable` is implemented for suitable tuples.
//!   * `NdaArgumentValue`: parsed value for a single argument;
//!     eg `NdaVoteStatus` representing the `vote` or `status` argument.

use super::*;

pub mod authcert;
pub mod netstatus;

#[cfg(test)]
mod test;
