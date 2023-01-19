#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![doc = include_str!("../README.md")]
// TODO hs: apply the standard warning list to this module.
#![allow(dead_code, unused_variables)]

mod macros;
pub mod ops;
pub mod pk;
pub mod time;

use macros::define_bytes;

/// The information that a client needs to know about an onion service in
/// order to connect to it.
#[derive(Copy, Clone, Debug)]
pub struct Credential {
    /// Representation for the onion service's public ID. (`N_hs_cred`)
    ///
    /// This is the same value as is expanded to an OnionIdKey.
    id: pk::OnionId,
    // secret: Vec<u8> // This is not well-supported in the C Tor
    // implementation; it's not clear to me that we should build it in either?
}

impl From<pk::OnionId> for Credential {
    fn from(id: pk::OnionId) -> Self {
        Self { id }
    }
}

define_bytes! {
/// A value to identify an onion service during a given period. (`N_hs_subcred`)
///
/// This is computed from the onion service's public ID and the blinded ID for
/// the current time period.
///
/// Given this piece of information, the original credential cannot be re-derived.
#[derive(Copy, Clone, Debug)]
pub struct Subcredential([u8; 32]);
}

/// Counts which revision of an onion service descriptor is which, within a
/// given time period.
///
/// There can be gaps in this numbering. A descriptor with a higher-valued
/// revision counter supersedes one with a lower revision counter.
#[derive(Copy, Clone, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct RevisionCounter(u64);

define_bytes! {
/// An opaque value used at a rendezvous point to match clients and services.
///
/// The client includes this value to the rendezvous point in its
/// `ESTABLISH_RENDEZVOUS` message; the service later provides the same value in its
/// `RENDEZVOUS1` message.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RendCookie([u8; 20]);
}
