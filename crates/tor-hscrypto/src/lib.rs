#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![doc = include_str!("../README.md")]
// TODO hs: apply the standard warning list to this module.
#![allow(dead_code, unused_variables)]

// TODO hs: Throughout this crate, only permit constant-time comparison functions.

mod macros;
pub mod ops;
pub mod pk;
pub mod time;

/// The information that a client needs to know about an onion service in
/// order to connect to it.
#[derive(Copy, Clone, Debug)]
pub struct Credential {
    /// Representation for the onion service's public ID. (`N_hs_cred`)
    ///
    /// This is the same value as is expanded to an OnionIdKey.
    id: [u8; 32],
    // secret: Vec<u8> // This is not well-supported in the C Tor
    // implementation; it's not clear to me that we should build it in either?
}

/// A value to identify an onion service during a given period. (`N_hs_subcred`)
///
/// This is computed from the onion service's public ID and the blinded ID for
/// the current time period.
///
/// Given this piece of information, the original credential cannot be re-derived.
#[derive(Copy, Clone, Debug)]
pub struct Subcredential([u8; 32]);

/// Counts which revision of an onion service descriptor is which, within a
/// given time period.
///
/// There can be gaps in this numbering. A descriptor with a higher-valued
/// revision counter supersedes one with a lower revision counter.
#[derive(Copy, Clone, Debug)]
pub struct RevisionCounter(u64);

/// An opaque value used by an onion service
// TODO hs: these values should only permit constant-time comparison.
#[derive(Copy, Clone, Debug)]
pub struct RendCookie([u8; 20]);
