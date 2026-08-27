//! Test data, downloaded from the live network, and filtered to reduce its size
//!
//! The parsed forms obtained by [`netstatus_plain()`] etc.
//! have retained unknown values iff the `retain-unknown` cargo feature is enabled.

use paste::paste;

use crate::doc::microdesc::Microdesc;
use crate::doc::netstatus;
use crate::doc::routerdesc::{RouterDesc, RouterDescUnverified};
use crate::parse2::{NetdocParseable, NetdocParseableUnverified};
use crate::test_support::parse_test_document;

#[macro_use]
#[path = "../testdata-live/generated_consts.rs"]
#[rustfmt::skip] // shell script output is nice, but not 100% identical to rustfmt
mod generated_consts;

pub use generated_consts::*;

/// Three test data file contents', one per variety
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct PerVariety {
    /// Plain consensus
    pub plain: &'static str,

    /// Microdescriptor consensus
    pub md: &'static str,

    /// Vote
    pub vote: &'static str,
}

/// Test data for one (selected) relay
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct PerRelay {
    /// Nickname
    pub nick: &'static str,

    /// Data for this relay
    pub data: PerVariety,
}

// ---------- parsed documents ----------

/// Relay-specific parsed test document or fragment
///
/// Used for routerstatus entries in network statuses, and also
/// relay descriptors and microdescriptors.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct RelayDocument<D: 'static> {
    /// Nickname
    pub nick: &'static str,

    /// Actual document
    pub doc: &'static D,
}

/// Parse and yield a `Vec<RelayDocument<_>>`
fn relay_documents<D, S>(inputs: &[PerRelay], selector: S) -> Vec<RelayDocument<D>>
where
    D: NetdocParseable + Sync,
    S: Fn(&PerVariety) -> &'static str,
{
    inputs
        .iter()
        .map(|relay| RelayDocument {
            nick: relay.nick,
            doc: parse_test_document::<D>(selector(&relay.data)),
        })
        // We don't memoise the Vec; it has only about 5 elements of 3 words each
        .collect()
}

/// Turn a `Vec<RelayDocument<FooUnverified>>` into a `Vec<RelayDocument<Foo>>`
fn unwrap_bodies<U>(u: Vec<RelayDocument<U>>) -> Vec<RelayDocument<U::Body>>
where
    U: NetdocParseableUnverified,
{
    u.into_iter()
        .map(|rd| RelayDocument {
            nick: rd.nick,
            doc: rd.doc.inspect_unverified().0,
        })
        .collect()
}

/// Define `netstatus_V`, `netstatus_V_unverified` and `relay_routerstatuses_V`
//
// We could use the per variety macros but that seems even more confusing
macro_rules! netstatus_variety { { $v:ident } => { paste!{
    /// Parsed network status, in unverified form
    pub fn [<netstatus_ $v _unverified>]() -> &'static netstatus::$v::NetworkStatusUnverified {
        parse_test_document(NETSTATUS.$v)
    }
    /// Parsed network status
    pub fn [<netstatus_ $v>]() -> &'static netstatus::$v::NetworkStatus {
        [<netstatus_ $v _unverified>]().inspect_unverified().0
    }
    /// Parsed routerstatus entries
    pub fn [<relay_routerstatuses_ $v>]() -> Vec<RelayDocument<netstatus::$v::RouterStatus>> {
        relay_documents(RELAY_ROUTERSTATUSES, |relay| relay.$v)
    }
} } }

netstatus_variety! { plain }
netstatus_variety! { md }
netstatus_variety! { vote }

/// Router descriptors (as listed in the consensus)
pub fn relay_routerdescs() -> Vec<RelayDocument<RouterDesc>> {
    unwrap_bodies(relay_routerdescs_unverified())
}
/// Router descriptors (as listed in the consensus), in unverified form
pub fn relay_routerdescs_unverified() -> Vec<RelayDocument<RouterDescUnverified>> {
    relay_documents(RELAY_DESCRIPTORS, |relay| relay.plain)
}
/// Router descriptors (as listed in the vote)
pub fn relay_routerdescs_vote() -> Vec<RelayDocument<RouterDesc>> {
    unwrap_bodies(relay_routerdescs_vote_unverified())
}
/// Router descriptors (as listed in the consensus), in unverified form
pub fn relay_routerdescs_vote_unverified() -> Vec<RelayDocument<RouterDescUnverified>> {
    relay_documents(RELAY_DESCRIPTORS, |relay| relay.vote)
}
/// Microdescriptors as listed in the consensus
// Microdescs aren't signed so there is no relay_microdescs_unverified
pub fn relay_microdescs() -> Vec<RelayDocument<Microdesc>> {
    relay_documents(RELAY_DESCRIPTORS, |relay| relay.md)
}

/// Find a particular relay's document, given the relay's nickname
///
/// This is sound for `testdata_live` data, because we only have a small curated
/// subset of of relays, all of which have distinct nicks.
///
/// # Panics
///
/// Panics if no relay with the given name is found.
///
/// # Example
///
/// ```
/// use tor_netdoc::doc::microdesc::Microdesc;
/// use tor_netdoc::testdata_live::{relay_document_by_nick, relay_microdescs};
///
/// let _: &'static Microdesc = relay_document_by_nick("lisdex", &relay_microdescs());
/// ```
pub fn relay_document_by_nick<D>(nick: &str, docs: &[RelayDocument<D>]) -> &'static D {
    docs.iter().find(|d| d.nick == nick).expect(nick).doc
}

#[test]
fn test_all() {
    netstatus_plain();
    netstatus_md();
    netstatus_vote();

    netstatus_plain_unverified();
    netstatus_md_unverified();
    netstatus_vote_unverified();

    relay_routerstatuses_plain();
    relay_routerstatuses_md();
    relay_routerstatuses_vote();

    relay_routerdescs();
    relay_routerdescs_unverified();

    relay_routerdescs_vote();
    relay_routerdescs_vote_unverified();

    relay_microdescs();
}
