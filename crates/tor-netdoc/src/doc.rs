//! Individual document types that we can parse in Tor's meta-format.
//!
//! Right now, we recognize four kinds of documents.
//!
//! A [netstatus::MdConsensus] is a multi-signed document that the
//! directory authorities use to tell clients and relays who is on the
//! network.  It contains information about each relay, and it links to
//! additional microdescriptors ([microdesc::Microdesc]) that have
//! more information about each relay.
//!
//! In order to validate a [netstatus::MdConsensus], you need to have
//! the authority certificate ([authcert::AuthCert]) for the directory
//! authorities that signed it.
//!
//! Finally, in order to use relays not listed in the consensus (such
//! as bridges), clients use those relays' self-signed router
//! descriptors ([routerdesc::RouterDesc]).  These router descriptors
//! are also uploaded to the authorities in order to tell them about
//! relays and their status.
//!
//! All of these formats are described in
//! [dir-spec.txt](https://spec.torproject.org/dir-spec).
//!
//! # Limitations
//!
//! Tor recognizes other kinds of documents that this crate doesn't
//! parse yet.  There are "ExtraInfo documents" that encode
//! information about relays that almost nobody needs.
//! Finally, there are the voting documents themselves that authorities
//! use in order to calculate the consensus.

#[macro_use]
mod ns_variety_definition_macros;

pub mod authcert;
#[cfg(feature = "hs-common")]
pub mod hsdesc;
pub mod microdesc;
pub mod netstatus;

#[cfg(any(doc, feature = "routerdesc"))]
pub mod routerdesc;

#[allow(missing_docs, clippy::missing_docs_in_private_items)]
#[cfg(not(any(doc, feature = "routerdesc")))]
pub mod routerdesc {
    /// The digest of a RouterDesc document, as reported in a NS consensus.
    pub type RdDigest = [u8; 20];
}
