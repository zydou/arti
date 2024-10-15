//! Support for modifying directories in various ways in order to cause
//! different kinds of network failure.

use anyhow::{anyhow, Result};
use rand::Rng;
use std::sync::{Arc, Mutex};
use tor_dirmgr::filter::DirFilter;
use tor_netdoc::{
    doc::{
        microdesc::Microdesc,
        netstatus::{RouterStatus, UncheckedMdConsensus},
    },
    types::{family::RelayFamily, policy::PortPolicy},
};

/// Return a new directory filter as configured by a specified string.
pub(crate) fn new_filter(s: &str) -> Result<Arc<dyn DirFilter + 'static>> {
    Ok(match s {
        "replace-onion-keys" => Arc::new(ReplaceOnionKeysFilter),
        "one-big-family" => Arc::new(OneBigFamilyFilter::default()),
        "no-exit-ports" => Arc::new(NoExitPortsFilter::default()),
        "bad-signatures" => Arc::new(BadSignaturesFilter),
        "non-existent-signing-keys" => Arc::new(NonexistentSigningKeysFilter),
        "bad-microdesc-digests" => Arc::new(BadMicrodescDigestsFilter),
        _ => {
            return Err(anyhow!(
                "Unrecognized filter. Options are: 
    replace-onion-keys, one-big-family, no-exit-ports, bad-signatures,
    non-existent-signing-keys, bad-microdesc-digests."
            ));
        }
    })
}

/// A filter that doesn't do anything.
///
/// We define this so we can set a filter unconditionally and simplify our code a
/// little.
#[derive(Debug)]
struct NilFilter;
impl DirFilter for NilFilter {}

/// Return a filter that doesn't do anything.
pub(crate) fn nil_filter() -> Arc<dyn DirFilter + 'static> {
    Arc::new(NilFilter)
}

/// A filter to replace onion keys with junk.
///
/// Doing this means that all CREATE2 attempts via ntor will fail.  (If any were
/// to succeed, they'd fail when they try to extend.)
#[derive(Debug, Default)]
struct ReplaceOnionKeysFilter;

impl DirFilter for ReplaceOnionKeysFilter {
    fn filter_md(&self, mut md: Microdesc) -> tor_dirmgr::Result<Microdesc> {
        let junk_key: [u8; 32] = rand::thread_rng().gen();
        md.ntor_onion_key = junk_key.into();
        Ok(md)
    }
}

/// A filter to put all relays into a family with one another.
///
/// This filter will prevent the client from generating any mult-hop circuits,
/// since they'll all violate our path constraints.
#[derive(Debug, Default)]
struct OneBigFamilyFilter {
    /// The family we're going to put all the microdescs into.  We set this to
    /// contain all the identities, every time we load a consensus.
    ///
    /// (This filter won't do a very good job of ensuring consistency between
    /// this family and the MDs we attach it to, but that's okay for the kind of
    /// testing we want to do.)
    new_family: Mutex<Arc<RelayFamily>>,
}

impl DirFilter for OneBigFamilyFilter {
    fn filter_consensus(
        &self,
        consensus: UncheckedMdConsensus,
    ) -> tor_dirmgr::Result<UncheckedMdConsensus> {
        let mut new_family = RelayFamily::new();
        for r in consensus.dangerously_peek().consensus.relays() {
            new_family.push(*r.rsa_identity());
        }

        *self.new_family.lock().expect("poisoned lock") = Arc::new(new_family);

        Ok(consensus)
    }

    fn filter_md(&self, mut md: Microdesc) -> tor_dirmgr::Result<Microdesc> {
        let big_family = self.new_family.lock().expect("poisoned lock").clone();
        md.family = big_family;
        Ok(md)
    }
}

/// A filter to remove all exit policies.
///
/// With this change, any attempt to build a circuit connecting for to an
/// address will fail, since no exit will appear to support it.
#[derive(Debug)]
struct NoExitPortsFilter {
    /// A "reject all ports" policy.
    reject_all: Arc<PortPolicy>,
}

impl Default for NoExitPortsFilter {
    fn default() -> Self {
        Self {
            reject_all: Arc::new(PortPolicy::new_reject_all()),
        }
    }
}

impl DirFilter for NoExitPortsFilter {
    fn filter_md(&self, mut md: Microdesc) -> tor_dirmgr::Result<Microdesc> {
        md.ipv4_policy = self.reject_all.clone();
        md.ipv6_policy = self.reject_all.clone();
        Ok(md)
    }
}

/// A filter to replace the signatures on a consensus with invalid ones.
///
/// This change will cause directory validation to fail: we'll get good
/// certificates and discover that our directory is invalid.
#[derive(Debug, Default)]
struct BadSignaturesFilter;

impl DirFilter for BadSignaturesFilter {
    fn filter_consensus(
        &self,
        consensus: UncheckedMdConsensus,
    ) -> tor_dirmgr::Result<UncheckedMdConsensus> {
        let (mut consensus, (start_time, end_time)) = consensus.dangerously_into_parts();

        // We retain the signatures, but change the declared digest of the
        // document. This will make all the signatures invalid.
        consensus.siggroup.sha1 = Some(*b"can you reverse sha1");
        consensus.siggroup.sha256 = Some(*b"sha256 preimage is harder so far");

        Ok(UncheckedMdConsensus::new_from_start_end(
            consensus, start_time, end_time,
        ))
    }
}

/// A filter that (nastily) claims all the authorities have changed their
/// signing keys.
///
/// This change will make us go looking for a set of certificates that don't
/// exist so that we can verify the consensus.
#[derive(Debug, Default)]
struct NonexistentSigningKeysFilter;

impl DirFilter for NonexistentSigningKeysFilter {
    fn filter_consensus(
        &self,
        consensus: UncheckedMdConsensus,
    ) -> tor_dirmgr::Result<UncheckedMdConsensus> {
        let (mut consensus, (start_time, end_time)) = consensus.dangerously_into_parts();
        let mut rng = rand::thread_rng();
        for signature in consensus.siggroup.signatures.iter_mut() {
            let sk_fingerprint: [u8; 20] = rng.gen();
            signature.key_ids.sk_fingerprint = sk_fingerprint.into();
        }

        Ok(UncheckedMdConsensus::new_from_start_end(
            consensus, start_time, end_time,
        ))
    }
}

/// A filter that replaces all the microdesc digests with ones that don't exist.
///
/// This filter will let us validate the consensus, but we'll look forever for
/// valid the microdescriptors it claims are present.
#[derive(Debug, Default)]
struct BadMicrodescDigestsFilter;

impl DirFilter for BadMicrodescDigestsFilter {
    fn filter_consensus(
        &self,
        consensus: UncheckedMdConsensus,
    ) -> tor_dirmgr::Result<UncheckedMdConsensus> {
        let (mut consensus, (start_time, end_time)) = consensus.dangerously_into_parts();
        let mut rng = rand::thread_rng();
        for rs in consensus.consensus.relays.iter_mut() {
            rs.rs.doc_digest = rng.gen();
        }

        Ok(UncheckedMdConsensus::new_from_start_end(
            consensus, start_time, end_time,
        ))
    }
}
