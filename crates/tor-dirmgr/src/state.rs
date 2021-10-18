//! Implementation for the primary directory state machine.
//!
//! There are three (active) states that a download can be in: looking
//! for a consensus ([`GetConsensusState`]), looking for certificates
//! to validate that consensus ([`GetCertsState`]), and looking for
//! microdescriptors ([`GetMicrodescsState`]).
//!
//! These states have no contact with the network, and are purely
//! reactive to other code that drives them.  See the
//! [`bootstrap`](crate::bootstrap) module for functions that actually
//! load or download directory information.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures::lock::Mutex;
use rand::Rng;
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::sync::Weak;
use std::time::{Duration, SystemTime};
use tor_netdir::{MdReceiver, NetDir, PartialNetDir};
use tor_netdoc::doc::netstatus::Lifetime;
use tracing::{info, warn};

use crate::{
    docmeta::{AuthCertMeta, ConsensusMeta},
    retry::RetryConfig,
    shared_ref::SharedMutArc,
    storage::sqlite::SqliteStore,
    CacheUsage, ClientRequest, DirMgrConfig, DirState, DocId, DocumentText, Error, Readiness,
    Result,
};
use tor_checkable::{ExternallySigned, SelfSigned, Timebound};
use tor_llcrypto::pk::rsa::RsaIdentity;
use tor_netdoc::doc::{
    microdesc::{MdDigest, Microdesc},
    netstatus::MdConsensus,
};
use tor_netdoc::{
    doc::{
        authcert::{AuthCert, AuthCertKeyIds},
        microdesc::MicrodescReader,
        netstatus::{ConsensusFlavor, UnvalidatedMdConsensus},
    },
    AllowAnnotations,
};
use tor_rtcompat::Runtime;

/// An object where we can put a usable netdir.
///
/// Note that there's only one implementation for this trait: DirMgr.
/// We make this a trait anyway to make sure that the different states
/// in this module can _only_ interact with the DirMgr through
/// modifying the NetDir and looking at the configuration.
pub(crate) trait WriteNetDir: 'static + Sync + Send {
    /// Return a DirMgrConfig to use when asked how to retry downloads,
    /// or when we need to find a list of descriptors.
    fn config(&self) -> &DirMgrConfig;

    /// Return a reference where we can write or modify a NetDir.
    fn netdir(&self) -> &SharedMutArc<NetDir>;

    /// Called to note that the consensus stored in [`Self::netdir()`] has been
    /// changed.
    fn netdir_consensus_changed(&self);

    /// Called to note that the descriptors stored in
    /// [`Self::netdir()`] have been changed.
    fn netdir_descriptors_changed(&self);
}

impl<R: Runtime> WriteNetDir for crate::DirMgr<R> {
    fn config(&self) -> &DirMgrConfig {
        &self.config
    }
    fn netdir(&self) -> &SharedMutArc<NetDir> {
        &self.netdir
    }
    fn netdir_consensus_changed(&self) {
        use std::sync::atomic::Ordering;
        self.netdir_consensus_changed.store(true, Ordering::SeqCst);
    }
    fn netdir_descriptors_changed(&self) {
        use std::sync::atomic::Ordering;
        self.netdir_descriptors_changed
            .store(true, Ordering::SeqCst);
    }
}

/// Initial state: fetching or loading a consensus directory.
#[derive(Clone, Debug)]
pub(crate) struct GetConsensusState<DM: WriteNetDir> {
    /// How should we get the consensus from the cache, if at all?
    cache_usage: CacheUsage,

    /// If present, our next state.
    ///
    /// (This is present once we have a consensus.)
    next: Option<GetCertsState<DM>>,

    /// A list of RsaIdentity for the authorities that we believe in.
    ///
    /// No consensus can be valid unless it purports to be signed by
    /// more than half of these authorities.
    authority_ids: Vec<RsaIdentity>,

    /// A weak reference to the directory manager that wants us to
    /// fetch this information.  When this references goes away, we exit.
    writedir: Weak<DM>,
}

impl<DM: WriteNetDir> GetConsensusState<DM> {
    /// Create a new GetConsensusState from a weak reference to a
    /// directory manager and a `cache_usage` flag.
    pub(crate) fn new(writedir: Weak<DM>, cache_usage: CacheUsage) -> Result<Self> {
        let authority_ids: Vec<_> = if let Some(writedir) = Weak::upgrade(&writedir) {
            writedir
                .config()
                .authorities()
                .iter()
                .map(|auth| *auth.v3ident())
                .collect()
        } else {
            return Err(Error::ManagerDropped);
        };
        Ok(GetConsensusState {
            cache_usage,
            next: None,
            authority_ids,
            writedir,
        })
    }
}

#[async_trait]
impl<DM: WriteNetDir> DirState for GetConsensusState<DM> {
    fn describe(&self) -> String {
        if self.next.is_some() {
            "About to fetch certificates."
        } else {
            match self.cache_usage {
                CacheUsage::CacheOnly => "Looking for a cached consensus.",
                CacheUsage::CacheOkay => "Looking for a consensus.",
                CacheUsage::MustDownload => "Downloading a consensus.",
            }
        }
        .to_string()
    }
    fn missing_docs(&self) -> Vec<DocId> {
        if self.can_advance() {
            return Vec::new();
        }
        let flavor = ConsensusFlavor::Microdesc;
        vec![DocId::LatestConsensus {
            flavor,
            cache_usage: self.cache_usage,
        }]
    }
    fn is_ready(&self, _ready: Readiness) -> bool {
        false
    }
    fn can_advance(&self) -> bool {
        self.next.is_some()
    }
    fn dl_config(&self) -> Result<(usize, RetryConfig)> {
        if let Some(wd) = Weak::upgrade(&self.writedir) {
            Ok((1, *wd.config().schedule().retry_consensus()))
        } else {
            Err(Error::ManagerDropped)
        }
    }
    fn add_from_cache(&mut self, docs: HashMap<DocId, DocumentText>) -> Result<bool> {
        let text = match docs.into_iter().next() {
            None => return Ok(false),
            Some((
                DocId::LatestConsensus {
                    flavor: ConsensusFlavor::Microdesc,
                    ..
                },
                text,
            )) => text,
            _ => return Err(Error::Unwanted("Not an md consensus")),
        };

        self.add_consensus_text(true, text.as_str()?)
            .map(|meta| meta.is_some())
    }
    async fn add_from_download(
        &mut self,
        text: &str,
        _request: &ClientRequest,
        storage: Option<&Mutex<SqliteStore>>,
    ) -> Result<bool> {
        if let Some(meta) = self.add_consensus_text(false, text)? {
            if let Some(store) = storage {
                let mut w = store.lock().await;
                w.store_consensus(meta, ConsensusFlavor::Microdesc, true, text)?;
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }
    fn advance(self: Box<Self>) -> Result<Box<dyn DirState>> {
        Ok(match self.next {
            Some(next) => Box::new(next),
            None => self,
        })
    }
    fn reset_time(&self) -> Option<SystemTime> {
        None
    }
    fn reset(self: Box<Self>) -> Result<Box<dyn DirState>> {
        Ok(self)
    }
}

impl<DM: WriteNetDir> GetConsensusState<DM> {
    /// Helper: try to set the current consensus text from an input
    /// string `text`.  Refuse it if the authorities could never be
    /// correct, or if it is illformed.
    fn add_consensus_text(
        &mut self,
        from_cache: bool,
        text: &str,
    ) -> Result<Option<&ConsensusMeta>> {
        // Try to parse it and get its metadata.
        let (consensus_meta, unvalidated) = {
            let (signedval, remainder, parsed) = MdConsensus::parse(text)?;
            if let Ok(timely) = parsed.check_valid_now() {
                let meta = ConsensusMeta::from_unvalidated(signedval, remainder, &timely);
                (meta, timely)
            } else {
                return Ok(None);
            }
        };

        // Check out what authorities we believe in, and see if enough
        // of them are purported to have singed this consensus.
        let n_authorities = self.authority_ids.len() as u16;
        let unvalidated = unvalidated.set_n_authorities(n_authorities);

        let id_refs: Vec<_> = self.authority_ids.iter().collect();
        if !unvalidated.authorities_are_correct(&id_refs[..]) {
            return Err(Error::UnrecognizedAuthorities);
        }

        // Make a set of all the certificates we want -- the subset of
        // those listed on the consensus that we would indeed accept as
        // authoritative.
        let desired_certs = unvalidated
            .signing_cert_ids()
            .filter(|m| self.recognizes_authority(&m.id_fingerprint))
            .collect();

        self.next = Some(GetCertsState {
            cache_usage: self.cache_usage,
            from_cache,
            unvalidated,
            consensus_meta,
            missing_certs: desired_certs,
            certs: Vec::new(),
            writedir: Weak::clone(&self.writedir),
        });

        // Unwrap should be safe because `next` was just assigned
        #[allow(clippy::unwrap_used)]
        Ok(Some(&self.next.as_ref().unwrap().consensus_meta))
    }

    /// Return true if `id` is an authority identity we recognize
    fn recognizes_authority(&self, id: &RsaIdentity) -> bool {
        self.authority_ids.iter().any(|auth| auth == id)
    }
}

/// Second state: fetching or loading authority certificates.
///
/// TODO: we should probably do what C tor does, and try to use the
/// same directory that gave us the consensus.
///
/// TODO SECURITY: This needs better handling for the DOS attack where
/// we are given a bad consensus signed with fictional certificates
/// that we can never find.
#[derive(Clone, Debug)]
struct GetCertsState<DM: WriteNetDir> {
    /// The cache usage we had in mind when we began.  Used to reset.
    cache_usage: CacheUsage,
    /// True iff we loaded the consensus from our cache.
    from_cache: bool,
    /// The consensus that we are trying to validate.
    unvalidated: UnvalidatedMdConsensus,
    /// Metadata for the consensus.
    consensus_meta: ConsensusMeta,
    /// A set of the certificate keypairs for the certificates we don't
    /// have yet.
    missing_certs: HashSet<AuthCertKeyIds>,
    /// A list of the certificates we've been able to load or download.
    certs: Vec<AuthCert>,
    /// Reference to our directory manager.
    writedir: Weak<DM>,
}

#[async_trait]
impl<DM: WriteNetDir> DirState for GetCertsState<DM> {
    fn describe(&self) -> String {
        let total = self.certs.len() + self.missing_certs.len();
        format!(
            "Downloading certificates for consensus (we are missing {}/{}).",
            self.missing_certs.len(),
            total
        )
    }
    fn missing_docs(&self) -> Vec<DocId> {
        self.missing_certs
            .iter()
            .map(|id| DocId::AuthCert(*id))
            .collect()
    }
    fn is_ready(&self, _ready: Readiness) -> bool {
        false
    }
    fn can_advance(&self) -> bool {
        self.unvalidated.key_is_correct(&self.certs[..]).is_ok()
    }
    fn dl_config(&self) -> Result<(usize, RetryConfig)> {
        if let Some(wd) = Weak::upgrade(&self.writedir) {
            Ok((1, *wd.config().schedule().retry_certs()))
        } else {
            Err(Error::ManagerDropped)
        }
    }
    fn add_from_cache(&mut self, docs: HashMap<DocId, DocumentText>) -> Result<bool> {
        let mut changed = false;
        // Here we iterate over the documents we want, taking them from
        // our input and remembering them.
        for id in self.missing_docs().iter() {
            if let Some(cert) = docs.get(id) {
                let parsed = AuthCert::parse(cert.as_str()?)?.check_signature()?;
                if let Ok(cert) = parsed.check_valid_now() {
                    self.missing_certs.remove(cert.key_ids());
                    self.certs.push(cert);
                    changed = true;
                } else {
                    warn!("Got a cert from our cache that we couldn't parse");
                }
            }
        }
        Ok(changed)
    }
    async fn add_from_download(
        &mut self,
        text: &str,
        request: &ClientRequest,
        storage: Option<&Mutex<SqliteStore>>,
    ) -> Result<bool> {
        let asked_for: HashSet<_> = match request {
            ClientRequest::AuthCert(a) => a.keys().collect(),
            _ => return Err(Error::BadArgument("Mismatched request")),
        };

        let mut newcerts = Vec::new();
        for cert in AuthCert::parse_multiple(text) {
            if let Ok(parsed) = cert {
                let s = parsed
                    .within(text)
                    .expect("Certificate was not in input as expected");
                if let Ok(wellsigned) = parsed.check_signature() {
                    if let Ok(timely) = wellsigned.check_valid_now() {
                        newcerts.push((timely, s));
                    }
                } else {
                    // TODO: note the source.
                    warn!("Badly signed certificate received and discarded.");
                }
            } else {
                // TODO: note the source.
                warn!("Unparsable certificate received and discarded.");
            }
        }

        // Now discard any certs we didn't ask for.
        let len_orig = newcerts.len();
        newcerts.retain(|(cert, _)| asked_for.contains(cert.key_ids()));
        if newcerts.len() != len_orig {
            warn!("Discarding certificates that we didn't ask for.");
        }

        // We want to exit early if we aren't saving any certificates.
        if newcerts.is_empty() {
            return Ok(false);
        }

        if let Some(store) = storage {
            // Write the certificates to the store.
            let v: Vec<_> = newcerts[..]
                .iter()
                .map(|(cert, s)| (AuthCertMeta::from_authcert(cert), *s))
                .collect();
            let mut w = store.lock().await;
            w.store_authcerts(&v[..])?;
        }

        // Remember the certificates in this state, and remove them
        // from our list of missing certs.
        let mut changed = false;
        for (cert, _) in newcerts {
            let ids = cert.key_ids();
            if self.missing_certs.contains(ids) {
                self.missing_certs.remove(ids);
                self.certs.push(cert);
                changed = true;
            }
        }

        Ok(changed)
    }
    fn advance(self: Box<Self>) -> Result<Box<dyn DirState>> {
        if self.can_advance() {
            let validated = self.unvalidated.check_signature(&self.certs[..])?;
            Ok(Box::new(GetMicrodescsState::new(
                validated,
                self.consensus_meta,
                self.writedir,
            )?))
        } else {
            Ok(self)
        }
    }
    fn reset_time(&self) -> Option<SystemTime> {
        Some(self.consensus_meta.lifetime().valid_until())
    }
    fn reset(self: Box<Self>) -> Result<Box<dyn DirState>> {
        Ok(Box::new(GetConsensusState::new(
            self.writedir,
            self.cache_usage,
        )?))
    }
}

/// Final state: we're fetching or loading microdescriptors
#[derive(Debug, Clone)]
struct GetMicrodescsState<DM: WriteNetDir> {
    /// The digests of the microdescriptors we are missing.
    missing: HashSet<MdDigest>,
    /// The dirmgr to inform about a usable directory.
    writedir: Weak<DM>,
    /// A NetDir that we are currently building, but which doesn't
    /// have enough microdescs yet.
    partial: Option<PartialNetDir>,
    /// Metadata for the current consensus.
    meta: ConsensusMeta,
    /// A pending list of microdescriptor digests whose
    /// "last-listed-at" times we should update.
    newly_listed: Vec<MdDigest>,
    /// A time after which we should try to replace this directory and
    /// find a new one.  Since this is randomized, we only compute it
    /// once.
    reset_time: SystemTime,
}

impl<DM: WriteNetDir> GetMicrodescsState<DM> {
    /// Create a new [`GetMicrodescsState`] from a provided
    /// microdescriptor consensus.
    fn new(consensus: MdConsensus, meta: ConsensusMeta, writedir: Weak<DM>) -> Result<Self> {
        let reset_time = consensus.lifetime().valid_until();

        let partial_dir = match Weak::upgrade(&writedir) {
            Some(wd) => {
                let params = wd.config().override_net_params();
                let mut dir = PartialNetDir::new(consensus, Some(params));
                if let Some(old_dir) = wd.netdir().get() {
                    dir.fill_from_previous_netdir(&old_dir);
                }
                dir
            }
            None => return Err(Error::ManagerDropped),
        };

        let missing = partial_dir.missing_microdescs().map(Clone::clone).collect();
        let mut result = GetMicrodescsState {
            missing,
            writedir,
            partial: Some(partial_dir),
            meta,
            newly_listed: Vec::new(),
            reset_time,
        };

        result.consider_upgrade();
        Ok(result)
    }

    /// Add a bunch of microdescriptors to the in-progress netdir.
    ///
    /// Return true if the netdir has just become usable.
    fn register_microdescs<I>(&mut self, mds: I) -> bool
    where
        I: IntoIterator<Item = Microdesc>,
    {
        if let Some(p) = &mut self.partial {
            for md in mds {
                self.newly_listed.push(*md.digest());
                p.add_microdesc(md);
            }
            return self.consider_upgrade();
        } else if let Some(wd) = Weak::upgrade(&self.writedir) {
            let _ = wd.netdir().mutate(|netdir| {
                for md in mds {
                    netdir.add_microdesc(md);
                }
                wd.netdir_descriptors_changed();
                Ok(())
            });
        }
        false
    }

    /// Check whether this netdir we're building has _just_ become
    /// usable when it was not previously usable.  If so, tell the
    /// dirmgr about it and return true; otherwise return false.
    fn consider_upgrade(&mut self) -> bool {
        if let Some(p) = self.partial.take() {
            match p.unwrap_if_sufficient() {
                Ok(netdir) => {
                    self.reset_time = pick_download_time(netdir.lifetime());
                    if let Some(wd) = Weak::upgrade(&self.writedir) {
                        wd.netdir().replace(netdir);
                        wd.netdir_consensus_changed();
                        wd.netdir_descriptors_changed();
                        return true;
                    }
                }
                Err(partial) => self.partial = Some(partial),
            }
        }
        false
    }
}

#[async_trait]
impl<DM: WriteNetDir> DirState for GetMicrodescsState<DM> {
    fn describe(&self) -> String {
        format!(
            "Downloading microdescriptors (we are missing {}).",
            self.missing.len()
        )
    }
    fn missing_docs(&self) -> Vec<DocId> {
        self.missing.iter().map(|d| DocId::Microdesc(*d)).collect()
    }
    fn is_ready(&self, ready: Readiness) -> bool {
        match ready {
            Readiness::Complete => self.missing.is_empty(),
            Readiness::Usable => self.partial.is_none(),
        }
    }
    fn can_advance(&self) -> bool {
        false
    }
    fn dl_config(&self) -> Result<(usize, RetryConfig)> {
        if let Some(wd) = Weak::upgrade(&self.writedir) {
            Ok((
                wd.config().schedule().microdesc_parallelism(),
                *wd.config().schedule().retry_microdescs(),
            ))
        } else {
            Err(Error::ManagerDropped)
        }
    }
    fn add_from_cache(&mut self, docs: HashMap<DocId, DocumentText>) -> Result<bool> {
        let mut microdescs = Vec::new();
        for (id, text) in docs {
            if let DocId::Microdesc(digest) = id {
                if !self.missing.remove(&digest) {
                    // we didn't want this.
                    continue;
                }
                if let Ok(md) = Microdesc::parse(text.as_str()?) {
                    if md.digest() == &digest {
                        microdescs.push(md);
                        continue;
                    }
                }
                warn!("Found a mismatched microdescriptor in cache; ignoring");
            }
        }

        let changed = !microdescs.is_empty();
        self.register_microdescs(microdescs);

        Ok(changed)
    }
    async fn add_from_download(
        &mut self,
        text: &str,
        request: &ClientRequest,
        storage: Option<&Mutex<SqliteStore>>,
    ) -> Result<bool> {
        let requested: HashSet<_> = if let ClientRequest::Microdescs(req) = request {
            req.digests().collect()
        } else {
            return Err(Error::BadArgument("Mismatched request"));
        };
        let mut new_mds = Vec::new();
        for anno in MicrodescReader::new(text, &AllowAnnotations::AnnotationsNotAllowed).flatten() {
            let txt = anno
                .within(text)
                .expect("annotation not from within text as expected");
            let md = anno.into_microdesc();
            if !requested.contains(md.digest()) {
                warn!(
                    "Received microdescriptor we did not ask for: {:?}",
                    md.digest()
                );
                continue;
            }
            self.missing.remove(md.digest());
            new_mds.push((txt, md));
        }

        let mark_listed = self.meta.lifetime().valid_after();
        if let Some(store) = storage {
            let mut s = store.lock().await;
            if !self.newly_listed.is_empty() {
                s.update_microdescs_listed(self.newly_listed.iter(), mark_listed)?;
                self.newly_listed.clear();
            }
            if !new_mds.is_empty() {
                s.store_microdescs(
                    new_mds.iter().map(|(txt, md)| (&txt[..], md.digest())),
                    mark_listed,
                )?;
            }
        }
        if self.register_microdescs(new_mds.into_iter().map(|(_, md)| md)) {
            // oh hey, this is no longer pending.
            if let Some(store) = storage {
                let mut store = store.lock().await;
                info!("Marked consensus usable.");
                store.mark_consensus_usable(&self.meta)?;
                // DOCDOC: explain why we're doing this here.
                store.expire_all()?;
            }
        }
        Ok(true)
    }
    fn advance(self: Box<Self>) -> Result<Box<dyn DirState>> {
        Ok(self)
    }
    fn reset_time(&self) -> Option<SystemTime> {
        Some(self.reset_time)
    }
    fn reset(self: Box<Self>) -> Result<Box<dyn DirState>> {
        Ok(Box::new(GetConsensusState::new(
            self.writedir,
            CacheUsage::MustDownload,
        )?))
    }
}

/// Choose a random download time to replace a consensus whose lifetime
/// is `lifetime`.
fn pick_download_time(lifetime: &Lifetime) -> SystemTime {
    let (lowbound, uncertainty) = client_download_range(lifetime);
    let zero = Duration::new(0, 0);
    let t = lowbound + rand::thread_rng().gen_range(zero..uncertainty);
    info!("The current consensus is fresh until {}, and valid until {}. I've picked {} as the earliest time to replace it.",
          DateTime::<Utc>::from(lifetime.fresh_until()),
          DateTime::<Utc>::from(lifetime.valid_until()),
          DateTime::<Utc>::from(t));
    t
}

/// Based on the lifetime for a consensus, return the time range during which
/// clients should fetch the next one.
fn client_download_range(lt: &Lifetime) -> (SystemTime, Duration) {
    let valid_after = lt.valid_after();
    let fresh_until = lt.fresh_until();
    let valid_until = lt.valid_until();
    let voting_interval = fresh_until
        .duration_since(valid_after)
        .expect("valid-after must precede fresh-until");
    let whole_lifetime = valid_until
        .duration_since(valid_after)
        .expect("valid-after must precede valid-until");

    // From dir-spec:
    // "This time is chosen uniformly at random from the interval
    // between the time 3/4 into the first interval after the
    // consensus is no longer fresh, and 7/8 of the time remaining
    // after that before the consensus is invalid."
    let lowbound = voting_interval + (voting_interval * 3) / 4;
    let remainder = whole_lifetime - lowbound;
    let uncertainty = (remainder * 7) / 8;

    (valid_after + lowbound, uncertainty)
}
