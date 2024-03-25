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

use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::mem;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use time::OffsetDateTime;
use tor_basic_utils::RngExt as _;
use tor_error::{internal, warn_report};
use tor_netdir::{MdReceiver, NetDir, PartialNetDir};
use tor_netdoc::doc::authcert::UncheckedAuthCert;
use tor_netdoc::doc::netstatus::Lifetime;
use tracing::{debug, warn};

use crate::event::DirProgress;

use crate::storage::DynStore;
use crate::{
    docmeta::{AuthCertMeta, ConsensusMeta},
    event,
    retry::DownloadSchedule,
    CacheUsage, ClientRequest, DirMgrConfig, DocId, DocumentText, Error, Readiness, Result,
};
use crate::{DocSource, SharedMutArc};
use tor_checkable::{ExternallySigned, SelfSigned, Timebound};
#[cfg(feature = "geoip")]
use tor_geoip::GeoipDb;
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

/// A change to the currently running `NetDir`, returned by the state machines in this module.
#[derive(Debug)]
pub(crate) enum NetDirChange<'a> {
    /// If the provided `NetDir` is suitable for use (i.e. the caller determines it can build
    /// circuits with it), replace the current `NetDir` with it.
    ///
    /// The caller must call `DirState::on_netdir_replaced` if the replace was successful.
    AttemptReplace {
        /// The netdir to replace the current one with, if it's usable.
        ///
        /// The `Option` is always `Some` when returned from the state machine; it's there
        /// so that the caller can call `.take()` to avoid cloning the netdir.
        netdir: &'a mut Option<NetDir>,
        /// The consensus metadata for this netdir.
        consensus_meta: &'a ConsensusMeta,
    },
    /// Add the provided microdescriptors to the current `NetDir`.
    AddMicrodescs(&'a mut Vec<Microdesc>),
}

/// A "state" object used to represent our progress in downloading a
/// directory.
///
/// These state objects are not meant to know about the network, or
/// how to fetch documents at all.  Instead, they keep track of what
/// information they are missing, and what to do when they get that
/// information.
///
/// Every state object has two possible transitions: "resetting", and
/// "advancing".  Advancing happens when a state has no more work to
/// do, and needs to transform into a different kind of object.
/// Resetting happens when this state needs to go back to an initial
/// state in order to start over -- either because of an error or
/// because the information it has downloaded is no longer timely.
pub(crate) trait DirState: Send {
    /// Return a human-readable description of this state.
    fn describe(&self) -> String;
    /// Return a list of the documents we're missing.
    ///
    /// If every document on this list were to be loaded or downloaded, then
    /// the state should either become "ready to advance", or "complete."
    ///
    /// This list should never _grow_ on a given state; only advancing
    /// or resetting the state should add new DocIds that weren't
    /// there before.
    fn missing_docs(&self) -> Vec<DocId>;
    /// Describe whether this state has reached `ready` status.
    fn is_ready(&self, ready: Readiness) -> bool;
    /// If the state object wants to make changes to the currently running `NetDir`,
    /// return the proposed changes.
    fn get_netdir_change(&mut self) -> Option<NetDirChange<'_>> {
        None
    }
    /// Return true if this state can advance to another state via its
    /// `advance` method.
    fn can_advance(&self) -> bool;
    /// Add one or more documents from our cache; returns 'true' if there
    /// was any change in this state.
    ///
    /// Set `changed` to true if any semantic changes in this state were made.
    ///
    /// An error return does not necessarily mean that no data was added;
    /// partial successes are possible.
    fn add_from_cache(
        &mut self,
        docs: HashMap<DocId, DocumentText>,
        changed: &mut bool,
    ) -> Result<()>;

    /// Add information that we have just downloaded to this state.
    ///
    /// This method receives a copy of the original request, and should reject
    /// any documents that do not pertain to it.
    ///
    /// If `storage` is provided, then we should write any accepted documents
    /// into `storage` so they can be saved in a cache.
    ///
    /// Set `changed` to true if any semantic changes in this state were made.
    ///
    /// An error return does not necessarily mean that no data was added;
    /// partial successes are possible.
    fn add_from_download(
        &mut self,
        text: &str,
        request: &ClientRequest,
        source: DocSource,
        storage: Option<&Mutex<DynStore>>,
        changed: &mut bool,
    ) -> Result<()>;
    /// Return a summary of this state as a [`DirProgress`].
    fn bootstrap_progress(&self) -> event::DirProgress;
    /// Return a configuration for attempting downloads.
    fn dl_config(&self) -> DownloadSchedule;
    /// If possible, advance to the next state.
    fn advance(self: Box<Self>) -> Box<dyn DirState>;
    /// Return a time (if any) when downloaders should stop attempting to
    /// advance this state, and should instead reset it and start over.
    fn reset_time(&self) -> Option<SystemTime>;
    /// Reset this state and start over.
    fn reset(self: Box<Self>) -> Box<dyn DirState>;
}

/// An object that can provide a previous netdir for the bootstrapping state machines to use.
pub(crate) trait PreviousNetDir: Send + Sync + 'static + Debug {
    /// Get the previous netdir, if there still is one.
    fn get_netdir(&self) -> Option<Arc<NetDir>>;
}

impl PreviousNetDir for SharedMutArc<NetDir> {
    fn get_netdir(&self) -> Option<Arc<NetDir>> {
        self.get()
    }
}

/// Initial state: fetching or loading a consensus directory.
#[derive(Clone, Debug)]
pub(crate) struct GetConsensusState<R: Runtime> {
    /// How should we get the consensus from the cache, if at all?
    cache_usage: CacheUsage,

    /// If present, a time after which we want our consensus to have
    /// been published.
    //
    // TODO: This is not yet used everywhere it could be.  In the future maybe
    // it should be inserted into the DocId::LatestConsensus  alternative rather
    // than being recalculated in make_consensus_request,
    after: Option<SystemTime>,

    /// If present, our next state.
    ///
    /// (This is present once we have a consensus.)
    next: Option<GetCertsState<R>>,

    /// A list of RsaIdentity for the authorities that we believe in.
    ///
    /// No consensus can be valid unless it purports to be signed by
    /// more than half of these authorities.
    authority_ids: Vec<RsaIdentity>,

    /// A `Runtime` implementation.
    rt: R,
    /// The configuration of the directory manager. Used for download configuration
    /// purposes.
    config: Arc<DirMgrConfig>,
    /// If one exists, the netdir we're trying to update.
    prev_netdir: Option<Arc<dyn PreviousNetDir>>,

    /// A filter that gets applied to directory objects before we use them.
    #[cfg(feature = "dirfilter")]
    filter: Arc<dyn crate::filter::DirFilter>,
}

impl<R: Runtime> GetConsensusState<R> {
    /// Create a new `GetConsensusState`, using the cache as per `cache_usage` and downloading as
    /// per the relevant sections of `config`. If `prev_netdir` is supplied, information from that
    /// directory may be used to complete the next one.
    pub(crate) fn new(
        rt: R,
        config: Arc<DirMgrConfig>,
        cache_usage: CacheUsage,
        prev_netdir: Option<Arc<dyn PreviousNetDir>>,
        #[cfg(feature = "dirfilter")] filter: Arc<dyn crate::filter::DirFilter>,
    ) -> Self {
        let authority_ids = config
            .authorities()
            .iter()
            .map(|auth| auth.v3ident)
            .collect();
        let after = prev_netdir
            .as_ref()
            .and_then(|x| x.get_netdir())
            .map(|nd| nd.lifetime().valid_after());

        GetConsensusState {
            cache_usage,
            after,
            next: None,
            authority_ids,
            rt,
            config,
            prev_netdir,
            #[cfg(feature = "dirfilter")]
            filter,
        }
    }
}

impl<R: Runtime> DirState for GetConsensusState<R> {
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
    fn bootstrap_progress(&self) -> DirProgress {
        if let Some(next) = &self.next {
            next.bootstrap_progress()
        } else {
            DirProgress::NoConsensus { after: self.after }
        }
    }
    fn dl_config(&self) -> DownloadSchedule {
        self.config.schedule.retry_consensus
    }
    fn add_from_cache(
        &mut self,
        docs: HashMap<DocId, DocumentText>,
        changed: &mut bool,
    ) -> Result<()> {
        let text = match docs.into_iter().next() {
            None => return Ok(()),
            Some((
                DocId::LatestConsensus {
                    flavor: ConsensusFlavor::Microdesc,
                    ..
                },
                text,
            )) => text,
            _ => return Err(Error::CacheCorruption("Not an md consensus")),
        };

        let source = DocSource::LocalCache;

        self.add_consensus_text(
            source,
            text.as_str().map_err(Error::BadUtf8InCache)?,
            None,
            changed,
        )?;
        Ok(())
    }
    fn add_from_download(
        &mut self,
        text: &str,
        request: &ClientRequest,
        source: DocSource,
        storage: Option<&Mutex<DynStore>>,
        changed: &mut bool,
    ) -> Result<()> {
        let requested_newer_than = match request {
            ClientRequest::Consensus(r) => r.last_consensus_date(),
            _ => None,
        };
        let meta = self.add_consensus_text(source, text, requested_newer_than, changed)?;

        if let Some(store) = storage {
            let mut w = store.lock().expect("Directory storage lock poisoned");
            w.store_consensus(meta, ConsensusFlavor::Microdesc, true, text)?;
        }
        Ok(())
    }
    fn advance(self: Box<Self>) -> Box<dyn DirState> {
        match self.next {
            Some(next) => Box::new(next),
            None => self,
        }
    }
    fn reset_time(&self) -> Option<SystemTime> {
        None
    }
    fn reset(self: Box<Self>) -> Box<dyn DirState> {
        self
    }
}

impl<R: Runtime> GetConsensusState<R> {
    /// Helper: try to set the current consensus text from an input string
    /// `text`.  Refuse it if the authorities could never be correct, or if it
    /// is ill-formed.
    ///
    /// If `cutoff` is provided, treat any consensus older than `cutoff` as
    /// older-than-requested.
    ///
    /// Errors from this method are not fatal to the download process.
    fn add_consensus_text(
        &mut self,
        source: DocSource,
        text: &str,
        cutoff: Option<SystemTime>,
        changed: &mut bool,
    ) -> Result<&ConsensusMeta> {
        // Try to parse it and get its metadata.
        let (consensus_meta, unvalidated) = {
            let (signedval, remainder, parsed) =
                MdConsensus::parse(text).map_err(|e| Error::from_netdoc(source.clone(), e))?;
            #[cfg(feature = "dirfilter")]
            let parsed = self.filter.filter_consensus(parsed)?;
            let parsed = self.config.tolerance.extend_tolerance(parsed);
            let now = self.rt.wallclock();
            let timely = parsed.check_valid_at(&now)?;
            if let Some(cutoff) = cutoff {
                if timely.peek_lifetime().valid_after() < cutoff {
                    return Err(Error::Unwanted("consensus was older than requested"));
                }
            }
            let meta = ConsensusMeta::from_unvalidated(signedval, remainder, &timely);
            (meta, timely)
        };

        // Check out what authorities we believe in, and see if enough
        // of them are purported to have signed this consensus.
        let n_authorities = self.authority_ids.len() as u16;
        let unvalidated = unvalidated.set_n_authorities(n_authorities);

        let id_refs: Vec<_> = self.authority_ids.iter().collect();
        if !unvalidated.authorities_are_correct(&id_refs[..]) {
            return Err(Error::UnrecognizedAuthorities);
        }
        // Yes, we've added the consensus.  That's a change.
        *changed = true;

        // Make a set of all the certificates we want -- the subset of
        // those listed on the consensus that we would indeed accept as
        // authoritative.
        let desired_certs = unvalidated
            .signing_cert_ids()
            .filter(|m| self.recognizes_authority(&m.id_fingerprint))
            .collect();

        self.next = Some(GetCertsState {
            cache_usage: self.cache_usage,
            consensus_source: source,
            consensus: GetCertsConsensus::Unvalidated(unvalidated),
            consensus_meta,
            missing_certs: desired_certs,
            certs: Vec::new(),
            rt: self.rt.clone(),
            config: self.config.clone(),
            prev_netdir: self.prev_netdir.take(),
            #[cfg(feature = "dirfilter")]
            filter: self.filter.clone(),
        });

        // Unwrap should be safe because `next` was just assigned
        #[allow(clippy::unwrap_used)]
        Ok(&self.next.as_ref().unwrap().consensus_meta)
    }

    /// Return true if `id` is an authority identity we recognize
    fn recognizes_authority(&self, id: &RsaIdentity) -> bool {
        self.authority_ids.iter().any(|auth| auth == id)
    }
}

/// One of two possible internal states for the consensus in a GetCertsState.
///
/// This inner object is advanced by `try_checking_sigs`.
#[derive(Clone, Debug)]
enum GetCertsConsensus {
    /// We have an unvalidated consensus; we haven't checked its signatures.
    Unvalidated(UnvalidatedMdConsensus),
    /// A validated consensus: the signatures are fine and we can advance.
    Validated(MdConsensus),
    /// We failed to validate the consensus, even after getting enough certificates.
    Failed,
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
struct GetCertsState<R: Runtime> {
    /// The cache usage we had in mind when we began.  Used to reset.
    cache_usage: CacheUsage,
    /// Where did we get our consensus?
    consensus_source: DocSource,
    /// The consensus that we are trying to validate, or an error if we've given
    /// up on validating it.
    consensus: GetCertsConsensus,
    /// Metadata for the consensus.
    consensus_meta: ConsensusMeta,
    /// A set of the certificate keypairs for the certificates we don't
    /// have yet.
    missing_certs: HashSet<AuthCertKeyIds>,
    /// A list of the certificates we've been able to load or download.
    certs: Vec<AuthCert>,

    /// A `Runtime` implementation.
    rt: R,
    /// The configuration of the directory manager. Used for download configuration
    /// purposes.
    config: Arc<DirMgrConfig>,
    /// If one exists, the netdir we're trying to update.
    prev_netdir: Option<Arc<dyn PreviousNetDir>>,

    /// A filter that gets applied to directory objects before we use them.
    #[cfg(feature = "dirfilter")]
    filter: Arc<dyn crate::filter::DirFilter>,
}

impl<R: Runtime> GetCertsState<R> {
    /// Handle a certificate result returned by `tor_netdoc`: checking it for timeliness
    /// and well-signedness.
    ///
    /// On success return the `AuthCert` and the string that represents it within the string `within`.
    /// On failure, return an error.
    fn check_parsed_certificate<'s>(
        &self,
        parsed: tor_netdoc::Result<UncheckedAuthCert>,
        source: &DocSource,
        within: &'s str,
    ) -> Result<(AuthCert, &'s str)> {
        let parsed = parsed.map_err(|e| Error::from_netdoc(source.clone(), e))?;
        let cert_text = parsed
            .within(within)
            .expect("Certificate was not in input as expected");
        let wellsigned = parsed.check_signature()?;
        let now = self.rt.wallclock();
        let timely_cert = self
            .config
            .tolerance
            .extend_tolerance(wellsigned)
            .check_valid_at(&now)?;
        Ok((timely_cert, cert_text))
    }

    /// If we have enough certificates, and we have not yet checked the
    /// signatures on the consensus, try checking them.
    ///
    /// If the consensus is valid, remove the unvalidated consensus from `self`
    /// and put the validated consensus there instead.
    ///
    /// If the consensus is invalid, throw it out set a blocking error.
    fn try_checking_sigs(&mut self) -> Result<()> {
        use GetCertsConsensus as C;
        // Temporary value; we'll replace the consensus field with something
        // better before the method returns.
        let mut consensus = C::Failed;
        std::mem::swap(&mut consensus, &mut self.consensus);

        let unvalidated = match consensus {
            C::Unvalidated(uv) if uv.key_is_correct(&self.certs[..]).is_ok() => uv,
            _ => {
                // nothing to check at this point.  Either we already checked the consensus, or we don't yet have enough certificates.
                self.consensus = consensus;
                return Ok(());
            }
        };

        let (new_consensus, outcome) = match unvalidated.check_signature(&self.certs[..]) {
            Ok(validated) => (C::Validated(validated), Ok(())),
            Err(cause) => (
                C::Failed,
                Err(Error::ConsensusInvalid {
                    source: self.consensus_source.clone(),
                    cause,
                }),
            ),
        };
        self.consensus = new_consensus;

        outcome
    }
}

impl<R: Runtime> DirState for GetCertsState<R> {
    fn describe(&self) -> String {
        use GetCertsConsensus as C;
        match &self.consensus {
            C::Unvalidated(_) => {
                let total = self.certs.len() + self.missing_certs.len();
                format!(
                    "Downloading certificates for consensus (we are missing {}/{}).",
                    self.missing_certs.len(),
                    total
                )
            }
            C::Validated(_) => "Validated consensus; about to get microdescriptors".to_string(),
            C::Failed => "Failed to validate consensus".to_string(),
        }
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
        matches!(self.consensus, GetCertsConsensus::Validated(_))
    }
    fn bootstrap_progress(&self) -> DirProgress {
        let n_certs = self.certs.len();
        let n_missing_certs = self.missing_certs.len();
        let total_certs = n_missing_certs + n_certs;
        DirProgress::FetchingCerts {
            lifetime: self.consensus_meta.lifetime().clone(),
            usable_lifetime: self
                .config
                .tolerance
                .extend_lifetime(self.consensus_meta.lifetime()),

            n_certs: (n_certs as u16, total_certs as u16),
        }
    }
    fn dl_config(&self) -> DownloadSchedule {
        self.config.schedule.retry_certs
    }
    fn add_from_cache(
        &mut self,
        docs: HashMap<DocId, DocumentText>,
        changed: &mut bool,
    ) -> Result<()> {
        // Here we iterate over the documents we want, taking them from
        // our input and remembering them.
        let source = DocSource::LocalCache;
        let mut nonfatal_error = None;
        for id in &self.missing_docs() {
            if let Some(cert) = docs.get(id) {
                let text = cert.as_str().map_err(Error::BadUtf8InCache)?;
                let parsed = AuthCert::parse(text);
                match self.check_parsed_certificate(parsed, &source, text) {
                    Ok((cert, _text)) => {
                        self.missing_certs.remove(cert.key_ids());
                        self.certs.push(cert);
                        *changed = true;
                    }
                    Err(e) => {
                        nonfatal_error.get_or_insert(e);
                    }
                }
            }
        }
        if *changed {
            self.try_checking_sigs()?;
        }
        opt_err_to_result(nonfatal_error)
    }
    fn add_from_download(
        &mut self,
        text: &str,
        request: &ClientRequest,
        source: DocSource,
        storage: Option<&Mutex<DynStore>>,
        changed: &mut bool,
    ) -> Result<()> {
        let asked_for: HashSet<_> = match request {
            ClientRequest::AuthCert(a) => a.keys().collect(),
            _ => return Err(internal!("expected an AuthCert request").into()),
        };

        let mut nonfatal_error = None;
        let mut newcerts = Vec::new();
        for cert in AuthCert::parse_multiple(text) {
            match self.check_parsed_certificate(cert, &source, text) {
                Ok((cert, cert_text)) => {
                    newcerts.push((cert, cert_text));
                }
                Err(e) => {
                    warn_report!(e, "Problem with certificate received from {}", &source);
                    nonfatal_error.get_or_insert(e);
                }
            }
        }

        // Now discard any certs we didn't ask for.
        let len_orig = newcerts.len();
        newcerts.retain(|(cert, _)| asked_for.contains(cert.key_ids()));
        if newcerts.len() != len_orig {
            warn!(
                "Discarding certificates from {} that we didn't ask for.",
                source
            );
            nonfatal_error.get_or_insert(Error::Unwanted("Certificate we didn't request"));
        }

        // We want to exit early if we aren't saving any certificates.
        if newcerts.is_empty() {
            return opt_err_to_result(nonfatal_error);
        }

        if let Some(store) = storage {
            // Write the certificates to the store.
            let v: Vec<_> = newcerts[..]
                .iter()
                .map(|(cert, s)| (AuthCertMeta::from_authcert(cert), *s))
                .collect();
            let mut w = store.lock().expect("Directory storage lock poisoned");
            w.store_authcerts(&v[..])?;
        }

        // Remember the certificates in this state, and remove them
        // from our list of missing certs.
        for (cert, _) in newcerts {
            let ids = cert.key_ids();
            if self.missing_certs.contains(ids) {
                self.missing_certs.remove(ids);
                self.certs.push(cert);
                *changed = true;
            }
        }

        if *changed {
            self.try_checking_sigs()?;
        }
        opt_err_to_result(nonfatal_error)
    }

    fn advance(self: Box<Self>) -> Box<dyn DirState> {
        use GetCertsConsensus::*;
        match self.consensus {
            Validated(validated) => Box::new(GetMicrodescsState::new(
                self.cache_usage,
                validated,
                self.consensus_meta,
                self.rt,
                self.config,
                self.prev_netdir,
                #[cfg(feature = "dirfilter")]
                self.filter,
            )),
            _ => self,
        }
    }

    fn reset_time(&self) -> Option<SystemTime> {
        Some(
            self.consensus_meta.lifetime().valid_until()
                + self.config.tolerance.post_valid_tolerance,
        )
    }
    fn reset(self: Box<Self>) -> Box<dyn DirState> {
        let cache_usage = if self.cache_usage == CacheUsage::CacheOnly {
            // Cache only means we can't ever download.
            CacheUsage::CacheOnly
        } else {
            // If we reset in this state, we should always go to "must
            // download": Either we've failed to get the certs we needed, or we
            // have found that the consensus wasn't valid.  Either case calls
            // for a fresh consensus download attempt.
            CacheUsage::MustDownload
        };

        Box::new(GetConsensusState::new(
            self.rt,
            self.config,
            cache_usage,
            self.prev_netdir,
            #[cfg(feature = "dirfilter")]
            self.filter,
        ))
    }
}

/// Final state: we're fetching or loading microdescriptors
#[derive(Debug, Clone)]
struct GetMicrodescsState<R: Runtime> {
    /// How should we get the consensus from the cache, if at all?
    cache_usage: CacheUsage,
    /// Total number of microdescriptors listed in the consensus.
    n_microdescs: usize,
    /// The current status of our netdir.
    partial: PendingNetDir,
    /// Metadata for the current consensus.
    meta: ConsensusMeta,
    /// A pending list of microdescriptor digests whose
    /// "last-listed-at" times we should update.
    newly_listed: Vec<MdDigest>,
    /// A time after which we should try to replace this directory and
    /// find a new one.  Since this is randomized, we only compute it
    /// once.
    reset_time: SystemTime,

    /// A `Runtime` implementation.
    rt: R,
    /// The configuration of the directory manager. Used for download configuration
    /// purposes.
    config: Arc<DirMgrConfig>,
    /// If one exists, the netdir we're trying to update.
    prev_netdir: Option<Arc<dyn PreviousNetDir>>,

    /// A filter that gets applied to directory objects before we use them.
    #[cfg(feature = "dirfilter")]
    filter: Arc<dyn crate::filter::DirFilter>,
}

/// Information about a network directory that might not be ready to become _the_ current network
/// directory.
#[derive(Debug, Clone)]
enum PendingNetDir {
    /// A NetDir for which we have a consensus, but not enough microdescriptors.
    Partial(PartialNetDir),
    /// A NetDir we're either trying to get our caller to replace, or that the caller
    /// has already taken from us.
    ///
    /// After the netdir gets taken, the `collected_microdescs` and `missing_microdescs`
    /// fields get used. Before then, we just do operations on the netdir.
    Yielding {
        /// The actual netdir. This starts out as `Some`, but our caller can `take()` it
        /// from us.
        netdir: Option<NetDir>,
        /// Microdescs we have collected in order to yield to our caller.
        collected_microdescs: Vec<Microdesc>,
        /// Which microdescs we need for the netdir that either is or used to be in `netdir`.
        ///
        /// NOTE(eta): This MUST always match the netdir's own idea of which microdescs we need.
        ///            We do this by copying the netdir's missing microdescs into here when we
        ///            instantiate it.
        ///            (This code assumes that it doesn't add more needed microdescriptors later!)
        missing_microdescs: HashSet<MdDigest>,
        /// The time at which we should renew this netdir, assuming we have
        /// driven it to a "usable" state.
        replace_dir_time: SystemTime,
    },
    /// A dummy value, so we can use `mem::replace`.
    Dummy,
}

impl MdReceiver for PendingNetDir {
    fn missing_microdescs(&self) -> Box<dyn Iterator<Item = &MdDigest> + '_> {
        match self {
            PendingNetDir::Partial(partial) => partial.missing_microdescs(),
            PendingNetDir::Yielding {
                netdir,
                missing_microdescs,
                ..
            } => {
                if let Some(nd) = netdir.as_ref() {
                    nd.missing_microdescs()
                } else {
                    Box::new(missing_microdescs.iter())
                }
            }
            PendingNetDir::Dummy => unreachable!(),
        }
    }

    fn add_microdesc(&mut self, md: Microdesc) -> bool {
        match self {
            PendingNetDir::Partial(partial) => partial.add_microdesc(md),
            PendingNetDir::Yielding {
                netdir,
                missing_microdescs,
                collected_microdescs,
                ..
            } => {
                let wanted = missing_microdescs.remove(md.digest());
                if let Some(nd) = netdir.as_mut() {
                    let nd_wanted = nd.add_microdesc(md);
                    // This shouldn't ever happen; if it does, our invariants are violated.
                    debug_assert_eq!(wanted, nd_wanted);
                    nd_wanted
                } else {
                    collected_microdescs.push(md);
                    wanted
                }
            }
            PendingNetDir::Dummy => unreachable!(),
        }
    }

    fn n_missing(&self) -> usize {
        match self {
            PendingNetDir::Partial(partial) => partial.n_missing(),
            PendingNetDir::Yielding {
                netdir,
                missing_microdescs,
                ..
            } => {
                if let Some(nd) = netdir.as_ref() {
                    // This shouldn't ever happen; if it does, our invariants are violated.
                    debug_assert_eq!(nd.n_missing(), missing_microdescs.len());
                    nd.n_missing()
                } else {
                    missing_microdescs.len()
                }
            }
            PendingNetDir::Dummy => unreachable!(),
        }
    }
}

impl PendingNetDir {
    /// If this PendingNetDir is Partial and could not be partial, upgrade it.
    fn upgrade_if_necessary(&mut self) {
        if matches!(self, PendingNetDir::Partial(..)) {
            match mem::replace(self, PendingNetDir::Dummy) {
                PendingNetDir::Partial(p) => match p.unwrap_if_sufficient() {
                    Ok(nd) => {
                        let missing: HashSet<_> = nd.missing_microdescs().copied().collect();
                        let replace_dir_time = pick_download_time(nd.lifetime());
                        debug!(
                            "Consensus now usable, with {} microdescriptors missing. \
                                The current consensus is fresh until {}, and valid until {}. \
                                I've picked {} as the earliest time to replace it.",
                            missing.len(),
                            OffsetDateTime::from(nd.lifetime().fresh_until()),
                            OffsetDateTime::from(nd.lifetime().valid_until()),
                            OffsetDateTime::from(replace_dir_time)
                        );
                        *self = PendingNetDir::Yielding {
                            netdir: Some(nd),
                            collected_microdescs: vec![],
                            missing_microdescs: missing,
                            replace_dir_time,
                        };
                    }
                    Err(p) => {
                        *self = PendingNetDir::Partial(p);
                    }
                },
                _ => unreachable!(),
            }
        }
        assert!(!matches!(self, PendingNetDir::Dummy));
    }
}

impl<R: Runtime> GetMicrodescsState<R> {
    /// Create a new [`GetMicrodescsState`] from a provided
    /// microdescriptor consensus.
    fn new(
        cache_usage: CacheUsage,
        consensus: MdConsensus,
        meta: ConsensusMeta,
        rt: R,
        config: Arc<DirMgrConfig>,
        prev_netdir: Option<Arc<dyn PreviousNetDir>>,
        #[cfg(feature = "dirfilter")] filter: Arc<dyn crate::filter::DirFilter>,
    ) -> Self {
        let reset_time = consensus.lifetime().valid_until() + config.tolerance.post_valid_tolerance;
        let n_microdescs = consensus.relays().len();

        let params = &config.override_net_params;
        #[cfg(not(feature = "geoip"))]
        let mut partial_dir = PartialNetDir::new(consensus, Some(params));
        // TODO(eta): Make this embedded database configurable using the `DirMgrConfig`.
        #[cfg(feature = "geoip")]
        let mut partial_dir =
            PartialNetDir::new_with_geoip(consensus, Some(params), &GeoipDb::new_embedded());

        if let Some(old_dir) = prev_netdir.as_ref().and_then(|x| x.get_netdir()) {
            partial_dir.fill_from_previous_netdir(old_dir);
        }

        // Always upgrade at least once: otherwise, we won't notice we're ready unless we
        // add a microdescriptor.
        let mut partial = PendingNetDir::Partial(partial_dir);
        partial.upgrade_if_necessary();

        GetMicrodescsState {
            cache_usage,
            n_microdescs,
            partial,
            meta,
            newly_listed: Vec::new(),
            reset_time,
            rt,
            config,
            prev_netdir,

            #[cfg(feature = "dirfilter")]
            filter,
        }
    }

    /// Add a bunch of microdescriptors to the in-progress netdir.
    fn register_microdescs<I>(&mut self, mds: I, _source: &DocSource, changed: &mut bool)
    where
        I: IntoIterator<Item = Microdesc>,
    {
        #[cfg(feature = "dirfilter")]
        let mds: Vec<Microdesc> = mds
            .into_iter()
            .filter_map(|m| self.filter.filter_md(m).ok())
            .collect();
        let is_partial = matches!(self.partial, PendingNetDir::Partial(..));
        for md in mds {
            if is_partial {
                self.newly_listed.push(*md.digest());
            }
            self.partial.add_microdesc(md);
            *changed = true;
        }
        self.partial.upgrade_if_necessary();
    }
}

impl<R: Runtime> DirState for GetMicrodescsState<R> {
    fn describe(&self) -> String {
        format!(
            "Downloading microdescriptors (we are missing {}).",
            self.partial.n_missing()
        )
    }
    fn missing_docs(&self) -> Vec<DocId> {
        self.partial
            .missing_microdescs()
            .map(|d| DocId::Microdesc(*d))
            .collect()
    }
    fn get_netdir_change(&mut self) -> Option<NetDirChange<'_>> {
        match self.partial {
            PendingNetDir::Yielding {
                ref mut netdir,
                ref mut collected_microdescs,
                ..
            } => {
                if netdir.is_some() {
                    Some(NetDirChange::AttemptReplace {
                        netdir,
                        consensus_meta: &self.meta,
                    })
                } else {
                    collected_microdescs
                        .is_empty()
                        .then_some(NetDirChange::AddMicrodescs(collected_microdescs))
                }
            }
            _ => None,
        }
    }
    fn is_ready(&self, ready: Readiness) -> bool {
        match ready {
            Readiness::Complete => self.partial.n_missing() == 0,
            Readiness::Usable => {
                // We're "usable" if the calling code thought our netdir was usable enough to
                // steal it.
                matches!(self.partial, PendingNetDir::Yielding { ref netdir, .. } if netdir.is_none())
            }
        }
    }
    fn can_advance(&self) -> bool {
        false
    }
    fn bootstrap_progress(&self) -> DirProgress {
        let n_present = self.n_microdescs - self.partial.n_missing();
        DirProgress::Validated {
            lifetime: self.meta.lifetime().clone(),
            usable_lifetime: self.config.tolerance.extend_lifetime(self.meta.lifetime()),
            n_mds: (n_present as u32, self.n_microdescs as u32),
            usable: self.is_ready(Readiness::Usable),
        }
    }
    fn dl_config(&self) -> DownloadSchedule {
        self.config.schedule.retry_microdescs
    }
    fn add_from_cache(
        &mut self,
        docs: HashMap<DocId, DocumentText>,
        changed: &mut bool,
    ) -> Result<()> {
        let mut microdescs = Vec::new();
        for (id, text) in docs {
            if let DocId::Microdesc(digest) = id {
                if let Ok(md) = Microdesc::parse(text.as_str().map_err(Error::BadUtf8InCache)?) {
                    if md.digest() == &digest {
                        microdescs.push(md);
                        continue;
                    }
                }
                warn!("Found a mismatched microdescriptor in cache; ignoring");
            }
        }

        self.register_microdescs(microdescs, &DocSource::LocalCache, changed);
        Ok(())
    }

    fn add_from_download(
        &mut self,
        text: &str,
        request: &ClientRequest,
        source: DocSource,
        storage: Option<&Mutex<DynStore>>,
        changed: &mut bool,
    ) -> Result<()> {
        let requested: HashSet<_> = if let ClientRequest::Microdescs(req) = request {
            req.digests().collect()
        } else {
            return Err(internal!("expected a microdesc request").into());
        };
        let mut new_mds = Vec::new();
        let mut nonfatal_err = None;

        for anno in MicrodescReader::new(text, &AllowAnnotations::AnnotationsNotAllowed) {
            let anno = match anno {
                Err(e) => {
                    nonfatal_err.get_or_insert_with(|| Error::from_netdoc(source.clone(), e));
                    continue;
                }
                Ok(a) => a,
            };
            let txt = anno
                .within(text)
                .expect("microdesc not from within text as expected");
            let md = anno.into_microdesc();
            if !requested.contains(md.digest()) {
                warn!(
                    "Received microdescriptor from {} we did not ask for: {:?}",
                    source,
                    md.digest()
                );
                nonfatal_err.get_or_insert(Error::Unwanted("un-requested microdescriptor"));
                continue;
            }
            new_mds.push((txt, md));
        }

        let mark_listed = self.meta.lifetime().valid_after();
        if let Some(store) = storage {
            let mut s = store
                .lock()
                //.get_mut()
                .expect("Directory storage lock poisoned");
            if !self.newly_listed.is_empty() {
                s.update_microdescs_listed(&self.newly_listed, mark_listed)?;
                self.newly_listed.clear();
            }
            if !new_mds.is_empty() {
                s.store_microdescs(
                    &new_mds
                        .iter()
                        .map(|(text, md)| (*text, md.digest()))
                        .collect::<Vec<_>>(),
                    mark_listed,
                )?;
            }
        }

        self.register_microdescs(new_mds.into_iter().map(|(_, md)| md), &source, changed);

        opt_err_to_result(nonfatal_err)
    }
    fn advance(self: Box<Self>) -> Box<dyn DirState> {
        self
    }
    fn reset_time(&self) -> Option<SystemTime> {
        // TODO(nickm): The reset logic is a little wonky here: we don't truly
        // want to _reset_ this state at `replace_dir_time`.  In fact, we ought
        // to be able to have multiple states running in parallel: one filling
        // in the mds for an old consensus, and one trying to fetch a better
        // one.  That's likely to require some amount of refactoring of the
        // bootstrap code.

        Some(match self.partial {
            // If the client has taken a completed netdir, the netdir is now
            // usable: We can reset our download attempt when we choose to try
            // to replace this directory.
            PendingNetDir::Yielding {
                replace_dir_time,
                netdir: None,
                ..
            } => replace_dir_time,
            // We don't have a completed netdir: Keep trying to fill this one in
            // until it is _definitely_ unusable.  (Our clock might be skewed;
            // there might be no up-to-date consensus.)
            _ => self.reset_time,
        })
    }
    fn reset(self: Box<Self>) -> Box<dyn DirState> {
        let cache_usage = if self.cache_usage == CacheUsage::CacheOnly {
            // Cache only means we can't ever download.
            CacheUsage::CacheOnly
        } else if self.is_ready(Readiness::Usable) {
            // If we managed to bootstrap a usable consensus, then we won't
            // accept our next consensus from the cache.
            CacheUsage::MustDownload
        } else {
            // If we didn't manage to bootstrap a usable consensus, then we can
            // indeed try again with the one in the cache.
            // TODO(nickm) is this right?
            CacheUsage::CacheOkay
        };
        Box::new(GetConsensusState::new(
            self.rt,
            self.config,
            cache_usage,
            self.prev_netdir,
            #[cfg(feature = "dirfilter")]
            self.filter,
        ))
    }
}

/// Choose a random download time to replace a consensus whose lifetime
/// is `lifetime`.
fn pick_download_time(lifetime: &Lifetime) -> SystemTime {
    let (lowbound, uncertainty) = client_download_range(lifetime);
    lowbound + rand::thread_rng().gen_range_infallible(..=uncertainty)
}

/// Based on the lifetime for a consensus, return the time range during which
/// clients should fetch the next one.
fn client_download_range(lt: &Lifetime) -> (SystemTime, Duration) {
    let valid_after = lt.valid_after();
    let valid_until = lt.valid_until();
    let voting_interval = lt.voting_period();
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

/// If `err` is some, return `Err(err)`.  Otherwise return Ok(()).
fn opt_err_to_result(e: Option<Error>) -> Result<()> {
    match e {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// A dummy state implementation, used when we need to temporarily write a
/// placeholder into a box.
///
/// Calling any method on this state will panic.
#[derive(Clone, Debug)]
pub(crate) struct PoisonedState;

impl DirState for PoisonedState {
    fn describe(&self) -> String {
        unimplemented!()
    }
    fn missing_docs(&self) -> Vec<DocId> {
        unimplemented!()
    }
    fn is_ready(&self, _ready: Readiness) -> bool {
        unimplemented!()
    }
    fn can_advance(&self) -> bool {
        unimplemented!()
    }
    fn add_from_cache(
        &mut self,
        _docs: HashMap<DocId, DocumentText>,
        _changed: &mut bool,
    ) -> Result<()> {
        unimplemented!()
    }
    fn add_from_download(
        &mut self,
        _text: &str,
        _request: &ClientRequest,
        _source: DocSource,
        _storage: Option<&Mutex<DynStore>>,
        _changed: &mut bool,
    ) -> Result<()> {
        unimplemented!()
    }
    fn bootstrap_progress(&self) -> event::DirProgress {
        unimplemented!()
    }
    fn dl_config(&self) -> DownloadSchedule {
        unimplemented!()
    }
    fn advance(self: Box<Self>) -> Box<dyn DirState> {
        unimplemented!()
    }
    fn reset_time(&self) -> Option<SystemTime> {
        unimplemented!()
    }
    fn reset(self: Box<Self>) -> Box<dyn DirState> {
        unimplemented!()
    }
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    #![allow(clippy::cognitive_complexity)]
    use super::*;
    use crate::{Authority, AuthorityBuilder, DownloadScheduleConfig};
    use std::convert::TryInto;
    use std::sync::Arc;
    use tempfile::TempDir;
    use time::macros::datetime;
    use tor_netdoc::doc::authcert::AuthCertKeyIds;
    use tor_rtcompat::CompoundRuntime;
    use tor_rtmock::time::MockSleepProvider;

    #[test]
    fn download_schedule() {
        let va = datetime!(2008-08-02 20:00 UTC).into();
        let fu = datetime!(2008-08-02 21:00 UTC).into();
        let vu = datetime!(2008-08-02 23:00 UTC).into();
        let lifetime = Lifetime::new(va, fu, vu).unwrap();

        let expected_start: SystemTime = datetime!(2008-08-02 21:45 UTC).into();
        let expected_range = Duration::from_millis((75 * 60 * 1000) * 7 / 8);

        let (start, range) = client_download_range(&lifetime);
        assert_eq!(start, expected_start);
        assert_eq!(range, expected_range);

        for _ in 0..100 {
            let when = pick_download_time(&lifetime);
            assert!(when > va);
            assert!(when >= expected_start);
            assert!(when < vu);
            assert!(when <= expected_start + range);
        }
    }

    /// Makes a memory-backed storage.
    fn temp_store() -> (TempDir, Mutex<DynStore>) {
        let tempdir = TempDir::new().unwrap();

        let store = crate::storage::SqliteStore::from_path_and_mistrust(
            tempdir.path(),
            &fs_mistrust::Mistrust::new_dangerously_trust_everyone(),
            false,
        )
        .unwrap();

        (tempdir, Mutex::new(Box::new(store)))
    }

    fn make_time_shifted_runtime(now: SystemTime, rt: impl Runtime) -> impl Runtime {
        let msp = MockSleepProvider::new(now);
        CompoundRuntime::new(rt.clone(), msp.clone(), msp, rt.clone(), rt.clone(), rt)
    }

    fn make_dirmgr_config(authorities: Option<Vec<AuthorityBuilder>>) -> Arc<DirMgrConfig> {
        let mut netcfg = crate::NetworkConfig::builder();
        netcfg.set_fallback_caches(vec![]);
        if let Some(a) = authorities {
            netcfg.set_authorities(a);
        }
        let cfg = DirMgrConfig {
            cache_dir: "/we_will_never_use_this/".into(),
            network: netcfg.build().unwrap(),
            ..Default::default()
        };
        Arc::new(cfg)
    }

    // Test data
    const CONSENSUS: &str = include_str!("../testdata/mdconsensus1.txt");
    const CONSENSUS2: &str = include_str!("../testdata/mdconsensus2.txt");
    const AUTHCERT_5696: &str = include_str!("../testdata/cert-5696.txt");
    const AUTHCERT_5A23: &str = include_str!("../testdata/cert-5A23.txt");
    #[allow(unused)]
    const AUTHCERT_7C47: &str = include_str!("../testdata/cert-7C47.txt");
    fn test_time() -> SystemTime {
        datetime!(2020-08-07 12:42:45 UTC).into()
    }
    fn rsa(s: &str) -> RsaIdentity {
        RsaIdentity::from_hex(s).unwrap()
    }
    fn test_authorities() -> Vec<AuthorityBuilder> {
        fn a(s: &str) -> AuthorityBuilder {
            Authority::builder().name("ignore").v3ident(rsa(s)).clone()
        }
        vec![
            a("5696AB38CB3852AFA476A5C07B2D4788963D5567"),
            a("5A23BA701776C9C1AB1C06E734E92AB3D5350D64"),
            // This is an authority according to the consensus, but we'll
            // pretend we don't recognize it, to make sure that we
            // don't fetch or accept it.
            // a("7C47DCB4A90E2C2B7C7AD27BD641D038CF5D7EBE"),
        ]
    }
    fn authcert_id_5696() -> AuthCertKeyIds {
        AuthCertKeyIds {
            id_fingerprint: rsa("5696ab38cb3852afa476a5c07b2d4788963d5567"),
            sk_fingerprint: rsa("f6ed4aa64d83caede34e19693a7fcf331aae8a6a"),
        }
    }
    fn authcert_id_5a23() -> AuthCertKeyIds {
        AuthCertKeyIds {
            id_fingerprint: rsa("5a23ba701776c9c1ab1c06e734e92ab3d5350d64"),
            sk_fingerprint: rsa("d08e965cc6dcb6cb6ed776db43e616e93af61177"),
        }
    }
    // remember, we're saying that we don't recognize this one as an authority.
    fn authcert_id_7c47() -> AuthCertKeyIds {
        AuthCertKeyIds {
            id_fingerprint: rsa("7C47DCB4A90E2C2B7C7AD27BD641D038CF5D7EBE"),
            sk_fingerprint: rsa("D3C013E0E6C82E246090D1C0798B75FCB7ACF120"),
        }
    }
    fn microdescs() -> HashMap<MdDigest, String> {
        const MICRODESCS: &str = include_str!("../testdata/microdescs.txt");
        let text = MICRODESCS;
        MicrodescReader::new(text, &AllowAnnotations::AnnotationsNotAllowed)
            .map(|res| {
                let anno = res.unwrap();
                let text = anno.within(text).unwrap();
                let md = anno.into_microdesc();
                (*md.digest(), text.to_owned())
            })
            .collect()
    }

    #[test]
    fn get_consensus_state() {
        tor_rtcompat::test_with_one_runtime!(|rt| async move {
            let rt = make_time_shifted_runtime(test_time(), rt);
            let cfg = make_dirmgr_config(None);

            let (_tempdir, store) = temp_store();

            let mut state = GetConsensusState::new(
                rt.clone(),
                cfg,
                CacheUsage::CacheOkay,
                None,
                #[cfg(feature = "dirfilter")]
                Arc::new(crate::filter::NilFilter),
            );

            // Is description okay?
            assert_eq!(&state.describe(), "Looking for a consensus.");

            // Basic properties: without a consensus it is not ready to advance.
            assert!(!state.can_advance());
            assert!(!state.is_ready(Readiness::Complete));
            assert!(!state.is_ready(Readiness::Usable));

            // Basic properties: it doesn't want to reset.
            assert!(state.reset_time().is_none());

            // Its starting DirStatus is "fetching a consensus".
            assert_eq!(
                state.bootstrap_progress().to_string(),
                "fetching a consensus"
            );

            // Download configuration is simple: only 1 request can be done in
            // parallel.  It uses a consensus retry schedule.
            let retry = state.dl_config();
            assert_eq!(retry, DownloadScheduleConfig::default().retry_consensus);

            // Do we know what we want?
            let docs = state.missing_docs();
            assert_eq!(docs.len(), 1);
            let docid = docs[0];

            assert!(matches!(
                docid,
                DocId::LatestConsensus {
                    flavor: ConsensusFlavor::Microdesc,
                    cache_usage: CacheUsage::CacheOkay,
                }
            ));
            let source = DocSource::DirServer { source: None };

            // Now suppose that we get some complete junk from a download.
            let req = tor_dirclient::request::ConsensusRequest::new(ConsensusFlavor::Microdesc);
            let req = crate::docid::ClientRequest::Consensus(req);
            let mut changed = false;
            let outcome = state.add_from_download(
                "this isn't a consensus",
                &req,
                source.clone(),
                Some(&store),
                &mut changed,
            );
            assert!(matches!(outcome, Err(Error::NetDocError { .. })));
            assert!(!changed);
            // make sure it wasn't stored...
            assert!(store
                .lock()
                .unwrap()
                .latest_consensus(ConsensusFlavor::Microdesc, None)
                .unwrap()
                .is_none());

            // Now try again, with a real consensus... but the wrong authorities.
            let mut changed = false;
            let outcome = state.add_from_download(
                CONSENSUS,
                &req,
                source.clone(),
                Some(&store),
                &mut changed,
            );
            assert!(matches!(outcome, Err(Error::UnrecognizedAuthorities)));
            assert!(!changed);
            assert!(store
                .lock()
                .unwrap()
                .latest_consensus(ConsensusFlavor::Microdesc, None)
                .unwrap()
                .is_none());

            // Great. Change the receiver to use a configuration where these test
            // authorities are recognized.
            let cfg = make_dirmgr_config(Some(test_authorities()));

            let mut state = GetConsensusState::new(
                rt.clone(),
                cfg,
                CacheUsage::CacheOkay,
                None,
                #[cfg(feature = "dirfilter")]
                Arc::new(crate::filter::NilFilter),
            );
            let mut changed = false;
            let outcome =
                state.add_from_download(CONSENSUS, &req, source, Some(&store), &mut changed);
            assert!(outcome.is_ok());
            assert!(changed);
            assert!(store
                .lock()
                .unwrap()
                .latest_consensus(ConsensusFlavor::Microdesc, None)
                .unwrap()
                .is_some());

            // And with that, we should be asking for certificates
            assert!(state.can_advance());
            assert_eq!(&state.describe(), "About to fetch certificates.");
            assert_eq!(state.missing_docs(), Vec::new());
            let next = Box::new(state).advance();
            assert_eq!(
                &next.describe(),
                "Downloading certificates for consensus (we are missing 2/2)."
            );

            // Try again, but this time get the state from the cache.
            let cfg = make_dirmgr_config(Some(test_authorities()));
            let mut state = GetConsensusState::new(
                rt,
                cfg,
                CacheUsage::CacheOkay,
                None,
                #[cfg(feature = "dirfilter")]
                Arc::new(crate::filter::NilFilter),
            );
            let text: crate::storage::InputString = CONSENSUS.to_owned().into();
            let map = vec![(docid, text.into())].into_iter().collect();
            let mut changed = false;
            let outcome = state.add_from_cache(map, &mut changed);
            assert!(outcome.is_ok());
            assert!(changed);
            assert!(state.can_advance());
        });
    }

    #[test]
    fn get_certs_state() {
        tor_rtcompat::test_with_one_runtime!(|rt| async move {
            /// Construct a GetCertsState with our test data
            fn new_getcerts_state(rt: impl Runtime) -> Box<dyn DirState> {
                let rt = make_time_shifted_runtime(test_time(), rt);
                let cfg = make_dirmgr_config(Some(test_authorities()));
                let mut state = GetConsensusState::new(
                    rt,
                    cfg,
                    CacheUsage::CacheOkay,
                    None,
                    #[cfg(feature = "dirfilter")]
                    Arc::new(crate::filter::NilFilter),
                );
                let source = DocSource::DirServer { source: None };
                let req = tor_dirclient::request::ConsensusRequest::new(ConsensusFlavor::Microdesc);
                let req = crate::docid::ClientRequest::Consensus(req);
                let mut changed = false;
                let outcome = state.add_from_download(CONSENSUS, &req, source, None, &mut changed);
                assert!(outcome.is_ok());
                Box::new(state).advance()
            }

            let (_tempdir, store) = temp_store();
            let mut state = new_getcerts_state(rt.clone());
            // Basic properties: description, status, reset time.
            assert_eq!(
                &state.describe(),
                "Downloading certificates for consensus (we are missing 2/2)."
            );
            assert!(!state.can_advance());
            assert!(!state.is_ready(Readiness::Complete));
            assert!(!state.is_ready(Readiness::Usable));
            let consensus_expires: SystemTime = datetime!(2020-08-07 12:43:20 UTC).into();
            let post_valid_tolerance = crate::DirTolerance::default().post_valid_tolerance;
            assert_eq!(
                state.reset_time(),
                Some(consensus_expires + post_valid_tolerance)
            );
            let retry = state.dl_config();
            assert_eq!(retry, DownloadScheduleConfig::default().retry_certs);

            // Bootstrap status okay?
            assert_eq!(
                state.bootstrap_progress().to_string(),
                "fetching authority certificates (0/2)"
            );

            // Check that we get the right list of missing docs.
            let missing = state.missing_docs();
            assert_eq!(missing.len(), 2); // We are missing two certificates.
            assert!(missing.contains(&DocId::AuthCert(authcert_id_5696())));
            assert!(missing.contains(&DocId::AuthCert(authcert_id_5a23())));
            // we don't ask for this one because we don't recognize its authority
            assert!(!missing.contains(&DocId::AuthCert(authcert_id_7c47())));

            // Add one from the cache; make sure the list is still right
            let text1: crate::storage::InputString = AUTHCERT_5696.to_owned().into();
            // let text2: crate::storage::InputString = AUTHCERT_5A23.to_owned().into();
            let docs = vec![(DocId::AuthCert(authcert_id_5696()), text1.into())]
                .into_iter()
                .collect();
            let mut changed = false;
            let outcome = state.add_from_cache(docs, &mut changed);
            assert!(changed);
            assert!(outcome.is_ok()); // no error, and something changed.
            assert!(!state.can_advance()); // But we aren't done yet.
            let missing = state.missing_docs();
            assert_eq!(missing.len(), 1); // Now we're only missing one!
            assert!(missing.contains(&DocId::AuthCert(authcert_id_5a23())));
            assert_eq!(
                state.bootstrap_progress().to_string(),
                "fetching authority certificates (1/2)"
            );

            // Now try to add the other from a download ... but fail
            // because we didn't ask for it.
            let source = DocSource::DirServer { source: None };
            let mut req = tor_dirclient::request::AuthCertRequest::new();
            req.push(authcert_id_5696()); // it's the wrong id.
            let req = ClientRequest::AuthCert(req);
            let mut changed = false;
            let outcome = state.add_from_download(
                AUTHCERT_5A23,
                &req,
                source.clone(),
                Some(&store),
                &mut changed,
            );
            assert!(matches!(outcome, Err(Error::Unwanted(_))));
            assert!(!changed);
            let missing2 = state.missing_docs();
            assert_eq!(missing, missing2); // No change.
            assert!(store
                .lock()
                .unwrap()
                .authcerts(&[authcert_id_5a23()])
                .unwrap()
                .is_empty());

            // Now try to add the other from a download ... for real!
            let mut req = tor_dirclient::request::AuthCertRequest::new();
            req.push(authcert_id_5a23()); // Right idea this time!
            let req = ClientRequest::AuthCert(req);
            let mut changed = false;
            let outcome =
                state.add_from_download(AUTHCERT_5A23, &req, source, Some(&store), &mut changed);
            assert!(outcome.is_ok()); // No error, _and_ something changed!
            assert!(changed);
            let missing3 = state.missing_docs();
            assert!(missing3.is_empty());
            assert!(state.can_advance());
            assert!(!store
                .lock()
                .unwrap()
                .authcerts(&[authcert_id_5a23()])
                .unwrap()
                .is_empty());

            let next = state.advance();
            assert_eq!(
                &next.describe(),
                "Downloading microdescriptors (we are missing 6)."
            );

            // If we start from scratch and reset, we're back in GetConsensus.
            let state = new_getcerts_state(rt);
            let state = state.reset();
            assert_eq!(&state.describe(), "Downloading a consensus.");

            // TODO: I'd like even more tests to make sure that we never
            // accept a certificate for an authority we don't believe in.
        });
    }

    #[test]
    fn get_microdescs_state() {
        tor_rtcompat::test_with_one_runtime!(|rt| async move {
            /// Construct a GetCertsState with our test data
            fn new_getmicrodescs_state(rt: impl Runtime) -> GetMicrodescsState<impl Runtime> {
                let rt = make_time_shifted_runtime(test_time(), rt);
                let cfg = make_dirmgr_config(Some(test_authorities()));
                let (signed, rest, consensus) = MdConsensus::parse(CONSENSUS2).unwrap();
                let consensus = consensus
                    .dangerously_assume_timely()
                    .dangerously_assume_wellsigned();
                let meta = ConsensusMeta::from_consensus(signed, rest, &consensus);
                GetMicrodescsState::new(
                    CacheUsage::CacheOkay,
                    consensus,
                    meta,
                    rt,
                    cfg,
                    None,
                    #[cfg(feature = "dirfilter")]
                    Arc::new(crate::filter::NilFilter),
                )
            }
            fn d64(s: &str) -> MdDigest {
                use base64ct::{Base64Unpadded, Encoding as _};
                Base64Unpadded::decode_vec(s).unwrap().try_into().unwrap()
            }

            // If we start from scratch and reset, we're back in GetConsensus.
            let state = new_getmicrodescs_state(rt.clone());
            let state = Box::new(state).reset();
            assert_eq!(&state.describe(), "Looking for a consensus.");

            // Check the basics.
            let mut state = new_getmicrodescs_state(rt.clone());
            assert_eq!(
                &state.describe(),
                "Downloading microdescriptors (we are missing 4)."
            );
            assert!(!state.can_advance());
            assert!(!state.is_ready(Readiness::Complete));
            assert!(!state.is_ready(Readiness::Usable));
            {
                let reset_time = state.reset_time().unwrap();
                let fresh_until: SystemTime = datetime!(2021-10-27 21:27:00 UTC).into();
                let valid_until: SystemTime = datetime!(2021-10-27 21:27:20 UTC).into();
                assert!(reset_time >= fresh_until);
                assert!(reset_time <= valid_until + state.config.tolerance.post_valid_tolerance);
            }
            let retry = state.dl_config();
            assert_eq!(retry, DownloadScheduleConfig::default().retry_microdescs);
            assert_eq!(
                state.bootstrap_progress().to_string(),
                "fetching microdescriptors (0/4)"
            );

            // Now check whether we're missing all the right microdescs.
            let missing = state.missing_docs();
            let md_text = microdescs();
            assert_eq!(missing.len(), 4);
            assert_eq!(md_text.len(), 4);
            let md1 = d64("LOXRj8YZP0kwpEAsYOvBZWZWGoWv5b/Bp2Mz2Us8d8g");
            let md2 = d64("iOhVp33NyZxMRDMHsVNq575rkpRViIJ9LN9yn++nPG0");
            let md3 = d64("/Cd07b3Bl0K0jX2/1cAvsYXJJMi5d8UBU+oWKaLxoGo");
            let md4 = d64("z+oOlR7Ga6cg9OoC/A3D3Ey9Rtc4OldhKlpQblMfQKo");
            for md_digest in [md1, md2, md3, md4] {
                assert!(missing.contains(&DocId::Microdesc(md_digest)));
                assert!(md_text.contains_key(&md_digest));
            }

            // Try adding a microdesc from the cache.
            let (_tempdir, store) = temp_store();
            let doc1: crate::storage::InputString = md_text.get(&md1).unwrap().clone().into();
            let docs = vec![(DocId::Microdesc(md1), doc1.into())]
                .into_iter()
                .collect();
            let mut changed = false;
            let outcome = state.add_from_cache(docs, &mut changed);
            assert!(outcome.is_ok()); // successfully loaded one MD.
            assert!(changed);
            assert!(!state.can_advance());
            assert!(!state.is_ready(Readiness::Complete));
            assert!(!state.is_ready(Readiness::Usable));

            // Now we should be missing 3.
            let missing = state.missing_docs();
            assert_eq!(missing.len(), 3);
            assert!(!missing.contains(&DocId::Microdesc(md1)));
            assert_eq!(
                state.bootstrap_progress().to_string(),
                "fetching microdescriptors (1/4)"
            );

            // Try adding the rest as if from a download.
            let mut req = tor_dirclient::request::MicrodescRequest::new();
            let mut response = "".to_owned();
            for md_digest in [md2, md3, md4] {
                response.push_str(md_text.get(&md_digest).unwrap());
                req.push(md_digest);
            }
            let req = ClientRequest::Microdescs(req);
            let source = DocSource::DirServer { source: None };
            let mut changed = false;
            let outcome = state.add_from_download(
                response.as_str(),
                &req,
                source,
                Some(&store),
                &mut changed,
            );
            assert!(outcome.is_ok()); // successfully loaded MDs
            assert!(changed);
            match state.get_netdir_change().unwrap() {
                NetDirChange::AttemptReplace { netdir, .. } => {
                    assert!(netdir.take().is_some());
                }
                x => panic!("wrong netdir change: {:?}", x),
            }
            assert!(state.is_ready(Readiness::Complete));
            assert!(state.is_ready(Readiness::Usable));
            assert_eq!(
                store
                    .lock()
                    .unwrap()
                    .microdescs(&[md2, md3, md4])
                    .unwrap()
                    .len(),
                3
            );

            let missing = state.missing_docs();
            assert!(missing.is_empty());
        });
    }
}
