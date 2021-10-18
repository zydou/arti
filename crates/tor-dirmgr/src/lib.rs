//! `tor-dirmgr`: Code to fetch, store, and update Tor directory information.
//!
//! # Overview
//!
//! This crate is part of
//! [Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
//! implement [Tor](https://www.torproject.org/) in Rust.
//!
//! In its current design, Tor requires a set of up-to-date
//! authenticated directory documents in order to build multi-hop
//! anonymized circuits through the network.
//!
//! This directory manager crate is responsible for figuring out which
//! directory information we lack, downloading what we're missing, and
//! keeping a cache of it on disk.
//!
//! # Compile-time features
//!
//! `mmap` (default) -- Use memory mapping to reduce the memory load for
//! reading large directory objects from disk.
//!
//! `static` -- Try to link with a static copy of sqlite3.

#![deny(missing_docs)]
#![warn(noop_method_call)]
#![deny(unreachable_pub)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::checked_conversions)]
#![warn(clippy::clone_on_ref_ptr)]
#![warn(clippy::cognitive_complexity)]
#![deny(clippy::debug_assert_with_mut_call)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::expl_impl_clone_on_copy)]
#![deny(clippy::fallible_impl_from)]
#![deny(clippy::implicit_clone)]
#![deny(clippy::large_stack_arrays)]
#![warn(clippy::manual_ok_or)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(clippy::missing_panics_doc)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]

pub mod authority;
mod bootstrap;
mod config;
mod docid;
mod docmeta;
mod err;
mod event;
mod retry;
mod shared_ref;
mod state;
mod storage;

use crate::docid::{CacheUsage, ClientRequest, DocQuery};
use crate::shared_ref::SharedMutArc;
use crate::storage::sqlite::SqliteStore;
use retry::RetryConfig;
use tor_circmgr::CircMgr;
use tor_netdir::NetDir;
use tor_netdoc::doc::netstatus::ConsensusFlavor;

use async_trait::async_trait;
use futures::{channel::oneshot, lock::Mutex, task::SpawnExt};
use tor_rtcompat::{Runtime, SleepProviderExt};
use tracing::{info, trace, warn};

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{collections::HashMap, sync::Weak};
use std::{fmt::Debug, time::SystemTime};

pub use authority::{Authority, AuthorityBuilder};
pub use config::{
    DirMgrConfig, DirMgrConfigBuilder, DownloadScheduleConfig, DownloadScheduleConfigBuilder,
    NetworkConfig, NetworkConfigBuilder,
};
pub use docid::DocId;
pub use err::Error;
pub use event::DirEvent;
pub use storage::DocumentText;
pub use tor_netdir::fallback::{FallbackDir, FallbackDirBuilder};

/// A Result as returned by this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// A directory manager to download, fetch, and cache a Tor directory.
///
/// A DirMgr can operate in three modes:
///   * In **offline** mode, it only reads from the cache, and can
///     only read once.
///   * In **read-only** mode, it reads from the cache, but checks
///     whether it can acquire an associated lock file.  If it can, then
///     it enters read-write mode.  If not, it checks the cache
///     periodically for new information.
///   * In **read-write** mode, it knows that no other process will be
///     writing to the cache, and it takes responsibility for fetching
///     data from the network and updating the directory with new
///     directory information.
pub struct DirMgr<R: Runtime> {
    /// Configuration information: where to find directories, how to
    /// validate them, and so on.
    config: DirMgrConfig,
    /// Handle to our sqlite cache.
    // XXXX I'd like to use an rwlock, but that's not feasible, since
    // rusqlite::Connection isn't Sync.
    // TODO: Does this have to be a futures::Mutex?  I would rather have
    // a rule that we never hold the guard for this mutex across an async
    // suspend point.  But that will be hard to enforce until the
    // `must_not_suspend` lint is in stable.
    store: Mutex<SqliteStore>,
    /// Our latest sufficiently bootstrapped directory, if we have one.
    ///
    /// We use the RwLock so that we can give this out to a bunch of other
    /// users, and replace it once a new directory is bootstrapped.
    netdir: SharedMutArc<NetDir>,

    /// A flag that gets set whenever the _consensus_ part of `netdir` has
    /// changed.
    netdir_consensus_changed: AtomicBool,

    /// A flag that gets set whenever the _descriptors_ part of `netdir` has
    /// changed without adding a new consensus.
    netdir_descriptors_changed: AtomicBool,

    /// A publisher handle, used to inform others about changes in the
    /// status of this directory handle.
    publisher: event::Publisher,

    /// A circuit manager, if this DirMgr supports downloading.
    circmgr: Option<Arc<CircMgr<R>>>,

    /// Our asynchronous runtime.
    runtime: R,
}

impl<R: Runtime> DirMgr<R> {
    /// Try to load the directory from disk, without launching any
    /// kind of update process.
    ///
    /// This function runs in **offline** mode: it will give an error
    /// if the result is not up-to-date, or not fully downloaded.
    ///
    /// In general, you shouldn't use this function in a long-running
    /// program; it's only suitable for command-line or batch tools.
    // TODO: I wish this function didn't have to be async or take a runtime.
    pub async fn load_once(runtime: R, config: DirMgrConfig) -> Result<Arc<NetDir>> {
        let dirmgr = Arc::new(Self::from_config(config, runtime, None)?);

        // TODO: add some way to return a directory that isn't up-to-date
        let _success = dirmgr.load_directory().await?;

        dirmgr.opt_netdir().ok_or(Error::DirectoryNotPresent)
    }

    /// Return a current netdir, either loading it or bootstrapping it
    /// as needed.
    ///
    /// Like load_once, but will try to bootstrap (or wait for another
    /// process to bootstrap) if we don't have an up-to-date
    /// bootstrapped directory.
    ///
    /// In general, you shouldn't use this function in a long-running
    /// program; it's only suitable for command-line or batch tools.
    pub async fn load_or_bootstrap_once(
        config: DirMgrConfig,
        runtime: R,
        circmgr: Arc<CircMgr<R>>,
    ) -> Result<Arc<NetDir>> {
        let dirmgr = DirMgr::bootstrap_from_config(config, runtime, circmgr).await?;
        Ok(dirmgr.netdir())
    }

    /// Return a new directory manager from a given configuration,
    /// bootstrapping from the network as necessary.
    ///
    /// This function will to return until the directory is
    /// bootstrapped enough to build circuits.  It will also launch a
    /// background task that fetches any missing information, and that
    /// replaces the directory when a new one is available.
    pub async fn bootstrap_from_config(
        config: DirMgrConfig,
        runtime: R,
        circmgr: Arc<CircMgr<R>>,
    ) -> Result<Arc<Self>> {
        let dirmgr = Arc::new(DirMgr::from_config(config, runtime.clone(), Some(circmgr))?);

        // Try to load from the cache.
        let have_directory = dirmgr.load_directory().await?;

        let (mut sender, receiver) = if have_directory {
            info!("Loaded a good directory from cache.");
            (None, None)
        } else {
            info!("Didn't get usable directory from cache.");
            let (sender, receiver) = oneshot::channel();
            (Some(sender), Some(receiver))
        };

        // Whether we loaded or not, we now start downloading.
        let dirmgr_weak = Arc::downgrade(&dirmgr);
        runtime.spawn(async move {
            // NOTE: This is a daemon task.  It should eventually get
            // treated as one.

            // TODO: don't warn when these are Error::ManagerDropped: that
            // means that the DirMgr has been shut down.
            if let Err(e) = Self::reload_until_owner(&dirmgr_weak, &mut sender).await {
                warn!("Unrecovered error while waiting for bootstrap: {}", e);
            } else if let Err(e) = Self::download_forever(dirmgr_weak, sender).await {
                warn!("Unrecovered error while downloading: {}", e);
            }
        })?;

        if let Some(receiver) = receiver {
            match receiver.await {
                Ok(()) => {
                    info!("We have enough information to build circuits.");
                }
                Err(_) => {
                    warn!("Bootstrapping task exited before finishing.");
                    return Err(Error::CantAdvanceState);
                }
            }
        }

        Ok(dirmgr)
    }

    /// Try forever to either lock the storage (and thereby become the
    /// owner), or to reload the database.
    ///
    /// If we have begin to have a bootstrapped directory, send a
    /// message using `on_complete`.
    ///
    /// If we eventually become the owner, return Ok().
    async fn reload_until_owner(
        weak: &Weak<Self>,
        on_complete: &mut Option<oneshot::Sender<()>>,
    ) -> Result<()> {
        let mut logged = false;
        let mut bootstrapped = false;
        let runtime = upgrade_weak_ref(weak)?.runtime.clone();

        loop {
            {
                let dirmgr = upgrade_weak_ref(weak)?;
                if dirmgr.try_upgrade_to_readwrite().await? {
                    // We now own the lock!  (Maybe we owned it before; the
                    // upgrade_to_readwrite() function is idempotent.)  We can
                    // do our own bootstrapping.
                    return Ok(());
                }
            }

            if !logged {
                logged = true;
                info!("Another process is bootstrapping. Waiting till it finishes or exits.");
            }

            // We don't own the lock.  Somebody else owns the cache.  They
            // should be updating it.  Wait a bit, then try again.
            let pause = if bootstrapped {
                std::time::Duration::new(120, 0)
            } else {
                std::time::Duration::new(5, 0)
            };
            runtime.sleep(pause).await;
            // TODO: instead of loading the whole thing we should have a
            // database entry that says when the last update was, or use
            // our state functions.
            {
                let dirmgr = upgrade_weak_ref(weak)?;
                if dirmgr.load_directory().await? {
                    // Successfully loaded a bootstrapped directory.
                    if let Some(send_done) = on_complete.take() {
                        let _ = send_done.send(());
                    }
                    bootstrapped = true;
                }
            }
        }
    }

    /// Try to fetch our directory info and keep it updated, indefinitely.
    ///
    /// If we have begin to have a bootstrapped directory, send a
    /// message using `on_complete`.
    async fn download_forever(
        weak: Weak<Self>,
        mut on_complete: Option<oneshot::Sender<()>>,
    ) -> Result<()> {
        let mut state: Box<dyn DirState> = Box::new(state::GetConsensusState::new(
            Weak::clone(&weak),
            CacheUsage::CacheOkay,
        )?);

        let (retry_config, runtime) = {
            let dirmgr = upgrade_weak_ref(&weak)?;
            (
                *dirmgr.config.schedule().retry_bootstrap(),
                dirmgr.runtime.clone(),
            )
        };

        loop {
            let mut usable = false;
            let mut retry_delay = retry_config.schedule();

            'retry_attempt: for _ in retry_config.attempts() {
                let (newstate, recoverable_err) =
                    bootstrap::download(Weak::clone(&weak), state, &mut on_complete).await?;
                state = newstate;

                if let Some(err) = recoverable_err {
                    if state.is_ready(Readiness::Usable) {
                        usable = true;
                        info!("Unable to completely download a directory: {}.  Nevertheless, the directory is usable, so we'll pause for now.", err);
                        break 'retry_attempt;
                    }

                    let delay = retry_delay.next_delay(&mut rand::thread_rng());
                    warn!(
                        "Unable to download a usable directory: {}.  We will restart in {:?}.",
                        err, delay
                    );
                    runtime.sleep(delay).await;
                    state = state.reset()?;
                } else {
                    info!("Directory is complete.");
                    usable = true;
                    break 'retry_attempt;
                }
            }

            if !usable {
                // we ran out of attempts.
                warn!(
                    "We failed {} times to bootstrap a directory. We're going to give up.",
                    retry_config.n_attempts()
                );
                return Err(Error::CantAdvanceState);
            } else {
                // Report success, if appropriate.
                if let Some(send_done) = on_complete.take() {
                    let _ = send_done.send(());
                }
            }

            let reset_at = state.reset_time();
            match reset_at {
                Some(t) => runtime.sleep_until_wallclock(t).await,
                None => return Ok(()),
            }
            state = state.reset()?;
        }
    }

    /// Get a reference to the circuit manager, if we have one.
    fn circmgr(&self) -> Result<Arc<CircMgr<R>>> {
        self.circmgr
            .as_ref()
            .map(Arc::clone)
            .ok_or(Error::NoDownloadSupport)
    }

    /// Try to make this a directory manager with read-write access to its
    /// storage.
    ///
    /// Return true if we got the lock, or if we already had it.
    ///
    /// Return false if another process has the lock
    async fn try_upgrade_to_readwrite(&self) -> Result<bool> {
        self.store.lock().await.upgrade_to_readwrite()
    }

    /// Construct a DirMgr from a DirMgrConfig.
    fn from_config(
        config: DirMgrConfig,
        runtime: R,
        circmgr: Option<Arc<CircMgr<R>>>,
    ) -> Result<Self> {
        let readonly = circmgr.is_none();
        let store = Mutex::new(config.open_sqlite_store(readonly)?);
        let netdir = SharedMutArc::new();
        let netdir_consensus_changed = AtomicBool::new(false);
        let netdir_descriptors_changed = AtomicBool::new(false);
        let publisher = event::Publisher::new();
        Ok(DirMgr {
            config,
            store,
            netdir,
            netdir_consensus_changed,
            netdir_descriptors_changed,
            publisher,
            circmgr,
            runtime,
        })
    }

    /// Load the latest non-pending non-expired directory from the
    /// cache, if it is newer than the one we have.
    ///
    /// Return false if there is no such consensus.
    async fn load_directory(self: &Arc<Self>) -> Result<bool> {
        //let store = &self.store;

        let state = state::GetConsensusState::new(Arc::downgrade(self), CacheUsage::CacheOnly)?;
        let _ = bootstrap::load(Arc::clone(self), Box::new(state)).await?;

        Ok(self.netdir.get().is_some())
    }

    /// Return an Arc handle to our latest directory, if we have one.
    ///
    /// This is a private method, since by the time anybody else has a
    /// handle to a DirMgr, the NetDir should definitely be
    /// bootstrapped.
    fn opt_netdir(&self) -> Option<Arc<NetDir>> {
        self.netdir.get()
    }

    /// Return an Arc handle to our latest directory, if we have one.
    // TODO: Add variants of this that make sure that it's up-to-date?
    pub fn netdir(&self) -> Arc<NetDir> {
        self.opt_netdir().expect("DirMgr was not bootstrapped!")
    }

    /// Return a new asynchronous stream about events taking place with
    /// this directory manager.
    ///
    /// The caller must regularly process events from this stream to
    /// prevent it from blocking.
    pub fn events(&self) -> impl futures::Stream<Item = DirEvent> {
        self.publisher.subscribe()
    }

    /// Try to load the text of a single document described by `doc` from
    /// storage.
    pub async fn text(&self, doc: &DocId) -> Result<Option<DocumentText>> {
        use itertools::Itertools;
        let mut result = HashMap::new();
        let query = (*doc).into();
        self.load_documents_into(&query, &mut result).await?;
        let item = result.into_iter().at_most_one().map_err(|_| {
            Error::CacheCorruption("Found more than one entry in storage for given docid")
        })?;
        if let Some((docid, doctext)) = item {
            if &docid != doc {
                return Err(Error::CacheCorruption(
                    "Item from storage had incorrect docid.",
                ));
            }
            Ok(Some(doctext))
        } else {
            Ok(None)
        }
    }

    /// Load the text for a collection of documents.
    ///
    /// If many of the documents have the same type, this can be more
    /// efficient than calling [`text`](Self::text).
    pub async fn texts<T>(&self, docs: T) -> Result<HashMap<DocId, DocumentText>>
    where
        T: IntoIterator<Item = DocId>,
    {
        let partitioned = docid::partition_by_type(docs);
        let mut result = HashMap::new();
        for (_, query) in partitioned.into_iter() {
            self.load_documents_into(&query, &mut result).await?
        }
        Ok(result)
    }

    /// If the consensus has changed, notify any subscribers.
    // TODO: I don't like all the different places in `bootstrap`
    // where we have to call this function.  Can we simplify it or
    // clean it up somehow?  Maybe we can build some kind of intelligence into
    // shared_ref?
    pub(crate) async fn notify(&self) {
        if self.netdir_consensus_changed.swap(false, Ordering::SeqCst) {
            self.publisher.send(DirEvent::NewConsensus).await;
        }
        if self
            .netdir_descriptors_changed
            .swap(false, Ordering::SeqCst)
        {
            self.publisher.send(DirEvent::NewDescriptors).await;
        }
    }

    /// Load all the documents for a single DocumentQuery from the store.
    async fn load_documents_into(
        &self,
        query: &DocQuery,
        result: &mut HashMap<DocId, DocumentText>,
    ) -> Result<()> {
        use DocQuery::*;
        let store = self.store.lock().await;
        match query {
            LatestConsensus {
                flavor,
                cache_usage,
            } => {
                if *cache_usage == CacheUsage::MustDownload {
                    // Do nothing: we don't want a cached consensus.
                    trace!("MustDownload is set; not checking for cached consensus.");
                } else if let Some(c) =
                    store.latest_consensus(*flavor, cache_usage.pending_requirement())?
                {
                    trace!("Found a reasonable consensus in the cache");
                    let id = DocId::LatestConsensus {
                        flavor: *flavor,
                        cache_usage: *cache_usage,
                    };
                    result.insert(id, c.into());
                }
            }
            AuthCert(ids) => result.extend(
                store
                    .authcerts(ids)?
                    .into_iter()
                    .map(|(id, c)| (DocId::AuthCert(id), DocumentText::from_string(c))),
            ),
            Microdesc(digests) => {
                result.extend(
                    store
                        .microdescs(digests)?
                        .into_iter()
                        .map(|(id, md)| (DocId::Microdesc(id), DocumentText::from_string(md))),
                );
            }
            RouterDesc(digests) => result.extend(
                store
                    .routerdescs(digests)?
                    .into_iter()
                    .map(|(id, rd)| (DocId::RouterDesc(id), DocumentText::from_string(rd))),
            ),
        }
        Ok(())
    }

    /// Convert a DocQuery into a set of ClientRequests, suitable for sending
    /// to a directory cache.
    ///
    /// This conversion has to be a function of the dirmgr, since it may
    /// require knowledge about our current state.
    async fn query_into_requests(&self, q: DocQuery) -> Result<Vec<ClientRequest>> {
        let mut res = Vec::new();
        for q in q.split_for_download() {
            match q {
                DocQuery::LatestConsensus { flavor, .. } => {
                    res.push(self.make_consensus_request(flavor).await?);
                }
                DocQuery::AuthCert(ids) => {
                    res.push(ClientRequest::AuthCert(ids.into_iter().collect()));
                }
                DocQuery::Microdesc(ids) => {
                    res.push(ClientRequest::Microdescs(ids.into_iter().collect()));
                }
                DocQuery::RouterDesc(ids) => {
                    res.push(ClientRequest::RouterDescs(ids.into_iter().collect()));
                }
            }
        }
        Ok(res)
    }

    /// Construct an appropriate ClientRequest to download a consensus
    /// of the given flavor.
    async fn make_consensus_request(&self, flavor: ConsensusFlavor) -> Result<ClientRequest> {
        let mut request = tor_dirclient::request::ConsensusRequest::new(flavor);

        let r = self.store.lock().await;
        match r.latest_consensus_meta(flavor) {
            Ok(Some(meta)) => {
                request.set_last_consensus_date(meta.lifetime().valid_after());
                request.push_old_consensus_digest(*meta.sha3_256_of_signed());
            }
            Ok(None) => {}
            Err(e) => {
                warn!("Error loading directory metadata: {}", e);
            }
        }

        Ok(ClientRequest::Consensus(request))
    }

    /// Given a request we sent and the response we got from a
    /// directory server, see whether we should expand that response
    /// into "something larger".
    ///
    /// Currently, this handles expanding consensus diffs, and nothing
    /// else.  We do it at this stage of our downloading operation
    /// because it requires access to the store.
    async fn expand_response_text(&self, req: &ClientRequest, text: String) -> Result<String> {
        if let ClientRequest::Consensus(req) = req {
            if tor_consdiff::looks_like_diff(&text) {
                if let Some(old_d) = req.old_consensus_digests().next() {
                    let db_val = {
                        let s = self.store.lock().await;
                        s.consensus_by_sha3_digest_of_signed_part(old_d)?
                    };
                    if let Some((old_consensus, meta)) = db_val {
                        info!("Applying a consensus diff");
                        let new_consensus = tor_consdiff::apply_diff(
                            old_consensus.as_str()?,
                            &text,
                            Some(*meta.sha3_256_of_signed()),
                        )?;
                        new_consensus.check_digest()?;
                        return Ok(new_consensus.to_string());
                    }
                }
                return Err(Error::Unwanted(
                    "Received a consensus diff we did not ask for",
                ));
            }
        }
        Ok(text)
    }
}

/// A degree of readiness for a given directory state object.
#[derive(Debug, Copy, Clone)]
enum Readiness {
    /// There is no more information to download.
    Complete,
    /// There is more information to download, but we don't need to
    Usable,
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
#[async_trait]
trait DirState: Send {
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
    /// Return true if this state can advance to another state via its
    /// `advance` method.
    fn can_advance(&self) -> bool;
    /// Add one or more documents from our cache; returns 'true' if there
    /// was any change in this state.
    fn add_from_cache(&mut self, docs: HashMap<DocId, DocumentText>) -> Result<bool>;

    /// Add information that we have just downloaded to this state; returns
    /// 'true' if there as any change in this state.
    ///
    /// This method receives a copy of the original request, and
    /// should reject any documents that do not pertain to it.
    ///
    /// If `storage` is provided, then we should write any accepted documents
    /// into `storage` so they can be saved in a cache.
    // TODO: It might be good to say "there was a change but also an
    // error" in this API if possible.
    // TODO: It would be better to not have this function be async,
    // once the `must_not_suspend` lint is stable.
    // TODO: this should take a "DirSource" too.
    async fn add_from_download(
        &mut self,
        text: &str,
        request: &ClientRequest,
        storage: Option<&Mutex<SqliteStore>>,
    ) -> Result<bool>;
    /// Return the number of attempts that should be made in parallel
    /// to attempt downloads for missing documents, and a
    /// configuration for retrying downloads.
    fn dl_config(&self) -> Result<(usize, RetryConfig)>;
    /// If possible, advance to the next state.
    fn advance(self: Box<Self>) -> Result<Box<dyn DirState>>;
    /// Return a time (if any) when downloaders should stop attempting to
    /// advance this state, and should instead reset it and start over.
    fn reset_time(&self) -> Option<SystemTime>;
    /// Reset this state and start over.
    fn reset(self: Box<Self>) -> Result<Box<dyn DirState>>;
}

/// Try to upgrade a weak reference to a DirMgr, and give an error on
/// failure.
fn upgrade_weak_ref<T>(weak: &Weak<T>) -> Result<Arc<T>> {
    Weak::upgrade(weak).ok_or(Error::ManagerDropped)
}
