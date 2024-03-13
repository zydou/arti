//! Functions to download or load directory objects, using the
//! state machines in the `states` module.

use std::num::NonZeroUsize;
use std::ops::Deref;
use std::{
    collections::HashMap,
    sync::{Arc, Weak},
    time::{Duration, SystemTime},
};

use crate::err::BootstrapAction;
use crate::state::{DirState, PoisonedState};
use crate::DirMgrConfig;
use crate::DocSource;
use crate::{
    docid::{self, ClientRequest},
    upgrade_weak_ref, DirMgr, DocId, DocQuery, DocumentText, Error, Readiness, Result,
};

use futures::FutureExt;
use futures::StreamExt;
use tor_async_utils::oneshot;
use tor_dirclient::DirResponse;
use tor_error::{info_report, warn_report};
use tor_rtcompat::scheduler::TaskSchedule;
use tor_rtcompat::Runtime;
use tracing::{debug, info, trace, warn};

use crate::storage::Store;
#[cfg(test)]
use once_cell::sync::Lazy;
#[cfg(test)]
use std::sync::Mutex;
use tor_circmgr::{CircMgr, DirInfo};
use tor_netdir::{NetDir, NetDirProvider as _};
use tor_netdoc::doc::netstatus::ConsensusFlavor;

/// Given a Result<()>, exit the current function if it is anything other than
/// Ok(), or a nonfatal error.
macro_rules! propagate_fatal_errors {
    ( $e:expr ) => {
        let v: Result<()> = $e;
        if let Err(e) = v {
            match e.bootstrap_action() {
                BootstrapAction::Nonfatal => {}
                _ => return Err(e),
            }
        }
    };
}

/// Identifier for an attempt to bootstrap a directory.
///
/// Every time that we decide to download a new directory, _despite already
/// having one_, counts as a new attempt.
///
/// These are used to track the progress of each attempt independently.
#[derive(Copy, Clone, Debug, derive_more::Display, Eq, PartialEq, Ord, PartialOrd)]
#[display(fmt = "{0}", id)]
pub(crate) struct AttemptId {
    /// Which attempt at downloading a directory is this?
    id: NonZeroUsize,
}

impl AttemptId {
    /// Return a new unused AtomicUsize that will be greater than any previous
    /// one.
    ///
    /// # Panics
    ///
    /// Panics if we have exhausted the possible space of AtomicIds.
    pub(crate) fn next() -> Self {
        use std::sync::atomic::{AtomicUsize, Ordering};
        /// atomic used to generate the next attempt.
        static NEXT: AtomicUsize = AtomicUsize::new(1);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let id = id.try_into().expect("Allocated too many AttemptIds");
        Self { id }
    }
}

/// If there were errors from a peer in `outcome`, record those errors by
/// marking the circuit (if any) as needing retirement, and noting the peer
/// (if any) as having failed.
fn note_request_outcome<R: Runtime>(
    circmgr: &CircMgr<R>,
    outcome: &tor_dirclient::Result<tor_dirclient::DirResponse>,
) {
    use tor_dirclient::{Error::RequestFailed, RequestFailedError};
    // Extract an error and a source from this outcome, if there is one.
    //
    // This is complicated because DirResponse can encapsulate the notion of
    // a response that failed part way through a download: in the case, it
    // has some data, and also an error.
    let (err, source) = match outcome {
        Ok(req) => {
            if let (Some(e), Some(source)) = (req.error(), req.source()) {
                (
                    RequestFailed(RequestFailedError {
                        error: e.clone(),
                        source: Some(source.clone()),
                    }),
                    source,
                )
            } else {
                return;
            }
        }
        Err(
            error @ RequestFailed(RequestFailedError {
                source: Some(source),
                ..
            }),
        ) => (error.clone(), source),
        _ => return,
    };

    note_cache_error(circmgr, source, &err.into());
}

/// Record that a problem has occurred because of a failure in an answer from `source`.
fn note_cache_error<R: Runtime>(
    circmgr: &CircMgr<R>,
    source: &tor_dirclient::SourceInfo,
    problem: &Error,
) {
    use tor_circmgr::ExternalActivity;

    if !problem.indicates_cache_failure() {
        return;
    }

    // Does the error here tell us whom to really blame?  If so, blame them
    // instead.
    //
    // (This can happen if we notice a problem while downloading a certificate,
    // but the real problem is that the consensus was no good.)
    let real_source = match problem {
        Error::NetDocError {
            source: DocSource::DirServer { source: Some(info) },
            ..
        } => info,
        _ => source,
    };

    info_report!(problem, "Marking {:?} as failed", real_source);
    circmgr.note_external_failure(real_source.cache_id(), ExternalActivity::DirCache);
    circmgr.retire_circ(source.unique_circ_id());
}

/// Record that `source` has successfully given us some directory info.
fn note_cache_success<R: Runtime>(circmgr: &CircMgr<R>, source: &tor_dirclient::SourceInfo) {
    use tor_circmgr::ExternalActivity;

    trace!("Marking {:?} as successful", source);
    circmgr.note_external_success(source.cache_id(), ExternalActivity::DirCache);
}

/// Load a set of documents from a `Store`, returning all documents found in the store.
/// Note that this may be less than the number of documents in `missing`.
fn load_documents_from_store(
    missing: &[DocId],
    store: &dyn Store,
) -> Result<HashMap<DocId, DocumentText>> {
    let mut loaded = HashMap::new();
    for query in docid::partition_by_type(missing.iter().copied()).values() {
        query.load_from_store_into(&mut loaded, store)?;
    }
    Ok(loaded)
}

/// Construct an appropriate ClientRequest to download a consensus
/// of the given flavor.
pub(crate) fn make_consensus_request(
    now: SystemTime,
    flavor: ConsensusFlavor,
    store: &dyn Store,
    config: &DirMgrConfig,
) -> Result<ClientRequest> {
    let mut request = tor_dirclient::request::ConsensusRequest::new(flavor);

    let default_cutoff = crate::default_consensus_cutoff(now, &config.tolerance)?;

    match store.latest_consensus_meta(flavor) {
        Ok(Some(meta)) => {
            let valid_after = meta.lifetime().valid_after();
            request.set_last_consensus_date(std::cmp::max(valid_after, default_cutoff));
            request.push_old_consensus_digest(*meta.sha3_256_of_signed());
        }
        latest => {
            if let Err(e) = latest {
                warn_report!(e, "Error loading directory metadata");
            }
            // If we don't have a consensus, then request one that's
            // "reasonably new".  That way, our clock is set far in the
            // future, we won't download stuff we can't use.
            request.set_last_consensus_date(default_cutoff);
        }
    }

    request.set_skew_limit(
        // If we are _fast_ by at least this much, then any valid directory will
        // seem to be at least this far in the past.
        config.tolerance.post_valid_tolerance,
        // If we are _slow_ by this much, then any valid directory will seem to
        // be at least this far in the future.
        config.tolerance.pre_valid_tolerance,
    );

    Ok(ClientRequest::Consensus(request))
}

/// Construct a set of `ClientRequest`s in order to fetch the documents in `docs`.
pub(crate) fn make_requests_for_documents<R: Runtime>(
    rt: &R,
    docs: &[DocId],
    store: &dyn Store,
    config: &DirMgrConfig,
) -> Result<Vec<ClientRequest>> {
    let mut res = Vec::new();
    for q in docid::partition_by_type(docs.iter().copied())
        .into_iter()
        .flat_map(|(_, x)| x.split_for_download().into_iter())
    {
        match q {
            DocQuery::LatestConsensus { flavor, .. } => {
                res.push(make_consensus_request(
                    rt.wallclock(),
                    flavor,
                    store,
                    config,
                )?);
            }
            DocQuery::AuthCert(ids) => {
                res.push(ClientRequest::AuthCert(ids.into_iter().collect()));
            }
            DocQuery::Microdesc(ids) => {
                res.push(ClientRequest::Microdescs(ids.into_iter().collect()));
            }
            #[cfg(feature = "routerdesc")]
            DocQuery::RouterDesc(ids) => {
                res.push(ClientRequest::RouterDescs(ids.into_iter().collect()));
            }
        }
    }
    Ok(res)
}

/// Launch a single client request and get an associated response.
async fn fetch_single<R: Runtime>(
    rt: &R,
    request: ClientRequest,
    current_netdir: Option<&NetDir>,
    circmgr: Arc<CircMgr<R>>,
) -> Result<(ClientRequest, DirResponse)> {
    let dirinfo: DirInfo = match current_netdir {
        Some(netdir) => netdir.into(),
        None => tor_circmgr::DirInfo::Nothing,
    };
    let outcome =
        tor_dirclient::get_resource(request.as_requestable(), dirinfo, rt, circmgr.clone()).await;

    note_request_outcome(&circmgr, &outcome);

    let resource = outcome?;
    Ok((request, resource))
}

/// Testing helper: if this is Some, then we return it in place of any
/// response to fetch_multiple.
///
/// Note that only one test uses this: otherwise there would be a race
/// condition. :p
#[cfg(test)]
static CANNED_RESPONSE: Lazy<Mutex<Vec<String>>> = Lazy::new(|| Mutex::new(vec![]));

/// Launch a set of download requests for a set of missing objects in
/// `missing`, and return each request along with the response it received.
///
/// Don't launch more than `parallelism` requests at once.
async fn fetch_multiple<R: Runtime>(
    dirmgr: Arc<DirMgr<R>>,
    attempt_id: AttemptId,
    missing: &[DocId],
    parallelism: usize,
) -> Result<Vec<(ClientRequest, DirResponse)>> {
    let requests = {
        let store = dirmgr.store.lock().expect("store lock poisoned");
        make_requests_for_documents(&dirmgr.runtime, missing, &**store, &dirmgr.config.get())?
    };

    trace!(attempt=%attempt_id, "Launching {} requests for {} documents",
           requests.len(), missing.len());

    #[cfg(test)]
    {
        let m = CANNED_RESPONSE.lock().expect("Poisoned mutex");
        if !m.is_empty() {
            return Ok(requests
                .into_iter()
                .zip(m.iter().map(DirResponse::from_body))
                .collect());
        }
    }

    let circmgr = dirmgr.circmgr()?;
    // Only use timely directories for bootstrapping directories; otherwise, we'll try fallbacks.
    let netdir = dirmgr.netdir(tor_netdir::Timeliness::Timely).ok();

    // TODO: instead of waiting for all the queries to finish, we
    // could stream the responses back or something.
    let responses: Vec<Result<(ClientRequest, DirResponse)>> = futures::stream::iter(requests)
        .map(|query| fetch_single(&dirmgr.runtime, query, netdir.as_deref(), circmgr.clone()))
        .buffer_unordered(parallelism)
        .collect()
        .await;

    let mut useful_responses = Vec::new();
    for r in responses {
        // TODO: on some error cases we might want to stop using this source.
        match r {
            Ok((request, response)) => {
                if response.status_code() == 200 {
                    useful_responses.push((request, response));
                } else {
                    trace!(
                        "cache declined request; reported status {:?}",
                        response.status_code()
                    );
                }
            }
            Err(e) => warn_report!(e, "error while downloading"),
        }
    }

    trace!(attempt=%attempt_id, "received {} useful responses from our requests.", useful_responses.len());

    Ok(useful_responses)
}

/// Try to update `state` by loading cached information from `dirmgr`.
async fn load_once<R: Runtime>(
    dirmgr: &Arc<DirMgr<R>>,
    state: &mut Box<dyn DirState>,
    attempt_id: AttemptId,
    changed_out: &mut bool,
) -> Result<()> {
    let missing = state.missing_docs();
    let mut changed = false;
    let outcome: Result<()> = if missing.is_empty() {
        trace!("Found no missing documents; can't advance current state");
        Ok(())
    } else {
        trace!(
            "Found {} missing documents; trying to load them",
            missing.len()
        );

        let documents = {
            let store = dirmgr.store.lock().expect("store lock poisoned");
            load_documents_from_store(&missing, &**store)?
        };

        state.add_from_cache(documents, &mut changed)
    };

    // We have to update the status here regardless of the outcome, if we got
    // any information: even if there was an error, we might have received
    // partial information that changed our status.
    if changed {
        dirmgr.update_progress(attempt_id, state.bootstrap_progress());
        *changed_out = true;
    }

    outcome
}

/// Try to load as much state as possible for a provided `state` from the
/// cache in `dirmgr`, advancing the state to the extent possible.
///
/// No downloads are performed; the provided state will not be reset.
pub(crate) async fn load<R: Runtime>(
    dirmgr: Arc<DirMgr<R>>,
    mut state: Box<dyn DirState>,
    attempt_id: AttemptId,
) -> Result<Box<dyn DirState>> {
    let mut safety_counter = 0_usize;
    loop {
        trace!(attempt=%attempt_id, state=%state.describe(), "Loading from cache");
        let mut changed = false;
        let outcome = load_once(&dirmgr, &mut state, attempt_id, &mut changed).await;
        {
            let mut store = dirmgr.store.lock().expect("store lock poisoned");
            dirmgr.apply_netdir_changes(&mut state, &mut **store)?;
        }
        trace!(attempt=%attempt_id, ?outcome, "Load operation completed.");

        if let Err(e) = outcome {
            match e.bootstrap_action() {
                BootstrapAction::Nonfatal => {
                    debug!("Recoverable error loading from cache: {}", e);
                }
                BootstrapAction::Fatal | BootstrapAction::Reset => {
                    return Err(e);
                }
            }
        }

        if state.can_advance() {
            state = state.advance();
            trace!(attempt=%attempt_id, state=state.describe(), "State has advanced.");
            safety_counter = 0;
        } else {
            if !changed {
                // TODO: Are there more nonfatal errors that mean we should
                // break?
                trace!(attempt=%attempt_id, state=state.describe(), "No state advancement after load; nothing more to find in the cache.");
                break;
            }
            safety_counter += 1;
            assert!(
                safety_counter < 100,
                "Spent 100 iterations in the same state: this is a bug"
            );
        }
    }

    Ok(state)
}

/// Helper: Make a set of download attempts for the current directory state,
/// and on success feed their results into the state object.
///
/// This can launch one or more download requests, but will not launch more
/// than `parallelism` requests at a time.
async fn download_attempt<R: Runtime>(
    dirmgr: &Arc<DirMgr<R>>,
    state: &mut Box<dyn DirState>,
    parallelism: usize,
    attempt_id: AttemptId,
) -> Result<()> {
    let missing = state.missing_docs();
    let fetched = fetch_multiple(Arc::clone(dirmgr), attempt_id, &missing, parallelism).await?;
    let mut n_errors = 0;
    for (client_req, dir_response) in fetched {
        let source = dir_response.source().cloned();
        let text = match String::from_utf8(dir_response.into_output_unchecked())
            .map_err(Error::BadUtf8FromDirectory)
        {
            Ok(t) => t,
            Err(e) => {
                if let Some(source) = source {
                    n_errors += 1;
                    note_cache_error(dirmgr.circmgr()?.deref(), &source, &e);
                }
                continue;
            }
        };
        match dirmgr.expand_response_text(&client_req, text) {
            Ok(text) => {
                let doc_source = DocSource::DirServer {
                    source: source.clone(),
                };
                let mut changed = false;
                let outcome = state.add_from_download(
                    &text,
                    &client_req,
                    doc_source,
                    Some(&dirmgr.store),
                    &mut changed,
                );

                if !changed {
                    debug_assert!(outcome.is_err());
                }

                if let Some(source) = source {
                    if let Err(e) = &outcome {
                        n_errors += 1;
                        note_cache_error(dirmgr.circmgr()?.deref(), &source, e);
                    } else {
                        note_cache_success(dirmgr.circmgr()?.deref(), &source);
                    }
                }

                if let Err(e) = &outcome {
                    dirmgr.note_errors(attempt_id, 1);
                    warn_report!(e, "error while adding directory info");
                }
                propagate_fatal_errors!(outcome);
            }
            Err(e) => {
                warn_report!(e, "Error when expanding directory text");
                if let Some(source) = source {
                    n_errors += 1;
                    note_cache_error(dirmgr.circmgr()?.deref(), &source, &e);
                }
                propagate_fatal_errors!(Err(e));
            }
        }
    }
    if n_errors != 0 {
        dirmgr.note_errors(attempt_id, n_errors);
    }
    dirmgr.update_progress(attempt_id, state.bootstrap_progress());

    Ok(())
}

/// Download information into a DirState state machine until it is
/// ["complete"](Readiness::Complete), or until we hit a non-recoverable error.
///
/// Use `dirmgr` to load from the cache or to launch downloads.
///
/// Keep resetting the state as needed.
///
/// The first time that the state becomes ["usable"](Readiness::Usable), notify
/// the sender in `on_usable`.
pub(crate) async fn download<R: Runtime>(
    dirmgr: Weak<DirMgr<R>>,
    state: &mut Box<dyn DirState>,
    schedule: &mut TaskSchedule<R>,
    attempt_id: AttemptId,
    on_usable: &mut Option<oneshot::Sender<()>>,
) -> Result<()> {
    let runtime = upgrade_weak_ref(&dirmgr)?.runtime.clone();

    trace!(attempt=%attempt_id, state=%state.describe(), "Trying to download directory material.");

    'next_state: loop {
        let retry_config = state.dl_config();
        let parallelism = retry_config.parallelism();

        // In theory this could be inside the loop below maybe?  If we
        // want to drop the restriction that the missing() members of a
        // state must never grow, then we'll need to move it inside.
        let mut now = {
            let dirmgr = upgrade_weak_ref(&dirmgr)?;
            let mut changed = false;
            trace!(attempt=%attempt_id, state=%state.describe(),"Attempting to load directory information from cache.");
            let load_result = load_once(&dirmgr, state, attempt_id, &mut changed).await;
            trace!(attempt=%attempt_id, state=%state.describe(), outcome=?load_result, "Load attempt complete.");
            if let Err(e) = &load_result {
                // If the load failed but the error can be blamed on a directory
                // cache, do so.
                if let Some(source) = e.responsible_cache() {
                    dirmgr.note_errors(attempt_id, 1);
                    note_cache_error(dirmgr.circmgr()?.deref(), source, e);
                }
            }
            propagate_fatal_errors!(load_result);
            dirmgr.runtime.wallclock()
        };

        // Skip the downloads if we can...
        if state.can_advance() {
            advance(state);
            trace!(attempt=%attempt_id, state=%state.describe(), "State has advanced.");
            continue 'next_state;
        }
        // Apply any netdir changes that the state gives us.
        // TODO(eta): Consider deprecating state.is_ready().
        {
            let dirmgr = upgrade_weak_ref(&dirmgr)?;
            let mut store = dirmgr.store.lock().expect("store lock poisoned");
            dirmgr.apply_netdir_changes(state, &mut **store)?;
        }
        if state.is_ready(Readiness::Complete) {
            trace!(attempt=%attempt_id, state=%state.describe(), "Directory is now Complete.");
            return Ok(());
        }

        let reset_time = no_more_than_a_week_from(runtime.wallclock(), state.reset_time());

        let mut retry = retry_config.schedule();
        let mut delay = None;

        // Make several attempts to fetch whatever we're missing,
        // until either we can advance, or we've got a complete
        // document, or we run out of tries, or we run out of time.
        'next_attempt: for attempt in retry_config.attempts() {
            // We wait at the start of this loop, on all attempts but the first.
            // This ensures that we always wait between attempts, but not after
            // the final attempt.
            let next_delay = retry.next_delay(&mut rand::thread_rng());
            if let Some(delay) = delay.replace(next_delay) {
                let time_until_reset = {
                    reset_time
                        .duration_since(now)
                        .unwrap_or(Duration::from_secs(0))
                };
                let real_delay = delay.min(time_until_reset);
                debug!(attempt=%attempt_id, "Waiting {:?} for next download attempt...", real_delay);
                schedule.sleep(real_delay).await?;

                now = upgrade_weak_ref(&dirmgr)?.runtime.wallclock();
                if now >= reset_time {
                    info!(attempt=%attempt_id, "Directory being fetched is now outdated; resetting download state.");
                    reset(state);
                    continue 'next_state;
                }
            }

            info!(attempt=%attempt_id, "{}: {}", attempt + 1, state.describe());
            let reset_time = no_more_than_a_week_from(now, state.reset_time());

            now = {
                let dirmgr = upgrade_weak_ref(&dirmgr)?;
                futures::select_biased! {
                    outcome = download_attempt(&dirmgr, state, parallelism.into(), attempt_id).fuse() => {
                        if let Err(e) = outcome {
                            // TODO: get warn_report! to support `attempt=%attempt_id`?
                            warn_report!(e, "Error while downloading (attempt {})", attempt_id);
                            propagate_fatal_errors!(Err(e));
                            continue 'next_attempt;
                        } else {
                            trace!(attempt=%attempt_id, "Successfully downloaded some information.");
                        }
                    }
                    _ = schedule.sleep_until_wallclock(reset_time).fuse() => {
                        // We need to reset. This can happen if (for
                        // example) we're downloading the last few
                        // microdescriptors on a consensus that now
                        // we're ready to replace.
                        info!(attempt=%attempt_id, "Directory being fetched is now outdated; resetting download state.");
                        reset(state);
                        continue 'next_state;
                    },
                };
                dirmgr.runtime.wallclock()
            };

            // Apply any netdir changes that the state gives us.
            // TODO(eta): Consider deprecating state.is_ready().
            {
                let dirmgr = upgrade_weak_ref(&dirmgr)?;
                let mut store = dirmgr.store.lock().expect("store lock poisoned");
                let outcome = dirmgr.apply_netdir_changes(state, &mut **store);
                propagate_fatal_errors!(outcome);
            }

            // Exit if there is nothing more to download.
            if state.is_ready(Readiness::Complete) {
                trace!(attempt=%attempt_id, state=%state.describe(), "Directory is now Complete.");
                return Ok(());
            }

            // Report usable-ness if appropriate.
            if on_usable.is_some() && state.is_ready(Readiness::Usable) {
                trace!(attempt=%attempt_id, state=%state.describe(), "Directory is now Usable.");
                // Unwrap should be safe due to parent `.is_some()` check
                #[allow(clippy::unwrap_used)]
                let _ = on_usable.take().unwrap().send(());
            }

            if state.can_advance() {
                // We have enough info to advance to another state.
                advance(state);
                trace!(attempt=%attempt_id, state=%state.describe(), "State has advanced.");
                continue 'next_state;
            }
        }

        // We didn't advance the state, after all the retries.
        warn!(n_attempts=retry_config.n_attempts(),
              state=%state.describe(),
              "Unable to advance downloading state");
        return Err(Error::CantAdvanceState);
    }
}

/// Replace `state` with `state.reset()`.
fn reset(state: &mut Box<dyn DirState>) {
    let cur_state = std::mem::replace(state, Box::new(PoisonedState));
    *state = cur_state.reset();
}

/// Replace `state` with `state.advance()`.
fn advance(state: &mut Box<dyn DirState>) {
    let cur_state = std::mem::replace(state, Box::new(PoisonedState));
    *state = cur_state.advance();
}

/// Helper: Clamp `v` so that it is no more than one week from `now`.
///
/// If `v` is absent, return the time that's one week from now.
///
/// We use this to determine a reset time when no reset time is
/// available, or when it is too far in the future.
fn no_more_than_a_week_from(now: SystemTime, v: Option<SystemTime>) -> SystemTime {
    let one_week_later = now + Duration::new(86400 * 7, 0);
    match v {
        Some(t) => std::cmp::min(t, one_week_later),
        None => one_week_later,
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
    use super::*;
    use crate::storage::DynStore;
    use crate::test::new_mgr;
    use crate::DownloadSchedule;
    use std::sync::Mutex;
    use tor_netdoc::doc::microdesc::MdDigest;
    use tor_rtcompat::SleepProvider;

    #[test]
    fn week() {
        let now = SystemTime::now();
        let one_day = Duration::new(86400, 0);

        assert_eq!(no_more_than_a_week_from(now, None), now + one_day * 7);
        assert_eq!(
            no_more_than_a_week_from(now, Some(now + one_day)),
            now + one_day
        );
        assert_eq!(
            no_more_than_a_week_from(now, Some(now - one_day)),
            now - one_day
        );
        assert_eq!(
            no_more_than_a_week_from(now, Some(now + 30 * one_day)),
            now + one_day * 7
        );
    }

    /// A fake implementation of DirState that just wants a fixed set
    /// of microdescriptors.  It doesn't care if it gets them: it just
    /// wants to be told that the IDs exist.
    #[derive(Debug, Clone)]
    struct DemoState {
        second_time_around: bool,
        got_items: HashMap<MdDigest, bool>,
    }

    // Constants from Lou Reed
    const H1: MdDigest = *b"satellite's gone up to the skies";
    const H2: MdDigest = *b"things like that drive me out of";
    const H3: MdDigest = *b"my mind i watched it for a littl";
    const H4: MdDigest = *b"while i like to watch things on ";
    const H5: MdDigest = *b"TV Satellite of love Satellite--";

    impl DemoState {
        fn new1() -> Self {
            DemoState {
                second_time_around: false,
                got_items: vec![(H1, false), (H2, false)].into_iter().collect(),
            }
        }
        fn new2() -> Self {
            DemoState {
                second_time_around: true,
                got_items: vec![(H3, false), (H4, false), (H5, false)]
                    .into_iter()
                    .collect(),
            }
        }
        fn n_ready(&self) -> usize {
            self.got_items.values().filter(|x| **x).count()
        }
    }

    impl DirState for DemoState {
        fn describe(&self) -> String {
            format!("{:?}", &self)
        }
        fn bootstrap_progress(&self) -> crate::event::DirProgress {
            crate::event::DirProgress::default()
        }
        fn is_ready(&self, ready: Readiness) -> bool {
            match (ready, self.second_time_around) {
                (_, false) => false,
                (Readiness::Complete, true) => self.n_ready() == self.got_items.len(),
                (Readiness::Usable, true) => self.n_ready() >= self.got_items.len() - 1,
            }
        }
        fn can_advance(&self) -> bool {
            if self.second_time_around {
                false
            } else {
                self.n_ready() == self.got_items.len()
            }
        }
        fn missing_docs(&self) -> Vec<DocId> {
            self.got_items
                .iter()
                .filter_map(|(id, have)| {
                    if *have {
                        None
                    } else {
                        Some(DocId::Microdesc(*id))
                    }
                })
                .collect()
        }
        fn add_from_cache(
            &mut self,
            docs: HashMap<DocId, DocumentText>,
            changed: &mut bool,
        ) -> Result<()> {
            for id in docs.keys() {
                if let DocId::Microdesc(id) = id {
                    if self.got_items.get(id) == Some(&false) {
                        self.got_items.insert(*id, true);
                        *changed = true;
                    }
                }
            }
            Ok(())
        }
        fn add_from_download(
            &mut self,
            text: &str,
            _request: &ClientRequest,
            _source: DocSource,
            _storage: Option<&Mutex<DynStore>>,
            changed: &mut bool,
        ) -> Result<()> {
            for token in text.split_ascii_whitespace() {
                if let Ok(v) = hex::decode(token) {
                    if let Ok(id) = v.try_into() {
                        if self.got_items.get(&id) == Some(&false) {
                            self.got_items.insert(id, true);
                            *changed = true;
                        }
                    }
                }
            }
            Ok(())
        }
        fn dl_config(&self) -> DownloadSchedule {
            DownloadSchedule::default()
        }
        fn advance(self: Box<Self>) -> Box<dyn DirState> {
            if self.can_advance() {
                Box::new(Self::new2())
            } else {
                self
            }
        }
        fn reset_time(&self) -> Option<SystemTime> {
            None
        }
        fn reset(self: Box<Self>) -> Box<dyn DirState> {
            Box::new(Self::new1())
        }
    }

    #[test]
    fn all_in_cache() {
        // Let's try bootstrapping when everything is in the cache.
        tor_rtcompat::test_with_one_runtime!(|rt| async {
            let now = rt.wallclock();
            let (_tempdir, mgr) = new_mgr(rt.clone());
            let (mut schedule, _handle) = TaskSchedule::new(rt);

            {
                let mut store = mgr.store_if_rw().unwrap().lock().unwrap();
                for h in [H1, H2, H3, H4, H5] {
                    store.store_microdescs(&[("ignore", &h)], now).unwrap();
                }
            }
            let mgr = Arc::new(mgr);
            let attempt_id = AttemptId::next();

            // Try just a load.
            let state = Box::new(DemoState::new1());
            let result = super::load(Arc::clone(&mgr), state, attempt_id)
                .await
                .unwrap();
            assert!(result.is_ready(Readiness::Complete));

            // Try a bootstrap that could (but won't!) download.
            let mut state: Box<dyn DirState> = Box::new(DemoState::new1());

            let mut on_usable = None;
            super::download(
                Arc::downgrade(&mgr),
                &mut state,
                &mut schedule,
                attempt_id,
                &mut on_usable,
            )
            .await
            .unwrap();
            assert!(state.is_ready(Readiness::Complete));
        });
    }

    #[test]
    fn partly_in_cache() {
        // Let's try bootstrapping with all of phase1 and part of
        // phase 2 in cache.
        tor_rtcompat::test_with_one_runtime!(|rt| async {
            let now = rt.wallclock();
            let (_tempdir, mgr) = new_mgr(rt.clone());
            let (mut schedule, _handle) = TaskSchedule::new(rt);

            {
                let mut store = mgr.store_if_rw().unwrap().lock().unwrap();
                for h in [H1, H2, H3] {
                    store.store_microdescs(&[("ignore", &h)], now).unwrap();
                }
            }
            {
                let mut resp = CANNED_RESPONSE.lock().unwrap();
                // H4 and H5.
                *resp = vec![
                    "7768696c652069206c696b6520746f207761746368207468696e6773206f6e20
                     545620536174656c6c697465206f66206c6f766520536174656c6c6974652d2d"
                        .to_owned(),
                ];
            }
            let mgr = Arc::new(mgr);
            let mut on_usable = None;
            let attempt_id = AttemptId::next();

            let mut state: Box<dyn DirState> = Box::new(DemoState::new1());
            super::download(
                Arc::downgrade(&mgr),
                &mut state,
                &mut schedule,
                attempt_id,
                &mut on_usable,
            )
            .await
            .unwrap();
            assert!(state.is_ready(Readiness::Complete));
        });
    }
}
