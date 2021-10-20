//! Functions to download or load directory objects, using the
//! state machines in the `states` module.

use std::{
    collections::HashMap,
    sync::{Arc, Weak},
    time::{Duration, SystemTime},
};

use crate::{
    docid::{self, ClientRequest},
    upgrade_weak_ref, DirMgr, DirState, DocId, DocumentText, Error, Readiness, Result,
};

use futures::channel::oneshot;
use futures::FutureExt;
use futures::StreamExt;
use tor_dirclient::DirResponse;
use tor_rtcompat::{Runtime, SleepProviderExt};
use tracing::{info, trace, warn};

/// Try to read a set of documents from `dirmgr` by ID.
fn load_all<R: Runtime>(
    dirmgr: &DirMgr<R>,
    missing: Vec<DocId>,
) -> Result<HashMap<DocId, DocumentText>> {
    let mut loaded = HashMap::new();
    for query in docid::partition_by_type(missing.into_iter()).values() {
        dirmgr.load_documents_into(query, &mut loaded)?;
    }
    Ok(loaded)
}

/// Launch a single client request and get an associated response.
async fn fetch_single<R: Runtime>(
    dirmgr: Arc<DirMgr<R>>,
    request: ClientRequest,
) -> Result<(ClientRequest, DirResponse)> {
    let circmgr = dirmgr.circmgr()?;
    let cur_netdir = dirmgr.opt_netdir();
    let dirinfo = match cur_netdir {
        Some(ref netdir) => netdir.as_ref().into(),
        None => dirmgr.config.fallbacks().into(),
    };
    let resource =
        tor_dirclient::get_resource(request.as_requestable(), dirinfo, &dirmgr.runtime, circmgr)
            .await?;

    Ok((request, resource))
}

/// Launch a set of download requests for a set of missing objects in
/// `missing`, and return each request along with the response it received.
///
/// Don't launch more than `parallelism` requests at once.
async fn fetch_multiple<R: Runtime>(
    dirmgr: Arc<DirMgr<R>>,
    missing: Vec<DocId>,
    parallelism: usize,
) -> Result<Vec<(ClientRequest, DirResponse)>> {
    let mut requests = Vec::new();
    for (_type, query) in docid::partition_by_type(missing.into_iter()) {
        requests.extend(dirmgr.query_into_requests(query)?);
    }

    // TODO: instead of waiting for all the queries to finish, we
    // could stream the responses back or something.
    let responses: Vec<Result<(ClientRequest, DirResponse)>> = futures::stream::iter(requests)
        .map(|query| fetch_single(Arc::clone(&dirmgr), query))
        .buffer_unordered(parallelism)
        .collect()
        .await;

    let mut useful_responses = Vec::new();
    for r in responses {
        match r {
            Ok(x) => useful_responses.push(x),
            // TODO: in this case we might want to stop using this source.
            Err(e) => warn!("error while downloading: {:?}", e),
        }
    }

    Ok(useful_responses)
}

/// Try tp update `state` by loading cached information from `dirmgr`.
/// Return true if anything changed.
async fn load_once<R: Runtime>(
    dirmgr: &Arc<DirMgr<R>>,
    state: &mut Box<dyn DirState>,
) -> Result<bool> {
    let missing = state.missing_docs();
    let outcome = if missing.is_empty() {
        trace!("Found no missing documents; can't advance current state");
        Ok(false)
    } else {
        trace!(
            "Found {} missing documents; trying to load them",
            missing.len()
        );
        let documents = load_all(dirmgr, missing)?;
        state.add_from_cache(documents, dirmgr.store_if_rw())
    };
    dirmgr.notify().await;
    outcome
}

/// Try to load as much state as possible for a provided `state` from the
/// cache in `dirmgr`, advancing the state to the extent possible.
///
/// No downloads are performed; the provided state will not be reset.
pub(crate) async fn load<R: Runtime>(
    dirmgr: Arc<DirMgr<R>>,
    mut state: Box<dyn DirState>,
) -> Result<Box<dyn DirState>> {
    let mut safety_counter = 0_usize;
    loop {
        trace!(state=%state.describe(), "Loading from cache");
        let changed = load_once(&dirmgr, &mut state).await?;

        if state.can_advance() {
            state = state.advance()?;
            dirmgr.notify().await;
            safety_counter = 0;
        } else {
            if !changed {
                break;
            }
            safety_counter += 1;
            if safety_counter == 100 {
                panic!("Spent 100 iterations in the same state: this is a bug");
            }
        }
    }

    Ok(state)
}

/// Helper: Make a set of download attempts for the current directory state,
/// and on success feed their results into the state object.
///
/// This can launch one or more download requests, but will not launch more
/// than `parallelism` requests at a time.
///
/// Return true if the state reports that it changed.
async fn download_attempt<R: Runtime>(
    dirmgr: &Arc<DirMgr<R>>,
    state: &mut Box<dyn DirState>,
    parallelism: usize,
) -> Result<bool> {
    let mut changed = false;
    let missing = state.missing_docs();
    let fetched = fetch_multiple(Arc::clone(dirmgr), missing, parallelism).await?;
    for (client_req, dir_response) in fetched {
        let text = String::from_utf8(dir_response.into_output())?;
        match dirmgr.expand_response_text(&client_req, text) {
            Ok(text) => {
                let outcome = state.add_from_download(&text, &client_req, Some(&dirmgr.store));
                dirmgr.notify().await;
                match outcome {
                    Ok(b) => changed |= b,
                    // TODO: in this case we might want to stop using this source.
                    Err(e) => warn!("error while adding directory info: {}", e),
                }
            }
            Err(e) => {
                // TODO: in this case we might want to stop using this source.
                warn!("Error when expanding directory text: {}", e);
            }
        }
    }

    Ok(changed)
}

/// Download information into a DirState state machine until it is
/// ["complete"](Readiness::Complete), or until we hit a
/// non-recoverable error.
///
/// Use `dirmgr` to load from the cache or to launch downloads.
///
/// Keep resetting the state as needed.
///
/// The first time that the state becomes ["usable"](Readiness::Usable),
/// notify the sender in `on_usable`.
///
/// Return Err only on a non-recoverable error.  On an error that
/// merits another bootstrap attempt with the same state, return the
/// state and an Error object in an option.
pub(crate) async fn download<R: Runtime>(
    dirmgr: Weak<DirMgr<R>>,
    mut state: Box<dyn DirState>,
    on_usable: &mut Option<oneshot::Sender<()>>,
) -> Result<(Box<dyn DirState>, Option<Error>)> {
    let runtime = upgrade_weak_ref(&dirmgr)?.runtime.clone();

    'next_state: loop {
        let (parallelism, retry_config) = state.dl_config()?;

        // In theory this could be inside the loop below maybe?  If we
        // want to drop the restriction that the missing() members of a
        // state must never grow, then we'll need to move it inside.
        {
            let dirmgr = upgrade_weak_ref(&dirmgr)?;
            load_once(&dirmgr, &mut state).await?;
        }

        // Skip the downloads if we can...
        if state.can_advance() {
            state = state.advance()?;
            continue 'next_state;
        }
        if state.is_ready(Readiness::Complete) {
            return Ok((state, None));
        }

        let mut retry = retry_config.schedule();

        // Make several attempts to fetch whatever we're missing,
        // until either we can advance, or we've got a complete
        // document, or we run out of tries, or we run out of time.
        'next_attempt: for attempt in retry_config.attempts() {
            info!("{}: {}", attempt + 1, state.describe());
            let reset_time = no_more_than_a_week_from(SystemTime::now(), state.reset_time());

            {
                let dirmgr = upgrade_weak_ref(&dirmgr)?;
                futures::select_biased! {
                    outcome = download_attempt(&dirmgr, &mut state, parallelism).fuse() => {
                        match outcome {
                            Err(e) => {
                                warn!("Error while downloading: {}", e);
                                continue 'next_attempt;
                            }
                            Ok(changed) => {
                                changed
                            }
                        }
                    }
                    _ = runtime.sleep_until_wallclock(reset_time).fuse() => {
                        // We need to reset. This can happen if (for
                        // example) we're downloading the last few
                        // microdescriptors on a consensus that now
                        // we're ready to replace.
                        state = state.reset()?;
                        continue 'next_state;
                    },
                };
            }

            // Exit if there is nothing more to download.
            if state.is_ready(Readiness::Complete) {
                return Ok((state, None));
            }

            // Report usable-ness if appropriate.
            if on_usable.is_some() && state.is_ready(Readiness::Usable) {
                // Unwrap should be safe due to parent `.is_some()` check
                #[allow(clippy::unwrap_used)]
                let _ = on_usable.take().unwrap().send(());
            }

            if state.can_advance() {
                // We have enough info to advance to another state.
                state = state.advance()?;
                upgrade_weak_ref(&dirmgr)?.notify().await;
                continue 'next_state;
            } else {
                // We should wait a bit, and then retry.
                // TODO: we shouldn't wait on the final attempt.
                let reset_time = no_more_than_a_week_from(SystemTime::now(), state.reset_time());
                let delay = retry.next_delay(&mut rand::thread_rng());
                futures::select_biased! {
                    _ = runtime.sleep_until_wallclock(reset_time).fuse() => {
                        state = state.reset()?;
                        continue 'next_state;
                    }
                    _ = FutureExt::fuse(runtime.sleep(delay)) => {}
                };
            }
        }

        // We didn't advance the state, after all the retries.
        warn!(n_attempts=retry_config.n_attempts(),
              state=%state.describe(),
              "Unable to advance downloading state");
        return Ok((state, Some(Error::CantAdvanceState)));
    }
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
    use super::*;
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
}
