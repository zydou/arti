//! Observe and enforce lists of recommended and required subprotocols.
//!
//! To prevent insecure clients from exposing themselves to attacks,
//! and to prevent obsolete clients from [inadvertently DoSing the network][fast-zombies]
//! by looking for relays with functionality that no longer exists,
//! we have a mechanism for ["recommended" and "required" subprotocols][recommended].
//!
//! When a subprotocol is recommended, we issue a warning whenever it is absent.
//! When a subprotocol is required, we (typically) shut down Arti whenever it is absent.
//!
//! While Arti is running, we check our subprotocols
//! whenever we find a new timely well-signed consensus.
//!
//! Additionally, we check our subprotocols at startup before any directory is received,
//! to ensure that we don't touch the network with invalid software.
//!
//! We ignore any list of required/recommended protocol
//! that is [older than the release date of this software].
//!
//! [fast-zombies]: https://spec.torproject.org/proposals/266-removing-current-obsolete-clients.html
//! [recommended]: https://spec.torproject.org/tor-spec/subprotocol-versioning.html#required-recommended
//! [older]: https://spec.torproject.org/proposals/297-safer-protover-shutdowns.html

use futures::{Stream, StreamExt as _};
use std::{
    future::Future,
    sync::{Arc, Weak},
    time::SystemTime,
};
use tor_config::MutCfg;
use tor_dirmgr::DirProvider;
use tor_error::{into_internal, warn_report};
use tor_netdir::DirEvent;
use tor_netdoc::doc::netstatus::{ProtoStatuses, ProtocolSupportError};
use tor_protover::Protocols;
use tor_rtcompat::{Runtime, SpawnExt as _};
use tracing::{debug, error, info, warn};

use crate::{config::SoftwareStatusOverrideConfig, err::ErrorDetail};

/// Check whether we have any cached protocol recommendations,
/// and report about them or enforce them immediately.
///
/// Then, launch a task to run indefinitely, and continue to enforce protocol recommendations.
/// If that task encounters a fatal error, it should invoke `on_fatal`.
pub(crate) fn enforce_protocol_recommendations<R, F, Fut>(
    runtime: &R,
    netdir_provider: Arc<dyn DirProvider>,
    software_publication_time: SystemTime,
    software_protocols: Protocols,
    override_status: Arc<MutCfg<SoftwareStatusOverrideConfig>>,
    on_fatal: F,
) -> Result<(), ErrorDetail>
where
    R: Runtime,
    F: FnOnce(ErrorDetail) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    // We need to get this stream before we check the initial status, to avoid race conditions.
    let events = netdir_provider.events();

    let initial_evaluated_proto_status = match netdir_provider.protocol_statuses() {
        Some((timestamp, recommended)) if timestamp >= software_publication_time => {
            // Here we exit if the initial (cached) status is bogus.
            evaluate_protocol_status(
                timestamp,
                &recommended,
                &software_protocols,
                override_status.get().as_ref(),
            )?;

            Some(recommended)
        }
        Some((_, _)) => {
            // In this case, our software is newer than the consensus, so we don't enforce it.
            None
        }
        None => None,
    };

    runtime
        .spawn(watch_protocol_statuses(
            netdir_provider,
            events,
            initial_evaluated_proto_status,
            software_publication_time,
            software_protocols,
            override_status,
            on_fatal,
        ))
        .map_err(|e| ErrorDetail::from_spawn("protocol status monitor", e))?;

    Ok(())
}

/// Run indefinitely, checking for any protocol-recommendation issues.
///
/// In addition to the arguments of `enforce_protocol_recommendations,`
/// this function expects `events` (a stream of DirEvent),
/// and `last_evaluated_proto_status` (the last protocol status that we passed to evaluate_protocol_status).
///
/// On a fatal error, invoke `on_fatal` and return.
async fn watch_protocol_statuses<S, F, Fut>(
    netdir_provider: Arc<dyn DirProvider>,
    mut events: S,
    mut last_evaluated_proto_status: Option<Arc<ProtoStatuses>>,
    software_publication_time: SystemTime,
    software_protocols: Protocols,
    override_status: Arc<MutCfg<SoftwareStatusOverrideConfig>>,
    on_fatal: F,
) where
    S: Stream<Item = DirEvent> + Send + Unpin,
    F: FnOnce(ErrorDetail) -> Fut + Send,
    Fut: Future<Output = ()> + Send,
{
    let weak_netdir_provider = Arc::downgrade(&netdir_provider);
    drop(netdir_provider);

    while let Some(e) = events.next().await {
        if e != DirEvent::NewProtocolRecommendation {
            continue;
        }

        let new_status = {
            let Some(provider) = Weak::upgrade(&weak_netdir_provider) else {
                break;
            };
            provider.protocol_statuses()
        };
        let Some((timestamp, new_status)) = new_status else {
            warn!(
                "Bug: Got DirEvent::NewProtocolRecommendation, but protocol_statuses() returned None."
            );
            continue;
        };
        // It information is older than this software, there is a good chance
        // that it has come from an invalid piece of data that somebody has cached.
        // We'll ignore it.
        //
        // For more information about this behavior, see:
        // https://spec.torproject.org/tor-spec/subprotocol-versioning.html#required-recommended
        if timestamp < software_publication_time {
            continue;
        }
        if last_evaluated_proto_status.as_ref() == Some(&new_status) {
            // We've already acted on this status information.
            continue;
        }

        if let Err(fatal) = evaluate_protocol_status(
            timestamp,
            &new_status,
            &software_protocols,
            override_status.get().as_ref(),
        ) {
            on_fatal(fatal).await;
            return;
        }
        last_evaluated_proto_status = Some(new_status);
    }

    // If we reach this point,
    // either we failed to upgrade the weak reference (because the netdir provider went away)
    // or the event stream was closed.
    // Either of these cases implies a clean shutdown.
}

/// Check whether we should take action based on the protocol `recommendation`
/// from `recommendation_timestamp`,
/// given that our own supported subprotocols are `software_protocols`.
///
/// - If any required protocols are missing, log and return an error.
/// - If no required protocols are missing, but some recommended protocols are missing,
///   log and return `Ok(())`.
/// - If no protocols are missing, return `Ok(())`.
///
/// Note: This function should ONLY return an error when the error is fatal.
#[allow(clippy::cognitive_complexity)] // complexity caused by trace macros.
pub(crate) fn evaluate_protocol_status(
    recommendation_timestamp: SystemTime,
    recommendation: &ProtoStatuses,
    software_protocols: &Protocols,
    override_status: &SoftwareStatusOverrideConfig,
) -> Result<(), ErrorDetail> {
    let result = recommendation.client().check_protocols(software_protocols);

    let rectime = || humantime::format_rfc3339(recommendation_timestamp);

    match &result {
        Ok(()) => Ok(()),
        Err(ProtocolSupportError::MissingRecommended(missing))
            if missing.difference(&missing_recommended_ok()).is_empty() =>
        {
            debug!(
                "Recommended protocols ({}) are missing, but that's expected: we haven't built them yet in Arti.",
                missing
            );
            Ok(())
        }
        Err(ProtocolSupportError::MissingRecommended(missing)) => {
            info!(
"At least one protocol not implemented by this version of Arti ({}) is listed as recommended for clients as of {}.
Please upgrade to a more recent version of Arti.",
                 missing, rectime());

            Ok(())
        }
        Err(e @ ProtocolSupportError::MissingRequired(missing)) => {
            error!(
"At least one protocol not implemented by this version of Arti ({}) is listed as required for clients, as of {}.
This version of Arti may not work correctly on the Tor network; please upgrade.",
                  &missing, rectime());
            if missing
                .difference(&override_status.ignore_missing_required_protocols)
                .is_empty()
            {
                warn!(
                    "(These protocols are listed in 'ignore_missing_required_protocols', so Arti won't exit now, but you should still upgrade.)"
                );
                return Ok(());
            }

            Err(ErrorDetail::MissingProtocol(e.clone()))
        }
        Err(e) => {
            // Because ProtocolSupportError is non-exhaustive, we need this case.
            warn_report!(
                e,
                "Unexpected problem while examining protocol recommendations"
            );
            if e.should_shutdown() {
                return Err(ErrorDetail::Bug(into_internal!(
                    "Unexpected fatal protocol error"
                )(e.clone())));
            }
            Ok(())
        }
    }
}

/// Return a list of the protocols which may be recommended,
/// and which we know are missing in Arti.
///
/// This function should go away in the future:
/// we use it to generate a slightly less alarming warning
/// when we have an _expected_ missing recommended protocol.
fn missing_recommended_ok() -> Protocols {
    // TODO: Remove this once congestion control is fully implemented.
    use tor_protover::named as n;
    [n::FLOWCTRL_CC].into_iter().collect()
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
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use tracing_test::traced_test;

    use super::*;

    #[test]
    #[traced_test]
    fn evaluate() {
        let rec: ProtoStatuses = serde_json::from_str(
            r#"{
                "client": { "recommended" : "Relay=1-5", "required" : "Relay=3" },
                "relay": { "recommended": "", "required" : ""}
            }"#,
        )
        .unwrap();
        let rec_date = humantime::parse_rfc3339("2025-03-08T10:16:00Z").unwrap();
        let no_override = SoftwareStatusOverrideConfig {
            ignore_missing_required_protocols: Protocols::default(),
        };
        let override_relay_3_4 = SoftwareStatusOverrideConfig {
            ignore_missing_required_protocols: "Relay=3-4".parse().unwrap(),
        };

        // nothing missing.
        let r =
            evaluate_protocol_status(rec_date, &rec, &"Relay=1-10".parse().unwrap(), &no_override);
        assert!(r.is_ok());
        assert!(!logs_contain("listed as required"));
        assert!(!logs_contain("listed as recommended"));

        // Missing recommended.
        let r =
            evaluate_protocol_status(rec_date, &rec, &"Relay=1-4".parse().unwrap(), &no_override);
        assert!(r.is_ok());
        assert!(!logs_contain("listed as required"));
        assert!(logs_contain("listed as recommended"));

        // Missing required, but override is there.
        let r = evaluate_protocol_status(
            rec_date,
            &rec,
            &"Relay=1".parse().unwrap(),
            &override_relay_3_4,
        );
        assert!(r.is_ok());
        assert!(logs_contain("listed as required"));
        assert!(logs_contain("but you should still upgrade"));

        // Missing required, no override.
        let r = evaluate_protocol_status(rec_date, &rec, &"Relay=1".parse().unwrap(), &no_override);
        assert!(r.is_err());
    }
}
