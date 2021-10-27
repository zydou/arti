//! Code to represent its single guard node and track its status.

use tor_linkspec::ChanTarget;
use tor_llcrypto::pk::{ed25519::Ed25519Identity, rsa::RsaIdentity};
use tor_netdir::{NetDir, Relay, RelayWeight};

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime};
use tracing::{trace, warn};

use crate::util::randomize_time;
use crate::{GuardId, GuardParams, GuardRestriction, GuardUsage};
use tor_persist::JsonValue;

/// Tri-state to represent whether a guard is believed to be reachable or not.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum Reachable {
    /// A guard is believed to be reachable, since we have successfully
    /// used it more recently than we've failed.
    Reachable,
    /// A guard is believed to be unreachable, since recent attempts
    /// to use it have failed.
    Unreachable,
    /// A guard's reachability status is unknown.
    ///
    /// The status might be unknown for a variety of reasons, including:
    ///   * We haven't tried to use the guard.
    ///   * Attempts to use it have failed, but those attempts are far
    ///     enough in the past that we're willing to retry them.
    Unknown,
}

impl Default for Reachable {
    fn default() -> Self {
        Reachable::Unknown
    }
}

/// The name and version of the crate that first picked a potential
/// guard.
///
/// The C Tor implementation has found it useful to keep this information
/// about guards, to better work around any bugs discovered in the guard
/// implementation.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct CrateId {
    /// The name of the crate that added this guard.
    #[serde(rename = "crate")]
    crate_name: String,
    /// The version of the crate that added this guard.
    version: String,
}

impl CrateId {
    /// Return a new CrateId representing this crate.
    fn this_crate() -> Option<Self> {
        let crate_name = option_env!("CARGO_PKG_NAME")?.to_string();
        let version = option_env!("CARGO_PKG_VERSION")?.to_string();
        Some(CrateId {
            crate_name,
            version,
        })
    }
}

/// A single guard node, as held by the guard manager.
///
/// A Guard is a Tor relay that clients use for the first hop of their
/// circuits.  It doesn't need to be a relay that's currently on the
/// network (that is, one that we could represent as a [`Relay`]):
/// guards might be temporarily unlisted.
///
/// Some fields in guards are persistent; others are reset with every
/// process.
///
/// # TODO
///
/// This structure uses [`Instant`] to represent non-persistent points
/// in time, and [`SystemTime`] to represent points in time that need
/// to be persistent.  That's possibly undesirable; maybe we should
/// come up with a better solution.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Guard {
    /// The identity keys for this guard.
    id: GuardId, // TODO: Maybe refactor this out as redundant someday.

    /// The most recently seen addresses for making OR connections to this
    /// guard.
    orports: Vec<SocketAddr>,

    /// When, approximately, did we first add this guard to our sample?
    #[serde(with = "humantime_serde")]
    added_at: SystemTime,

    /// What version of this crate added this guard to our sample?
    added_by: Option<CrateId>,

    /// If present, this guard is permanently disabled, and this
    /// object tells us why.
    // TODO: Wrap this in some kind of a future-proofing wrapper so that
    // we can safely add more variants to GuardDisabled.
    #[serde(default)]
    disabled: Option<GuardDisabled>,

    /// When, approximately, did we first successfully use this guard?
    ///
    /// (We call a guard "confirmed" if we have successfully used it at
    /// least once.)
    #[serde(with = "humantime_serde")]
    confirmed_at: Option<SystemTime>,

    /// If this guard is not listed in the current-consensus, this is the
    /// `valid_after` date of the oldest consensus in which it was not listed.
    ///
    /// A guard counts as "unlisted" if it is absent, unusable, or
    /// doesn't have the Guard flag.
    #[serde(with = "humantime_serde")]
    unlisted_since: Option<SystemTime>,

    /// When did we last give out this guard in response to a request?
    #[serde(skip)]
    last_tried_to_connect_at: Option<Instant>,

    /// If this guard is currently Unreachable, when should we next
    /// retry it?
    ///
    /// (Retrying a guard involves clearing this field, and seetting
    /// `reachable`
    #[serde(skip)]
    retry_at: Option<Instant>, // derived from tried_to_connect_at.

    /// Current reachability status for this guard.
    #[serde(skip)]
    reachable: Reachable,

    /// If this guard is currently failing, when did it start to fail?
    #[serde(skip)]
    failing_since: Option<Instant>,

    /// If true, then the last time we saw a relay entry for this
    /// guard, it seemed like a valid directory cache.
    #[serde(skip)]
    is_dir_cache: bool,

    /// If true, we have given this guard out for an exploratory circuit,
    /// and that exploratory circuit is still pending.
    ///
    /// A circuit is "exploratory" if we launched it on a non-primary guard.
    // TODO: Maybe this should be an integer that counts a number of such
    // circuits?
    #[serde(skip)]
    exploratory_circ_pending: bool,

    /// A count of all the circuit statuses we've seen on this guard.
    ///
    /// Used to implement a lightweight version of path-bias detection.
    #[serde(skip)]
    circ_history: CircHistory,

    /// True if we have warned about this guard behaving suspiciously.
    #[serde(skip)]
    suspicious_behavior_warned: bool,

    /// Fields from the state file that was used to make this `Guard` that
    /// this version of Arti doesn't understand.
    #[serde(flatten)]
    unknown_fields: HashMap<String, JsonValue>,
}

/// Wrapper to declare whether a given successful use of a guard is the
/// _first_ successful use of the guard.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum NewlyConfirmed {
    /// This was the first successful use of a guard.
    Yes,
    /// This guard has been used successfully before.
    No,
}

impl Guard {
    /// Create a new unused [`Guard`] from a [`Relay`].
    ///
    /// This function doesn't check whether the provided relay is a
    /// suitable guard node or not: that's up to the caller to decide.
    pub(crate) fn from_relay(relay: &Relay<'_>, now: SystemTime, params: &GuardParams) -> Self {
        let added_at = randomize_time(
            &mut rand::thread_rng(),
            now,
            params.lifetime_unconfirmed / 10,
        );

        Self::new(GuardId::from_relay(relay), relay.addrs().into(), added_at)
    }

    /// Return a new, manually constructed [`Guard`].
    fn new(id: GuardId, orports: Vec<SocketAddr>, added_at: SystemTime) -> Self {
        Guard {
            id,
            orports,
            added_at,
            added_by: CrateId::this_crate(),
            disabled: None,

            confirmed_at: None,
            unlisted_since: None,
            last_tried_to_connect_at: None,
            reachable: Reachable::Unknown,
            failing_since: None,
            retry_at: None,
            is_dir_cache: true,
            exploratory_circ_pending: false,
            circ_history: CircHistory::default(),
            suspicious_behavior_warned: false,
            unknown_fields: Default::default(),
        }
    }

    /// Return the identity of this Guard.
    pub(crate) fn guard_id(&self) -> &GuardId {
        &self.id
    }

    /// Return the reachability status for this guard.
    pub(crate) fn reachable(&self) -> Reachable {
        self.reachable
    }

    /// Return true if this guard is listed in the latest NetDir, and hasn't
    /// been turned off for some other reason.
    pub(crate) fn usable(&self) -> bool {
        self.unlisted_since.is_none() && self.disabled.is_none()
    }

    /// Copy all _non-persistent_ status from `other` to self.
    ///
    /// Requires that the two `Guard`s have the same ID.
    pub(crate) fn copy_status_from(&mut self, other: &Guard) {
        debug_assert_eq!(self.id, other.id);

        self.last_tried_to_connect_at = other.last_tried_to_connect_at;
        self.retry_at = other.retry_at;
        self.reachable = other.reachable;
        self.failing_since = other.failing_since;
        self.is_dir_cache = other.is_dir_cache;
        self.exploratory_circ_pending = other.exploratory_circ_pending;
    }

    /// Change the reachability status for this guard.
    fn set_reachable(&mut self, r: Reachable) {
        if self.reachable != r {
            trace!(guard_id = ?self.id, old=?self.reachable, new=?r, "Guard status changed.");
            self.reachable = r;
        }
    }

    /// Return true if at least one exploratory circuit is pending to this
    /// guard.
    ///
    /// A circuit is "exploratory" if launched on a non-primary guard.
    ///
    /// # TODO
    ///
    /// The "exploratory" definition doesn't quite match up with the behavior
    /// in the spec, but it is what Tor does.
    pub(crate) fn exploratory_circ_pending(&self) -> bool {
        self.exploratory_circ_pending
    }

    /// Note that an exploratory circuit is pending (if `pending` is true),
    /// or not pending (if `pending` is false.
    pub(crate) fn note_exploratory_circ(&mut self, pending: bool) {
        self.exploratory_circ_pending = pending;
    }

    /// Possibly mark this guard as retriable, if it has been down for
    /// long enough.
    ///
    /// Specifically, if the guard is to be Unreachable, and our last attempt
    /// to connect to it is far enough in the past from `now`, we change its
    /// status to Unknown.
    pub(crate) fn consider_retry(&mut self, now: Instant) {
        if let Some(retry_at) = self.retry_at {
            debug_assert!(self.reachable == Reachable::Unreachable);
            if retry_at <= now {
                self.mark_retriable();
            }
        }
    }

    /// If this guard is marked Unreachable, clear its unreachability status
    /// and mark it as Unknown.
    pub(crate) fn mark_retriable(&mut self) {
        if self.reachable != Reachable::Reachable {
            self.set_reachable(Reachable::Unknown);
            self.retry_at = None;
        }
    }

    /// Return true if this guard obeys the restriction in `rest`.
    fn obeys_restriction(&self, rest: &GuardRestriction) -> bool {
        match rest {
            GuardRestriction::AvoidId(ed) => &self.id.ed25519 != ed,
        }
    }

    /// Return true if this guard is suitable to use for the provided `usage`.
    pub(crate) fn conforms_to_usage(&self, usage: &GuardUsage) -> bool {
        use crate::GuardUsageKind;
        if usage.kind == GuardUsageKind::OneHopDirectory && !self.is_dir_cache {
            return false;
        }
        match &usage.restriction {
            Some(rest) => self.obeys_restriction(rest),
            None => true,
        }
    }

    /// Change this guard's status based on a newly received or newly
    /// updated [`NetDir`].
    ///
    /// A guard may become "listed" or "unlisted": a listed guard is
    /// one that appears in the consensus with the Guard flag.
    ///
    /// Additionally, a guard's orports may change, if the directory
    /// lists a new address for the relay.
    pub(crate) fn update_from_netdir(&mut self, netdir: &NetDir) {
        // This is a tricky check, since if we're missing a microdescriptor
        // for the RSA id, we won't know whether the ed25519 id is listed or
        // not.
        let listed = match netdir.id_pair_listed(&self.id.ed25519, &self.id.rsa) {
            Some(true) => {
                // Definitely listed.
                let relay = self
                    .id
                    .get_relay(netdir)
                    .expect("Couldn't get a listed relay?!");
                // Update address information.
                self.orports = relay.addrs().into();
                // Check whether we can currently use it as a directory cache.
                self.is_dir_cache = relay.is_dir_cache();

                relay.is_flagged_guard()
            }
            Some(false) => false, // Definitely not listed.
            None => return,       // Nothing to do: we can't tell if it's listed.
        };

        if listed {
            // Definitely listed, so clear unlisted_since.
            self.mark_listed();
        } else {
            // Unlisted or not a guard; mark it unlisted.
            self.mark_unlisted(netdir.lifetime().valid_after());
        }
    }

    /// Mark this guard as currently listed in the directory.
    fn mark_listed(&mut self) {
        if self.unlisted_since.is_some() {
            trace!(guard_id = ?self.id, "Guard is now listed again.");
            self.unlisted_since = None;
        }
    }

    /// Mark this guard as having been unlisted since `now`, if it is not
    /// already so marked.
    fn mark_unlisted(&mut self, now: SystemTime) {
        if self.unlisted_since.is_none() {
            trace!(guard_id = ?self.id, "Guard is now unlisted.");
            self.unlisted_since = Some(now);
        }
    }

    /// Return true if we should remove this guard from the current guard
    /// sample.
    ///
    /// Guards may be ready for removal because they have been
    /// confirmed too long ago, if they have been sampled too long ago
    /// (if they are not confirmed), or if they have been unlisted for
    /// too long.
    pub(crate) fn is_expired(&self, params: &GuardParams, now: SystemTime) -> bool {
        /// Helper: Return true if `t2` is after `t1` by at least `d`.
        fn expired_by(t1: SystemTime, d: Duration, t2: SystemTime) -> bool {
            if let Ok(elapsed) = t2.duration_since(t1) {
                elapsed > d
            } else {
                false
            }
        }
        if self.disabled.is_some() {
            // We never forget a guard that we've disabled: we've disabled
            // it for a reason.
            return false;
        }
        if let Some(confirmed_at) = self.confirmed_at {
            if expired_by(confirmed_at, params.lifetime_confirmed, now) {
                return true;
            }
        } else if expired_by(self.added_at, params.lifetime_unconfirmed, now) {
            return true;
        }

        if let Some(unlisted_since) = self.unlisted_since {
            if expired_by(unlisted_since, params.lifetime_unlisted, now) {
                return true;
            }
        }

        false
    }

    /// Record that a failure has happened for this guard.
    ///
    /// If `is_primary` is true, this is a primary guard (q.v.).
    pub(crate) fn record_failure(&mut self, now: Instant, is_primary: bool) {
        let failing_since = self.failing_since.get_or_insert(now);
        let failing_time = now.saturating_duration_since(*failing_since);
        self.set_reachable(Reachable::Unreachable);
        self.exploratory_circ_pending = false;

        let connect_attempt = self.last_tried_to_connect_at.unwrap_or(now);

        // This matches tor, but not the spec.
        let retry_interval = retry_interval(is_primary, failing_time);

        // TODO-SPEC: Oughtn't we randomize this?
        self.retry_at = Some(connect_attempt + retry_interval);

        self.circ_history.n_failures += 1;
    }

    /// Note that we have launch an attempted use of this guard.
    ///
    /// We use this time to decide when to retry failing guards, and
    /// to see if the guard has been "pending" for a long time.
    pub(crate) fn record_attempt(&mut self, connect_attempt: Instant) {
        self.last_tried_to_connect_at = self
            .last_tried_to_connect_at
            .map(|last| last.max(connect_attempt))
            .or(Some(connect_attempt));
    }

    /// Return true if this guard has an exploratory circuit pending and
    /// if the most recent attempt to connect to it is after `when`.
    ///
    /// See [`Self::exploratory_circ_pending`].
    pub(crate) fn exploratory_attempt_after(&self, when: Instant) -> bool {
        self.exploratory_circ_pending
            && self.last_tried_to_connect_at.map(|t| t > when) == Some(true)
    }

    /// Note that a guard has been used successfully.
    ///
    /// Updates that guard's status to reachable, clears any failing status
    /// information for it, and decides whether the guard is newly confirmed.
    ///
    /// If the guard is newly confirmed, the caller must add it to the
    /// list of confirmed guards.
    #[must_use = "You need to check whether a succeeding guard is confirmed."]
    pub(crate) fn record_success(
        &mut self,
        now: SystemTime,
        params: &GuardParams,
    ) -> NewlyConfirmed {
        self.failing_since = None;
        self.retry_at = None;
        self.set_reachable(Reachable::Reachable);
        self.exploratory_circ_pending = false;
        self.circ_history.n_successes += 1;

        if self.confirmed_at.is_none() {
            self.confirmed_at = Some(
                randomize_time(
                    &mut rand::thread_rng(),
                    now,
                    params.lifetime_unconfirmed / 10,
                )
                .max(self.added_at),
            );
            // TODO-SPEC: The "max" above isn't specified by guard-spec,
            // but I think it's wise.
            trace!(guard_id = ?self.id, "Newly confirmed");
            NewlyConfirmed::Yes
        } else {
            NewlyConfirmed::No
        }
    }

    /// Note that a cicuit through this guard died in a way that we couldn't
    /// necessarily attribute to the guard.
    pub(crate) fn record_indeterminate_result(&mut self) {
        self.circ_history.n_indeterminate += 1;

        if let Some(ratio) = self.circ_history.indeterminate_ratio() {
            // TODO: These should not be hardwired, and they may be set
            // too high.
            /// If this fraction of circs are suspcious, we should disable
            /// the guard.
            const DISABLE_THRESHOLD: f64 = 0.7;
            /// If this fractino of circuits are suspicious, we should
            /// warn.
            const WARN_THRESHOLD: f64 = 0.5;

            if ratio > DISABLE_THRESHOLD {
                let reason = GuardDisabled::TooManyIndeterminateFailures {
                    history: self.circ_history.clone(),
                    failure_ratio: ratio,
                    threshold_ratio: DISABLE_THRESHOLD,
                };
                warn!(guard=?self.id, "Disabling guard: {:.1}% of circuits died under mysterious circumstances, exceeding threshold of {:.1}%", ratio*100.0, (DISABLE_THRESHOLD*100.0));
                self.disabled = Some(reason);
            } else if ratio > WARN_THRESHOLD && !self.suspicious_behavior_warned {
                warn!(guard=?self.id, "Questionable guard: {:.1}% of circuits died under mysterious circumstances.", ratio*100.0);
                self.suspicious_behavior_warned = true;
            }
        }
    }

    /// Return the weight of this guard (if any) according to `dir`.
    ///
    /// We use this information to decide whether we are about to sample
    /// too much of the network as guards.
    pub(crate) fn get_weight(&self, dir: &NetDir) -> Option<RelayWeight> {
        dir.weight_by_rsa_id(&self.id.rsa, tor_netdir::WeightRole::Guard)
    }

    /// Return a [`crate::Guard`] object to represent this guard.
    pub(crate) fn get_external_rep(&self) -> crate::Guard {
        crate::Guard {
            id: self.id.clone(),
            orports: self.orports.clone(),
        }
    }
}

impl tor_linkspec::ChanTarget for Guard {
    fn addrs(&self) -> &[SocketAddr] {
        &self.orports[..]
    }
    fn ed_identity(&self) -> &Ed25519Identity {
        &self.id.ed25519
    }
    fn rsa_identity(&self) -> &RsaIdentity {
        &self.id.rsa
    }
}

/// A reason for permanently disabling a guard.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
enum GuardDisabled {
    /// Too many attempts to use this guard failed for indeterminate reasons.
    TooManyIndeterminateFailures {
        /// Observed count of status reports about this guard.
        history: CircHistory,
        /// Observed fraction of indeterminate status reports.
        failure_ratio: f64,
        /// Threshold that was exceeded.
        threshold_ratio: f64,
    },
}

/// Return the interval after which we should retry a guard that has
/// been failing for the last `failing`.
///
/// If the guard `is_primary`, we use a more aggressive retry schedule.
fn retry_interval(is_primary: bool, failing: Duration) -> Duration {
    /// One minute.
    const MIN: Duration = Duration::from_secs(60);
    /// One hour.
    const HOUR: Duration = Duration::from_secs(60 * 60);
    /// One (normal) day.
    const DAY: Duration = Duration::from_secs(24 * 60 * 60);

    // TODO-SPEC: This matches tor, not guardspec.
    // TODO: Hardcoding this feels ugly.
    #[allow(clippy::collapsible_else_if)]
    if is_primary {
        if failing < 6 * HOUR {
            10 * MIN
        } else if failing < 4 * DAY {
            90 * MIN
        } else if failing < 7 * DAY {
            4 * HOUR
        } else {
            9 * HOUR
        }
    } else {
        if failing < 6 * HOUR {
            HOUR
        } else if failing < 4 * DAY {
            4 * HOUR
        } else if failing < 7 * DAY {
            18 * HOUR
        } else {
            36 * HOUR
        }
    }
}

/// The recent history of circuit activity on this guard.
///
/// We keep this information so that we can tell if too many circuits are
/// winding up in "indeterminate" status.
///
/// # What's this for?
///
/// Recall that an "indeterminate" circuit failure is one that might
/// or might not be the guard's fault.  For example, if the second hop
/// of the circuit fails, we can't tell whether to blame the guard,
/// the second hop, or the internet between them.
///
/// But we don't want to allow an unbounded number of indeterminate
/// failures: if we did, it would allow a malicious guard to simply
/// reject any circuit whose second hop it didn't like, and thereby
/// filter the client's paths down to a hostile subset.
///
/// So as a workaround, and to discourage this kind of behavior, we
/// track the fraction of indeterminate circuits, and disable any guard
/// where the fraction is too high.
//
// TODO: We may eventually want to make this structure persistent.  If we
// do, however, we'll need a way to make ancient history expire.  We might
// want that anyway, to make attacks harder.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct CircHistory {
    /// How many times have we seen this guard succeed?
    n_successes: u32,
    /// How many times have we seen this guard fail?
    #[allow(dead_code)] // not actually used yet.
    n_failures: u32,
    /// How many times has this guard given us indeterminate results?
    n_indeterminate: u32,
}

impl CircHistory {
    /// If we hae seen enough, return the fraction of circuits that have
    /// "died under mysterious circumstances".
    fn indeterminate_ratio(&self) -> Option<f64> {
        // TODO: This should probably not be hardwired

        /// Don't try to give a ratio unless we've seen this many observations.
        const MIN_OBSERVATIONS: u32 = 15;

        let total = self.n_successes + self.n_indeterminate;
        if total < MIN_OBSERVATIONS {
            return None;
        }

        Some(f64::from(self.n_indeterminate) / f64::from(total))
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn crate_id() {
        let id = CrateId::this_crate().unwrap();
        assert_eq!(&id.crate_name, "tor-guardmgr");
        dbg!(&id.version);

        assert_eq!(Some(id.version.as_ref()), option_env!("CARGO_PKG_VERSION"));
    }

    fn basic_id() -> GuardId {
        GuardId::new([13; 32].into(), [37; 20].into())
    }
    fn basic_guard() -> Guard {
        let id = basic_id();
        let ports = vec!["127.0.0.7:7777".parse().unwrap()];
        let added = SystemTime::now();
        Guard::new(id, ports, added)
    }

    #[test]
    fn simple_accessors() {
        let id = basic_id();
        let g = basic_guard();

        assert_eq!(g.guard_id(), &id);
        assert_eq!(g.ed_identity(), &id.ed25519);
        assert_eq!(g.rsa_identity(), &id.rsa);
        assert_eq!(g.addrs(), &["127.0.0.7:7777".parse().unwrap()]);
        assert_eq!(g.reachable(), Reachable::Unknown);
        assert_eq!(g.reachable(), Reachable::default());

        use crate::GuardUsageBuilder;
        let usage1 = GuardUsageBuilder::new()
            .restriction(GuardRestriction::AvoidId([22; 32].into()))
            .build()
            .unwrap();
        let usage2 = GuardUsageBuilder::new()
            .restriction(GuardRestriction::AvoidId([13; 32].into()))
            .build()
            .unwrap();
        let usage3 = GuardUsage::default();
        assert!(g.conforms_to_usage(&usage1));
        assert!(!g.conforms_to_usage(&usage2));
        assert!(g.conforms_to_usage(&usage3));
    }

    #[test]
    fn retry_interval_check() {
        const MIN: Duration = Duration::from_secs(60);
        const HOUR: Duration = Duration::from_secs(60 * 60);
        const DAY: Duration = Duration::from_secs(24 * 60 * 60);

        assert_eq!(retry_interval(true, MIN), 10 * MIN);
        assert_eq!(retry_interval(true, 5 * MIN), 10 * MIN);
        assert_eq!(retry_interval(true, 7 * HOUR), 90 * MIN);
        assert_eq!(retry_interval(true, 24 * HOUR), 90 * MIN);
        assert_eq!(retry_interval(true, 5 * DAY), 4 * HOUR);
        assert_eq!(retry_interval(true, 100 * DAY), 9 * HOUR);

        assert_eq!(retry_interval(false, MIN), HOUR);
        assert_eq!(retry_interval(false, 5 * MIN), HOUR);
        assert_eq!(retry_interval(false, 7 * HOUR), 4 * HOUR);
        assert_eq!(retry_interval(false, 24 * HOUR), 4 * HOUR);
        assert_eq!(retry_interval(false, 5 * DAY), 18 * HOUR);
        assert_eq!(retry_interval(false, 100 * DAY), 36 * HOUR);
    }

    #[test]
    fn record_attempt() {
        let t1 = Instant::now() - Duration::from_secs(10);
        let t2 = Instant::now() - Duration::from_secs(5);
        let t3 = Instant::now();

        let mut g = basic_guard();

        assert!(g.last_tried_to_connect_at.is_none());
        g.record_attempt(t1);
        assert_eq!(g.last_tried_to_connect_at, Some(t1));
        g.record_attempt(t3);
        assert_eq!(g.last_tried_to_connect_at, Some(t3));
        g.record_attempt(t2);
        assert_eq!(g.last_tried_to_connect_at, Some(t3));
    }

    #[test]
    fn record_failure() {
        let t1 = Instant::now() - Duration::from_secs(10);
        let t2 = Instant::now();

        let mut g = basic_guard();
        assert!(g.failing_since.is_none());
        g.record_failure(t1, true);
        assert_eq!(g.failing_since, Some(t1));
        assert_eq!(g.reachable(), Reachable::Unreachable);
        assert_eq!(g.retry_at, Some(t1 + Duration::from_secs(600)));

        g.record_failure(t2, true);
        assert_eq!(g.failing_since, Some(t1));
    }

    #[test]
    fn record_success() {
        let t1 = Instant::now() - Duration::from_secs(10);
        // has to be in the future, since the guard's "added_at" time is based on now.
        let t2 = SystemTime::now() + Duration::from_secs(300 * 86400);
        let t3 = Instant::now() + Duration::from_secs(310 * 86400);
        let t4 = SystemTime::now() + Duration::from_secs(320 * 86400);

        let mut g = basic_guard();
        g.record_failure(t1, true);
        assert_eq!(g.reachable(), Reachable::Unreachable);

        let conf = g.record_success(t2, &GuardParams::default());
        assert_eq!(g.reachable(), Reachable::Reachable);
        assert_eq!(conf, NewlyConfirmed::Yes);
        assert!(g.retry_at.is_none());
        assert!(g.failing_since.is_none());
        assert!(g.confirmed_at.unwrap() <= t2);
        assert!(g.confirmed_at.unwrap() >= t2 - Duration::from_secs(12 * 86400));
        let confirmed_at_orig = g.confirmed_at;

        g.record_failure(t3, true);
        assert_eq!(g.reachable(), Reachable::Unreachable);

        let conf = g.record_success(t4, &GuardParams::default());
        assert_eq!(conf, NewlyConfirmed::No);
        assert_eq!(g.reachable(), Reachable::Reachable);
        assert!(g.retry_at.is_none());
        assert!(g.failing_since.is_none());
        assert_eq!(g.confirmed_at, confirmed_at_orig);
    }

    #[test]
    fn retry() {
        let t1 = Instant::now();
        let mut g = basic_guard();

        g.record_failure(t1, true);
        assert!(g.retry_at.is_some());
        assert_eq!(g.reachable(), Reachable::Unreachable);

        // Not yet retriable.
        g.consider_retry(t1);
        assert!(g.retry_at.is_some());
        assert_eq!(g.reachable(), Reachable::Unreachable);

        // Not retriable right before the retry time.
        g.consider_retry(g.retry_at.unwrap() - Duration::from_secs(1));
        assert!(g.retry_at.is_some());
        assert_eq!(g.reachable(), Reachable::Unreachable);

        // Retriable right after the retry time.
        g.consider_retry(g.retry_at.unwrap() + Duration::from_secs(1));
        assert!(g.retry_at.is_none());
        assert_eq!(g.reachable(), Reachable::Unknown);
        assert_eq!(g.failing_since, Some(t1));
    }

    #[test]
    fn expiration() {
        const DAY: Duration = Duration::from_secs(24 * 60 * 60);
        let params = GuardParams::default();
        let now = SystemTime::now();

        let g = basic_guard();
        assert!(!g.is_expired(&params, now));
        assert!(!g.is_expired(&params, now + 10 * DAY));
        assert!(!g.is_expired(&params, now + 25 * DAY));
        assert!(!g.is_expired(&params, now + 70 * DAY));
        assert!(g.is_expired(&params, now + 200 * DAY)); // lifetime_unconfirmed.

        let mut g = basic_guard();
        let _ = g.record_success(now, &params);
        assert!(!g.is_expired(&params, now));
        assert!(!g.is_expired(&params, now + 10 * DAY));
        assert!(!g.is_expired(&params, now + 25 * DAY));
        assert!(g.is_expired(&params, now + 70 * DAY)); // lifetime_confirmed.

        let mut g = basic_guard();
        g.mark_unlisted(now);
        assert!(!g.is_expired(&params, now));
        assert!(!g.is_expired(&params, now + 10 * DAY));
        assert!(g.is_expired(&params, now + 25 * DAY)); // lifetime_unlisted
    }

    #[test]
    fn netdir_integration() {
        use tor_netdir::testnet;
        let netdir = testnet::construct_netdir()
            .unwrap()
            .unwrap_if_sufficient()
            .unwrap();
        let params = GuardParams::default();
        let now = SystemTime::now();

        // Construct a guard from a relay from the netdir.
        let relay22 = netdir.by_id(&[22; 32].into()).unwrap();
        let guard22 = Guard::from_relay(&relay22, now, &params);
        assert_eq!(guard22.ed_identity(), relay22.ed_identity());
        assert_eq!(guard22.rsa_identity(), relay22.rsa_identity());
        assert!(Some(guard22.added_at) <= Some(now));

        // Can we still get the relay back?
        let r = guard22.id.get_relay(&netdir).unwrap();
        assert_eq!(r.ed_identity(), relay22.ed_identity());

        // Can we check on the guard's weight?
        let w = guard22.get_weight(&netdir).unwrap();
        assert_eq!(w, 3000.into());

        // Now try a guard that isn't in the netdir.
        let guard255 = Guard::new(
            GuardId::new([255; 32].into(), [255; 20].into()),
            vec![],
            now,
        );
        assert!(guard255.id.get_relay(&netdir).is_none());
        assert!(guard255.get_weight(&netdir).is_none());
    }

    #[test]
    fn update_from_netdir() {
        use tor_netdir::testnet;
        let netdir = testnet::construct_netdir()
            .unwrap()
            .unwrap_if_sufficient()
            .unwrap();
        // Same as above but omit [22]
        let netdir2 = testnet::construct_custom_netdir(|idx, mut node| {
            if idx == 22 {
                node.omit_rs = true;
            }
        })
        .unwrap()
        .unwrap_if_sufficient()
        .unwrap();
        //let params = GuardParams::default();
        let now = SystemTime::now();

        // Try a guard that isn't in the netdir at all.
        let mut guard255 = Guard::new(
            GuardId::new([255; 32].into(), [255; 20].into()),
            vec!["8.8.8.8:53".parse().unwrap()],
            now,
        );
        assert_eq!(guard255.unlisted_since, None);
        guard255.update_from_netdir(&netdir);
        assert_eq!(
            guard255.unlisted_since,
            Some(netdir.lifetime().valid_after())
        );
        assert!(!guard255.orports.is_empty());

        // Try a guard that is in netdir, but not netdir2.
        let mut guard22 = Guard::new(GuardId::new([22; 32].into(), [22; 20].into()), vec![], now);
        let relay22 = guard22.id.get_relay(&netdir).unwrap();
        guard22.update_from_netdir(&netdir);
        assert_eq!(guard22.unlisted_since, None); // It's listed.
        assert_eq!(&guard22.orports, relay22.addrs()); // Addrs are set.
        guard22.update_from_netdir(&netdir2);
        assert_eq!(
            guard22.unlisted_since,
            Some(netdir2.lifetime().valid_after())
        );
        assert_eq!(&guard22.orports, relay22.addrs()); // Addrs still set.
    }

    #[test]
    fn pending() {
        let mut g = basic_guard();
        let t1 = Instant::now();
        let t2 = t1 + Duration::from_secs(100);
        let t3 = t1 + Duration::from_secs(200);

        assert!(!g.exploratory_attempt_after(t1));
        assert!(!g.exploratory_circ_pending());

        g.note_exploratory_circ(true);
        g.record_attempt(t2);
        assert!(g.exploratory_circ_pending());
        assert!(g.exploratory_attempt_after(t1));
        assert!(!g.exploratory_attempt_after(t3));

        g.note_exploratory_circ(false);
        assert!(!g.exploratory_circ_pending());
        assert!(!g.exploratory_attempt_after(t1));
        assert!(!g.exploratory_attempt_after(t3));
    }

    #[test]
    fn circ_history() {
        let mut h = CircHistory {
            n_successes: 3,
            n_failures: 4,
            n_indeterminate: 3,
        };
        assert!(h.indeterminate_ratio().is_none());

        h.n_successes = 20;
        assert!((h.indeterminate_ratio().unwrap() - 3.0 / 23.0).abs() < 0.0001);
    }

    #[test]
    fn disable_on_failure() {
        let mut g = basic_guard();
        let params = GuardParams::default();

        let now = SystemTime::now();

        let _ignore = g.record_success(now, &params);
        for _ in 0..13 {
            g.record_indeterminate_result();
        }
        // We're still under the observation threshold.
        assert!(g.disabled.is_none());

        // This crosses the threshold.
        g.record_indeterminate_result();
        assert!(g.disabled.is_some());

        #[allow(unreachable_patterns)]
        match g.disabled.unwrap() {
            GuardDisabled::TooManyIndeterminateFailures {
                history: _,
                failure_ratio,
                threshold_ratio,
            } => {
                assert!((failure_ratio - 0.933).abs() < 0.01);
                assert!((threshold_ratio - 0.7).abs() < 0.01);
            }
            other => {
                panic!("Wrong variant: {:?}", other);
            }
        }
    }
}
