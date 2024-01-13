//! IPT Establisher
//!
//! Responsible for maintaining and establishing one introduction point.
//!
//! TODO (#1235): move docs from `hssvc-ipt-algorithm.md`
//!
//! See the docs for
//! [`IptManager::idempotently_progress_things_now`](crate::ipt_mgr::IptManager::idempotently_progress_things_now)
//! for details of our algorithm.

use std::sync::{Arc, Mutex};

use educe::Educe;
use futures::{channel::mpsc, task::SpawnExt as _, Future, FutureExt as _};
use itertools::Itertools;
use postage::watch;
use safelog::Redactable as _;
use tor_async_utils::oneshot;
use tor_async_utils::DropNotifyWatchSender;
use tor_cell::relaycell::{
    hs::est_intro::{self, EstablishIntroDetails},
    msg::{AnyRelayMsg, IntroEstablished},
    RelayMsg as _,
};
use tor_circmgr::hspool::HsCircPool;
use tor_error::{bad_api_usage, debug_report, internal, into_internal};
use tor_hscrypto::{
    pk::{HsBlindIdKeypair, HsIdKey, HsIntroPtSessionIdKeypair, HsSvcNtorKeypair},
    time::TimePeriod,
    Subcredential,
};
use tor_keymgr::ArtiPathComponent;
use tor_keymgr::KeyPath;
use tor_keymgr::KeySpecifierComponent;
use tor_keymgr::KeySpecifierPattern as _;
use tor_keymgr::{KeyMgr, KeyPathRange};
use tor_linkspec::CircTarget;
use tor_linkspec::{HasRelayIds as _, RelayIds};
use tor_netdir::NetDirProvider;
use tor_proto::circuit::{ClientCirc, ConversationInHandler, MetaCellDisposition};
use tor_rtcompat::{Runtime, SleepProviderExt as _};
use tracing::debug;
use void::{ResultVoidErrExt as _, Void};

use crate::keys::BlindIdKeypairSpecifierPattern;
use crate::replay::ReplayError;
use crate::replay::ReplayLog;
use crate::HsIdPublicKeySpecifier;
use crate::OnionServiceConfig;
use crate::{
    req::RendRequestContext,
    svc::{LinkSpecs, NtorPublicKey},
    HsNickname,
};
use crate::{FatalError, IptLocalId, RendRequest};

use super::netdir::{wait_for_netdir, wait_for_netdir_to_list, NetdirProviderShutdown};

/// Handle onto the task which is establishing and maintaining one IPT
pub(crate) struct IptEstablisher {
    /// A oneshot sender that notifies the running task that it's time to shut
    /// down.
    #[allow(dead_code)] // TODO HSS: Make sure this is okay.
    terminate_tx: oneshot::Sender<Void>,

    /// Mutable state shared with the Establisher, Reactor, and MsgHandler.
    state: Arc<Mutex<EstablisherState>>,
}

/// When the `IptEstablisher` is dropped it is torn down
///
/// Synchronously
///
///  * No rendezvous requests will be accepted
///    that arrived after `Drop::drop` returns.
///
/// Asynchronously
///
///  * Circuits constructed for this IPT are torn down
///  * The `rend_reqs` sink is closed (dropped)
///  * `IptStatusStatus::Faulty` will be indicated
impl Drop for IptEstablisher {
    fn drop(&mut self) {
        // Make sure no more requests are accepted once this returns.
        //
        // (Note that if we didn't care about the "no more rendezvous
        // requests will be accepted" requirement, we could do away with this
        // code and the corresponding check for `RequestDisposition::Shutdown` in
        // `IptMsgHandler::handle_msg`.)
        self.state.lock().expect("poisoned lock").accepting_requests = RequestDisposition::Shutdown;

        // Tell the reactor to shut down... by doing nothing.
        //
        // (When terminate_tx is dropped, it will send an error to the
        // corresponding terminate_rx.)
    }
}

/// An error from trying to work with an IptEstablisher.
#[derive(Clone, Debug, thiserror::Error)]
pub(crate) enum IptError {
    /// We couldn't get a network directory to use when building circuits.
    #[error("No network directory available")]
    #[allow(dead_code)] // TODO HSS emit this error, or verify that it isn't needed
    NoNetdir(#[source] tor_netdir::Error),

    /// The network directory provider is shutting down without giving us the
    /// netdir we asked for.
    #[error("{0}")]
    NetdirProviderShutdown(#[from] NetdirProviderShutdown),

    /// When we tried to establish this introduction point, we found that the
    /// netdir didn't list it.
    #[error("Introduction point not listed in network directory")]
    IntroPointNotListed,

    /// We encountered an error while building a circuit to an intro point.
    #[error("Unable to build circuit to introduction point")]
    BuildCircuit(#[source] tor_circmgr::Error),

    /// We encountered an error while building and signing our establish_intro
    /// message.
    #[error("Unable to construct signed ESTABLISH_INTRO message")]
    CreateEstablishIntro(#[source] tor_cell::Error),

    /// We encountered a timeout after building the circuit.
    #[error("Timeout during ESTABLISH_INTRO handshake.")]
    EstablishTimeout,

    /// We encountered an error while sending our establish_intro
    /// message.
    #[error("Unable to send an ESTABLISH_INTRO message")]
    SendEstablishIntro(#[source] tor_proto::Error),

    /// We did not receive an INTRO_ESTABLISHED message like we wanted.
    #[error("Did not receive INTRO_ESTABLISHED message")]
    // TODO HSS: I'd like to receive more information here.  What happened
    // instead?  But the information might be in the MsgHandler, might be in the
    // Circuit,...
    ReceiveAck,

    /// We received an invalid INTRO_ESTABLISHED message.
    #[error("Got an invalid INTRO_ESTABLISHED message")]
    BadEstablished,

    /// We encountered a programming error.
    #[error("Internal error")]
    Bug(#[from] tor_error::Bug),
}

impl tor_error::HasKind for IptError {
    fn kind(&self) -> tor_error::ErrorKind {
        use tor_error::ErrorKind as EK;
        use IptError as E;
        match self {
            E::NoNetdir(_) => EK::BootstrapRequired, // TODO (#1225) maybe not right.
            E::NetdirProviderShutdown(e) => e.kind(),
            E::IntroPointNotListed => EK::TorDirectoryError, // TODO (#1225) Not correct kind.
            E::BuildCircuit(e) => e.kind(),
            E::EstablishTimeout => EK::TorNetworkTimeout, // TODO (#1225) right?
            E::SendEstablishIntro(e) => e.kind(),
            E::ReceiveAck => EK::RemoteProtocolViolation, // TODO (#1225) not always right.
            E::BadEstablished => EK::RemoteProtocolViolation,
            E::CreateEstablishIntro(_) => EK::Internal,
            E::Bug(e) => e.kind(),
        }
    }
}

impl IptError {
    /// Return true if this error appears to be the introduction point's fault.
    fn is_ipt_failure(&self) -> bool {
        // TODO (#1234): actually test something here.
        true
    }
}

/// Parameters for an introduction point
///
/// Consumed by `IptEstablisher::new`.
/// Primarily serves as a convenient way to bundle the many arguments required.
///
/// Does not include:
///  * The runtime (which would force this struct to have a type parameter)
///  * The circuit builder (leaving this out makes it possible to use this
///    struct during mock execution, where we don't call `IptEstablisher::new`).
#[derive(Educe)]
#[educe(Debug)]
pub(crate) struct IptParameters {
    /// A receiver that we can use to tell us about updates in our configuration.
    ///
    /// Configuration changes may tell us to change our introduction points or build new
    /// circuits to them.
    //
    // TODO (#1209):
    //
    // We want to make a new introduction circuit if our dos parameters change,
    // which means that we should possibly be watching for changes in our
    // configuration.  Right now, though, we only copy out the configuration
    // on startup.
    #[educe(Debug(ignore))]
    pub(crate) config_rx: watch::Receiver<Arc<OnionServiceConfig>>,
    /// A `NetDirProvider` that we'll use to find changes in the network
    /// parameters, and to look up oinformation about routers.
    #[educe(Debug(ignore))]
    pub(crate) netdir_provider: Arc<dyn NetDirProvider>,
    /// A shared sender that we'll use to report incoming INTRODUCE2 requests
    /// for rendezvous circuits.
    #[educe(Debug(ignore))]
    pub(crate) introduce_tx: mpsc::Sender<RendRequest>,
    /// Opaque local ID for this introduction point.
    ///
    /// This ID does not change within the lifetime of an [`IptEstablisher`].
    /// See [`IptLocalId`] for information about what changes would require a
    /// new ID (and hence a new `IptEstablisher`).
    pub(crate) lid: IptLocalId,
    /// Persistent log for INTRODUCE2 requests.
    ///
    /// We use this to record the requests that we see, and to prevent replays.
    #[educe(Debug(ignore))]
    pub(crate) replay_log: ReplayLog,
    /// A set of identifiers for the Relay that we intend to use as the
    /// introduction point.
    ///
    /// We use this to identify the relay within a `NetDir`, ant to make sure
    /// we're connecting to the right introduction point.
    pub(crate) target: RelayIds,
    /// Keypair used to authenticate and identify ourselves to this introduction
    /// point.
    ///
    /// Later, we publish the public component of this keypair in our HsDesc,
    /// and clients use it to tell the introduction point which introduction circuit
    /// should receive their requests.
    ///
    /// This is the `K_hs_ipt_sid` keypair.
    pub(crate) k_sid: Arc<HsIntroPtSessionIdKeypair>,
    /// Whether this `IptEstablisher` should begin by accepting requests, or
    /// wait to be told that requests are okay.
    pub(crate) accepting_requests: RequestDisposition,
    /// Keypair used to decrypt INTRODUCE2 requests from clients.
    ///
    /// This is the `K_hss_ntor` keypair, used with the "HS_NTOR" handshake to
    /// form a shared key set of keys with the client, and decrypt information
    /// about the client's chosen rendezvous point and extensions.
    pub(crate) k_ntor: Arc<HsSvcNtorKeypair>,
}

impl IptEstablisher {
    /// Try to set up, and maintain, an IPT at `target`.
    ///
    /// Rendezvous requests will be rejected or accepted
    /// depending on the value of `accepting_requests`
    /// (which must be `Advertised` or `NotAdvertised`).
    ///
    /// Also returns a stream of events that is produced whenever we have a
    /// change in the IptStatus for this intro point.  Note that this stream is
    /// potentially lossy.
    ///
    /// The returned `watch::Receiver` will yield `Faulty` if the IPT
    /// establisher is shut down (or crashes).
    // TODO HSS rename to "launch" since it starts the task?
    pub(crate) fn new<R: Runtime>(
        runtime: &R,
        params: IptParameters,
        pool: Arc<HsCircPool<R>>,
        keymgr: &Arc<KeyMgr>,
    ) -> Result<(Self, postage::watch::Receiver<IptStatus>), FatalError> {
        // This exhaustive deconstruction ensures that we don't
        // accidentally forget to handle any of our inputs.
        let IptParameters {
            config_rx,
            netdir_provider,
            introduce_tx,
            lid,
            target,
            k_sid,
            k_ntor,
            accepting_requests,
            replay_log,
        } = params;
        let config = Arc::clone(&config_rx.borrow());
        let nickname = config.nickname().clone();

        if matches!(accepting_requests, RequestDisposition::Shutdown) {
            return Err(bad_api_usage!(
                "Tried to create a IptEstablisher that that was already shutting down?"
            )
            .into());
        }

        let state = Arc::new(Mutex::new(EstablisherState { accepting_requests }));

        // We need the subcredential for the *current time period* in order to do the hs_ntor
        // handshake. But that can change over time.  We will instead use KeyMgr::get_matching to
        // find all current subcredentials.
        //
        // TODO HSS: perhaps the subcredentials should be retrieved in
        // server_receive_intro_no_keygen instead? See also the TODO in HsNtorServiceInput
        let subcredentials = compute_subcredentials(&nickname, keymgr)?;

        let request_context = Arc::new(RendRequestContext {
            // TODO HSS: This is a workaround because HsSvcNtorSecretKey is not
            // clone.  We should either make it Clone, or hold it in an Arc.
            kp_hss_ntor: Arc::clone(&k_ntor),
            kp_hs_ipt_sid: k_sid.as_ref().as_ref().verifying_key().into(),
            subcredentials,
            netdir_provider: netdir_provider.clone(),
            circ_pool: pool.clone(),
        });

        let reactor = Reactor {
            runtime: runtime.clone(),
            nickname,
            pool,
            netdir_provider,
            lid,
            target,
            k_sid,
            introduce_tx,
            extensions: EstIntroExtensionSet {
                dos_params: config.dos_extension()?,
            },
            state: state.clone(),
            request_context,
            replay_log: Arc::new(replay_log.into()),
        };

        let (status_tx, status_rx) = postage::watch::channel_with(IptStatus::new());
        let (terminate_tx, mut terminate_rx) = oneshot::channel::<Void>();
        let status_tx = DropNotifyWatchSender::new(status_tx);

        runtime
            .spawn(async move {
                futures::select_biased!(
                    terminated = terminate_rx => {
                        // Only Err is possible, but the compiler can't tell that.
                        let oneshot::Canceled = terminated.void_unwrap_err();
                    }
                    outcome = reactor.keep_intro_established(status_tx).fuse() =>  {
                        // TODO HSS: probably we should report this outcome.
                        let _ = outcome;
                    }
                );
            })
            .map_err(|e| FatalError::Spawn {
                spawning: "introduction point establisher",
                cause: Arc::new(e),
            })?;
        let establisher = IptEstablisher {
            terminate_tx,
            state,
        };
        Ok((establisher, status_rx))
    }

    /// Begin accepting requests from this introduction point.
    ///
    /// If any introduction requests are sent before we have called this method,
    /// they are treated as an error and our connection to this introduction
    /// point is closed.
    pub(crate) fn start_accepting(&self) {
        self.state.lock().expect("poisoned lock").accepting_requests =
            RequestDisposition::Advertised;
    }
}

/// Obtain the all current `Subcredential`s of `nickname`
/// from the `K_hs_blind_id` read from the keystore.
fn compute_subcredentials(
    nickname: &HsNickname,
    keymgr: &Arc<KeyMgr>,
) -> Result<Vec<Subcredential>, FatalError> {
    let hsid_key_spec = HsIdPublicKeySpecifier::new(nickname.clone());

    let hsid = keymgr
        .get::<HsIdKey>(&hsid_key_spec)?
        .ok_or_else(|| FatalError::MissingHsIdKeypair(nickname.clone()))?;

    let pattern = BlindIdKeypairSpecifierPattern {
        nickname: Some(nickname.clone()),
        period: None,
    }
    .arti_pattern()?;

    let blind_id_kps: Vec<(HsBlindIdKeypair, TimePeriod)> = keymgr
        .list_matching(&pattern)?
        .iter()
        .map(|(path, key_type)| -> Result<Option<_>, FatalError> {
            let matches = path
                .matches(&pattern)
                .ok_or_else(|| internal!("path matched but no longer does?!"))?;
            let period = parse_time_period(path, &matches)?;
            // Try to retrieve the key.
            keymgr
                .get_with_type::<HsBlindIdKeypair>(path, key_type)
                .map_err(FatalError::Keystore)
                // If the key is not found, it means it has been garbage collected between the time
                // we queried the keymgr for the list of keys matching the pattern and now.
                // This is OK, because we only need the "current" keys
                .map(|maybe_key| maybe_key.map(|key| (key, period)))
        })
        .flatten_ok()
        .collect::<Result<Vec<_>, FatalError>>()?;

    Ok(blind_id_kps
        .iter()
        .map(|(blind_id_key, period)| hsid.compute_subcredential(&blind_id_key.into(), *period))
        .collect())
}

/// Try to parse the `captures` of `path` as a [`TimePeriod`].
fn parse_time_period(
    path: &KeyPath,
    captures: &[KeyPathRange],
) -> Result<TimePeriod, tor_keymgr::Error> {
    use tor_keymgr::{KeyPathError, KeystoreCorruptionError as KCE};

    let path = match path {
        KeyPath::Arti(path) => path,
        KeyPath::CTor(_) => todo!(),
        _ => todo!(),
    };

    let [denotator] = captures else {
        return Err(internal!(
            "invalid number of denotator captures: expected 1, found {}",
            captures.len()
        )
        .into());
    };

    let Some(denotator) = path.substring(denotator) else {
        return Err(internal!("captured substring out of range?!").into());
    };

    let comp = ArtiPathComponent::new(denotator.to_string())
        .map_err(|e| KCE::KeyPath(KeyPathError::InvalidArtiPath(e)))?;
    let tp = TimePeriod::from_component(&comp).map_err(|error| {
        KCE::KeyPath(KeyPathError::InvalidKeyPathComponentValue {
            key: "time_period".to_owned(),
            value: comp,
            error,
        })
    })?;

    Ok(tp)
}

/// The current status of an introduction point, as defined in
/// `hssvc-ipt-algorithms.md`.
///
/// TODO (#1235) Make that file unneeded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum IptStatusStatus {
    /// We are (re)establishing our connection to the IPT
    ///
    /// But we don't think there's anything wrong with it.
    ///
    /// The IPT manager should *not* arrange to include this in descriptors.
    Establishing,

    /// The IPT is established and ready to accept rendezvous requests
    ///
    /// Also contains information about the introduction point
    /// necessary for making descriptors,
    /// including information from the netdir about the relay
    ///
    /// The IPT manager *should* arrange to include this in descriptors.
    Good(GoodIptDetails),

    /// We don't have the IPT and it looks like it was the IPT's fault
    ///
    /// This should be used whenever trying another IPT relay is likely to work better;
    /// regardless of whether attempts to establish *this* IPT can continue.
    ///
    /// The IPT manager should *not* arrange to include this in descriptors.
    /// If this persists, the IPT manager should replace this IPT
    /// with a new IPT at a different relay.
    Faulty,
}

/// Details of a good introduction point
///
/// This struct contains similar information to
/// [`tor_linkspec::verbatim::VerbatimLinkSpecCircTarget`].
/// However, that insists that the contained `T` is a [`CircTarget`],
/// which `<NtorPublicKey>` isn't.
/// And, we don't use this as a circuit target (at least, not here -
/// the client will do so, as a result of us publishing the information).
///
/// See <https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1559#note_2937974>
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GoodIptDetails {
    /// The link specifiers to be used in the descriptor
    ///
    /// As obtained and converted from the netdir.
    pub(crate) link_specifiers: LinkSpecs,

    /// The introduction point relay's ntor key (from the netdir)
    pub(crate) ipt_kp_ntor: NtorPublicKey,
}

impl GoodIptDetails {
    /// Try to copy out the relevant parts of a CircTarget into a GoodIptDetails.
    fn try_from_circ_target(relay: &impl CircTarget) -> Result<Self, IptError> {
        Ok(Self {
            link_specifiers: relay
                .linkspecs()
                .map_err(into_internal!("Unable to encode relay link specifiers"))?,
            ipt_kp_ntor: *relay.ntor_onion_key(),
        })
    }
}

/// `Err(IptWantsToRetire)` indicates that the IPT Establisher wants to retire this IPT
///
/// This happens when the IPT has had (too) many rendezvous requests.
///
/// This must *not* be used for *errors*, because it will cause the IPT manager to
/// *immediately* start to replace the IPT, regardless of rate limits etc.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IptWantsToRetire;

/// State shared between the IptEstablisher and the Reactor.
struct EstablisherState {
    /// True if we are accepting requests right now.
    accepting_requests: RequestDisposition,
}

/// Current state of an introduction point; determines what we want to do with
/// any incoming messages.
#[derive(Copy, Clone, Debug)]
pub(crate) enum RequestDisposition {
    /// We are not yet advertised: the message handler should complain if it
    /// gets any requests and shut down.
    NotAdvertised,
    /// We are advertised: the message handler should pass along any requests
    Advertised,
    /// We are shutting down cleanly: the message handler should exit but not complain.
    Shutdown,
}

/// The current status of an introduction point.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IptStatus {
    /// The current state of this introduction point as defined by
    /// `hssvc-ipt-algorithms.md`.
    ///
    /// TODO (#1235): Make that file unneeded.
    pub(crate) status: IptStatusStatus,

    /// The current status of whether this introduction point circuit wants to be
    /// retired based on having processed too many requests.
    pub(crate) wants_to_retire: Result<(), IptWantsToRetire>,
}

impl IptStatus {
    /// Record that we have successfully connected to an introduction point.
    fn note_open(&mut self, ipt_details: GoodIptDetails) {
        self.status = IptStatusStatus::Good(ipt_details);
    }

    /// Record that we are trying to connect to an introduction point.
    fn note_attempt(&mut self) {
        use IptStatusStatus::*;
        self.status = match self.status {
            Establishing | Good(..) => Establishing,
            Faulty => Faulty, // We don't change status if we think we're broken.
        }
    }

    /// Record that an error has occurred.
    fn note_error(&mut self, err: &IptError) {
        use IptStatusStatus::*;
        if err.is_ipt_failure() {
            self.status = Faulty;
        }
    }

    /// Return an `IptStatus` representing an establisher that has not yet taken
    /// any action.
    fn new() -> Self {
        Self {
            status: IptStatusStatus::Establishing,
            wants_to_retire: Ok(()),
        }
    }

    /// Produce an `IptStatus` representing a shut down or crashed establisher
    fn new_terminated() -> Self {
        IptStatus {
            status: IptStatusStatus::Faulty,
            // If we're broken, we simply tell the manager that that is the case.
            // It will decide for itself whether it wants to replace us.
            wants_to_retire: Ok(()),
        }
    }
}

impl Default for IptStatus {
    fn default() -> Self {
        Self::new()
    }
}

impl tor_async_utils::DropNotifyEofSignallable for IptStatus {
    fn eof() -> IptStatus {
        IptStatus::new_terminated()
    }
}

tor_cell::restricted_msg! {
    /// An acceptable message to receive from an introduction point.
     enum IptMsg : RelayMsg {
         IntroEstablished,
         Introduce2,
     }
}

/// A set of extensions to send with our `ESTABLISH_INTRO` message.
///
/// NOTE: we eventually might want to support unrecognized extensions.  But
/// that's potentially troublesome, since the set of extensions we sent might
/// have an affect on how we validate the reply.
#[derive(Clone, Debug)]
pub(crate) struct EstIntroExtensionSet {
    /// Parameters related to rate-limiting to prevent denial-of-service
    /// attacks.
    dos_params: Option<est_intro::DosParams>,
}

/// Implementation structure for the task that implements an IptEstablisher.
struct Reactor<R: Runtime> {
    /// A copy of our runtime, used for timeouts and sleeping.
    runtime: R,
    /// The nickname of the onion service we're running. Used when logging.
    nickname: HsNickname,
    /// A pool used to create circuits to the introduction point.
    pool: Arc<HsCircPool<R>>,
    /// A provider used to select the other relays in the circuit.
    netdir_provider: Arc<dyn NetDirProvider>,
    /// Identifier for the intro point.
    lid: IptLocalId,
    /// The target introduction point.
    target: RelayIds,
    /// The keypair to use when establishing the introduction point.
    ///
    /// Knowledge of this private key prevents anybody else from impersonating
    /// us to the introduction point.
    k_sid: Arc<HsIntroPtSessionIdKeypair>,
    /// The extensions to use when establishing the introduction point.
    ///
    /// TODO (#1209): This should be able to change over time as we re-establish
    /// the intro point.
    extensions: EstIntroExtensionSet,

    /// The stream that will receive INTRODUCE2 messages.
    introduce_tx: mpsc::Sender<RendRequest>,

    /// Mutable state shared with the Establisher, Reactor, and MsgHandler.
    state: Arc<Mutex<EstablisherState>>,

    /// Context information that we'll need to answer rendezvous requests.
    request_context: Arc<RendRequestContext>,

    /// Introduction request replay log
    ///
    /// Shared between multiple IPT circuit control message handlers -
    /// [`IptMsgHandler`] contains the lock guard.
    ///
    /// Has to be an async mutex since it's locked for a long time,
    /// so we mustn't block the async executor thread on it.
    replay_log: Arc<futures::lock::Mutex<ReplayLog>>,
}

/// An open session with a single introduction point.
//
// TODO: I've used Ipt and IntroPt in this module; maybe we shouldn't.
pub(crate) struct IntroPtSession {
    /// The circuit to the introduction point, on which we're receiving
    /// Introduce2 messages.
    intro_circ: Arc<ClientCirc>,
}

impl<R: Runtime> Reactor<R> {
    /// Run forever, keeping an introduction point established.
    #[allow(clippy::blocks_in_conditions)]
    async fn keep_intro_established(
        &self,
        mut status_tx: DropNotifyWatchSender<IptStatus>,
    ) -> Result<(), IptError> {
        let mut retry_delay = tor_basic_utils::retry::RetryDelay::from_msec(1000);
        loop {
            status_tx.borrow_mut().note_attempt();
            match self.establish_intro_once().await.and_then(|session| {
                let netdir = self
                    .netdir_provider
                    .timely_netdir()
                    .map_err(|_| IptError::IntroPointNotListed)?;
                let relay = netdir
                    .by_ids(&self.target)
                    .ok_or(IptError::IntroPointNotListed)?;
                Ok((session, GoodIptDetails::try_from_circ_target(&relay)?))
            }) {
                Ok((session, good_ipt_details)) => {
                    // TODO HSS we need to monitor the netdir for changes to this relay
                    // Eg,
                    //   - if it becomes unlisted, we should declare the IPT faulty
                    //     (until it perhaps reappears)
                    //
                    //     TODO SPEC  Continuing to use an unlisted relay is dangerous
                    //     It might be malicious.  We should withdraw our IPT then,
                    //     and hope that clients find another, working, IPT.
                    //
                    //   - if it changes its ntor key or link specs,
                    //     we need to update the GoodIptDetails in our status report,
                    //     so that the updated info can make its way to the descriptor
                    //
                    // Possibly some this could/should be done by the IPT Manager instead,
                    // but Diziet thinks it is probably cleanest to do it here.

                    status_tx.borrow_mut().note_open(good_ipt_details);

                    debug!(
                        "{}: Successfully established introduction point with {}",
                        &self.nickname,
                        self.target.display_relay_ids().redacted()
                    );
                    // Now that we've succeeded, we can stop backing off for our
                    // next attempt.
                    retry_delay.reset();

                    // Wait for the session to be closed.
                    session.wait_for_close().await;
                }
                Err(e @ IptError::IntroPointNotListed) => {
                    // The network directory didn't include this relay.  Wait
                    // until it does.
                    //
                    // TODO HSS: Perhaps we should distinguish possible error cases
                    // here?  See notes in `wait_for_netdir_to_list`.
                    status_tx.borrow_mut().note_error(&e);
                    wait_for_netdir_to_list(self.netdir_provider.as_ref(), &self.target).await?;
                }
                Err(e) => {
                    status_tx.borrow_mut().note_error(&e);
                    debug_report!(
                        e,
                        "{}: Problem establishing introduction point with {}",
                        &self.nickname,
                        self.target.display_relay_ids().redacted()
                    );
                    let retry_after = retry_delay.next_delay(&mut rand::thread_rng());
                    self.runtime.sleep(retry_after).await;
                }
            }
        }
    }

    /// Try, once, to make a circuit to a single relay and establish an introduction
    /// point there.
    ///
    /// Does not retry.  Does not time out except via `HsCircPool`.
    async fn establish_intro_once(&self) -> Result<IntroPtSession, IptError> {
        let (protovers, circuit) = {
            let netdir = wait_for_netdir(
                self.netdir_provider.as_ref(),
                tor_netdir::Timeliness::Timely,
            )
            .await?;
            let circ_target = netdir
                .by_ids(&self.target)
                .ok_or(IptError::IntroPointNotListed)?;

            let kind = tor_circmgr::hspool::HsCircKind::SvcIntro;
            let protovers = circ_target.protovers().clone();
            let circuit = self
                .pool
                .get_or_launch_specific(netdir.as_ref(), kind, circ_target)
                .await
                .map_err(IptError::BuildCircuit)?;
            // note that netdir is dropped here, to avoid holding on to it any
            // longer than necessary.
            (protovers, circuit)
        };
        let intro_pt_hop = circuit
            .last_hop_num()
            .map_err(into_internal!("Somehow built a circuit with no hops!?"))?;

        let establish_intro = {
            let ipt_sid_id = (*self.k_sid).as_ref().verifying_key().into();
            let mut details = EstablishIntroDetails::new(ipt_sid_id);
            if let Some(dos_params) = &self.extensions.dos_params {
                // We only send the Dos extension when the relay is known to
                // support HsIntro=5.
                if protovers.supports_known_subver(tor_protover::ProtoKind::HSIntro, 5) {
                    details.set_extension_dos(dos_params.clone());
                }
            }
            let circuit_binding_key = circuit
                .binding_key(intro_pt_hop)
                .ok_or(internal!("No binding key for introduction point!?"))?;
            let body: Vec<u8> = details
                .sign_and_encode((*self.k_sid).as_ref(), circuit_binding_key.hs_mac())
                .map_err(IptError::CreateEstablishIntro)?;

            // TODO HSS: This is ugly, but it is the sensible way to munge the above
            // body into a format that AnyRelayMsgOuter will accept without doing a
            // redundant parse step.
            //
            // One alternative would be allowing start_conversation to take an `impl
            // RelayMsg` rather than an AnyRelayMsg.
            //
            // Or possibly, when we feel like it, we could rename one or more of
            // these "Unrecognized"s to Unparsed or Uninterpreted.  If we do that, however, we'll
            // potentially face breaking changes up and down our crate stack.
            AnyRelayMsg::Unrecognized(tor_cell::relaycell::msg::Unrecognized::new(
                tor_cell::relaycell::RelayCmd::ESTABLISH_INTRO,
                body,
            ))
        };

        let (established_tx, established_rx) = oneshot::channel();

        // In theory there ought to be only one IptMsgHandler in existence at any one time,
        // for any one IptLocalId (ie for any one ReplayLog).  However, the teardown
        // arrangements are (i) complicated (so might have bugs) and (ii) asynchronous
        // (so we need to synchronise).  Therefore:
        //
        // Make sure we don't start writing to the replay log until any previous
        // IptMsgHandler has been torn down.  (Using an async mutex means we
        // don't risk blocking the whole executor even if we have teardown bugs.)
        let replay_log = self.replay_log.clone().lock_owned().await;

        let handler = IptMsgHandler {
            established_tx: Some(established_tx),
            introduce_tx: self.introduce_tx.clone(),
            state: self.state.clone(),
            lid: self.lid,
            request_context: self.request_context.clone(),
            replay_log,
        };
        let _conversation = circuit
            .start_conversation(Some(establish_intro), handler, intro_pt_hop)
            .await
            .map_err(IptError::SendEstablishIntro)?;
        // At this point, we have `await`ed for the Conversation to exist, so we know
        // that the message was sent.  We have to wait for any actual `established`
        // message, though.

        let ack_timeout = self
            .pool
            .estimate_timeout(&tor_circmgr::timeouts::Action::RoundTrip {
                length: circuit.n_hops(),
            });
        let established = self
            .runtime
            .timeout(ack_timeout, established_rx)
            .await
            .map_err(|_| IptError::EstablishTimeout)?
            .map_err(|_| IptError::ReceiveAck)?;

        if established.iter_extensions().next().is_some() {
            // We do not support any extensions from the introduction point; if it
            // sent us any, that's a protocol violation.
            //
            // TODO HSS this check needs to happen in IptMsgHandler::handle_msg,
            // because otherwise handle_msg might go on to handle messages despite
            // us wanting to crash, here.  (Providing reliable teardown of the
            // IptMsgHandler wouldn't be sufficient, since there would be a race.)
            return Err(IptError::BadEstablished);
        }

        // TODO HSS arrange for the IptMsgHandler to be torn down if the
        // Establisher (and this IntroPtSession) is - or if this function returns
        // early somehow.  Otherwise we might leak the IptMsgHandler and the whole
        // circuit?  Given the design of the circuit msg interface this seems nontrivial.
        Ok(IntroPtSession {
            intro_circ: circuit,
        })
    }
}

impl IntroPtSession {
    /// Wait for this introduction point session to be closed.
    fn wait_for_close(&self) -> impl Future<Output = ()> {
        self.intro_circ.wait_for_close()
    }
}

/// MsgHandler type to implement a conversation with an introduction point.
///
/// This, like all MsgHandlers, is installed at the circuit's reactor, and used
/// to handle otherwise unrecognized message types.
struct IptMsgHandler {
    /// A oneshot sender used to report our IntroEstablished message.
    ///
    /// If this is None, then we already sent an IntroEstablished and we shouldn't
    /// send any more.
    established_tx: Option<oneshot::Sender<IntroEstablished>>,

    /// A channel used to report Introduce2 messages.
    introduce_tx: mpsc::Sender<RendRequest>,

    /// Keys that we'll need to answer the introduction requests.
    request_context: Arc<RendRequestContext>,

    /// Mutable state shared with the Establisher, Reactor, and MsgHandler.
    state: Arc<Mutex<EstablisherState>>,

    /// Unique identifier for the introduction point (including the current
    /// keys).  Used to tag requests.
    lid: IptLocalId,

    /// A replay log used to detect replayed introduction requests.
    replay_log: futures::lock::OwnedMutexGuard<ReplayLog>,
}

impl tor_proto::circuit::MsgHandler for IptMsgHandler {
    fn handle_msg(
        &mut self,
        _conversation: ConversationInHandler<'_, '_, '_>,
        any_msg: AnyRelayMsg,
    ) -> tor_proto::Result<MetaCellDisposition> {
        // TODO HSS: Is CircProto right or should this be a new error type?
        let msg: IptMsg = any_msg.try_into().map_err(|m: AnyRelayMsg| {
            tor_proto::Error::CircProto(format!("Invalid message type {}", m.cmd()))
        })?;

        if match msg {
            IptMsg::IntroEstablished(established) => match self.established_tx.take() {
                Some(tx) => tx.send(established).map_err(|_| ()),
                None => {
                    return Err(tor_proto::Error::CircProto(
                        "Received a redundant INTRO_ESTABLISHED".into(),
                    ));
                }
            },
            IptMsg::Introduce2(introduce2) => {
                if self.established_tx.is_some() {
                    return Err(tor_proto::Error::CircProto(
                        "Received an INTRODUCE2 message before INTRO_ESTABLISHED".into(),
                    ));
                }
                let disp = self.state.lock().expect("poisoned lock").accepting_requests;
                match disp {
                    RequestDisposition::NotAdvertised => {
                        return Err(tor_proto::Error::CircProto(
                            "Received an INTRODUCE2 message before we were accepting requests!"
                                .into(),
                        ))
                    }
                    RequestDisposition::Shutdown => return Ok(MetaCellDisposition::CloseCirc),
                    RequestDisposition::Advertised => {}
                }
                match self.replay_log.check_for_replay(&introduce2) {
                    Ok(()) => {}
                    Err(ReplayError::AlreadySeen) => {
                        // This is probably a replay, but maybe an accident. We
                        // just drop the request.

                        // TODO (#1233): Log that this has occurred, with a rate
                        // limit.  Possibly, we should allow it to fail once or
                        // twice per circuit before we log, since we expect
                        // a nonzero false-positive rate.
                        //
                        // Note that we should NOT close the circuit in this
                        // case: the repeated message could come from a hostile
                        // introduction point trying to do traffic analysis, but
                        // it could also come from a user trying to make it look
                        // like the intro point is doing traffic analysis.
                        return Ok(MetaCellDisposition::Consumed);
                    }
                    Err(ReplayError::Log(_)) => {
                        // Uh-oh! We failed to write the data persistently!
                        //
                        // TODO (#1226): We need to decide what to do here.  Right
                        // now we close the circuit, which is wrong.
                        return Ok(MetaCellDisposition::CloseCirc);
                    }
                }

                let request = RendRequest::new(self.lid, introduce2, self.request_context.clone());
                match self.introduce_tx.try_send(request) {
                    Ok(()) => Ok(()),
                    Err(e) => {
                        if e.is_disconnected() {
                            // The receiver is disconnected, meaning that
                            // messages from this intro point are no longer
                            // wanted.  Close the circuit.
                            Err(())
                        } else {
                            // The receiver is full; we have no real option but
                            // to drop the request like C-tor does when the
                            // backlog is too large.
                            //
                            // See discussion at
                            // https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1465#note_2928349
                            //
                            // TODO HSS: record when this happens.
                            Ok(())
                        }
                    }
                }
            }
        } == Err(())
        {
            // If the above return an error, we failed to send.  That means that
            // we need to close the circuit, since nobody is listening on the
            // other end of the tx.
            return Ok(MetaCellDisposition::CloseCirc);
        }

        Ok(MetaCellDisposition::Consumed)
    }
}
