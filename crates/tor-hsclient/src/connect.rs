//! Main implementation of the connection functionality
#![allow(clippy::print_stderr)] // Code here is not finished.  TODO hs remove.

use std::any::Any;
use std::time::Duration;

use std::collections::HashMap;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::sync::Arc;

use async_trait::async_trait;
use educe::Educe;
use futures::channel::oneshot;
use futures::{AsyncRead, AsyncWrite};
use itertools::Itertools;
use rand::Rng;
use tor_bytes::Writeable;
use tor_cell::relaycell::hs::intro_payload::{self, IntroduceHandshakePayload};
use tor_cell::relaycell::msg::{AnyRelayMsg, Introduce1, Rendezvous2};
use tor_hscrypto::Subcredential;
use tor_proto::circuit::handshake::{self, hs_ntor};
use tracing::{debug, trace};

use retry_error::RetryError;
use safelog::Redacted;
use tor_cell::relaycell::hs::{
    AuthKeyType, EstablishRendezvous, IntroduceHeader, RendezvousEstablished,
};
use tor_cell::relaycell::{AnyRelayCell, RelayMsg, UnparsedRelayCell};
use tor_checkable::{timed::TimerangeBound, Timebound};
use tor_circmgr::hspool::{HsCircKind, HsCircPool};
use tor_dirclient::request::Requestable as _;
use tor_error::RetryTime;
use tor_error::{internal, into_internal, ErrorReport as _};
use tor_hscrypto::pk::{HsBlindId, HsBlindIdKey, HsClientDescEncKey, HsId, HsIdKey};
use tor_hscrypto::RendCookie;
use tor_linkspec::{CircTarget, OwnedCircTarget, RelayId};
use tor_llcrypto::pk::ed25519::Ed25519Identity;
use tor_netdir::{HsDirOp, NetDir, Relay};
use tor_netdoc::doc::hsdesc::{HsDesc, IntroPointDesc};
use tor_proto::circuit::{CircParameters, ClientCirc, MetaCellDisposition, MsgHandler};
use tor_rtcompat::{Runtime, SleepProviderExt as _, TimeoutError};

use crate::proto_oneshot;
use crate::relay_info::ipt_to_circtarget;
use crate::state::MockableConnectorData;
use crate::{rend_pt_identity_for_error, FailedAttemptError, IntroPtIndex, RendPtIdentityForError};
use crate::{ConnError, DescriptorError, DescriptorErrorDetail};
use crate::{HsClientConnector, HsClientSecretKeys};

use ConnError as CE;
use FailedAttemptError as FAE;

/// Given `R, M` where `M: MocksForConnect<M>`, expand to the mockable `ClientCirc`
// This is quite annoying.  But the alternative is to write out `<... as // ...>`
// each time, since otherwise the compile complains about ambiguous associated types.
macro_rules! ClientCirc { { $R:ty, $M:ty } => {
    <<$M as MocksForConnect<$R>>::HsCircPool as MockableCircPool<$R>>::ClientCirc
} }

/// Information about a hidden service, including our connection history
#[allow(dead_code, unused_variables)] // TODO hs remove.
#[derive(Default, Educe)]
#[educe(Debug)]
// This type is actually crate-private, since it isn't re-exported, but it must
// be `pub` because it appears as a default for a type parameter in HsClientConnector.
pub struct Data {
    /// The latest known onion service descriptor for this service.
    #[educe(Debug(ignore))] // TODO HS do better than this
    desc: DataHsDesc,
    /// Information about the latest status of trying to connect to this service
    /// through each of its introduction points.
    ///
    /// We store the information under an arbitrary one of the relay's identities,
    /// as returned by HasRelayIds::identities().first().
    /// When we do lookups, we check all the relay's identities to see if we find
    /// anything relevant.
    /// If relay identities permute in strange ways, whether we find our previous
    /// knowledge about them is not particularly well defined, but that's fine.
    // TODO HS we don't actually store or use this yet
    ipts: DataIpts,
}

/// Part of `Data` that relates to the HS descriptor
type DataHsDesc = Option<TimerangeBound<HsDesc>>;

/// Part of `Data` that relates to our information about introduction points
type DataIpts = HashMap<RelayId, IptExperience>;

/// How things went last time we tried to use this introduction point
///
/// Neither this data structure, nor [`Data`], is responsible for arranging that we expire this
/// information eventually.  If we keep reconnecting to the service, we'll retain information
/// about each IPT indefinitely, at least so long as they remain listed in the descriptors we
/// receive.
///
/// Expiry of unused data is handled by `state.rs`, according to `last_used` in `ServiceState`.
#[derive(Debug)]
// TODO HS implement Ord for this according to the specs here
struct IptExperience {
    /// How long it took us to get whatever outcome occurred
    ///
    /// We prefer fast successes to slow ones.
    /// Then, we prefer failures with earlier `RetryTime`,
    /// and, lastly, faster failures to slower ones.
    duration: Duration,

    /// What happened and when we might try again
    ///
    /// Note that we don't actually *enforce* the `RetryTime` here, just sort by it
    /// using `RetryTime::loose_cmp`.
    ///
    /// We *do* return an error that is itself `HasRetryTime` and expect our callers
    /// to honour that.
    // TODO HS implement HasRetryTime for ConnError and its pieces, as appropriate
    outcome: Result<(), RetryTime>,
}

/// Actually make a HS connection, updating our recorded state as necessary
///
/// `connector` is provided only for obtaining the runtime and netdir (and `mock_for_state`).
/// Obviously, `connect` is not supposed to go looking in `services`.
///
/// This function handles all necessary retrying of fallible operations,
/// (and, therefore, must also limit the total work done for a particular call).
///
/// This function has a minimum of functionality, since it is the boundary
/// between "mock connection, used for testing `state.rs`" and
/// "mock circuit and netdir, used for testing `connnect.rs`",
/// so it is not, itself, unit-testable.
#[allow(dead_code, unused_variables)] // TODO hs remove.
pub(crate) async fn connect<R: Runtime>(
    connector: &HsClientConnector<R>,
    netdir: Arc<NetDir>,
    hsid: HsId,
    data: &mut Data,
    secret_keys: HsClientSecretKeys,
) -> Result<Arc<ClientCirc>, ConnError> {
    Context::new(
        &connector.runtime,
        &*connector.circpool,
        netdir,
        hsid,
        secret_keys,
        (),
    )?
    .connect(data)
    .await
}

/// Common context for a single request to connect to a hidden service
///
/// This saves on passing this same set of (immuntable) values (or subsets thereof)
/// to each method in the principal functional code, everywhere.
/// It also provides a convenient type to be `Self`.
///
/// Its lifetime is one request to make a new client circuit to a hidden service,
/// including all the retries and timeouts.
#[allow(dead_code)] // TODO HS remove
struct Context<'c, R: Runtime, M: MocksForConnect<R>> {
    /// Runtime
    runtime: &'c R,
    /// Circpool
    circpool: &'c M::HsCircPool,
    /// Netdir
    //
    // TODO holding onto the netdir for the duration of our attempts is not ideal
    // but doing better is fairly complicated.  See discussions here:
    //   https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1228#note_2910545
    //   https://gitlab.torproject.org/tpo/core/arti/-/issues/884
    netdir: Arc<NetDir>,
    /// Secret keys to use
    secret_keys: HsClientSecretKeys,
    /// HS ID
    hsid: HsId,
    /// Blinded HS ID
    hs_blind_id: HsBlindId,
    /// Blinded HS ID as a key
    hs_blind_id_key: HsBlindIdKey,
    /// The subcredential to use during this time period
    subcredential: Subcredential,
    /// Mock data
    mocks: M,
}

/// Details of an established rendezvous point
///
/// Intermediate value for progress during a connection attempt.
struct Rendezvous<'r, R: Runtime, M: MocksForConnect<R>> {
    /// RPT as a `Relay`
    rend_relay: Relay<'r>,
    /// Rendezvous circuit
    rend_circ: Arc<ClientCirc!(R, M)>,
    /// Rendezvous cookie
    rend_cookie: RendCookie,

    /// Receiver that will give us the RENDEZVOUS2 message.
    ///
    /// The sending ended is owned by the handler
    /// which receives control messages on the rednezvous circuit,
    /// and which was installed when we sent `ESTABLISH_RENDEZVOUS`.
    ///
    /// (`RENDEZVOUS2` is the message containing the onion service's side of the handshake.)
    rend2_rx: proto_oneshot::Receiver<Rendezvous2>,

    /// Dummy, to placate compiler
    ///
    /// Covariant without dropck or interfering with Send/Sync will do fine.
    marker: PhantomData<fn() -> (R, M)>,
}

/// Details of an apparently-useable introduction point
///
/// Intermediate value for progress during a connection attempt.
struct UsableIntroPt<'i> {
    /// Index in HS descriptor
    intro_index: IntroPtIndex,
    /// IPT descriptor
    intro_desc: &'i IntroPointDesc,
    /// IPT `CircTarget`
    intro_target: OwnedCircTarget,
}

/// Details of an apparently-successful INTRODUCE exchange
///
/// Intermediate value for progress during a connection attempt.
struct Introduced<R: Runtime, M: MocksForConnect<R>> {
    ///
    intro_circ: Arc<ClientCirc!(R, M)>,

    // TODO HS this will need to contain key exchange information
    // for completing the handshake
    /// Dummy, to placate compiler
    ///
    /// `R` and `M` only used for getting to mocks.
    /// Covariant without dropck or interfering with Send/Sync will do fine.
    marker: PhantomData<fn() -> (R, M)>,
}

impl<'c, R: Runtime, M: MocksForConnect<R>> Context<'c, R, M> {
    /// Make a new `Context` from the input data
    fn new(
        runtime: &'c R,
        circpool: &'c M::HsCircPool,
        netdir: Arc<NetDir>,
        hsid: HsId,
        secret_keys: HsClientSecretKeys,
        mocks: M,
    ) -> Result<Self, ConnError> {
        let time_period = netdir.hs_time_period();
        let (hs_blind_id_key, subcredential) = HsIdKey::try_from(hsid)
            .map_err(|_| CE::InvalidHsId)?
            .compute_blinded_key(time_period)
            .map_err(
                // TODO HS what on earth do these errors mean, in practical terms ?
                // In particular, we'll want to convert them to a ConnError variant,
                // but what ErrorKind should they have ?
                into_internal!("key blinding error, don't know how to handle"),
            )?;
        let hs_blind_id = hs_blind_id_key.id();

        Ok(Context {
            netdir,
            hsid,
            hs_blind_id,
            hs_blind_id_key,
            subcredential,
            circpool,
            runtime,
            secret_keys,
            mocks,
        })
    }

    /// Actually make a HS connection, updating our recorded state as necessary
    ///
    /// Called by the `connect` function in this module.
    ///
    /// This function handles all necessary retrying of fallible operations,
    /// (and, therefore, must also limit the total work done for a particular call).
    async fn connect(&self, data: &mut Data) -> Result<Arc<ClientCirc!(R, M)>, ConnError> {
        // This function must do the following, retrying as appropriate.
        //  - Look up the onion descriptor in the state.
        //  - Download the onion descriptor if one isn't there.
        //  - In parallel:
        //    - Pick a rendezvous point from the netdirprovider and launch a
        //      rendezvous circuit to it. Then send ESTABLISH_INTRO.
        //    - Pick a number of introduction points (1 or more) and try to
        //      launch circuits to them.
        //  - On a circuit to an introduction point, send an INTRODUCE1 cell.
        //  - Wait for a RENDEZVOUS2 cell on the rendezvous circuit
        //  - Add a virtual hop to the rendezvous circuit.
        //  - Return the rendezvous circuit.

        let mocks = self.mocks.clone();

        let desc = self.descriptor_ensure(&mut data.desc).await?;

        mocks.test_got_desc(desc);

        let circ = self.intro_rend_connect(desc, &mut data.ipts).await?;
        mocks.test_got_circ(&circ);

        Ok(circ)
    }

    /// Ensure that `Data.desc` contains the HS descriptor
    ///
    /// If we have a previously-downloaded descriptor, which is still valid,
    /// just returns a reference to it.
    ///
    /// Otherwise, tries to obtain the descriptor by downloading it from hsdir(s).
    ///
    /// Does all necessary retries and timeouts.
    /// Returns an error if no valid descriptor could be found.
    async fn descriptor_ensure<'d>(&self, data: &'d mut DataHsDesc) -> Result<&'d HsDesc, CE> {
        // TODO HS are these right? make configurable? get from netdir?
        // TODO HS should we even have MAX_TOTAL_ATTEMPTS or should we just try each one once?
        /// Maxmimum number of hsdir connection and retrieval attempts we'll make
        const MAX_TOTAL_ATTEMPTS: usize = 6;
        /// Limit on the duration of each retrieval attempt
        const EACH_TIMEOUT: Duration = Duration::from_secs(10);

        if let Some(previously) = data {
            let now = self.runtime.wallclock();
            if let Ok(_desc) = previously.as_ref().check_valid_at(&now) {
                // Ideally we would just return desc but that confuses borrowck.
                // https://github.com/rust-lang/rust/issues/51545
                return Ok(data
                    .as_ref()
                    .expect("Some but now None")
                    .as_ref()
                    .check_valid_at(&now)
                    .expect("Ok but now Err"));
            }
            // Seems to be not valid now.  Try to fetch a fresh one.
        }

        let hs_dirs = self.netdir.hs_dirs(
            &self.hs_blind_id,
            HsDirOp::Download,
            &mut self.mocks.thread_rng(),
        );

        trace!(
            "HS desc fetch for {}, using {} hsdirs",
            &self.hsid,
            hs_dirs.len()
        );

        // TODO HS consider launching multiple requests in parallel
        // https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1118#note_2894463
        let mut attempts = hs_dirs.iter().cycle().take(MAX_TOTAL_ATTEMPTS);
        let mut errors = RetryError::in_attempt_to("retrieve hidden service descriptor");
        let desc = loop {
            let relay = match attempts.next() {
                Some(relay) => relay,
                None => {
                    return Err(if errors.is_empty() {
                        CE::NoHsDirs
                    } else {
                        CE::DescriptorDownload(errors)
                    })
                }
            };
            let hsdir_for_error: Redacted<Ed25519Identity> = (*relay.id()).into();
            match self
                .runtime
                .timeout(EACH_TIMEOUT, self.descriptor_fetch_attempt(relay))
                .await
                .unwrap_or(Err(DescriptorErrorDetail::Timeout))
            {
                Ok(desc) => break desc,
                Err(error) => {
                    debug!(
                        "failed hsdir desc fetch for {} from {}: {}",
                        &self.hsid,
                        &relay.id(),
                        error.report()
                    );
                    errors.push(tor_error::Report(DescriptorError {
                        hsdir: hsdir_for_error,
                        error,
                    }));
                }
            }
        };

        // Store the bounded value in the cache for reuse,
        // but return a reference to the unwrapped `HsDesc`.
        //
        // The `HsDesc` must be owned by `data.desc`,
        // so first add it to `data.desc`,
        // and then dangerously_assume_timely to get a reference out again.
        //
        // It is safe to dangerously_assume_timely,
        // as descriptor_fetch_attempt has already checked the timeliness of the descriptor.
        let ret = data.insert(desc);
        Ok(ret.as_ref().dangerously_assume_timely())
    }

    /// Make one attempt to fetch the descriptor from a specific hsdir
    ///
    /// No timeout
    ///
    /// On success, returns the descriptor.
    ///
    /// While the returned descriptor is `TimerangeBound`, its validity at the current time *has*
    /// been checked.
    async fn descriptor_fetch_attempt(
        &self,
        hsdir: &Relay<'_>,
    ) -> Result<TimerangeBound<HsDesc>, DescriptorErrorDetail> {
        let request = tor_dirclient::request::HsDescDownloadRequest::new(self.hs_blind_id);
        trace!(
            "hsdir for {}, trying {}/{}, request {:?} (http request {:?}",
            &self.hsid,
            &hsdir.id(),
            &hsdir.rsa_id(),
            &request,
            request.make_request()
        );

        let circuit = self
            .circpool
            .get_or_launch_specific(
                &self.netdir,
                HsCircKind::ClientHsDir,
                OwnedCircTarget::from_circ_target(hsdir),
            )
            .await?;
        let mut stream = circuit
            .begin_dir_stream()
            .await
            .map_err(DescriptorErrorDetail::Stream)?;

        let response = tor_dirclient::download(self.runtime, &request, &mut stream, None)
            .await
            .map_err(|dir_error| match dir_error {
                tor_dirclient::Error::RequestFailed(rfe) => DescriptorErrorDetail::from(rfe.error),
                tor_dirclient::Error::CircMgr(ce) => into_internal!(
                    "tor-dirclient complains about circmgr going wrong but we gave it a stream"
                )(ce)
                .into(),
                other => into_internal!(
                    "tor-dirclient gave unexpected error, tor-hsclient code needs updating"
                )(other)
                .into(),
            })?;

        let desc_text = response.into_output_string().map_err(|rfe| rfe.error)?;
        let hsc_desc_enc = self
            .secret_keys
            .keys
            .ks_hsc_desc_enc
            .as_ref()
            .map(|ks| (HsClientDescEncKey::from(ks), ks));

        let now = self.runtime.wallclock();

        HsDesc::parse_decrypt_validate(
            &desc_text,
            &self.hs_blind_id,
            now,
            &self.subcredential,
            hsc_desc_enc.as_ref().map(|(kp, ks)| (kp, *ks)),
        )
        .map_err(DescriptorErrorDetail::from)
    }

    /// Given the descriptor, try to connect to service
    ///
    /// Does all necessary retries, timeouts, etc.
    async fn intro_rend_connect(
        &self,
        desc: &HsDesc,
        data: &mut DataIpts,
    ) -> Result<Arc<ClientCirc!(R, M)>, CE> {
        // TODO HS are these right? make configurable? get from netdir?
        // TODO HS should we even have this or should we just try each one once?
        /// Maxmimum number of rendezvous/introduction attempts we'll make
        const MAX_TOTAL_ATTEMPTS: usize = 6;
        /// Limit on the duration of each attempt to establishg a rendezvous point
        const REND_TIMEOUT: Duration = Duration::from_secs(10);
        /// Limit on the duration of each attempt to negotiate with an introduction point
        const INTRO_TIMEOUT: Duration = Duration::from_secs(10);
        /// Limit on the duration of each attempt for activities involving both RPT and IPT
        const RPT_IPT_TIMEOUT: Duration = Duration::from_secs(10);

        // We can't reliably distinguish IPT failure from RPT failure, so we iterate over IPTs
        // (best first) and each time use a random RPT.

        // We limit the number of rendezvous establishment attempts, separately, since we don't
        // try to talk to the intro pt until we've established the rendezvous circuit.
        let mut rend_attempts = 0..MAX_TOTAL_ATTEMPTS;

        // But, we put all the errors into the same bucket, since we might have a mixture.
        let mut errors = RetryError::in_attempt_to("make circuit to to hidden service");

        // TODO HS desc.intro_points() ought not to be able to be empty
        // however currently nothing in crates/tor-netdoc/src/doc/hsdesc/inner.rs
        // seems to ensure this.  Until that's fixed, we might produce unhelpful errors here.
        //
        // Note that IntroPtIndex is *not* the index into this Vec.
        // It is the index into the original list of introduction points in the descriptor.
        let usable_intros: Vec<UsableIntroPt> = desc
            .intro_points()
            .iter()
            .enumerate()
            .map(|(intro_index, intro_desc)| {
                let intro_index = intro_index.into();
                let intro_target = ipt_to_circtarget(intro_desc, &self.netdir)
                    .map_err(|error| FAE::UnusableIntro { error, intro_index })?;
                // Lack of TAIT means this clone
                let intro_target = OwnedCircTarget::from_circ_target(&intro_target);
                Ok(UsableIntroPt {
                    intro_index,
                    intro_desc,
                    intro_target,
                })
            })
            .filter_map(|entry| match entry {
                Ok(y) => Some(y),
                Err(e) => {
                    errors.push(tor_error::Report(e));
                    None
                }
            })
            .collect_vec();

        // TODO HS join with existing state recording our experiences,
        // sort by descending goodness, and then randomly
        // (so clients without any experience don't all pile onto the same, first, IPT)
        let mut intro_attempts = usable_intros.iter().cycle().take(MAX_TOTAL_ATTEMPTS);

        // We retain a rendezvous we managed to set up in here.  That way if we created it, and
        // then failed before we actually needed it, we can reuse it.
        // If we exit with an error, we will waste it - but because we isolate things we do
        // for different services, it wouldn't be reuseable anway.
        let mut saved_rendezvous = None;

        // TODO HS make multiple attempts to different IPTs in in parallel, and somehow
        // aggregate the errors and experiences.
        loop {
            // Error handling inner async block (analogous to an IEFE):
            //  * Ok(Some()) means this attempt succeeded
            //  * Ok(None) means all attempts exhausted
            //  * Err(error) means this attempt failed
            //
            // Error handling is rather complex here.  It's the primary job of *this* code to
            // make sure that it's done right for timeouts.  (The individual component
            // functions handle non-timeout errors.)  The different timeout errors have
            // different amounts of information about the identity of the RPT and IPT: in each
            // case, the error only mentions the RPT or IPT if that node is implicated in the
            // timeout.
            match async {
                // We establish a rendezvous point first.  Although it appears from reading
                // this code that this means we serialise establishment of the rendezvous and
                // introduction circuits, this isn't actually the case.  The circmgr maintains
                // a pool of circuits.  What actually happens in the "standing start" case is
                // that we obtain a circuit for rendezvous from the circmgr's pool, expecting
                // one to be available immediately; the circmgr will then start to build a new
                // one to replenish its pool, and that happens in parallel with the work we do
                // here - but in arrears.  If the circmgr pool is empty, then we must wait.
                //
                // TODO: Perhaps this should be parallelised here.  But in that case it's not
                // 100% clear why the pool exists, since we expect building the rendezvous
                // circuit and building the introduction circuit to take about the same
                // length of time.
                //
                // TODO: We *do* serialise the ESTABLISH_RENDEZVOUS exchange, with the
                // building of the introduction circuit.  That could be improved, at the cost
                // of some additional complexity here.
                if saved_rendezvous.is_none() {
                    debug!("hs conn to {}: setting up rendezvous point", &self.hsid);
                    // Establish a rendezvous circuit.
                    let Some(_): Option<usize> = rend_attempts.next() else { return Ok(None) };

                    let mut using_rend_pt = None;
                    saved_rendezvous = Some(
                        self.runtime
                            .timeout(REND_TIMEOUT, self.establish_rendezvous(&mut using_rend_pt))
                            .await
                            .map_err(|_: TimeoutError| match using_rend_pt {
                                None => FAE::RendezvousObtainCircuit {
                                    error: tor_circmgr::Error::CircTimeout,
                                },
                                Some(rend_pt) => FAE::RendezvousTimeout { rend_pt },
                            })??,
                    );
                }

                let Some(ipt) = intro_attempts.next() else { return Ok(None) };
                let intro_index = ipt.intro_index;

                // TODO HS record how long things take, starting from here, as
                // as a statistic we'll use for the IPT in future.
                // This will need to be stored in a variable outside this async block,
                // so that the outcome handling can use it.

                // No `Option::get_or_try_insert_with`, or we'd avoid this expect()
                let rend_pt_for_error = rend_pt_identity_for_error(
                    &saved_rendezvous
                        .as_ref()
                        .expect("just made Some")
                        .rend_relay,
                );
                debug!(
                    "hs conn to {}: RPT {}",
                    &self.hsid,
                    rend_pt_for_error.as_inner()
                );

                let (rendezvous, introduced) = self
                    .runtime
                    .timeout(
                        INTRO_TIMEOUT,
                        self.exchange_introduce(ipt, &mut saved_rendezvous),
                    )
                    .await
                    .map_err(|_: TimeoutError| {
                        // The intro point ought to give us a prompt ACK regardless of HS
                        // behaviour or whatever is happening at the RPT, so blame the IPT.
                        FAE::IntroductionTimeout { intro_index }
                    })??;
                let saved_rendezvous = (); // don't use `saved_rendezvous` any more, use rendezvous

                let rend_pt = rend_pt_identity_for_error(&rendezvous.rend_relay);
                let circ = self
                    .runtime
                    .timeout(RPT_IPT_TIMEOUT, self.complete_rendezvous(ipt, rendezvous))
                    .await
                    .map_err(|_: TimeoutError| FAE::RendezvousCompletionTimeout {
                        intro_index,
                        rend_pt: rend_pt.clone(),
                    })??;

                debug!(
                    "hs conn to {}: RPT {} IPT {}: success",
                    &self.hsid,
                    rend_pt.as_inner(),
                    intro_index,
                );
                Ok::<_, FAE>(Some((intro_index, circ)))
            }
            .await
            {
                Ok(Some((intro_index, y))) => {
                    // TODO HS record successful outcome in Data
                    return Ok(y);
                }
                Ok(None) => return Err(CE::Failed(errors)),
                Err(error) => {
                    debug!(
                        "hs conn to {}: attempt failed: {}",
                        &self.hsid,
                        error.report(),
                    );
                    // TODO HS record error outcome in Data, if in fact we involved the IPT
                    // at all.  The IPT information ought to be retrieved from `error`;
                    // this will have to be a new method on FailedAttemptError for that.
                    // (Only some of the errors implicate the introduction point.)
                    errors.push(tor_error::Report(error));
                }
            }
        }
    }

    /// Make one attempt to establish a rendezvous circuit
    ///
    /// This doesn't really depend on anything,
    /// other than (obviously) the isolation implied by our circuit pool.
    /// In particular it doesn't depend on the introduction point.
    ///
    /// Does not apply a timeout.
    ///
    /// On entry `using_rend_pt` is `None`.
    /// This function will store `Some` when it finds out which relay
    /// it is talking to and starts to converse with it.
    /// That way, if a timeout occurs, the caller can add that information to the error.
    async fn establish_rendezvous(
        &'c self,
        using_rend_pt: &mut Option<RendPtIdentityForError>,
    ) -> Result<Rendezvous<R, M>, FAE> {
        let (rend_circ, rend_relay) = self
            .circpool
            .get_or_launch_client_rend(&self.netdir)
            .await
            .map_err(|error| FAE::RendezvousObtainCircuit { error })?;

        let rend_pt = rend_pt_identity_for_error(&rend_relay);
        *using_rend_pt = Some(rend_pt.clone());

        let rend_cookie: RendCookie = self.mocks.thread_rng().gen();
        let message = EstablishRendezvous::new(rend_cookie);

        let (rend_established_tx, rend_established_rx) = proto_oneshot::channel();
        let (rend2_tx, rend2_rx) = proto_oneshot::channel();

        /// Handler which expects `RENDEZVOUS_ESTABLISHED` and then
        /// `RENDEZVOUS2`.   Returns each message and returns it via the `oneshot`s.
        struct Handler {
            /// Sender for a RENDEZVOUS_ESTABLISHED message.
            rend_established_tx: proto_oneshot::Sender<RendezvousEstablished>,
            /// Sender for a RENDEZVOUS2 message.
            rend2_tx: proto_oneshot::Sender<Rendezvous2>,
        }
        impl MsgHandler for Handler {
            fn handle_msg(
                &mut self,
                msg: AnyRelayMsg,
            ) -> Result<MetaCellDisposition, tor_proto::Error> {
                // The first message we expect is a RENDEZVOUS_ESTABALISHED.
                if self.rend_established_tx.still_expected() {
                    self.rend_established_tx
                        .deliver_expected_message(msg, MetaCellDisposition::Consumed)
                } else {
                    self.rend2_tx
                        .deliver_expected_message(msg, MetaCellDisposition::UninstallHandler)
                }
            }
        }

        debug!(
            "hs conn to {}: RPT {}: sending ESTABLISH_RENDEZVOUS",
            &self.hsid,
            rend_pt.as_inner(),
        );

        let handle_proto_error = |error| FAE::RendezvousEstablish {
            error,
            rend_pt: rend_pt.clone(),
        };
        let handler = Handler {
            rend_established_tx,
            rend2_tx,
        };

        rend_circ
            .send_control_message(message.into(), handler)
            .await
            .map_err(handle_proto_error)?;

        trace!("SEND CONTROL MESSAGE RETURNED"); // TODO HS REMOVE RSN!

        // `send_control_message` returns as soon as the control message has been sent.
        // We need to obtain the RENDEZVOUS_ESTABLISHED message, which is "returned" via the oneshot.
        let _: RendezvousEstablished = rend_established_rx.recv(handle_proto_error).await?;

        trace!("RENDEZVOUS"); // TODO HS REMOVE RSN!

        debug!(
            "hs conn to {}: RPT {}: got RENDEZVOUS_ESTABLISHED",
            &self.hsid,
            rend_pt.as_inner(),
        );

        Ok(Rendezvous {
            rend_circ,
            rend_cookie,
            rend_relay,
            rend2_rx,
            marker: PhantomData,
        })
    }

    /// Attempt (once) to send an INTRODUCE1 and wait for the INTRODUCE_ACK
    ///
    /// `take`s the input `rednezvous` (but only takes it if it gets that far)
    /// and, if successful, returns it.
    /// (This arranges that the rendezvous is "used up" precisely if
    /// we sent its secret somewhere.)
    ///
    /// Although this function handles the `Rendezvous`,
    /// nothing in it actually involves the rendezvous point.
    /// So if there's a failure, it's purely to do with the introduction point.
    ///
    /// Does not apply a timeout.
    async fn exchange_introduce(
        &'c self,
        ipt: &UsableIntroPt<'_>,
        rendezvous: &mut Option<Rendezvous<'c, R, M>>,
    ) -> Result<(Rendezvous<R, M>, Introduced<R, M>), FAE> {
        let intro_index = ipt.intro_index;

        debug!(
            "hs conn to {}: IPT {}: obtaining intro circuit",
            &self.hsid, intro_index,
        );

        let intro_circ = self
            .circpool
            .get_or_launch_specific(
                &self.netdir,
                HsCircKind::ClientIntro,
                ipt.intro_target.clone(), // &OwnedCircTarget isn't CircTarget apparently
            )
            .await
            .map_err(|error| FAE::IntroObtainCircuit { error, intro_index })?;

        let rendezvous = rendezvous.take().ok_or_else(|| internal!("no rend"))?;

        let rend_pt = rend_pt_identity_for_error(&rendezvous.rend_relay);

        debug!(
            "hs conn to {}: RPT {} IPT {}: making introduction",
            &self.hsid,
            rend_pt.as_inner(),
            intro_index,
        );

        // Now we construct an introduce1 message and perform the first part of the
        // rendezvous handshake.
        //
        // This process is tricky because the header of the INTRODUCE1 message
        // -- which depends on the IntroPt configuration -- is authenticated as
        // part of the HsDesc handshake.

        // Construct the header, since we need it as input to our encryption.
        let intro_header = {
            let ipt_sid_key = ipt.intro_desc.ipt_sid_key();
            let intro1 = Introduce1::new(
                AuthKeyType::ED25519_SHA3_256,
                ipt_sid_key.as_bytes().to_vec(),
                vec![],
            );
            let mut header = vec![];
            intro1
                .encode_onto(&mut header)
                .map_err(into_internal!("couldn't encode intro1 header"))?;
            header
        };

        // Construct the introduce payload, which tells the onion service how to find
        // our rendezvous point.  (We could do this earlier if we wanted.)
        let intro_payload = {
            let onion_key =
                intro_payload::OnionKey::NtorOnionKey(*rendezvous.rend_relay.ntor_onion_key());
            let linkspecs = rendezvous
                .rend_relay
                .linkspecs()
                .map_err(into_internal!("Couldn't encode link specifiers"))?;
            let payload =
                IntroduceHandshakePayload::new(rendezvous.rend_cookie, onion_key, linkspecs);
            let mut encoded = vec![];
            payload
                .write_onto(&mut encoded)
                .map_err(into_internal!("Couldn't encode introduce1 payload"))?;
            encoded
        };

        // Perform the cryptographic handshake with the onion service.
        let service_info = hs_ntor::HsNtorServiceInfo::new(
            ipt.intro_desc.svc_ntor_key().clone(),
            ipt.intro_desc.ipt_sid_key().clone(),
            self.subcredential,
        );
        let handshake_state =
            hs_ntor::HsNtorClientState::new(&mut self.mocks.thread_rng(), service_info);
        let encrypted_body = handshake_state
            .client_send_intro(&intro_header, &intro_payload)
            .map_err(into_internal!("can't begin hs-ntor handshake"))?;

        // Build our actual INTRODUCE1 message.
        let intro1_real = Introduce1::new(
            AuthKeyType::ED25519_SHA3_256,
            ipt.intro_desc.ipt_sid_key().as_bytes().to_vec(),
            encrypted_body,
        );

        // TODO HS: Send intro1_real on the introduce circuit and wait for
        // either an error or an INTRO_ACK.
        // intro_circ.send_control_message(intro1_real)...

        // TODO HS: We need to remember handshake_state so we can later handle a
        // RENDEZVOUS2 message!

        Err(internal!("sending INTRODUCE1 is not yet implemented!").into()) // TODO HS
    }

    /// Attempt (once) to connect a rendezvous circuit using the given intro pt
    ///
    /// Timeouts here might be due to the IPT, RPT, service,
    /// or any of the intermediate relays.
    ///
    /// If, rather than a timeout, we actually encounter some kind of error,
    /// we'll return the appropriate `FailedAttemptError`.
    /// (Who is responsible may vary, so the `FailedAttemptError` variant will reflect that.)
    ///
    /// Does not apply a timeout
    async fn complete_rendezvous(
        &'c self,
        ipt: &UsableIntroPt<'_>,
        rendezvous: Rendezvous<'c, R, M>,
    ) -> Result<Arc<ClientCirc!(R, M)>, FAE> {
        #![allow(unreachable_code, clippy::diverging_sub_expression)] // TODO HS remove.
        use tor_proto::circuit::handshake;

        let handle_proto_error = |error| FAE::RendezvousCircuitCompletionExpected {
            error,
            intro_index: ipt.intro_index,
            rend_pt: rend_pt_identity_for_error(&rendezvous.rend_relay),
        };

        let rend2_msg: Rendezvous2 = rendezvous.rend2_rx.recv(handle_proto_error).await?;

        // TODO HS: get handshake_state form wherever we stored it above.
        //
        // TODO: It would be great if we could have multiple of these existing
        // in parallel with similar x,X values but different ipts. I believe C
        // tor manages it somehow.
        let handshake_state: &hs_ntor::HsNtorClientState = todo!(); // TODO HS

        // Try to complete the cryptographic handshake.
        let keygen = handshake_state
            .client_receive_rend(rend2_msg.handshake_info())
            .map_err(into_internal!(
                "ACTUALLY this is a protocol violation, make a better error" // TODO HS
            ))?;
        // TODO HS: make sure that we do the correct error recovery from the
        // above error.  Either the onion service has failed, or the rendezvous
        // point has misbehaved, or we have used the wrong handshake_state.

        // TODO HS: Generate this more sensibly!
        let params = CircParameters::default();

        rendezvous
            .rend_circ
            .extend_virtual(
                handshake::RelayProtocol::HsV3,
                handshake::HandshakeRole::Initiator,
                keygen,
                params,
            )
            .await
            .map_err(into_internal!(
                "actually this is probably a 'circuit closed' error" // TODO HS
            ))?;

        // TODO HS: Now we can return the rend_circ circuit to the calling code,
        // which can start using it!  Isn't that great?  we're done!

        todo!() // HS implement
    }
}

/// Mocks used for testing `connect.rs`
///
/// This is different to `MockableConnectorData`,
/// which is used to *replace* this file, when testing `state.rs`.
///
/// `MocksForConnect` provides mock facilities for *testing* this file.
//
// TODO this should probably live somewhere else, maybe tor-circmgr even?
// TODO this really ought to be made by macros or something
trait MocksForConnect<R>: Clone {
    /// HS circuit pool
    type HsCircPool: MockableCircPool<R>;

    /// A random number generator
    type Rng: rand::Rng + rand::CryptoRng;

    /// Tell tests we got this descriptor text
    fn test_got_desc(&self, desc: &HsDesc) {
        eprintln!("HS DESC:\n{:?}\n", &desc); // TODO HS remove
    }
    /// Tell tests we got this circuit
    fn test_got_circ(&self, circ: &Arc<ClientCirc!(R, Self)>) {
        eprintln!("HS CIRC:\n{:?}\n", &circ); // TODO HS remove
    }

    /// Return a random number generator
    fn thread_rng(&self) -> Self::Rng;
}
/// Mock for `HsCircPool`
#[async_trait]
trait MockableCircPool<R> {
    /// Client circuit
    type ClientCirc: MockableClientCirc;
    async fn get_or_launch_specific(
        &self,
        netdir: &NetDir,
        kind: HsCircKind,
        target: impl CircTarget + Send + Sync + 'async_trait,
    ) -> tor_circmgr::Result<Arc<Self::ClientCirc>>;

    /// Client circuit
    async fn get_or_launch_client_rend<'a>(
        &self,
        netdir: &'a NetDir,
    ) -> tor_circmgr::Result<(Arc<Self::ClientCirc>, Relay<'a>)>;
}
/// Mock for `ClientCirc`
#[async_trait]
trait MockableClientCirc: Debug {
    /// Client circuit
    type DirStream: AsyncRead + AsyncWrite + Send + Unpin;
    async fn begin_dir_stream(self: Arc<Self>) -> tor_proto::Result<Self::DirStream>;

    /// Send a control message
    async fn send_control_message(
        &self,
        msg: AnyRelayMsg,
        reply_handler: impl MsgHandler + Send + 'static,
    ) -> tor_proto::Result<()>;

    /// Add a virtual hop to the circuit.
    async fn extend_virtual(
        &self,
        protocol: tor_proto::circuit::handshake::RelayProtocol,
        protocol: tor_proto::circuit::handshake::HandshakeRole,
        handshake: impl tor_proto::circuit::handshake::KeyGenerator + Send,
        params: CircParameters,
    ) -> tor_proto::Result<()>;
}

impl<R: Runtime> MocksForConnect<R> for () {
    type HsCircPool = HsCircPool<R>;
    type Rng = rand::rngs::ThreadRng;

    fn thread_rng(&self) -> Self::Rng {
        rand::thread_rng()
    }
}
#[async_trait]
impl<R: Runtime> MockableCircPool<R> for HsCircPool<R> {
    type ClientCirc = ClientCirc;
    async fn get_or_launch_specific(
        &self,
        netdir: &NetDir,
        kind: HsCircKind,
        target: impl CircTarget + Send + Sync + 'async_trait,
    ) -> tor_circmgr::Result<Arc<ClientCirc>> {
        HsCircPool::get_or_launch_specific(self, netdir, kind, target).await
    }
    async fn get_or_launch_client_rend<'a>(
        &self,
        netdir: &'a NetDir,
    ) -> tor_circmgr::Result<(Arc<ClientCirc>, Relay<'a>)> {
        HsCircPool::get_or_launch_client_rend(self, netdir).await
    }
}
#[async_trait]
impl MockableClientCirc for ClientCirc {
    /// Client circuit
    type DirStream = tor_proto::stream::DataStream;
    async fn begin_dir_stream(self: Arc<Self>) -> tor_proto::Result<Self::DirStream> {
        ClientCirc::begin_dir_stream(self).await
    }
    async fn send_control_message(
        &self,
        msg: AnyRelayMsg,
        reply_handler: impl MsgHandler + Send + 'static,
    ) -> tor_proto::Result<()> {
        ClientCirc::send_control_message(self, msg, reply_handler).await
    }

    async fn extend_virtual(
        &self,
        protocol: tor_proto::circuit::handshake::RelayProtocol,
        role: tor_proto::circuit::handshake::HandshakeRole,
        handshake: impl tor_proto::circuit::handshake::KeyGenerator + Send,
        params: CircParameters,
    ) -> tor_proto::Result<()> {
        ClientCirc::extend_virtual(self, protocol, role, handshake, params).await
    }
}

#[async_trait]
impl MockableConnectorData for Data {
    type ClientCirc = ClientCirc;
    type MockGlobalState = ();

    async fn connect<R: Runtime>(
        connector: &HsClientConnector<R>,
        netdir: Arc<NetDir>,
        hsid: HsId,
        data: &mut Self,
        secret_keys: HsClientSecretKeys,
    ) -> Result<Arc<Self::ClientCirc>, ConnError> {
        connect(connector, netdir, hsid, data, secret_keys).await
    }

    fn circuit_is_ok(circuit: &Self::ClientCirc) -> bool {
        !circuit.is_closing()
    }
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    use crate::*;
    use futures::FutureExt as _;
    use std::ops::{Bound, RangeBounds};
    use std::{iter, panic::AssertUnwindSafe};
    use tokio_crate as tokio;
    use tor_async_utils::JoinReadWrite;
    use tor_basic_utils::test_rng::{testing_rng, TestingRng};
    use tor_llcrypto::pk::curve25519;
    use tor_netdoc::doc::{hsdesc::test_data, netstatus::Lifetime};
    use tor_rtcompat::{tokio::TokioNativeTlsRuntime, CompoundRuntime};
    use tor_rtmock::time::MockSleepProvider;
    use tracing_test::traced_test;

    #[derive(Debug, Default)]
    struct MocksGlobal {
        hsdirs_asked: Vec<OwnedCircTarget>,
        got_desc: Option<HsDesc>,
    }
    #[derive(Clone, Debug)]
    struct Mocks<I> {
        mglobal: Arc<Mutex<MocksGlobal>>,
        id: I,
    }

    #[allow(dead_code)] // TODO HS delete this, and maybe id, if it ends up indeed unused
    impl<I> Mocks<I> {
        fn map_id<J>(&self, f: impl FnOnce(&I) -> J) -> Mocks<J> {
            Mocks {
                mglobal: self.mglobal.clone(),
                id: f(&self.id),
            }
        }
    }

    impl<R: Runtime> MocksForConnect<R> for Mocks<()> {
        type HsCircPool = Mocks<()>;
        type Rng = TestingRng;

        fn test_got_desc(&self, desc: &HsDesc) {
            self.mglobal.lock().unwrap().got_desc = Some(desc.clone());
        }

        fn thread_rng(&self) -> Self::Rng {
            testing_rng()
        }
    }
    #[async_trait]
    impl<R: Runtime> MockableCircPool<R> for Mocks<()> {
        type ClientCirc = Mocks<()>;
        async fn get_or_launch_specific(
            &self,
            _netdir: &NetDir,
            kind: HsCircKind,
            target: impl CircTarget + Send + Sync + 'async_trait,
        ) -> tor_circmgr::Result<Arc<Self::ClientCirc>> {
            assert_eq!(kind, HsCircKind::ClientHsDir);
            let target = OwnedCircTarget::from_circ_target(&target);
            self.mglobal.lock().unwrap().hsdirs_asked.push(target);
            // Adding the `Arc` here is a little ugly, but that's what we get
            // for using the same Mocks for everything.
            Ok(Arc::new(self.clone()))
        }
        /// Client circuit
        async fn get_or_launch_client_rend<'a>(
            &self,
            netdir: &'a NetDir,
        ) -> tor_circmgr::Result<(Arc<ClientCirc!(R, Self)>, Relay<'a>)> {
            todo!()
        }
    }
    #[async_trait]
    impl MockableClientCirc for Mocks<()> {
        type DirStream = JoinReadWrite<futures::io::Cursor<Box<[u8]>>, futures::io::Sink>;
        async fn begin_dir_stream(self: Arc<Self>) -> tor_proto::Result<Self::DirStream> {
            let response = format!(
                r#"HTTP/1.1 200 OK

{}"#,
                test_data::TEST_DATA_2
            )
            .into_bytes()
            .into_boxed_slice();

            Ok(JoinReadWrite::new(
                futures::io::Cursor::new(response),
                futures::io::sink(),
            ))
        }
        async fn send_control_message(
            &self,
            msg: AnyRelayMsg,
            reply_handler: impl MsgHandler + Send + 'static,
        ) -> tor_proto::Result<()> {
            todo!()
        }

        async fn extend_virtual(
            &self,
            protocol: tor_proto::circuit::handshake::RelayProtocol,
            role: tor_proto::circuit::handshake::HandshakeRole,
            handshake: impl tor_proto::circuit::handshake::KeyGenerator + Send,
            params: CircParameters,
        ) -> tor_proto::Result<()> {
            todo!()
        }
    }

    #[traced_test]
    #[tokio::test]
    async fn test_connect() {
        let valid_after = humantime::parse_rfc3339("2023-02-09T12:00:00Z").unwrap();
        let fresh_until = valid_after + humantime::parse_duration("1 hours").unwrap();
        let valid_until = valid_after + humantime::parse_duration("24 hours").unwrap();
        let lifetime = Lifetime::new(valid_after, fresh_until, valid_until).unwrap();

        let netdir = tor_netdir::testnet::construct_custom_netdir_with_params(
            tor_netdir::testnet::simple_net_func,
            iter::empty::<(&str, _)>(),
            Some(lifetime),
        )
        .expect("failed to build default testing netdir");

        let netdir = Arc::new(netdir.unwrap_if_sufficient().unwrap());
        let runtime = TokioNativeTlsRuntime::current().unwrap();
        let now = humantime::parse_rfc3339("2023-02-09T12:00:00Z").unwrap();
        let mock_sp = MockSleepProvider::new(now);
        let runtime = CompoundRuntime::new(
            runtime.clone(),
            mock_sp,
            runtime.clone(),
            runtime.clone(),
            runtime,
        );
        let time_period = netdir.hs_time_period();

        let mglobal = Arc::new(Mutex::new(MocksGlobal::default()));
        let mocks = Mocks { mglobal, id: () };
        // From C Tor src/test/test_hs_common.c test_build_address
        let hsid = test_data::TEST_HSID_2.into();
        let mut data = Data::default();

        let pk = curve25519::PublicKey::from(test_data::TEST_PUBKEY_2).into();
        let sk = curve25519::StaticSecret::from(test_data::TEST_SECKEY_2).into();
        let mut secret_keys_builder = HsClientSecretKeysBuilder::default();
        secret_keys_builder.ks_hsc_desc_enc(sk);
        let secret_keys = secret_keys_builder.build().unwrap();

        let ctx = Context::new(&runtime, &mocks, netdir, hsid, secret_keys, mocks.clone()).unwrap();

        let _got = AssertUnwindSafe(ctx.connect(&mut data))
            .catch_unwind() // TODO HS remove this and the AssertUnwindSafe
            .await;

        let (hs_blind_id_key, subcredential) = HsIdKey::try_from(hsid)
            .unwrap()
            .compute_blinded_key(time_period)
            .unwrap();
        let hs_blind_id = hs_blind_id_key.id();

        let sk = curve25519::StaticSecret::from(test_data::TEST_SECKEY_2).into();

        let hsdesc = HsDesc::parse_decrypt_validate(
            test_data::TEST_DATA_2,
            &hs_blind_id,
            now,
            &subcredential,
            Some((&pk, &sk)),
        )
        .unwrap()
        .dangerously_assume_timely();

        let mglobal = mocks.mglobal.lock().unwrap();
        assert_eq!(mglobal.hsdirs_asked.len(), 1);
        // TODO hs: here and in other places, consider implementing PartialEq instead, or creating
        // an assert_dbg_eq macro (which would be part of a test_helpers crate or something)
        assert_eq!(
            format!("{:?}", mglobal.got_desc),
            format!("{:?}", Some(hsdesc))
        );

        // Check how long the descriptor is valid for
        let bounds = data.desc.as_ref().unwrap().bounds();
        assert_eq!(bounds.start_bound(), Bound::Unbounded);

        let desc_valid_until = humantime::parse_rfc3339("2023-02-11T20:00:00Z").unwrap();
        assert_eq!(
            bounds.end_bound(),
            Bound::Included(desc_valid_until).as_ref()
        );

        // TODO hs check the circuit in got is the one we gave out

        // TODO hs continue with this
    }

    // TODO HS: test retries (of every retry loop we have here)
    // TODO HS: test error paths
}
