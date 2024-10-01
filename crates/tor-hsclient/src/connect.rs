//! Main implementation of the connection functionality

use std::time::Duration;

use std::collections::HashMap;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use educe::Educe;
use futures::{AsyncRead, AsyncWrite};
use itertools::Itertools;
use rand::Rng;
use tor_bytes::Writeable;
use tor_cell::relaycell::hs::intro_payload::{self, IntroduceHandshakePayload};
use tor_cell::relaycell::msg::{AnyRelayMsg, Introduce1, Rendezvous2};
use tor_error::{debug_report, warn_report, Bug};
use tor_hscrypto::Subcredential;
use tor_proto::circuit::handshake::hs_ntor;
use tracing::{debug, trace};

use retry_error::RetryError;
use safelog::Sensitive;
use tor_cell::relaycell::hs::{
    AuthKeyType, EstablishRendezvous, IntroduceAck, RendezvousEstablished,
};
use tor_cell::relaycell::RelayMsg;
use tor_checkable::{timed::TimerangeBound, Timebound};
use tor_circmgr::build::circparameters_from_netparameters;
use tor_circmgr::hspool::{HsCircKind, HsCircPool};
use tor_circmgr::timeouts::Action as TimeoutsAction;
use tor_dirclient::request::Requestable as _;
use tor_error::{internal, into_internal};
use tor_error::{HasRetryTime as _, RetryTime};
use tor_hscrypto::pk::{HsBlindId, HsId, HsIdKey};
use tor_hscrypto::RendCookie;
use tor_linkspec::{CircTarget, HasRelayIds, OwnedCircTarget, RelayId};
use tor_llcrypto::pk::ed25519::Ed25519Identity;
use tor_netdir::{NetDir, Relay};
use tor_netdoc::doc::hsdesc::{HsDesc, IntroPointDesc};
use tor_proto::circuit::{
    CircParameters, ClientCirc, ConversationInHandler, MetaCellDisposition, MsgHandler,
};
use tor_rtcompat::{Runtime, SleepProviderExt as _, TimeoutError};

use crate::proto_oneshot;
use crate::relay_info::ipt_to_circtarget;
use crate::state::MockableConnectorData;
use crate::Config;
use crate::{rend_pt_identity_for_error, FailedAttemptError, IntroPtIndex, RendPtIdentityForError};
use crate::{ConnError, DescriptorError, DescriptorErrorDetail};
use crate::{HsClientConnector, HsClientSecretKeys};

use ConnError as CE;
use FailedAttemptError as FAE;

/// Number of hops in our hsdir, introduction, and rendezvous circuits
///
/// Required by `tor_circmgr`'s timeout estimation API
/// ([`tor_circmgr::CircMgr::estimate_timeout`], [`HsCircPool::estimate_timeout`]).
///
/// TODO HS hardcoding the number of hops to 3 seems wrong.
/// This is really something that HsCircPool knows.  And some setups might want to make
/// shorter circuits for some reason.  And it will become wrong with vanguards?
/// But right now I think this is what HsCircPool does.
//
// Some commentary from
//   https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1342#note_2918050
// Possibilities:
//  * Look at n_hops() on the circuits we get, if we don't need this estimate
//    till after we have the circuit.
//  * Add a function to HsCircPool to tell us what length of circuit to expect
//    for each given type of circuit.
const HOPS: usize = 3;

/// Given `R, M` where `M: MocksForConnect<M>`, expand to the mockable `ClientCirc`
// This is quite annoying.  But the alternative is to write out `<... as // ...>`
// each time, since otherwise the compile complains about ambiguous associated types.
macro_rules! ClientCirc { { $R:ty, $M:ty } => {
    <<$M as MocksForConnect<$R>>::HsCircPool as MockableCircPool<$R>>::ClientCirc
} }

/// Information about a hidden service, including our connection history
#[derive(Default, Educe)]
#[educe(Debug)]
// This type is actually crate-private, since it isn't re-exported, but it must
// be `pub` because it appears as a default for a type parameter in HsClientConnector.
pub struct Data {
    /// The latest known onion service descriptor for this service.
    desc: DataHsDesc,
    /// Information about the latest status of trying to connect to this service
    /// through each of its introduction points.
    ipts: DataIpts,
}

/// Part of `Data` that relates to the HS descriptor
type DataHsDesc = Option<TimerangeBound<HsDesc>>;

/// Part of `Data` that relates to our information about introduction points
type DataIpts = HashMap<RelayIdForExperience, IptExperience>;

/// How things went last time we tried to use this introduction point
///
/// Neither this data structure, nor [`Data`], is responsible for arranging that we expire this
/// information eventually.  If we keep reconnecting to the service, we'll retain information
/// about each IPT indefinitely, at least so long as they remain listed in the descriptors we
/// receive.
///
/// Expiry of unused data is handled by `state.rs`, according to `last_used` in `ServiceState`.
///
/// Choosing which IPT to prefer is done by obtaining an `IptSortKey`
/// (from this and other information).
//
// Don't impl Ord for IptExperience.  We obtain `Option<&IptExperience>` from our
// data structure, and if IptExperience were Ord then Option<&IptExperience> would be Ord
// but it would be the wrong sort order: it would always prefer None, ie untried IPTs.
#[derive(Debug)]
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
/// "mock circuit and netdir, used for testing `connect.rs`",
/// so it is not, itself, unit-testable.
pub(crate) async fn connect<R: Runtime>(
    connector: &HsClientConnector<R>,
    netdir: Arc<NetDir>,
    config: Arc<Config>,
    hsid: HsId,
    data: &mut Data,
    secret_keys: HsClientSecretKeys,
) -> Result<Arc<ClientCirc>, ConnError> {
    Context::new(
        &connector.runtime,
        &*connector.circpool,
        netdir,
        config,
        hsid,
        secret_keys,
        (),
    )?
    .connect(data)
    .await
}

/// Common context for a single request to connect to a hidden service
///
/// This saves on passing this same set of (immutable) values (or subsets thereof)
/// to each method in the principal functional code, everywhere.
/// It also provides a convenient type to be `Self`.
///
/// Its lifetime is one request to make a new client circuit to a hidden service,
/// including all the retries and timeouts.
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
    /// Configuration
    config: Arc<Config>,
    /// Secret keys to use
    secret_keys: HsClientSecretKeys,
    /// HS ID
    hsid: HsId,
    /// Blinded HS ID
    hs_blind_id: HsBlindId,
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
    /// which receives control messages on the rendezvous circuit,
    /// and which was installed when we sent `ESTABLISH_RENDEZVOUS`.
    ///
    /// (`RENDEZVOUS2` is the message containing the onion service's side of the handshake.)
    rend2_rx: proto_oneshot::Receiver<Rendezvous2>,

    /// Dummy, to placate compiler
    ///
    /// Covariant without dropck or interfering with Send/Sync will do fine.
    marker: PhantomData<fn() -> (R, M)>,
}

/// Random value used as part of IPT selection
type IptSortRand = u32;

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
    /// Random value used as part of IPT selection
    sort_rand: IptSortRand,
}

/// Lookup key for looking up and recording our IPT use experiences
///
/// Used to identify a relay when looking to see what happened last time we used it,
/// and storing that information after we tried it.
///
/// We store the experience information under an arbitrary one of the relay's identities,
/// as returned by the `HasRelayIds::identities().next()`.
/// When we do lookups, we check all the relay's identities to see if we find
/// anything relevant.
/// If relay identities permute in strange ways, whether we find our previous
/// knowledge about them is not particularly well defined, but that's fine.
///
/// While this is, structurally, a relay identity, it is not suitable for other purposes.
#[derive(Hash, Eq, PartialEq, Ord, PartialOrd, Debug)]
struct RelayIdForExperience(RelayId);

/// Details of an apparently-successful INTRODUCE exchange
///
/// Intermediate value for progress during a connection attempt.
struct Introduced<R: Runtime, M: MocksForConnect<R>> {
    /// End-to-end crypto NTORv3 handshake with the service
    ///
    /// Created as part of generating our `INTRODUCE1`,
    /// and then used when processing `RENDEZVOUS2`.
    handshake_state: hs_ntor::HsNtorClientState,

    /// Dummy, to placate compiler
    ///
    /// `R` and `M` only used for getting to mocks.
    /// Covariant without dropck or interfering with Send/Sync will do fine.
    marker: PhantomData<fn() -> (R, M)>,
}

impl RelayIdForExperience {
    /// Identities to use to try to find previous experience information about this IPT
    fn for_lookup(intro_target: &OwnedCircTarget) -> impl Iterator<Item = Self> + '_ {
        intro_target
            .identities()
            .map(|id| RelayIdForExperience(id.to_owned()))
    }

    /// Identity to use to store previous experience information about this IPT
    fn for_store(intro_target: &OwnedCircTarget) -> Result<Self, Bug> {
        let id = intro_target
            .identities()
            .next()
            .ok_or_else(|| internal!("introduction point relay with no identities"))?
            .to_owned();
        Ok(RelayIdForExperience(id))
    }
}

/// Sort key for an introduction point, for selecting the best IPTs to try first
///
/// Ordering is most preferable first.
///
/// We use this to sort our `UsableIpt`s using `.sort_by_key`.
/// (This implementation approach ensures that we obey all the usual ordering invariants.)
#[derive(Ord, PartialOrd, Eq, PartialEq, Debug)]
struct IptSortKey {
    /// Sort by how preferable the experience was
    outcome: IptSortKeyOutcome,
    /// Failing that, choose randomly
    sort_rand: IptSortRand,
}

/// Component of the [`IptSortKey`] representing outcome of our last attempt, if any
///
/// This is the main thing we use to decide which IPTs to try first.
/// It is calculated for each IPT
/// (via `.sort_by_key`, so repeatedly - it should therefore be cheap to make.)
///
/// Ordering is most preferable first.
#[derive(Ord, PartialOrd, Eq, PartialEq, Debug)]
enum IptSortKeyOutcome {
    /// Prefer successes
    Success {
        /// Prefer quick ones
        duration: Duration,
    },
    /// Failing that, try one we don't know to have failed
    Untried,
    /// Failing that, it'll have to be ones that didn't work last time
    Failed {
        /// Prefer failures with an earlier retry time
        retry_time: tor_error::LooseCmpRetryTime,
        /// Failing that, prefer quick failures (rather than slow ones eg timeouts)
        duration: Duration,
    },
}

impl From<Option<&IptExperience>> for IptSortKeyOutcome {
    fn from(experience: Option<&IptExperience>) -> IptSortKeyOutcome {
        use IptSortKeyOutcome as O;
        match experience {
            None => O::Untried,
            Some(IptExperience { duration, outcome }) => match outcome {
                Ok(()) => O::Success {
                    duration: *duration,
                },
                Err(retry_time) => O::Failed {
                    retry_time: (*retry_time).into(),
                    duration: *duration,
                },
            },
        }
    }
}

impl<'c, R: Runtime, M: MocksForConnect<R>> Context<'c, R, M> {
    /// Make a new `Context` from the input data
    fn new(
        runtime: &'c R,
        circpool: &'c M::HsCircPool,
        netdir: Arc<NetDir>,
        config: Arc<Config>,
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
            config,
            hsid,
            hs_blind_id,
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
        // Maximum number of hsdir connection and retrieval attempts we'll make
        let max_total_attempts = self
            .config
            .retry
            .hs_desc_fetch_attempts()
            .try_into()
            // User specified a very large u32.  We must be downcasting it to 16bit!
            // let's give them as many retries as we can manage.
            .unwrap_or(usize::MAX);

        // Limit on the duration of each retrieval attempt
        let each_timeout = self.estimate_timeout(&[
            (1, TimeoutsAction::BuildCircuit { length: HOPS }), // build circuit
            (1, TimeoutsAction::RoundTrip { length: HOPS }),    // One HTTP query/response
        ]);

        // We retain a previously obtained descriptor precisely until its lifetime expires,
        // and pay no attention to the descriptor's revision counter.
        // When it expires, we discard it completely and try to obtain a new one.
        //   https://gitlab.torproject.org/tpo/core/arti/-/issues/913#note_2914448
        // TODO SPEC: Discuss HS descriptor lifetime and expiry client behaviour
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

        let hs_dirs = self.netdir.hs_dirs_download(
            self.hs_blind_id,
            self.netdir.hs_time_period(),
            &mut self.mocks.thread_rng(),
        )?;

        trace!(
            "HS desc fetch for {}, using {} hsdirs",
            &self.hsid,
            hs_dirs.len()
        );

        // We might consider launching requests to multiple HsDirs in parallel.
        //   https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1118#note_2894463
        // But C Tor doesn't and our HS experts don't consider that important:
        //   https://gitlab.torproject.org/tpo/core/arti/-/issues/913#note_2914436
        // (Additionally, making multiple HSDir requests at once may make us
        // more vulnerable to traffic analysis.)
        let mut attempts = hs_dirs.iter().cycle().take(max_total_attempts);
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
            let hsdir_for_error: Sensitive<Ed25519Identity> = (*relay.id()).into();
            match self
                .runtime
                .timeout(each_timeout, self.descriptor_fetch_attempt(relay))
                .await
                .unwrap_or(Err(DescriptorErrorDetail::Timeout))
            {
                Ok(desc) => break desc,
                Err(error) => {
                    debug_report!(
                        &error,
                        "failed hsdir desc fetch for {} from {}",
                        &self.hsid,
                        &relay.id(),
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
        let max_len: usize = self
            .netdir
            .params()
            .hsdir_max_desc_size
            .get()
            .try_into()
            .map_err(into_internal!("BoundedInt was not truly bounded!"))?;
        let request = {
            let mut r = tor_dirclient::request::HsDescDownloadRequest::new(self.hs_blind_id);
            r.set_max_len(max_len);
            r
        };
        trace!(
            "hsdir for {}, trying {}/{}, request {:?} (http request {:?})",
            &self.hsid,
            &hsdir.id(),
            &hsdir.rsa_id(),
            &request,
            request.debug_request()
        );

        let circuit = self
            .circpool
            .m_get_or_launch_specific(
                &self.netdir,
                HsCircKind::ClientHsDir,
                OwnedCircTarget::from_circ_target(hsdir),
            )
            .await?;
        let mut stream = circuit
            .m_begin_dir_stream()
            .await
            .map_err(DescriptorErrorDetail::Stream)?;

        let response = tor_dirclient::send_request(self.runtime, &request, &mut stream, None)
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
        let hsc_desc_enc = self.secret_keys.keys.ks_hsc_desc_enc.as_ref();

        let now = self.runtime.wallclock();

        HsDesc::parse_decrypt_validate(
            &desc_text,
            &self.hs_blind_id,
            now,
            &self.subcredential,
            hsc_desc_enc,
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
        // Maximum number of rendezvous/introduction attempts we'll make
        let max_total_attempts = self
            .config
            .retry
            .hs_intro_rend_attempts()
            .try_into()
            // User specified a very large u32.  We must be downcasting it to 16bit!
            // let's give them as many retries as we can manage.
            .unwrap_or(usize::MAX);

        // Limit on the duration of each attempt to establish a rendezvous point
        //
        // This *might* include establishing a fresh circuit,
        // if the HsCircPool's pool is empty.
        let rend_timeout = self.estimate_timeout(&[
            (1, TimeoutsAction::BuildCircuit { length: HOPS }), // build circuit
            (1, TimeoutsAction::RoundTrip { length: HOPS }),    // One ESTABLISH_RENDEZVOUS
        ]);

        // Limit on the duration of each attempt to negotiate with an introduction point
        //
        // *Does* include establishing the circuit.
        let intro_timeout = self.estimate_timeout(&[
            (1, TimeoutsAction::BuildCircuit { length: HOPS }), // build circuit
            // This does some crypto too, but we don't account for that.
            (1, TimeoutsAction::RoundTrip { length: HOPS }), // One INTRODUCE1/INTRODUCE_ACK
        ]);

        // Timeout estimator for the action that the HS will take in building
        // its circuit to the RPT.
        let hs_build_action = TimeoutsAction::BuildCircuit {
            length: if desc.is_single_onion_service() {
                1
            } else {
                HOPS
            },
        };
        // Limit on the duration of each attempt for activities involving both
        // RPT and IPT.
        let rpt_ipt_timeout = self.estimate_timeout(&[
            // The API requires us to specify a number of circuit builds and round trips.
            // So what we tell the estimator is a rather imprecise description.
            // (TODO it would be nice if the circmgr offered us a one-way trip Action).
            //
            // What we are timing here is:
            //
            //    INTRODUCE2 goes from IPT to HS
            //    but that happens in parallel with us waiting for INTRODUCE_ACK,
            //    which is controlled by `intro_timeout` so not pat of `ipt_rpt_timeout`.
            //    and which has to come HOPS hops.  So don't count INTRODUCE2 here.
            //
            //    HS builds to our RPT
            (1, hs_build_action),
            //
            //    RENDEZVOUS1 goes from HS to RPT.  `hs_hops`, one-way.
            //    RENDEZVOUS2 goes from RPT to us.  HOPS, one-way.
            //    Together, we squint a bit and call this a HOPS round trip:
            (1, TimeoutsAction::RoundTrip { length: HOPS }),
        ]);

        // We can't reliably distinguish IPT failure from RPT failure, so we iterate over IPTs
        // (best first) and each time use a random RPT.

        // We limit the number of rendezvous establishment attempts, separately, since we don't
        // try to talk to the intro pt until we've established the rendezvous circuit.
        let mut rend_attempts = 0..max_total_attempts;

        // But, we put all the errors into the same bucket, since we might have a mixture.
        let mut errors = RetryError::in_attempt_to("make circuit to to hidden service");

        // Note that IntroPtIndex is *not* the index into this Vec.
        // It is the index into the original list of introduction points in the descriptor.
        let mut usable_intros: Vec<UsableIntroPt> = desc
            .intro_points()
            .iter()
            .enumerate()
            .map(|(intro_index, intro_desc)| {
                let intro_index = intro_index.into();
                let intro_target = ipt_to_circtarget(intro_desc, &self.netdir)
                    .map_err(|error| FAE::UnusableIntro { error, intro_index })?;
                // Lack of TAIT means this clone
                let intro_target = OwnedCircTarget::from_circ_target(&intro_target);
                Ok::<_, FailedAttemptError>(UsableIntroPt {
                    intro_index,
                    intro_desc,
                    intro_target,
                    sort_rand: self.mocks.thread_rng().gen(),
                })
            })
            .filter_map(|entry| match entry {
                Ok(y) => Some(y),
                Err(e) => {
                    errors.push(e);
                    None
                }
            })
            .collect_vec();

        // Delete experience information for now-unlisted intro points
        // Otherwise, as the IPTs change `Data` might grow without bound,
        // if we keep reconnecting to the same HS.
        data.retain(|k, _v| {
            usable_intros
                .iter()
                .any(|ipt| RelayIdForExperience::for_lookup(&ipt.intro_target).any(|id| &id == k))
        });

        // Join with existing state recording our experiences,
        // sort by descending goodness, and then randomly
        // (so clients without any experience don't all pile onto the same, first, IPT)
        usable_intros.sort_by_key(|ipt: &UsableIntroPt| {
            let experience =
                RelayIdForExperience::for_lookup(&ipt.intro_target).find_map(|id| data.get(&id));
            IptSortKey {
                outcome: experience.into(),
                sort_rand: ipt.sort_rand,
            }
        });
        self.mocks.test_got_ipts(&usable_intros);

        let mut intro_attempts = usable_intros.iter().cycle().take(max_total_attempts);

        // We retain a rendezvous we managed to set up in here.  That way if we created it, and
        // then failed before we actually needed it, we can reuse it.
        // If we exit with an error, we will waste it - but because we isolate things we do
        // for different services, it wouldn't be reusable anyway.
        let mut saved_rendezvous = None;

        // We might consider making multiple INTRODUCE attempts to different
        // IPTs in in parallel, and somehow aggregating the errors and
        // experiences.
        // However our HS experts don't consider that important:
        //   https://gitlab.torproject.org/tpo/core/arti/-/issues/913#note_2914438
        // Parallelizing our HsCircPool circuit building would likely have
        // greater impact. (See #1149.)
        loop {
            // When did we start doing things that depended on the IPT?
            //
            // Used for recording our experience with the selected IPT
            let mut ipt_use_started = None::<Instant>;

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
            let outcome = async {
                // We establish a rendezvous point first.  Although it appears from reading
                // this code that this means we serialise establishment of the rendezvous and
                // introduction circuits, this isn't actually the case.  The circmgr maintains
                // a pool of circuits.  What actually happens in the "standing start" case is
                // that we obtain a circuit for rendezvous from the circmgr's pool, expecting
                // one to be available immediately; the circmgr will then start to build a new
                // one to replenish its pool, and that happens in parallel with the work we do
                // here - but in arrears.  If the circmgr pool is empty, then we must wait.
                //
                // Perhaps this should be parallelised here.  But that's really what the pool
                // is for, since we expect building the rendezvous circuit and building the
                // introduction circuit to take about the same length of time.
                //
                // We *do* serialise the ESTABLISH_RENDEZVOUS exchange, with the
                // building of the introduction circuit.  That could be improved, at the cost
                // of some additional complexity here.
                //
                // Our HS experts don't consider it important to increase the parallelism:
                //   https://gitlab.torproject.org/tpo/core/arti/-/issues/913#note_2914444
                //   https://gitlab.torproject.org/tpo/core/arti/-/issues/913#note_2914445
                if saved_rendezvous.is_none() {
                    debug!("hs conn to {}: setting up rendezvous point", &self.hsid);
                    // Establish a rendezvous circuit.
                    let Some(_): Option<usize> = rend_attempts.next() else {
                        return Ok(None);
                    };

                    let mut using_rend_pt = None;
                    saved_rendezvous = Some(
                        self.runtime
                            .timeout(rend_timeout, self.establish_rendezvous(&mut using_rend_pt))
                            .await
                            .map_err(|_: TimeoutError| match using_rend_pt {
                                None => FAE::RendezvousCircuitObtain {
                                    error: tor_circmgr::Error::CircTimeout(None),
                                },
                                Some(rend_pt) => FAE::RendezvousEstablishTimeout { rend_pt },
                            })??,
                    );
                }

                let Some(ipt) = intro_attempts.next() else {
                    return Ok(None);
                };
                let intro_index = ipt.intro_index;

                // We record how long things take, starting from here, as
                // as a statistic we'll use for the IPT in future.
                // This is stored in a variable outside this async block,
                // so that the outcome handling can use it.
                ipt_use_started = Some(self.runtime.now());

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
                        intro_timeout,
                        self.exchange_introduce(ipt, &mut saved_rendezvous),
                    )
                    .await
                    .map_err(|_: TimeoutError| {
                        // The intro point ought to give us a prompt ACK regardless of HS
                        // behaviour or whatever is happening at the RPT, so blame the IPT.
                        FAE::IntroductionTimeout { intro_index }
                    })?
                    // TODO: Maybe try, once, to extend-and-reuse the intro circuit.
                    //
	            // If the introduction fails, the introduction circuit is in principle
                    // still usable.  We believe that in this case, C Tor extends the intro
	            // circuit by one hop to the next IPT to try.  That saves on building a
                    // whole new 3-hop intro circuit.  However, our HS experts tell us that
                    // if introduction fails at one IPT it is likely to fail at the others too,
                    // so that optimisation might reduce our network impact and time to failure,
                    // but isn't likely to improve our chances of success.
                    //
                    // However, it's not clear whether this approach risks contaminating
                    // the 2nd attempt with some fault relating to the introduction point.
                    // The 1st ipt might also gain more knowledge about which HS we're talking to.
                    //
                    // TODO SPEC: Discuss extend-and-reuse HS intro circuit after nack
                    ?;
                #[allow(unused_variables)] // it's *supposed* to be unused
                let saved_rendezvous = (); // don't use `saved_rendezvous` any more, use rendezvous

                let rend_pt = rend_pt_identity_for_error(&rendezvous.rend_relay);
                let circ = self
                    .runtime
                    .timeout(
                        rpt_ipt_timeout,
                        self.complete_rendezvous(ipt, rendezvous, introduced),
                    )
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
            .await;

            // Store the experience `outcome` we had with IPT `intro_index`, in `data`
            #[allow(clippy::unused_unit)] // -> () is here for error handling clarity
            let mut store_experience = |intro_index, outcome| -> () {
                (|| {
                    let ipt = usable_intros
                        .iter()
                        .find(|ipt| ipt.intro_index == intro_index)
                        .ok_or_else(|| internal!("IPT not found by index"))?;
                    let id = RelayIdForExperience::for_store(&ipt.intro_target)?;
                    let started = ipt_use_started.ok_or_else(|| {
                        internal!("trying to record IPT use but no IPT start time noted")
                    })?;
                    let duration = self
                        .runtime
                        .now()
                        .checked_duration_since(started)
                        .ok_or_else(|| internal!("clock overflow calculating IPT use duration"))?;
                    data.insert(id, IptExperience { duration, outcome });
                    Ok::<_, Bug>(())
                })()
                .unwrap_or_else(|e| warn_report!(e, "error recording HS IPT use experience"));
            };

            match outcome {
                Ok(Some((intro_index, y))) => {
                    // Record successful outcome in Data
                    store_experience(intro_index, Ok(()));
                    return Ok(y);
                }
                Ok(None) => return Err(CE::Failed(errors)),
                Err(error) => {
                    debug_report!(&error, "hs conn to {}: attempt failed", &self.hsid);
                    // Record error outcome in Data, if in fact we involved the IPT
                    // at all.  The IPT information is be retrieved from `error`,
                    // since only some of the errors implicate the introduction point.
                    if let Some(intro_index) = error.intro_index() {
                        store_experience(intro_index, Err(error.retry_time()));
                    }
                    errors.push(error);
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
    ) -> Result<Rendezvous<'c, R, M>, FAE> {
        let (rend_circ, rend_relay) = self
            .circpool
            .m_get_or_launch_client_rend(&self.netdir)
            .await
            .map_err(|error| FAE::RendezvousCircuitObtain { error })?;

        let rend_pt = rend_pt_identity_for_error(&rend_relay);
        *using_rend_pt = Some(rend_pt.clone());

        let rend_cookie: RendCookie = self.mocks.thread_rng().gen();
        let message = EstablishRendezvous::new(rend_cookie);

        let (rend_established_tx, rend_established_rx) = proto_oneshot::channel();
        let (rend2_tx, rend2_rx) = proto_oneshot::channel();

        /// Handler which expects `RENDEZVOUS_ESTABLISHED` and then
        /// `RENDEZVOUS2`.   Returns each message via the corresponding `oneshot`.
        struct Handler {
            /// Sender for a RENDEZVOUS_ESTABLISHED message.
            rend_established_tx: proto_oneshot::Sender<RendezvousEstablished>,
            /// Sender for a RENDEZVOUS2 message.
            rend2_tx: proto_oneshot::Sender<Rendezvous2>,
        }
        impl MsgHandler for Handler {
            fn handle_msg(
                &mut self,
                _conversation: ConversationInHandler<'_, '_, '_>,
                msg: AnyRelayMsg,
            ) -> Result<MetaCellDisposition, tor_proto::Error> {
                // The first message we expect is a RENDEZVOUS_ESTABALISHED.
                if self.rend_established_tx.still_expected() {
                    self.rend_established_tx
                        .deliver_expected_message(msg, MetaCellDisposition::Consumed)
                } else {
                    self.rend2_tx
                        .deliver_expected_message(msg, MetaCellDisposition::ConversationFinished)
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
            .m_start_conversation_last_hop(Some(message.into()), handler)
            .await
            .map_err(handle_proto_error)?;

        // `start_conversation` returns as soon as the control message has been sent.
        // We need to obtain the RENDEZVOUS_ESTABLISHED message, which is "returned" via the oneshot.
        let _: RendezvousEstablished = rend_established_rx.recv(handle_proto_error).await?;

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
    ) -> Result<(Rendezvous<'c, R, M>, Introduced<R, M>), FAE> {
        let intro_index = ipt.intro_index;

        debug!(
            "hs conn to {}: IPT {}: obtaining intro circuit",
            &self.hsid, intro_index,
        );

        let intro_circ = self
            .circpool
            .m_get_or_launch_specific(
                &self.netdir,
                HsCircKind::ClientIntro,
                ipt.intro_target.clone(), // &OwnedCircTarget isn't CircTarget apparently
            )
            .await
            .map_err(|error| FAE::IntroductionCircuitObtain { error, intro_index })?;

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

        /// Handler which expects just `INTRODUCE_ACK`
        struct Handler {
            /// Sender for `INTRODUCE_ACK`
            intro_ack_tx: proto_oneshot::Sender<IntroduceAck>,
        }
        impl MsgHandler for Handler {
            fn handle_msg(
                &mut self,
                _conversation: ConversationInHandler<'_, '_, '_>,
                msg: AnyRelayMsg,
            ) -> Result<MetaCellDisposition, tor_proto::Error> {
                self.intro_ack_tx
                    .deliver_expected_message(msg, MetaCellDisposition::ConversationFinished)
            }
        }
        let handle_intro_proto_error = |error| FAE::IntroductionExchange { error, intro_index };
        let (intro_ack_tx, intro_ack_rx) = proto_oneshot::channel();
        let handler = Handler { intro_ack_tx };

        debug!(
            "hs conn to {}: RPT {} IPT {}: making introduction - sending INTRODUCE1",
            &self.hsid,
            rend_pt.as_inner(),
            intro_index,
        );

        intro_circ
            .m_start_conversation_last_hop(Some(intro1_real.into()), handler)
            .await
            .map_err(handle_intro_proto_error)?;

        // Status is checked by `.success()`, and we don't look at the extensions;
        // just discard the known-successful `IntroduceAck`
        let _: IntroduceAck = intro_ack_rx
            .recv(handle_intro_proto_error)
            .await?
            .success()
            .map_err(|status| FAE::IntroductionFailed {
                status,
                intro_index,
            })?;

        debug!(
            "hs conn to {}: RPT {} IPT {}: making introduction - success",
            &self.hsid,
            rend_pt.as_inner(),
            intro_index,
        );

        // Having received INTRODUCE_ACK. we can forget about this circuit
        // (and potentially tear it down).
        drop(intro_circ);

        Ok((
            rendezvous,
            Introduced {
                handshake_state,
                marker: PhantomData,
            },
        ))
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
        introduced: Introduced<R, M>,
    ) -> Result<Arc<ClientCirc!(R, M)>, FAE> {
        use tor_proto::circuit::handshake;

        let rend_pt = rend_pt_identity_for_error(&rendezvous.rend_relay);
        let intro_index = ipt.intro_index;
        let handle_proto_error = |error| FAE::RendezvousCompletionCircuitError {
            error,
            intro_index,
            rend_pt: rend_pt.clone(),
        };

        debug!(
            "hs conn to {}: RPT {} IPT {}: awaiting rendezvous completion",
            &self.hsid,
            rend_pt.as_inner(),
            intro_index,
        );

        let rend2_msg: Rendezvous2 = rendezvous.rend2_rx.recv(handle_proto_error).await?;

        debug!(
            "hs conn to {}: RPT {} IPT {}: received RENDEZVOUS2",
            &self.hsid,
            rend_pt.as_inner(),
            intro_index,
        );

        // In theory would be great if we could have multiple introduction attempts in parallel
        // with similar x,X values but different IPTs.  However, our HS experts don't
        // think increasing parallelism here is important:
        //   https://gitlab.torproject.org/tpo/core/arti/-/issues/913#note_2914438
        let handshake_state = introduced.handshake_state;

        // Try to complete the cryptographic handshake.
        let keygen = handshake_state
            .client_receive_rend(rend2_msg.handshake_info())
            // If this goes wrong. either the onion service has mangled the crypto,
            // or the rendezvous point has misbehaved (that that is possible is a protocol bug),
            // or we have used the wrong handshake_state (let's assume that's not true).
            //
            // If this happens we'll go and try another RPT.
            .map_err(|error| FAE::RendezvousCompletionHandshake {
                error,
                intro_index,
                rend_pt: rend_pt.clone(),
            })?;

        let params = circparameters_from_netparameters(self.netdir.params());

        rendezvous
            .rend_circ
            .m_extend_virtual(
                handshake::RelayProtocol::HsV3,
                handshake::HandshakeRole::Initiator,
                keygen,
                params,
            )
            .await
            .map_err(into_internal!(
                "actually this is probably a 'circuit closed' error" // TODO HS
            ))?;

        debug!(
            "hs conn to {}: RPT {} IPT {}: HS circuit established",
            &self.hsid,
            rend_pt.as_inner(),
            intro_index,
        );

        Ok(rendezvous.rend_circ)
    }

    /// Helper to estimate a timeout for a complicated operation
    ///
    /// `actions` is a list of `(count, action)`, where each entry
    /// represents doing `action`, `count` times sequentially.
    ///
    /// Combines the timeout estimates and returns an overall timeout.
    fn estimate_timeout(&self, actions: &[(u32, TimeoutsAction)]) -> Duration {
        // This algorithm is, perhaps, wrong.  For uncorrelated variables, a particular
        // percentile estimate for a sum of random variables, is not calculated by adding the
        // percentile estimates of the individual variables.
        //
        // But the actual lengths of times of the operations aren't uncorrelated.
        // If they were *perfectly* correlated, then this addition would be correct.
        // It will do for now; it just might be rather longer than it ought to be.
        actions
            .iter()
            .map(|(count, action)| {
                self.circpool
                    .m_estimate_timeout(action)
                    .saturating_mul(*count)
            })
            .fold(Duration::ZERO, Duration::saturating_add)
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
    fn test_got_desc(&self, _: &HsDesc) {}
    /// Tell tests we got this circuit
    fn test_got_circ(&self, _: &Arc<ClientCirc!(R, Self)>) {}
    /// Tell tests we have obtained and sorted the intros like this
    fn test_got_ipts(&self, _: &[UsableIntroPt]) {}

    /// Return a random number generator
    fn thread_rng(&self) -> Self::Rng;
}
/// Mock for `HsCircPool`
///
/// Methods start with `m_` to avoid the following problem:
/// `ClientCirc::start_conversation` (say) means
/// to use the inherent method if one exists,
/// but will use a trait method if there isn't an inherent method.
///
/// So if the inherent method is renamed, the call in the impl here
/// turns into an always-recursive call.
/// This is not detected by the compiler due to the situation being
/// complicated by futures, `#[async_trait]` etc.
/// <https://github.com/rust-lang/rust/issues/111177>
#[async_trait]
trait MockableCircPool<R> {
    /// Client circuit
    type ClientCirc: MockableClientCirc;
    async fn m_get_or_launch_specific(
        &self,
        netdir: &NetDir,
        kind: HsCircKind,
        target: impl CircTarget + Send + Sync + 'async_trait,
    ) -> tor_circmgr::Result<Arc<Self::ClientCirc>>;

    /// Client circuit
    async fn m_get_or_launch_client_rend<'a>(
        &self,
        netdir: &'a NetDir,
    ) -> tor_circmgr::Result<(Arc<Self::ClientCirc>, Relay<'a>)>;

    /// Estimate timeout
    fn m_estimate_timeout(&self, action: &TimeoutsAction) -> Duration;
}
/// Mock for `ClientCirc`
#[async_trait]
trait MockableClientCirc: Debug {
    /// Client circuit
    type DirStream: AsyncRead + AsyncWrite + Send + Unpin;
    async fn m_begin_dir_stream(self: Arc<Self>) -> tor_proto::Result<Self::DirStream>;

    /// Converse
    async fn m_start_conversation_last_hop(
        &self,
        msg: Option<AnyRelayMsg>,
        reply_handler: impl MsgHandler + Send + 'static,
    ) -> tor_proto::Result<Self::Conversation<'_>>;
    /// Conversation
    type Conversation<'r>
    where
        Self: 'r;

    /// Add a virtual hop to the circuit.
    async fn m_extend_virtual(
        &self,
        protocol: tor_proto::circuit::handshake::RelayProtocol,
        role: tor_proto::circuit::handshake::HandshakeRole,
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
    async fn m_get_or_launch_specific(
        &self,
        netdir: &NetDir,
        kind: HsCircKind,
        target: impl CircTarget + Send + Sync + 'async_trait,
    ) -> tor_circmgr::Result<Arc<ClientCirc>> {
        HsCircPool::get_or_launch_specific(self, netdir, kind, target).await
    }
    async fn m_get_or_launch_client_rend<'a>(
        &self,
        netdir: &'a NetDir,
    ) -> tor_circmgr::Result<(Arc<ClientCirc>, Relay<'a>)> {
        HsCircPool::get_or_launch_client_rend(self, netdir).await
    }
    fn m_estimate_timeout(&self, action: &TimeoutsAction) -> Duration {
        HsCircPool::estimate_timeout(self, action)
    }
}
#[async_trait]
impl MockableClientCirc for ClientCirc {
    /// Client circuit
    type DirStream = tor_proto::stream::DataStream;
    async fn m_begin_dir_stream(self: Arc<Self>) -> tor_proto::Result<Self::DirStream> {
        ClientCirc::begin_dir_stream(self).await
    }
    async fn m_start_conversation_last_hop(
        &self,
        msg: Option<AnyRelayMsg>,
        reply_handler: impl MsgHandler + Send + 'static,
    ) -> tor_proto::Result<Self::Conversation<'_>> {
        let last_hop = self.last_hop_num()?;
        ClientCirc::start_conversation(self, msg, reply_handler, last_hop).await
    }
    type Conversation<'r> = tor_proto::circuit::Conversation<'r>;

    async fn m_extend_virtual(
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
        config: Arc<Config>,
        hsid: HsId,
        data: &mut Self,
        secret_keys: HsClientSecretKeys,
    ) -> Result<Arc<Self::ClientCirc>, ConnError> {
        connect(connector, netdir, config, hsid, data, secret_keys).await
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
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    #![allow(dead_code, unused_variables)] // TODO HS TESTS delete, after tests are completed

    use super::*;
    use crate::*;
    use futures::FutureExt as _;
    use std::ops::{Bound, RangeBounds};
    use std::{iter, panic::AssertUnwindSafe};
    use tokio_crate as tokio;
    use tor_async_utils::JoinReadWrite;
    use tor_basic_utils::test_rng::{testing_rng, TestingRng};
    use tor_hscrypto::pk::{HsClientDescEncKey, HsClientDescEncKeypair};
    use tor_llcrypto::pk::curve25519;
    use tor_netdoc::doc::{hsdesc::test_data, netstatus::Lifetime};
    use tor_rtcompat::tokio::TokioNativeTlsRuntime;
    use tor_rtcompat::RuntimeSubstExt as _;
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

        fn test_got_ipts(&self, desc: &[UsableIntroPt]) {}

        fn thread_rng(&self) -> Self::Rng {
            testing_rng()
        }
    }
    #[allow(clippy::diverging_sub_expression)] // async_trait + todo!()
    #[async_trait]
    impl<R: Runtime> MockableCircPool<R> for Mocks<()> {
        type ClientCirc = Mocks<()>;
        async fn m_get_or_launch_specific(
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
        async fn m_get_or_launch_client_rend<'a>(
            &self,
            netdir: &'a NetDir,
        ) -> tor_circmgr::Result<(Arc<ClientCirc!(R, Self)>, Relay<'a>)> {
            todo!()
        }

        fn m_estimate_timeout(&self, action: &TimeoutsAction) -> Duration {
            Duration::from_secs(10)
        }
    }
    #[allow(clippy::diverging_sub_expression)] // async_trait + todo!()
    #[async_trait]
    impl MockableClientCirc for Mocks<()> {
        type DirStream = JoinReadWrite<futures::io::Cursor<Box<[u8]>>, futures::io::Sink>;
        type Conversation<'r> = &'r ();
        async fn m_begin_dir_stream(self: Arc<Self>) -> tor_proto::Result<Self::DirStream> {
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
        async fn m_start_conversation_last_hop(
            &self,
            msg: Option<AnyRelayMsg>,
            reply_handler: impl MsgHandler + Send + 'static,
        ) -> tor_proto::Result<Self::Conversation<'_>> {
            todo!()
        }

        async fn m_extend_virtual(
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
        let runtime = runtime
            .with_sleep_provider(mock_sp.clone())
            .with_coarse_time_provider(mock_sp);
        let time_period = netdir.hs_time_period();

        let mglobal = Arc::new(Mutex::new(MocksGlobal::default()));
        let mocks = Mocks { mglobal, id: () };
        // From C Tor src/test/test_hs_common.c test_build_address
        let hsid = test_data::TEST_HSID_2.into();
        let mut data = Data::default();

        let pk: HsClientDescEncKey = curve25519::PublicKey::from(test_data::TEST_PUBKEY_2).into();
        let sk = curve25519::StaticSecret::from(test_data::TEST_SECKEY_2).into();
        let mut secret_keys_builder = HsClientSecretKeysBuilder::default();
        secret_keys_builder.ks_hsc_desc_enc(HsClientDescEncKeypair::new(pk.clone(), sk));
        let secret_keys = secret_keys_builder.build().unwrap();

        let ctx = Context::new(
            &runtime,
            &mocks,
            netdir,
            Default::default(),
            hsid,
            secret_keys,
            mocks.clone(),
        )
        .unwrap();

        let _got = AssertUnwindSafe(ctx.connect(&mut data))
            .catch_unwind() // TODO HS TESTS: remove this and the AssertUnwindSafe
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
            Some(&HsClientDescEncKeypair::new(pk, sk)),
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

        // TODO HS TESTS: check the circuit in got is the one we gave out

        // TODO HS TESTS: continue with this
    }

    // TODO HS TESTS: Test IPT state management and expiry:
    //   - obtain a test descriptor with only a broken ipt
    //     (broken in the sense that intro can be attempted, but will fail somehow)
    //   - try to make a connection and expect it to fail
    //   - assert that the ipt data isn't empty
    //   - cause the descriptor to expire (advance clock)
    //   - start using a mocked RNG if we weren't already and pin its seed here
    //   - make a new descriptor with two IPTs: the broken one from earlier, and a new one
    //   - make a new connection
    //   - use test_got_ipts to check that the random numbers
    //     would sort the bad intro first, *and* that the good one is appears first
    //   - assert that connection succeeded
    //   - cause the circuit and descriptor to expire (advance clock)
    //   - go back to the previous descriptor contents, but with a new validity period
    //   - try to make a connection
    //   - use test_got_ipts to check that only the broken ipt is present

    // TODO HS TESTS: test retries (of every retry loop we have here)
    // TODO HS TESTS: test error paths
}
