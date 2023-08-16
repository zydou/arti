//! IPT Establisher
//!
//! Responsible for maintaining and establishing one introduction point.
//!
//! TODO HSS: move docs from `hssvc-ipt-algorithm.md`

#![allow(clippy::needless_pass_by_value)] // TODO HSS remove

use std::{sync::Arc, time::Duration};

use futures::{
    channel::{
        mpsc::{self, UnboundedReceiver},
        oneshot,
    },
    StreamExt as _,
};
use tor_cell::relaycell::{
    hs::est_intro::{self, EstablishIntroDetails},
    msg::{AnyRelayMsg, IntroEstablished, Introduce2},
    RelayMsg as _,
};
use tor_circmgr::hspool::HsCircPool;
use tor_error::{debug_report, internal, into_internal};
use tor_hscrypto::pk::HsIntroPtSessionIdKeypair;
use tor_linkspec::{ChanTarget as _, OwnedCircTarget};
use tor_netdir::{NetDir, NetDirProvider, Relay};
use tor_proto::circuit::{ClientCirc, ConversationInHandler, MetaCellDisposition};
use tor_rtcompat::{Runtime, SleepProviderExt as _};
use tracing::debug;

use crate::RendRequest;

/// Handle onto the task which is establishing and maintaining one IPT
pub(crate) struct IptEstablisher {
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
        todo!()
    }
}

/// An error from trying to work with an IptEstablisher.
#[derive(Clone, Debug, thiserror::Error)]
pub(crate) enum IptError {
    /// We couldn't get a network directory to use when building circuits.
    #[error("No network directory available")]
    NoNetdir(#[source] tor_netdir::Error),

    /// The network directory provider is shutting down without giving us the
    /// netdir we asked for.
    #[error("Network directory provider is shutting down")]
    NetdirProviderShutdown,

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
            E::NoNetdir(_) => EK::BootstrapRequired, // TODO HSS maybe not right.
            E::NetdirProviderShutdown => EK::ArtiShuttingDown,
            E::BuildCircuit(e) => e.kind(),
            E::EstablishTimeout => EK::TorNetworkTimeout, // TODO HSS right?
            E::SendEstablishIntro(e) => e.kind(),
            E::ReceiveAck => EK::RemoteProtocolViolation, // TODO HSS not always right.
            E::BadEstablished => EK::RemoteProtocolViolation,
            E::CreateEstablishIntro(_) => EK::Internal,
            E::Bug(e) => e.kind(),
        }
    }
}

impl IptError {
    /// Return true if this error appears to be the introduction point's fault.
    fn is_ipt_failure(&self) -> bool {
        // TODO HSS: actually test something here.
        true
    }
}

impl IptEstablisher {
    /// Try to set up, and maintain, an IPT at `Relay`
    ///
    /// Rendezvous requests will be rejected
    ///
    /// Also returns
    /// a stream of events that is produced whenever we have a change in the
    /// IptStatus for this intro point.  Note that this stream is potentially
    /// lossy.
    pub(crate) fn new<R: Runtime>(
        circ_pool: Arc<HsCircPool<R>>,
        dirprovider: Arc<dyn NetDirProvider>,
        relay: &Relay<'_>,
        // TODO HSS: this needs to take some configuration
    ) -> Result<(Self, postage::watch::Receiver<IptStatus>), IptError> {
        todo!()
    }

    /// Begin accepting connections from this introduction point.
    //
    // TODO HSS: Perhaps we want to provide rend_reqs as part of the
    // new() API instead.  If we do, we must make sure there's a way to
    // turn requests on and off, so that we can say "now we have advertised this
    // so requests are okay."
    pub(crate) fn start_accepting(&self, rend_reqs: mpsc::Sender<RendRequest>) {
        todo!()
    }
}

/// The current status of an introduction point, as defined in
/// `hssvc-ipt-algorithms.md`.
///
/// TODO HSS Make that file unneeded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum IptStatusStatus {
    /// We are (re)establishing our connection to the IPT
    ///
    /// But we don't think there's anything wrong with it.
    Establishing,

    /// The IPT is established and ready to accept rendezvous requests
    Good,

    /// We don't have the IPT and it looks like it was the IPT's fault
    Faulty,
}

/// `Err(IptWantsToRetire)` indicates that the IPT Establisher wants to retire this IPT
///
/// This happens when the IPT has had (too) many rendezvous requests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IptWantsToRetire;

/// The current status of an introduction point.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IptStatus {
    /// The current state of this introduction point as defined by
    /// `hssvc-ipt-algorithms.md`.
    ///
    /// TODO HSS Make that file unneeded.
    pub(crate) status: IptStatusStatus,

    /// How many times have we transitioned into a Faulty state?
    ///
    /// (This is not the same as the total number of failed attempts, since it
    /// does not count times we retry from a Faulty state.)
    pub(crate) n_faults: u32,

    /// The current status of whether this introduction point circuit wants to be
    /// retired based on having processed too many requests.
    pub(crate) wants_to_retire: Result<(), IptWantsToRetire>,
}

impl IptStatus {
    /// Record that we have successfully connected to an introduction point.
    fn note_open(&mut self) {
        self.status = IptStatusStatus::Good;
    }

    /// Record that we are trying to connect to an introduction point.
    fn note_attempt(&mut self) {
        use IptStatusStatus::*;
        self.status = match self.status {
            Establishing | Good => Establishing,
            Faulty => Faulty, // We don't change status if we think we're broken.
        }
    }

    /// Record that an error has occurred.
    fn note_error(&mut self, err: &IptError) {
        use IptStatusStatus::*;
        if err.is_ipt_failure() && self.status == Good {
            self.n_faults += 1;
            self.status = Faulty;
        }
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
    /// A pool used to create circuits to the introduction point.
    pool: Arc<HsCircPool<R>>,
    /// A provider used to select the other relays in the circuit.
    netdir_provider: Arc<dyn NetDirProvider>,
    /// The target introduction point.
    ///
    /// TODO: Should this instead be an identity that we look up in the netdir
    /// provider?
    target: OwnedCircTarget,
    /// The keypair to use when establishing the introduction point.
    ///
    /// Knowledge of this private key prevents anybody else from impersonating
    /// us to the introduction point.
    ipt_sid_keypair: HsIntroPtSessionIdKeypair,
    /// The extensions to use when establishing the introduction point.
    ///
    /// TODO: Should this be able to change over time if we re-establish this
    /// intro point?
    extensions: EstIntroExtensionSet,
}

/// An open session with a single introduction point.
//
// TODO: I've used Ipt and IntroPt in this module; maybe we shouldn't.
pub(crate) struct IntroPtSession {
    /// The circuit to the introduction point, on which we're receiving
    /// Introduce2 messages.
    intro_circ: Arc<ClientCirc>,

    /// The stream that will receive Introduce2 messages.
    ///
    /// TODO: we'll likely want to refactor this.  @diziet favors having
    /// `establish_intro_once` take a Sink as an argument, but I think that we
    /// may need to keep this separate so that we can keep the ability to
    /// start/stop the stream of Introduce2 messages, and/or detect when it's
    /// closed.  If we don't need to do that, we can refactor.
    introduce_rx: UnboundedReceiver<Introduce2>,
    // TODO HSS: How shall we know if the other side has closed the circuit?  We
    // can either wait for introduce_rx to close, or we can use
    // ClientCirc::wait_for_close, if we stabilize it.
}

/// How long to allow for an introduction point to get established?
const ESTABLISH_TIMEOUT: Duration = Duration::new(10, 0); // TODO use a better timeout, taken from circuit estimator.

/// How long to wait after a single failure.
const DELAY_ON_FAILURE: Duration = Duration::new(2, 0); // TODO use stochastic jitter.

impl<R: Runtime> Reactor<R> {
    /// Run forever, keeping an introduction point established.
    ///
    /// TODO: If we're running this in its own task, we'll want some way to
    /// cancel it.
    async fn keep_intro_established(
        &self,
        mut status_tx: postage::watch::Sender<IptStatus>,
    ) -> Result<(), IptError> {
        loop {
            status_tx.borrow_mut().note_attempt();
            let outcome = self
                .runtime
                .timeout(ESTABLISH_TIMEOUT, self.establish_intro_once())
                .await
                .unwrap_or(Err(IptError::EstablishTimeout));

            match self.establish_intro_once().await {
                Ok(session) => {
                    status_tx.borrow_mut().note_open();
                    debug!(
                        "Successfully established introduction point with {}",
                        self.target.display_chan_target()
                    );

                    // TODO HSS: let session continue until it dies, actually
                    // implementing it.
                }
                Err(e) => {
                    status_tx.borrow_mut().note_error(&e);
                    debug_report!(
                        e,
                        "Problem establishing introduction point with {}",
                        self.target.display_chan_target()
                    );
                    self.runtime.sleep(DELAY_ON_FAILURE).await;
                }
            }
        }
    }

    /// Try, once, to make a circuit to a single relay and establish an introduction
    /// point there.
    ///
    /// Does not retry.  Does not time out except via `HsCircPool`.
    async fn establish_intro_once(&self) -> Result<IntroPtSession, IptError> {
        let circuit = {
            let netdir = wait_for_netdir(
                self.netdir_provider.as_ref(),
                tor_netdir::Timeliness::Timely,
            )
            .await?;
            let kind = tor_circmgr::hspool::HsCircKind::SvcIntro;
            self.pool
                .get_or_launch_specific(netdir.as_ref(), kind, self.target.clone())
                .await
                .map_err(IptError::BuildCircuit)?
            // note that netdir is dropped here, to avoid holding on to it any
            // longer than necessary.
        };
        let intro_pt_hop = circuit
            .last_hop_num()
            .map_err(into_internal!("Somehow built a circuit with no hops!?"))?;

        let establish_intro = {
            let ipt_sid_id = self.ipt_sid_keypair.as_ref().public.into();
            let mut details = EstablishIntroDetails::new(ipt_sid_id);
            if let Some(dos_params) = &self.extensions.dos_params {
                details.set_extension_dos(dos_params.clone());
            }
            let circuit_binding_key = circuit
                .binding_key(intro_pt_hop)
                .ok_or(internal!("No binding key for introduction point!?"))?;
            let body: Vec<u8> = details
                .sign_and_encode(self.ipt_sid_keypair.as_ref(), circuit_binding_key.hs_mac())
                .map_err(IptError::CreateEstablishIntro)?;

            // TODO HSS: This is ugly, but it is the sensible way to munge the above
            // body into a format that AnyRelayCell will accept without doing a
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
        let (introduce_tx, introduce_rx) = mpsc::unbounded();

        let handler = IptMsgHandler {
            established_tx: Some(established_tx),
            introduce_tx,
        };
        let conversation = circuit
            .start_conversation(Some(establish_intro), handler, intro_pt_hop)
            .await
            .map_err(IptError::SendEstablishIntro)?;
        // At this point, we have `await`ed for the Conversation to exist, so we know
        // that the message was sent.  We have to wait for any actual `established`
        // message, though.

        let established = established_rx.await.map_err(|_| IptError::ReceiveAck)?;

        if established.iter_extensions().next().is_some() {
            // We do not support any extensions from the introduction point; if it
            // sent us any, that's a protocol violation.
            return Err(IptError::BadEstablished);
        }

        Ok(IntroPtSession {
            intro_circ: circuit,
            introduce_rx,
        })
    }
}

/// Get a NetDir from `provider`, waiting until one exists.
///
/// TODO: perhaps this function would be more generally useful if it were not here?
async fn wait_for_netdir(
    provider: &dyn NetDirProvider,
    timeliness: tor_netdir::Timeliness,
) -> Result<Arc<NetDir>, IptError> {
    if let Ok(nd) = provider.netdir(timeliness) {
        return Ok(nd);
    }

    let mut stream = provider.events();
    loop {
        // We need to retry `provider.netdir()` before waiting for any stream events, to
        // avoid deadlock.
        //
        // TODO HSS: propagate _some_ possible errors here.
        if let Ok(nd) = provider.netdir(timeliness) {
            return Ok(nd);
        }
        match stream.next().await {
            Some(_) => {}
            None => {
                return Err(IptError::NetdirProviderShutdown);
            }
        }
    }
}

/// MsgHandler type to implement a conversation with an introduction point.
///
/// This, like all MsgHandlers, is installed at the circuit's reactor, and used
/// to handle otherwise unrecognized message types.
#[derive(Debug)]
struct IptMsgHandler {
    /// A oneshot sender used to report our IntroEstablished message.
    ///
    /// If this is None, then we already sent an IntroEstablished and we shouldn't
    /// send any more.
    established_tx: Option<oneshot::Sender<IntroEstablished>>,
    /// A channel used to report Introduce2 messages.
    //
    // TODO HSS: I don't like having this be unbounded, but `handle_msg` can't
    // block.  On the other hand maybe we can just discard excessive introduce2
    // messages if we're under high load?  I think that's what C tor does,
    // especially when under DoS conditions.
    //
    // See discussion at
    // https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1465#note_2928349
    introduce_tx: mpsc::UnboundedSender<Introduce2>,
}

impl tor_proto::circuit::MsgHandler for IptMsgHandler {
    fn handle_msg(
        &mut self,
        conversation: ConversationInHandler<'_, '_, '_>,
        any_msg: AnyRelayMsg,
    ) -> tor_proto::Result<MetaCellDisposition> {
        // TODO HSS: Implement rate-limiting.
        //
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
                self.introduce_tx.unbounded_send(introduce2).map_err(|_| ())
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
