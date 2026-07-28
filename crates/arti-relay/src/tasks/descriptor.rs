//! Relay descriptor publishing task.
//!
//! This task is responsible for building our relay descriptor and uploading it to the directory
//! authorities using [`tor_dirpublish`].
//!
//! It is driven by two sources of input:
//!   * When receiving a [`DescriptorCommand`]. For instance, the crypto task
//!     ([`crate::tasks::crypto`]) will send a [`DescriptorCommand::Publish`] when at least
//!     one of the relay keys changes. It triggers a rebuild and publish of the relay descriptor.
//!   * Consensus events from the [`NetDirProvider`], so that we can pick up new consensus
//!     parameters when a new consensus arrives.
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use futures::channel::mpsc;
use futures::{StreamExt as _, select_biased};
use tracing::{debug, trace};

use tor_async_utils::{mpsc_channel_no_memquota, oneshot};
use tor_dirclient::request::{Requestable, UploadRouterDesc};
use tor_dircommon::authority::AuthorityContacts;
use tor_dirpublish::{Publisher, http::DirectHttpUploader};
use tor_netdir::{DirEvent, NetDirProvider};
use tor_rtcompat::Runtime;

use crate::tasks::crypto::{CryptoCommand, CryptoCommandSender};

/// Initial delay before retrying a failed descriptor upload.
///
/// This is simply the initial delay then the [`tor_dirpublish::Publisher`] has its back off
/// algorithm seeded with this value.
const INITIAL_RETRY_DELAY: Duration = Duration::from_secs(60);

/// A command sent to the [`RelayDescriptorPublisherTask`] over its control channel.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub(crate) enum DescriptorCommand {
    /// Rebuild the relay descriptor and publish it to the directory authorities. This
    /// task asks the crypto task for the latest known identities/keys in order to
    /// rebuild a new descriptor.
    Publish,
}

/// The sending side of the [`DescriptorCommand`] channel.
pub(crate) type DescriptorCommandSender = mpsc::Sender<DescriptorCommand>;

/// The receiving side of the [`DescriptorCommand`] channel.
pub(crate) type DescriptorCommandReceiver = mpsc::Receiver<DescriptorCommand>;

/// Returns a new [`DescriptorCommand`] channel.
///
/// This is a bounded to limit descriptor publication spamming (in case of a bug).
pub(crate) fn new_command_channel() -> (DescriptorCommandSender, DescriptorCommandReceiver) {
    // TODO(relay): We might want to make those memquota actually?
    mpsc_channel_no_memquota(16)
}

/// Background task that builds and publishes the relay's descriptor.
pub(crate) struct RelayDescriptorPublisherTask {
    /// Directory provider, used to learn about new consensus documents and parameters.
    netdir: Arc<dyn NetDirProvider>,

    /// The directory authorities we upload our descriptor to.
    ///
    /// This is either from the config file or the compiled-in default list.
    authorities: AuthorityContacts,

    /// Channel on which we receive [`DescriptorCommand`]s from other tasks.
    command_rx: DescriptorCommandReceiver,

    /// The [`tor_dirpublish`] publisher that manages uploads to all targets.
    publisher: Arc<Publisher<dyn Requestable, Vec<SocketAddr>>>,

    /// The crypto task sender channel.
    crypto_tx: CryptoCommandSender,
}

impl RelayDescriptorPublisherTask {
    /// Construct a new descriptor publisher task.
    ///
    /// This launches the underlying [`tor_dirpublish`] publisher (which spawns its own reactor),
    /// but does not start listening for commands or consensus events until start() is called.
    ///
    /// The publisher reactor won't try to upload until the
    /// [`tor_dirpublish::Publisher::set_document`] is called.
    pub(crate) fn new<R: Runtime>(
        runtime: &R,
        netdir: Arc<dyn NetDirProvider>,
        authorities: AuthorityContacts,
        crypto_tx: CryptoCommandSender,
        command_rx: DescriptorCommandReceiver,
    ) -> anyhow::Result<Self> {
        let uploader = Arc::new(DirectHttpUploader::new(runtime.clone()));

        // We start with no document and no targets. Both are populated once we build a descriptor.
        // This way we catch any new directory authorities showing up in the config or consensus.
        let publisher = Publisher::launch(
            runtime,
            "relay descriptor".to_string(),
            /* initial_document=*/ None,
            /* initial_targets=*/ HashSet::new(),
            INITIAL_RETRY_DELAY,
            uploader,
        )
        .context("Failed to launch descriptor publisher")?;

        Ok(Self {
            netdir,
            authorities,
            command_rx,
            publisher,
            crypto_tx,
        })
    }

    /// Build the relay's descriptor document as ready to be uploaded.
    ///
    /// Returns `None` if we don't have everything we need to build a descriptor.
    #[allow(clippy::unused_async)] // TODO(relay): remove once used.
    async fn build_descriptor(&mut self) -> anyhow::Result<Option<Arc<str>>> {
        // TODO(relay): No relay desc encoding support yet from tor-netdoc.
        //
        // Once encoding exists, this should:
        //   * encode and sign the descriptor,

        // Get the latest ntor key (onion key) from the crypto task.
        let (tx, rx) = oneshot::channel();
        self.crypto_tx
            .try_send(CryptoCommand::GetLatestNtorKey { tx })
            .context("Crypto task try_send failed")?;
        let _ntor_key = rx.await.context("Unable to get ntor key")?;

        // Get the relay signing key from the crypto task.
        let (tx, rx) = oneshot::channel();
        self.crypto_tx
            .try_send(CryptoCommand::GetSignKey { tx })
            .context("Crypto task try_send failed")?;
        let _relay_sign_kp = rx.await.context("Unable to get relay sign keypair")?;

        // Keep the publisher idle until descriptor encoding is implemented.
        Ok(None)
    }

    /// Recompute the set of directory authorities we upload to.
    ///
    /// Each authority becomes one target, carrying all of its upload addresses so the
    /// [`DirectHttpUploader`] can try them in turn.
    ///
    /// Returns an empty set if we somehow have no authorities at all.
    fn compute_targets(&self) -> HashSet<Vec<SocketAddr>> {
        // This should never be empty because we have compiled in authorities by default.
        // If that case ever happens, the publisher will just do nothing.
        //
        // TODO(relay): We have to check those against our relay capabilities as in if we
        // support IPv6 or if we have an IPv4. For now, we pass all targets and let any
        // failures be handled at the connect() attempt.
        self.authorities
            .uploads()
            .iter()
            .filter(|&addrs| !addrs.is_empty())
            .cloned()
            .collect()
    }

    /// Rebuild the descriptor (and refresh targets) and hand it to the publisher.
    async fn rebuild_and_publish(&mut self) -> anyhow::Result<()> {
        // Adjust the targets onto our publisher if we have any targets. An empty set
        // means something has gone wrong somehow so don't touch the publisher in an
        // attempt to use what was there before.
        let targets = self.compute_targets();
        if !targets.is_empty() {
            let targets = targets.into_iter().map(Arc::new).collect();
            self.publisher.adjust_targets(|t| *t = targets);
        }

        // Get the latest descriptor.
        let desc = self
            .build_descriptor()
            .await
            .context("Failed to build relay descriptor")?;
        // Turn the encoded descriptor into a request and erase its concrete type for the
        // generic HTTP publisher.
        let doc = desc.map(|desc| Arc::new(UploadRouterDesc::new(desc)) as Arc<dyn Requestable>);

        // Tell the publisher to publish the new document. Failing to build the descriptor, as in a
        // None value, will make the publisher wait and do nothing.
        self.publisher.set_document(doc, false);
        Ok(())
    }

    /// Start the task.
    ///
    /// This runs forever. It listens for [`DescriptorCommand`] and consensus events.
    pub(crate) async fn start(mut self) -> anyhow::Result<void::Void> {
        debug!("Starting Relay descriptor publisher task");

        // Subscribe before the first run so we don't miss any events that arrive between
        // startup and entering the select loop.
        let mut consensus_events = self
            .netdir
            .events()
            .filter(|ev| std::future::ready(matches!(ev, DirEvent::NewConsensus)))
            .fuse();

        // Do an initial build now, in case we already have a consensus.
        self.rebuild_and_publish()
            .await
            .context("Failed initial descriptor publish")?;

        loop {
            select_biased! {
                command = self.command_rx.next() => {
                    let command = command
                        .context("descriptor command channel closed unexpectedly")?;
                    trace!(?command, "Descriptor publisher received command");
                    match command {
                        DescriptorCommand::Publish => {
                            self.rebuild_and_publish()
                                .await
                                .context("Failed to publish descriptor on command")?;
                        }
                    }
                }
                event = consensus_events.next() => {
                    let _event = event
                        .context("netdir consensus event stream ended unexpectedly")?;
                    trace!("Descriptor publisher task saw new consensus. Rebuilding and publishing.");
                    self.rebuild_and_publish()
                        .await
                        .context("Failed to publish descriptor on new consensus")?;
                }
                // TODO(relay)
                //
                // Here are the other conditions documented in the spec for when we
                // upload a new descriptor:
                // https://spec.torproject.org/dir-spec/uploading-relay-documents.html
                //
                //  - A period of time (18 hrs by default) has passed since the last
                //  upload.
                //  - A descriptor field other than bandwidth or uptime has changed.
                //  Its uptime is less than 24h and bandwidth has changed by a factor of
                //  2 from the last time a descriptor was generated, and at least a given
                //  interval of time (3 hours by default) has passed since then.
                //  - Its uptime has been reset (by restarting).
                //  - It receives a networkstatus consensus in which it is not listed.
                //  - It receives a networkstatus consensus in which it is listed with
                //  the StaleDesc flag.
            }
        }
    }
}
