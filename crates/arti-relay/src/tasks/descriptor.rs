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
use async_trait::async_trait;
use futures::channel::mpsc;
use futures::{StreamExt as _, select_biased};
use tracing::{debug, trace};

use tor_dirpublish::{Publisher, UploadError, Uploader};
use tor_netdir::{DirEvent, NetDirProvider};
use tor_rtcompat::Runtime;

/// Initial delay before retrying a failed descriptor upload.
///
/// This is simply the initial delay then the [`tor_dirpublish::Publisher`] has its back off
/// algorithm seeded with this value.
const INITIAL_RETRY_DELAY: Duration = Duration::from_secs(60);

/// Type alias representing Relay descriptor document.
///
/// It is a flat string as when we encode a descriptor, that is what we get.
pub(crate) type RelayDescDocument = String;

/// A directory authority we upload our descriptor to.
///
/// This holds the upload endpoint, DirPort, of a single logical authority. There may be
/// an IPv4 or/and IPv6.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct DirAuthorityTarget {
    /// The upload (DirPort) socket addresses of this authority, possibly dual-stack.
    // TODO(relay): remove once used.
    #[allow(dead_code)]
    addrs: Vec<SocketAddr>,
}

/// A command sent to the [`RelayDescriptorPublisherTask`] over its control channel.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub(crate) enum DescriptorCommand {
    /// Rebuild the relay descriptor and publish it to the directory authorities.
    // TODO(relay): constructed once the crypto task is wired up to send commands.
    #[allow(dead_code)]
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
    mpsc::channel(16)
}

/// The [`Uploader`] used to deliver our descriptor to a directory authority.
struct RelayDescUploader<R: Runtime> {
    #[allow(dead_code)] // TODO(relay): used once upload() is implemented
    runtime: R,
}

#[async_trait]
impl<R: Runtime> Uploader for RelayDescUploader<R> {
    type Doc = RelayDescDocument;
    type Target = DirAuthorityTarget;

    async fn upload(
        self: Arc<Self>,
        _target: Arc<Self::Target>,
        _document: Arc<Self::Doc>,
    ) -> Result<(), UploadError> {
        // TODO(relay): upload the descriptor to the target which should be a dirauth.
        //
        // This should:
        //   * open a directory connection/circuit to target,
        //   * POST the encoded descriptor document,
        todo!("descriptor upload not yet implemented");
    }
}

/// Background task that builds and publishes the relay's descriptor.
pub(crate) struct RelayDescriptorPublisherTask<R: Runtime> {
    /// Asynchronous runtime object.
    // TODO(relay): used once we build circuits/connections to upload the descriptor.
    #[allow(dead_code)]
    runtime: R,

    /// Directory provider, used to learn about new consensus documents and parameters.
    netdir: Arc<dyn NetDirProvider>,

    /// Channel on which we receive [`DescriptorCommand`]s from other tasks.
    command_rx: DescriptorCommandReceiver,

    /// The [`tor_dirpublish`] publisher that manages uploads to all targets.
    publisher: Arc<Publisher<RelayDescDocument, DirAuthorityTarget>>,
}

impl<R: Runtime> RelayDescriptorPublisherTask<R> {
    /// Construct a new descriptor publisher task.
    ///
    /// This launches the underlying [`tor_dirpublish`] publisher (which spawns its own reactor),
    /// but does not start listening for commands or consensus events until start() is called.
    ///
    /// The publisher reactor won't try to upload until the
    /// [`tor_dirpublish::Publisher::set_document`] is called.
    pub(crate) fn new(
        runtime: R,
        netdir: Arc<dyn NetDirProvider>,
        command_rx: DescriptorCommandReceiver,
    ) -> anyhow::Result<Self> {
        let uploader = Arc::new(RelayDescUploader {
            runtime: runtime.clone(),
        });

        // We start with no document and no targets. Both are populated once we build a descriptor.
        // This way we catch any new directory authorities showing up in the config or consensus.
        let publisher = Publisher::launch(
            &runtime,
            "relay descriptor".to_string(),
            /* initial_document=*/ None,
            /* initial_targets=*/ HashSet::new(),
            INITIAL_RETRY_DELAY,
            uploader,
        )
        .context("Failed to launch descriptor publisher")?;

        Ok(Self {
            runtime,
            netdir,
            command_rx,
            publisher,
        })
    }

    /// Build the relay's descriptor document as ready to be uploaded.
    ///
    /// Returns `None` if we don't have everything we need to build a descriptor.
    #[allow(clippy::unused_async)] // TODO(relay): remove once used.
    async fn build_descriptor(&self) -> anyhow::Result<Option<Arc<RelayDescDocument>>> {
        // TODO(relay): No relay desc encoding support yet from tor-netdoc.
        //
        // Once encoding exists, this should:
        //   * gather the relay's keys by asking the crypto task.
        //   * encode and sign the descriptor,
        todo!("descriptor building not yet implemented");
    }

    /// Recompute the set of directory authorities we should upload to.
    ///
    /// Returns `None` if we don't yet know the targets.
    fn compute_targets(&self) -> Option<HashSet<Arc<DirAuthorityTarget>>> {
        // TODO(relay): get the directory authorities to upload to. There is a challenge here
        // because we will allow to have authorites in the config file or use the hardcoded one or
        // from NetDir?
        todo!("computing dirauth target not yet implemented");
    }

    /// Rebuild the descriptor (and refresh targets) and hand it to the publisher.
    async fn rebuild_and_publish(&self) -> anyhow::Result<()> {
        // Adjust the targets onto our publisher before.
        if let Some(targets) = self.compute_targets() {
            self.publisher.adjust_targets(|t| *t = targets);
        }

        // Get the latest descriptor.
        let document = self
            .build_descriptor()
            .await
            .context("Failed to build relay descriptor")?;

        // Tell the publisher to publish the new document. Failing to build the descriptor, as in a
        // None value, will make the publisher wait and do nothing.
        self.publisher.set_document(document, false);
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
