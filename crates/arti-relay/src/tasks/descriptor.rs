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
use tor_async_utils::oneshot;
use tracing::{debug, trace};

use tor_dirclient::request::UploadRouterDesc;
use tor_dircommon::authority::AuthorityContacts;
use tor_dirpublish::{Publisher, UploadError, Uploader};
use tor_netdir::{DirEvent, NetDirProvider};
use tor_rtcompat::Runtime;

use crate::tasks::crypto::{CryptoCommand, CryptoCommandSender};

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
    addrs: Vec<SocketAddr>,
}

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
    mpsc::channel(16)
}

/// The [`Uploader`] used to deliver our descriptor to a directory authority.
struct RelayDescUploader<R: Runtime> {
    /// Asynchronous runtime, used to open the connection to the authority.
    runtime: R,
}

#[async_trait]
impl<R: Runtime> Uploader for RelayDescUploader<R> {
    type Doc = RelayDescDocument;
    type Target = DirAuthorityTarget;

    async fn upload(
        self: Arc<Self>,
        target: Arc<Self::Target>,
        document: Arc<Self::Doc>,
    ) -> Result<(), UploadError> {
        let request = UploadRouterDesc::new(Arc::from(document.as_str()));

        // Try the authority's addresses in turn. On connection failure, move on to the
        // next address else upload over the first one we manage to reach.
        //
        // TODO(relay): We need to check our relay capabilities for IPv6 and not try
        // that. We might also want to sort this list in a preferred order.
        let mut connect_err = None;
        for addr in &target.addrs {
            let mut stream = match self.runtime.connect(addr).await {
                Ok(stream) => stream,
                Err(e) => {
                    connect_err = Some(e);
                    continue;
                }
            };

            let response =
                tor_dirclient::send_request(&self.runtime, &request, &mut stream, None).await;
            return UploadError::from_directory_response(response);
        }

        // We couldn't connect to any of the authority's addresses.
        Err(UploadError::Connect(Arc::new(connect_err.unwrap_or_else(
            || std::io::Error::other("authority has no upload addresses"),
        ))))
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

    /// The directory authorities we upload our descriptor to.
    ///
    /// This is either from the config file or the compiled-in default list.
    authorities: AuthorityContacts,

    /// Channel on which we receive [`DescriptorCommand`]s from other tasks.
    command_rx: DescriptorCommandReceiver,

    /// The [`tor_dirpublish`] publisher that manages uploads to all targets.
    publisher: Arc<Publisher<RelayDescDocument, DirAuthorityTarget>>,

    /// The crypto task sender channel.
    crypto_tx: CryptoCommandSender,
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
        authorities: AuthorityContacts,
        crypto_tx: CryptoCommandSender,
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
    async fn build_descriptor(&mut self) -> anyhow::Result<Option<Arc<RelayDescDocument>>> {
        // TODO(relay): No relay desc encoding support yet from tor-netdoc.
        //
        // Once encoding exists, this should:
        //   * encode and sign the descriptor,

        // Get the latest ntor key (onion key) from the crypto task.
        let (tx, rx) = oneshot::channel();
        self.crypto_tx
            .try_send(CryptoCommand::GetLatestNtorKey { tx })
            .context("Crypto task is gone")?;
        let _ntor_key = rx.await.context("Unable to get ntor key")?;

        // Get the relay signing key from the crypto task.
        let (tx, rx) = oneshot::channel();
        self.crypto_tx
            .try_send(CryptoCommand::GetSignKey { tx })
            .context("Crypto task is gone")?;
        let _relay_sign_kp = rx.await.context("Unable to get relay sign keypair")?;

        todo!("descriptor building not yet implemented");
    }

    /// Recompute the set of directory authorities we upload to.
    ///
    /// Each authority becomes one target, carrying all of its upload addresses so the [`Uploader`]
    /// can try them in turn.
    ///
    /// Returns `None` if we somehow have no authorities at all.
    fn compute_targets(&self) -> Option<HashSet<Arc<DirAuthorityTarget>>> {
        let targets: HashSet<Arc<DirAuthorityTarget>> = self
            .authorities
            .uploads()
            .iter()
            .filter(|&addrs| !addrs.is_empty())
            .cloned()
            .map(|addrs| Arc::new(DirAuthorityTarget { addrs }))
            .collect();

        // This should never be None because we have compiled in authorities by default but better
        // safe than sorry. If that case ever happens, the publisher will just do nothing.
        (!targets.is_empty()).then_some(targets)
    }

    /// Rebuild the descriptor (and refresh targets) and hand it to the publisher.
    async fn rebuild_and_publish(&mut self) -> anyhow::Result<()> {
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
