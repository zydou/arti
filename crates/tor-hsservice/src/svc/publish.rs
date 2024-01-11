//! Publish and maintain onion service descriptors

mod backoff;
mod descriptor;
mod reactor;

use futures::task::SpawnExt;
use postage::{broadcast, watch};
use std::sync::Arc;
use tor_keymgr::KeyMgr;
use tracing::warn;
use void::Void;

use tor_error::warn_report;
use tor_netdir::NetDirProvider;
use tor_rtcompat::Runtime;

use crate::{ipt_set::IptsPublisherView, StartupError};
use crate::{HsNickname, OnionServiceConfig};

use reactor::Reactor;

pub(crate) use reactor::{Mockable, Real};

/// A handle for the Hsdir Publisher for an onion service.
///
/// This handle represents a set of tasks that identify the hsdirs for each
/// relevant time period, construct descriptors, publish them, and keep them
/// up-to-date.
#[must_use = "If you don't call launch() on the publisher, it won't publish any descriptors."]
pub(crate) struct Publisher<R: Runtime, M: Mockable> {
    /// The runtime.
    runtime: R,
    /// The service for which we're publishing descriptors.
    nickname: HsNickname,
    /// A source for new network directories that we use to determine
    /// our HsDirs.
    dir_provider: Arc<dyn NetDirProvider>,
    /// Mockable state.
    ///
    /// This is used for launching circuits and for obtaining random number generators.
    mockable: M,
    /// The onion service config.
    config: Arc<OnionServiceConfig>,
    /// A channel for receiving IPT change notifications.
    ipt_watcher: IptsPublisherView,
    /// A channel for receiving onion service config change notifications.
    config_rx: watch::Receiver<Arc<OnionServiceConfig>>,
    /// A channel for receiving the signal to shut down.
    shutdown_rx: broadcast::Receiver<Void>,
    /// The key manager.
    keymgr: Arc<KeyMgr>,
}

impl<R: Runtime, M: Mockable> Publisher<R, M> {
    /// Create a new publisher.
    ///
    /// When it launches, it will know no keys or introduction points,
    /// and will therefore not upload any descriptors.
    ///
    /// The publisher won't start publishing until you call [`Publisher::launch`].
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        runtime: R,
        nickname: HsNickname,
        dir_provider: Arc<dyn NetDirProvider>,
        mockable: impl Into<M>,
        ipt_watcher: IptsPublisherView,
        config_rx: watch::Receiver<Arc<OnionServiceConfig>>,
        shutdown_rx: broadcast::Receiver<Void>,
        keymgr: Arc<KeyMgr>,
    ) -> Self {
        let config = config_rx.borrow().clone();
        Self {
            runtime,
            nickname,
            dir_provider,
            mockable: mockable.into(),
            config,
            ipt_watcher,
            config_rx,
            shutdown_rx,
            keymgr,
        }
    }

    /// Launch the publisher reactor.
    pub(crate) fn launch(self) -> Result<(), StartupError> {
        let Publisher {
            runtime,
            nickname,
            dir_provider,
            mockable,
            config,
            ipt_watcher,
            config_rx,
            shutdown_rx,
            keymgr,
        } = self;

        let reactor = Reactor::new(
            runtime.clone(),
            nickname,
            dir_provider,
            mockable,
            config,
            ipt_watcher,
            config_rx,
            shutdown_rx,
            keymgr,
        );

        runtime
            .spawn(async move {
                match reactor.run().await {
                    Ok(()) => warn!("the publisher reactor has shut down"),
                    Err(e) => warn_report!(e, "the publisher reactor has shut down"),
                }
            })
            .map_err(|e| StartupError::Spawn {
                spawning: "publisher reactor task",
                cause: e.into(),
            })?;

        Ok(())
    }

    /// Inform this publisher that its set of keys has changed.
    ///
    /// TODO HSS: Either this needs to take new keys as an argument, or there
    /// needs to be a source of keys (including public keys) in Publisher.
    pub(crate) fn new_hs_keys(&self, keys: ()) {
        todo!()
    }

    /// Return our current status.
    //
    // TODO HSS: There should also be a postage::Watcher -based stream of status
    // change events.
    pub(crate) fn status(&self) -> PublisherStatus {
        todo!()
    }

    // TODO HSS: We may also need to update descriptors based on configuration
    // or authentication changes.
}

/// Current status of our attempts to publish an onion service descriptor.
#[derive(Debug, Clone)]
pub(crate) struct PublisherStatus {
    // TODO HSS add fields
}

//
// Our main loop has to look something like:

// Whenever time period or keys or netdir changes: Check whether our list of
// HsDirs has changed.  If it is, add and/or remove hsdirs as needed.

// "when learning about new keys, new intro points, or new configurations,
// or whenever the time period changes: Mark descriptors dirty."

// Whenever descriptors are dirty, we have enough info to generate
// descriptors, and we aren't upload-rate-limited: Generate new descriptors
// and mark descriptors clean.  Mark all hsdirs as needing new versions of
// this descriptor.

// While any hsdir does not have the latest version of its any descriptor:
// upload it.  Retry with usual timeouts on failure."

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
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;

    use std::collections::HashMap;
    use std::io;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::task::{Context, Poll};
    use std::time::Duration;

    use async_trait::async_trait;
    use fs_mistrust::Mistrust;
    use futures::{AsyncRead, AsyncWrite};
    use tempfile::{tempdir, TempDir};

    use tor_basic_utils::test_rng::{testing_rng, TestingRng};
    use tor_circmgr::hspool::HsCircKind;
    use tor_hscrypto::pk::{HsBlindId, HsDescSigningKeypair, HsId, HsIdKey, HsIdKeypair};
    use tor_keymgr::{ArtiNativeKeystore, KeyMgrBuilder, KeySpecifier, ToEncodableKey};
    use tor_llcrypto::pk::{ed25519, rsa};
    use tor_netdir::testprovider::TestNetDirProvider;
    use tor_netdir::{testnet, NetDir};
    use tor_netdoc::doc::hsdesc::test_data;
    use tor_rtcompat::BlockOn;
    use tor_rtmock::MockRuntime;

    use crate::config::OnionServiceConfigBuilder;
    use crate::ipt_set::{ipts_channel, IptInSet, IptSet};
    use crate::svc::publish::reactor::MockableClientCirc;
    use crate::svc::test::create_storage_handles;
    use crate::{Anonymity, HsNickname, IptLocalId};
    use crate::{
        BlindIdKeypairSpecifier, BlindIdPublicKeySpecifier, DescSigningKeypairSpecifier,
        HsIdKeypairSpecifier, HsIdPublicKeySpecifier,
    };

    /// The nickname of the test service.
    const TEST_SVC_NICKNAME: &str = "test-svc";

    /// The HTTP response the HSDir returns if everything went well.
    const OK_RESPONSE: &str = "HTTP/1.1 200 OK\r\n\r\n";

    /// The HTTP response the HSDir returns if something went wrong
    const ERR_RESPONSE: &str = "HTTP/1.1 500 UH_OH\r\n\r\n";

    /// The error doesn't matter (we return a dummy io::Error from poll_read).
    ///
    /// NOTE: ideally, this would be an io::Result, but io::Error isn't Clone (the tests need to
    /// clone the iterator over these Results for each HSDir).
    type PollReadResult<T> = Result<T, ()>;

    /// A trait for our poll_read response iterator.
    trait PollReadIter:
        Iterator<Item = PollReadResult<String>> + Send + Sync + Clone + Unpin + 'static
    {
    }

    impl<I> PollReadIter for I where
        I: Iterator<Item = PollReadResult<String>> + Send + Sync + Clone + Unpin + 'static
    {
    }

    #[derive(Clone, Debug, Default)]
    struct MockReactorState<I: PollReadIter> {
        /// The number of `POST /tor/hs/3/publish` requests sent by the reactor.
        publish_count: Arc<AtomicUsize>,
        /// The values returned by `DataStream::poll_read` when uploading to an HSDir.
        ///
        /// The values represent the HTTP response (or lack thereof) each HSDir sends upon
        /// receiving a POST request for uploading a descriptor.
        ///
        /// Note: this field is only used for populating responses_for_hsdir. Each time
        /// get_or_launch_specific is called for a new CircTarget, this iterator is cloned and
        /// added to the responses_for_hsdir entry corresponding to the new CircTarget (HSDir).
        poll_read_responses: I,
        /// The responses that will be returned by each test HSDir (identified by its RsaIdentity).
        ///
        /// Used for testing whether the reactor correctly retries on failure.
        responses_for_hsdir: Arc<Mutex<HashMap<rsa::RsaIdentity, Arc<Mutex<I>>>>>,
    }

    #[async_trait]
    impl<I: PollReadIter> Mockable for MockReactorState<I> {
        type Rng = TestingRng;
        type ClientCirc = MockClientCirc<I>;

        fn thread_rng(&self) -> Self::Rng {
            testing_rng()
        }

        async fn get_or_launch_specific<T>(
            &self,
            netdir: &tor_netdir::NetDir,
            kind: HsCircKind,
            target: T,
        ) -> Result<Arc<Self::ClientCirc>, tor_circmgr::Error>
        where
            T: tor_linkspec::CircTarget + Send + Sync,
        {
            assert_eq!(kind, HsCircKind::SvcHsDir);

            // Look up the next poll_read value to return for this relay.
            let id = target.rsa_identity().unwrap();
            let mut map = self.responses_for_hsdir.lock().unwrap();
            let poll_read_responses = map
                .entry(*id)
                .or_insert_with(|| Arc::new(Mutex::new(self.poll_read_responses.clone())));

            Ok(MockClientCirc {
                publish_count: Arc::clone(&self.publish_count),
                poll_read_responses: Arc::clone(poll_read_responses),
            }
            .into())
        }
    }

    #[derive(Debug, Clone)]
    struct MockClientCirc<I: PollReadIter> {
        /// The number of `POST /tor/hs/3/publish` requests sent by the reactor.
        publish_count: Arc<AtomicUsize>,
        /// The values to return from `poll_read`.
        ///
        /// Used for testing whether the reactor correctly retries on failure.
        poll_read_responses: Arc<Mutex<I>>,
    }

    #[async_trait]
    impl<I: PollReadIter> MockableClientCirc for MockClientCirc<I> {
        type DataStream = MockDataStream<I>;

        async fn begin_dir_stream(self: Arc<Self>) -> Result<Self::DataStream, tor_proto::Error> {
            Ok(MockDataStream {
                publish_count: Arc::clone(&self.publish_count),
                // TODO HSS: this will need to change when we start reusing circuits (currently,
                // we only ever create one data stream per circuit).
                poll_read_responses: Arc::clone(&self.poll_read_responses),
            })
        }
    }

    #[derive(Debug)]
    struct MockDataStream<I: PollReadIter> {
        /// The number of `POST /tor/hs/3/publish` requests sent by the reactor.
        publish_count: Arc<AtomicUsize>,
        /// The values to return from `poll_read`.
        ///
        /// Used for testing whether the reactor correctly retries on failure.
        poll_read_responses: Arc<Mutex<I>>,
    }

    impl<I: PollReadIter> AsyncRead for MockDataStream<I> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            match self.poll_read_responses.lock().unwrap().next() {
                Some(res) => {
                    match res {
                        Ok(res) => {
                            buf[..res.len()].copy_from_slice(res.as_bytes());

                            Poll::Ready(Ok(res.len()))
                        }
                        Err(()) => {
                            // Return an error. This should cause the reactor to reattempt the
                            // upload.
                            Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, "test error")))
                        }
                    }
                }
                None => Poll::Ready(Ok(0)),
            }
        }
    }

    impl<I: PollReadIter> AsyncWrite for MockDataStream<I> {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let request = std::str::from_utf8(buf).unwrap();

            assert!(request.starts_with("POST /tor/hs/3/publish HTTP/1.0\r\n"));
            let _prev = self.publish_count.fetch_add(1, Ordering::SeqCst);

            Poll::Ready(Ok(request.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// Insert the specified key into the keystore.
    fn insert_svc_key<K>(key: K, keymgr: &KeyMgr, svc_key_spec: &dyn KeySpecifier)
    where
        K: ToEncodableKey,
    {
        keymgr
            .insert(key, svc_key_spec, tor_keymgr::KeystoreSelector::Default)
            .unwrap();
    }

    /// Create a new `KeyMgr`, provisioning its keystore with the necessary keys.
    fn init_keymgr(
        keystore_dir: &TempDir,
        nickname: &HsNickname,
        netdir: &NetDir,
    ) -> (HsId, HsBlindId, Arc<KeyMgr>) {
        let period = netdir.hs_time_period();

        let mut rng = testing_rng();
        let keypair = ed25519::Keypair::generate(&mut rng);
        let id_pub = HsIdKey::from(keypair.verifying_key());
        let id_keypair = HsIdKeypair::from(ed25519::ExpandedKeypair::from(&keypair));

        let (hs_blind_id_key, hs_blind_id_kp, _subcredential) =
            id_keypair.compute_blinded_key(period).unwrap();

        let keystore = ArtiNativeKeystore::from_path_and_mistrust(
            keystore_dir,
            &Mistrust::new_dangerously_trust_everyone(),
        )
        .unwrap();

        // Provision the keystore with the necessary keys:
        let keymgr = KeyMgrBuilder::default()
            .default_store(Box::new(keystore))
            .build()
            .unwrap();

        insert_svc_key(
            id_keypair,
            &keymgr,
            &HsIdKeypairSpecifier::new(nickname.clone()),
        );

        insert_svc_key(
            id_pub.clone(),
            &keymgr,
            &HsIdPublicKeySpecifier::new(nickname.clone()),
        );

        insert_svc_key(
            hs_blind_id_kp,
            &keymgr,
            &BlindIdKeypairSpecifier::new(nickname.clone(), period),
        );

        insert_svc_key(
            hs_blind_id_key.clone(),
            &keymgr,
            &BlindIdPublicKeySpecifier::new(nickname.clone(), period),
        );

        insert_svc_key(
            HsDescSigningKeypair::from(ed25519::Keypair::generate(&mut rng)),
            &keymgr,
            &DescSigningKeypairSpecifier::new(nickname.clone(), period),
        );

        let hs_id = id_pub.into();
        (hs_id, hs_blind_id_key.into(), keymgr.into())
    }

    fn build_test_config(nickname: HsNickname) -> OnionServiceConfig {
        OnionServiceConfigBuilder::default()
            .nickname(nickname)
            .anonymity(Anonymity::Anonymous)
            .rate_limit_at_intro(None)
            .build()
            .unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn run_test<I: PollReadIter>(
        runtime: MockRuntime,
        hsid: HsId,
        nickname: HsNickname,
        keymgr: Arc<KeyMgr>,
        pv: IptsPublisherView,
        config_rx: watch::Receiver<Arc<OnionServiceConfig>>,
        shutdown_rx: broadcast::Receiver<Void>,
        netdir: NetDir,
        reactor_event: impl FnOnce(),
        poll_read_responses: I,
        expected_upload_count: usize,
    ) {
        runtime.clone().block_on(async move {
            let netdir_provider: Arc<dyn NetDirProvider> =
                Arc::new(TestNetDirProvider::from(netdir));
            let publish_count = Default::default();
            let circpool = MockReactorState {
                publish_count: Arc::clone(&publish_count),
                poll_read_responses,
                responses_for_hsdir: Arc::new(Mutex::new(Default::default())),
            };

            let publisher: Publisher<MockRuntime, MockReactorState<_>> = Publisher::new(
                runtime.clone(),
                nickname,
                netdir_provider,
                circpool,
                pv,
                config_rx,
                shutdown_rx,
                keymgr,
            );

            publisher.launch().unwrap();
            runtime.advance_until_stalled().await;

            // Check that we haven't published anything yet
            assert_eq!(publish_count.load(Ordering::SeqCst), 0);

            reactor_event();

            runtime.advance_until_stalled().await;

            assert_eq!(publish_count.load(Ordering::SeqCst), expected_upload_count);
        });
    }

    /// Test that the publisher publishes the descriptor when the IPTs change.
    ///
    /// The `poll_read_responses` are returned by each HSDir, in order, in response to each POST
    /// request received from the publisher.
    ///
    /// The `multiplier` represents the multiplier by which to multiply the number of HSDirs to
    /// obtain the total expected number of uploads (this works because the test "HSDirs" all
    /// behave the same, so the number of uploads is the number of HSDirs multiplied by the number
    /// of retries).
    fn publish_after_ipt_change<I: PollReadIter>(poll_read_responses: I, multiplier: usize) {
        let runtime = MockRuntime::new();
        let nickname = HsNickname::try_from(TEST_SVC_NICKNAME.to_string()).unwrap();
        let config = build_test_config(nickname.clone());
        let (config_tx, config_rx) = watch::channel_with(Arc::new(config));

        let (mut mv, pv) = ipts_channel(&runtime, create_storage_handles().1).unwrap();
        let update_ipts = || {
            let ipts: Vec<IptInSet> = test_data::test_parsed_hsdesc()
                .unwrap()
                .intro_points()
                .iter()
                .enumerate()
                .map(|(i, ipt)| IptInSet {
                    ipt: ipt.clone(),
                    lid: IptLocalId([i.try_into().unwrap(); 32]),
                })
                .collect();

            mv.borrow_for_update(runtime.clone()).ipts = Some(IptSet {
                ipts,
                lifetime: Duration::from_secs(20),
            });
        };

        let netdir = testnet::construct_netdir().unwrap_if_sufficient().unwrap();
        let keystore_dir = tempdir().unwrap();

        let (hsid, blind_id, keymgr) = init_keymgr(&keystore_dir, &nickname, &netdir);

        let hsdir_count = netdir
            .hs_dirs_upload([(blind_id, netdir.hs_time_period())].into_iter())
            .unwrap()
            .collect::<Vec<_>>()
            .len();

        assert!(hsdir_count > 0);

        // If any of the uploads fail, they will be retried. Note that the upload failure will
        // affect _each_ hsdir, so the expected number of uploads is a multiple of hsdir_count.
        let expected_upload_count = hsdir_count * multiplier;
        let (_shutdown_tx, shutdown_rx) = broadcast::channel(0);

        run_test(
            runtime.clone(),
            hsid,
            nickname,
            keymgr,
            pv,
            config_rx,
            shutdown_rx,
            netdir,
            update_ipts,
            poll_read_responses,
            expected_upload_count,
        );
    }

    #[test]
    fn publish_after_ipt_change_no_errors() {
        // The HSDirs always respond with 200 OK, so we expect to publish hsdir_count times.
        let poll_reads = [Ok(OK_RESPONSE.into())].into_iter();

        publish_after_ipt_change(poll_reads, 1);
    }

    #[test]
    fn publish_after_ipt_change_with_errors() {
        let err_responses = vec![
            // The HSDir closed the connection without sending a response.
            Err(()),
            // The HSDir responded with an internal server error,
            Ok(ERR_RESPONSE.to_string()),
        ];

        for error_res in err_responses.into_iter() {
            let poll_reads = vec![
                // Each HSDir first responds with an error, which causes the publisher to retry the
                // upload. The HSDir then responds with "200 OK".
                //
                // We expect to publish hsdir_count * 2 times (for each HSDir, the first upload
                // attempt fails, but the second succeeds).
                error_res,
                Ok(OK_RESPONSE.to_string()),
            ]
            .into_iter();

            publish_after_ipt_change(poll_reads, 2);
        }
    }

    // TODO (#1120): test that the descriptor is republished when the config changes

    // TODO (#1120): test that the descriptor is reuploaded only to the HSDirs that need it (i.e. the
    // ones for which it's dirty)

    // TODO (#1120): test that rate-limiting works correctly

    // TODO (#1120): test that the uploaded descriptor contains the expected values

    // TODO (#1120): test that the publisher stops publishing if the IPT manager sets the IPTs to
    // `None`.
}
