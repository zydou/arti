//! Main implementation of the connection functionality

use std::time::Duration;

use std::ops::{Bound, RangeBounds};
use std::sync::Arc;
use std::time::SystemTime;

use async_trait::async_trait;
use educe::Educe;
use futures::{AsyncRead, AsyncWrite};
use itertools::Itertools;
use tracing::{debug, trace};

use retry_error::RetryError;
use safelog::Redacted;
use tor_checkable::{timed::TimerangeBound, Timebound};
use tor_circmgr::hspool::{HsCircKind, HsCircPool};
use tor_dirclient::request::Requestable as _;
use tor_error::{into_internal, ErrorReport as _};
use tor_hscrypto::pk::{HsBlindId, HsBlindIdKey, HsId, HsIdKey};
use tor_linkspec::OwnedCircTarget;
use tor_llcrypto::pk::ed25519::Ed25519Identity;
use tor_netdir::{HsDirOp, NetDir, Relay};
use tor_proto::circuit::ClientCirc;
use tor_rtcompat::{Runtime, SleepProviderExt as _};

use crate::state::MockableConnectorData;
use crate::{ConnError, DescriptorError, DescriptorErrorDetail};
use crate::{HsClientConnector, HsClientSecretKeys};

use ConnError as CE;

/// Information about a hidden service, including our connection history
#[allow(dead_code, unused_variables)] // TODO hs remove.
#[derive(Default, Educe)]
#[educe(Debug)]
// This type is actually crate-private, since it isn't re-exported, but it must
// be `pub` because it appears as a default for a type parameter in HsClientConnector.
pub struct Data {
    /// The latest known onion service descriptor for this service.
    #[educe(Debug(ignore))] // TODO HS do better than this
    desc: Option<TimerangeBound<HsDesc>>,
    /// Information about the latest status of trying to connect to this service
    /// through each of its introduction points.
    ///
    ipts: (), // TODO hs: make this type real, use `RetryDelay`, etc.
}

/// A downloaded hidden service descriptor - dummy alias
// TODO HS make this a real `tor_netdoc::doc::hsdesc::HsDesc`.
type HsDesc = String;

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
) -> Result<ClientCirc, ConnError> {
    Context::new(
        &connector.runtime,
        &*connector.circpool,
        netdir,
        hsid,
        data,
        secret_keys,
        (),
    )?
    .connect()
    .await
}

/// Common context for hidden service connection operations
///
/// TODO HS: this struct will grow a generic parameter, and mock state variable,
/// for allowing its impls to be unit tested.
#[allow(dead_code)] // TODO HS remove
struct Context<'c, 'd, R: Runtime, M: MocksForConnect<R>> {
    /// Runtime
    runtime: &'c R,
    /// Circpool
    circpool: &'c M::HsCircPool,
    /// Netdir
    netdir: Arc<NetDir>,
    /// Per-HS-association long term mutable state
    data: &'d mut Data,
    /// Secret keys to use
    secret_keys: HsClientSecretKeys,
    /// HS ID
    hsid: HsId,
    /// Blinded HS ID
    hs_blind_id: HsBlindId,
    /// Blinded HS ID as a key
    hs_blind_id_key: HsBlindIdKey,
    /// Mock data
    mocks: M,
}

impl<'c, 'd, R: Runtime, M: MocksForConnect<R>> Context<'c, 'd, R, M> {
    /// Make a new `Context` from the input data
    fn new(
        runtime: &'c R,
        circpool: &'c M::HsCircPool,
        netdir: Arc<NetDir>,
        hsid: HsId,
        data: &'d mut Data,
        secret_keys: HsClientSecretKeys,
        mocks: M,
    ) -> Result<Self, ConnError> {
        let time_period = netdir.hs_time_period();
        let (hs_blind_id_key, _subcred) = HsIdKey::try_from(hsid)
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
            circpool,
            runtime,
            data,
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
    async fn connect(&mut self) -> Result<ClientCirc, ConnError> {
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

        let desc = self.descriptor_ensure().await?;

        mocks.test_got_desc(desc);

        // TODO HS complete the implementation
        todo!()
    }

    /// Ensure that `Data.desc` contains the HS descriptor
    ///
    /// Does retries and timeouts
    async fn descriptor_ensure(&mut self) -> Result<&HsDesc, CE> {
        // TODO HS are these right? make configurable?
        // TODO HS should we even have MAX_TOTAL_ATTEMPTS or should we just try each one once?
        /// Maxmimum number of hsdir connection and retrieval attempts we'll make
        const MAX_TOTAL_ATTEMPTS: usize = 6;
        /// Limit on the duration of each retrieval attempt
        const EACH_TIMEOUT: Duration = Duration::from_secs(10);

        if let Some(previously) = &self.data.desc {
            let now = self.runtime.wallclock();
            if let Ok(_desc) = previously.as_ref().check_valid_at(&now) {
                // Ideally we would just return desc but that confuses borrowck.
                // https://github.com/rust-lang/rust/issues/51545
                return Ok(self
                    .data
                    .desc
                    .as_ref()
                    .expect("Some but now None")
                    .as_ref()
                    .check_valid_at(&now)
                    .expect("Ok but now Err"));
            }
            // Seems to be not valid now.  Try to fetch a fresh one.
        }

        let hs_dirs = self
            .netdir
            .hs_dirs(&self.hs_blind_id, HsDirOp::Download)
            .collect_vec();
        trace!(
            "HS desc fetch for {}, using {} hsdirs",
            &self.hsid,
            hs_dirs.len()
        );

        let mut attempts = hs_dirs.iter().cycle().take(MAX_TOTAL_ATTEMPTS);
        let mut errors = RetryError::in_attempt_to("retrieve hidden service descriptor");
        let (desc, bounds) = loop {
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
                .unwrap_or_else(|_timeout| Err(DescriptorErrorDetail::Timeout))
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
        // Because the `HsDesc` must be owned by `data.desc`,
        // we must first wrap it in the TimerangeBound,
        // and then dangerously_assume_timely to get a reference out again.
        let ret = self.data.desc.insert(TimerangeBound::new(desc, bounds));
        let ret: &String = ret.as_ref().dangerously_assume_timely();

        Ok(ret)
    }

    /// Make one attempt to fetch the descriptor from a specific hsdir
    ///
    /// No timeout
    ///
    /// On success, returns the descriptor.
    ///
    /// Also returns a `RangeBounds<SystemTime>` which represents the descriptor's validity.
    /// (This is separate, because the descriptor's validity at the current time *has* been checked,)
    async fn descriptor_fetch_attempt(
        &self,
        hsdir: &Relay<'_>,
    ) -> Result<(HsDesc, impl RangeBounds<SystemTime>), DescriptorErrorDetail> {
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
        // TODO HS parse and check signatures and times, instead of this nonsense
        let hsdesc = desc_text;
        let unbounded_todo = Bound::Unbounded::<SystemTime>; // TODO HS remove
        let bound = (unbounded_todo, unbounded_todo);

        Ok((hsdesc, bound))
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
    /// Tell tests we got this descriptor text
    fn test_got_desc(&self, desc: &HsDesc) {
        eprintln!("HS DESC:\n{}\n", &desc); // TODO HS remove
    }
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
        target: OwnedCircTarget,
    ) -> tor_circmgr::Result<Self::ClientCirc>;
}
/// Mock for `ClientCirc`
#[async_trait]
trait MockableClientCirc {
    /// Client circuit
    type DirStream: AsyncRead + AsyncWrite + Send + Unpin;
    async fn begin_dir_stream(&self) -> tor_proto::Result<Self::DirStream>;
}

impl<R: Runtime> MocksForConnect<R> for () {
    type HsCircPool = HsCircPool<R>;
}
#[async_trait]
impl<R: Runtime> MockableCircPool<R> for HsCircPool<R> {
    type ClientCirc = ClientCirc;
    async fn get_or_launch_specific(
        &self,
        netdir: &NetDir,
        kind: HsCircKind,
        target: OwnedCircTarget,
    ) -> tor_circmgr::Result<ClientCirc> {
        self.get_or_launch_specific(netdir, kind, target).await
    }
}
#[async_trait]
impl MockableClientCirc for ClientCirc {
    /// Client circuit
    type DirStream = tor_proto::stream::DataStream;
    async fn begin_dir_stream(&self) -> tor_proto::Result<Self::DirStream> {
        self.begin_dir_stream().await
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
    ) -> Result<Self::ClientCirc, ConnError> {
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
    use std::panic::AssertUnwindSafe;
    use tokio_crate as tokio;
    use tor_async_utils::JoinReadWrite;
    use tor_netdoc::doc::hsdesc::test_data;
    use tor_rtcompat::tokio::TokioNativeTlsRuntime;
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
        fn test_got_desc(&self, desc: &HsDesc) {
            self.mglobal.lock().unwrap().got_desc = Some(desc.clone());
        }
    }
    #[async_trait]
    impl<R: Runtime> MockableCircPool<R> for Mocks<()> {
        type ClientCirc = Mocks<()>;
        async fn get_or_launch_specific(
            &self,
            _netdir: &NetDir,
            kind: HsCircKind,
            target: OwnedCircTarget,
        ) -> tor_circmgr::Result<Self::ClientCirc> {
            assert_eq!(kind, HsCircKind::ClientHsDir);
            self.mglobal.lock().unwrap().hsdirs_asked.push(target);
            Ok(self.clone())
        }
    }
    #[async_trait]
    impl MockableClientCirc for Mocks<()> {
        type DirStream = JoinReadWrite<futures::io::Cursor<Box<[u8]>>, futures::io::Sink>;
        async fn begin_dir_stream(&self) -> tor_proto::Result<Self::DirStream> {
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
    }

    #[traced_test]
    #[tokio::test]
    async fn test_connect() {
        let netdir = tor_netdir::testnet::construct_netdir();
        let netdir = Arc::new(netdir.unwrap_if_sufficient().unwrap());
        let runtime = TokioNativeTlsRuntime::current().unwrap();
        let mglobal = Arc::new(Mutex::new(MocksGlobal::default()));
        let mocks = Mocks { mglobal, id: () };
        // From C Tor src/test/test_hs_common.c test_build_address
        let hsid = test_data::TEST_HSID_2.into();
        let mut data = Data::default();

        let _got = AssertUnwindSafe(
            Context::new(
                &runtime,
                &mocks,
                netdir,
                hsid,
                &mut data,
                HsClientSecretKeys::default(),
                mocks.clone(),
            )
            .unwrap()
            .connect(),
        )
        .catch_unwind() // TODO HS remove this and the AssertUnwindSafe
        .await;

        let mglobal = mocks.mglobal.lock().unwrap();

        assert_eq!(mglobal.hsdirs_asked.len(), 1);
        assert_eq!(mglobal.got_desc, Some(test_data::TEST_DATA_2.to_string()));

        // TODO hs check the circuit in got is the one we gave out
    }
}
