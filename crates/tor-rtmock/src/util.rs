//! Internal utilities for `tor_rtmock`

use derive_deftly::define_derive_deftly;
use futures::channel::mpsc;

define_derive_deftly! {
/// Implements `Runtime` for a struct made of multiple sub-providers
///
/// The type must be a struct containing
/// field(s) which implement `SleepProvider`, `NetProvider`, etc.
///
/// The corresponding fields must be decorated with:
///
///  * `#[deftly(mock(task))]` to indicate the field implementing `Spawn + BlockOn`
///  * `#[deftly(mock(net))]` to indicate the field implementing `NetProvider`
///  * `#[deftly(mock(sleep))]` to indicate the field implementing `SleepProvider`
///     and `CoarseTimeProvider`.
// This could perhaps be further reduced:
// ambassador might be able to remove most of the body (although does it do async well?)
    SomeMockRuntime for struct, expect items:

 $(
  ${when fmeta(mock(task))}

    impl <$tgens> Spawn for $ttype {
        fn spawn_obj(&self, future: FutureObj<'static, ()>) -> Result<(), SpawnError> {
            self.$fname.spawn_obj(future)
        }
    }

    impl <$tgens> BlockOn for $ttype {
        fn block_on<F: Future>(&self, future: F) -> F::Output {
            self.$fname.block_on(future)
        }
    }

 )
 $(
  ${when fmeta(mock(net))}

    #[async_trait]
    impl <$tgens> NetStreamProvider for $ttype {
        type Stream = <$ftype as NetStreamProvider>::Stream;
        type Listener = <$ftype as NetStreamProvider>::Listener;

        async fn connect(&self, addr: &SocketAddr) -> IoResult<Self::Stream> {
            self.$fname.connect(addr).await
        }
        async fn listen(&self, addr: &SocketAddr) -> IoResult<Self::Listener> {
            self.$fname.listen(addr).await
        }
    }

    #[async_trait]
    impl <$tgens> NetStreamProvider<tor_rtcompat::unix::SocketAddr> for $ttype {
        type Stream = FakeStream;
        type Listener = FakeListener<tor_rtcompat::unix::SocketAddr>;

        async fn connect(&self, _addr: &tor_rtcompat::unix::SocketAddr) -> IoResult<Self::Stream> {
            Err(tor_rtcompat::unix::NoUnixAddressSupport::default().into())
        }
        async fn listen(&self, _addr: &tor_rtcompat::unix::SocketAddr) -> IoResult<Self::Listener> {
            Err(tor_rtcompat::unix::NoUnixAddressSupport::default().into())
        }
    }

    impl <$tgens> TlsProvider<<$ftype as NetStreamProvider>::Stream> for $ttype {
        type Connector = <$ftype as TlsProvider<
            <$ftype as NetStreamProvider>::Stream
            >>::Connector;
        type TlsStream = <$ftype as TlsProvider<
            <$ftype as NetStreamProvider>::Stream
            >>::TlsStream;
        fn tls_connector(&self) -> Self::Connector {
            self.$fname.tls_connector()
        }
        fn supports_keying_material_export(&self) -> bool {
            self.$fname.supports_keying_material_export()
        }
    }

    #[async_trait]
    impl <$tgens> UdpProvider for $ttype {
        type UdpSocket = <$ftype as UdpProvider>::UdpSocket;

        #[inline]
        async fn bind(&self, addr: &SocketAddr) -> IoResult<Self::UdpSocket> {
            self.$fname.bind(addr).await
        }
    }

 )
 $(
  ${when fmeta(mock(sleep))}

    impl <$tgens> SleepProvider for $ttype {
        type SleepFuture = <$ftype as SleepProvider>::SleepFuture;

        fn sleep(&self, dur: Duration) -> Self::SleepFuture {
            self.$fname.sleep(dur)
        }
        fn now(&self) -> Instant {
            self.$fname.now()
        }
        fn wallclock(&self) -> SystemTime {
            self.$fname.wallclock()
        }
        fn block_advance<T: Into<String>>(&self, reason: T) {
            self.$fname.block_advance(reason);
        }
        fn release_advance<T: Into<String>>(&self, reason: T) {
            self.$fname.release_advance(reason);
        }
        fn allow_one_advance(&self, dur: Duration) {
            self.$fname.allow_one_advance(dur);
        }
    }

    impl <$tgens> CoarseTimeProvider for $ttype {
        fn now_coarse(&self) -> CoarseInstant {
            self.$fname.now_coarse()
        }
    }

 )

   // TODO this wants to be assert_impl but it fails at generics
   const _: fn() = || {
       fn x(_: impl Runtime) { }
       fn check_impl_runtime<$tgens>(t: $ttype) { x(t) }
   };
}

/// Prelude that must be imported to derive
/// [`SomeMockRuntime`](derive_deftly_template_SomeMockRuntime)
//
// This could have been part of the expansion of `impl_runtime!`,
// but it seems rather too exciting for a macro to import things as a side gig.
//
// Arguably this ought to be an internal crate::prelude instead.
// But crate-internal preludes are controversial within the Arti team.  -Diziet
//
// For macro visibility reasons, this must come *lexically after* the macro,
// to allow it to refer to the macro in the doc comment.
pub(crate) mod impl_runtime_prelude {
    pub(crate) use async_trait::async_trait;
    pub(crate) use derive_deftly::Deftly;
    pub(crate) use futures::task::{FutureObj, Spawn, SpawnError};
    pub(crate) use futures::Future;
    pub(crate) use std::io::Result as IoResult;
    pub(crate) use std::net::SocketAddr;
    pub(crate) use std::time::{Duration, Instant, SystemTime};
    pub(crate) use tor_rtcompat::{
        unimpl::FakeListener, unimpl::FakeStream, BlockOn, CoarseInstant, CoarseTimeProvider,
        NetStreamProvider, Runtime, SleepProvider, TlsProvider, UdpProvider,
    };
}

/// Wrapper for `futures::channel::mpsc::channel` that embodies the `#[allow]`
///
/// We don't care about mq tracking in this test crate.
///
/// Exactly like `tor_async_utils::mpsc_channel_no_memquota`,
/// but we can't use that here for crate hierarchy reasons.
#[allow(clippy::disallowed_methods)]
pub(crate) fn mpsc_channel<T>(buffer: usize) -> (mpsc::Sender<T>, mpsc::Receiver<T>) {
    mpsc::channel(buffer)
}
