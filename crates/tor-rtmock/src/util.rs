//! Internal utilities for `tor_rtmock`

/// Implements `Runtime` for a struct made of multiple sub-providers
///
/// The `$SomeMockRuntime` type must be a struct containing
/// field(s) which implement `SleepProvider`, `NetProvider`, etc.
///
/// `$gens` are the generics, written as (for example) `[ <R: Runtime> ]`.
///
/// The remaining arguments are the fields.
/// For each field there's:
///   - the short name of what is being provided (a fixed identifier)
///   - the field name in `$SockMockRuntime`
///   - for some cases, the type of that field
///
/// The fields must be specified in the expected order!
//
// This could be further reduced with more macrology:
// ambassador might be able to remove most of the body (although does it do async well?)
// derive-adhoc would allow a more natural input syntax and avoid restating field types
macro_rules! impl_runtime { {
    [ $($gens:tt)* ] $SomeMockRuntime:ty,
    spawn: $spawn:ident,
    block: $block:ident,
    sleep: $sleep:ident: $SleepProvider:ty,
    net: $net:ident: $NetProvider:ty,
    udp: $udp:ident: $UdpProvider:ty, // TODO when MockNetProvider is fixed, abolish this
} => {
    impl $($gens)* Spawn for $SomeMockRuntime {
        fn spawn_obj(&self, future: FutureObj<'static, ()>) -> Result<(), SpawnError> {
            self.$spawn.spawn_obj(future)
        }
    }

    impl $($gens)* BlockOn for $SomeMockRuntime {
        fn block_on<F: Future>(&self, future: F) -> F::Output {
            self.$block.block_on(future)
        }
    }

    #[async_trait]
    impl $($gens)* TcpProvider for $SomeMockRuntime {
        type TcpStream = <$NetProvider as TcpProvider>::TcpStream;
        type TcpListener = <$NetProvider as TcpProvider>::TcpListener;

        async fn connect(&self, addr: &SocketAddr) -> IoResult<Self::TcpStream> {
            self.$net.connect(addr).await
        }
        async fn listen(&self, addr: &SocketAddr) -> IoResult<Self::TcpListener> {
            self.$net.listen(addr).await
        }
    }

    impl $($gens)* TlsProvider<<$NetProvider as TcpProvider>::TcpStream> for $SomeMockRuntime {
        type Connector = <$NetProvider as TlsProvider<
            <$NetProvider as TcpProvider>::TcpStream
            >>::Connector;
        type TlsStream = <$NetProvider as TlsProvider<
            <$NetProvider as TcpProvider>::TcpStream
            >>::TlsStream;
        fn tls_connector(&self) -> Self::Connector {
            self.$net.tls_connector()
        }
    }

    #[async_trait]
    impl $($gens)* UdpProvider for $SomeMockRuntime {
        type UdpSocket = <$UdpProvider as UdpProvider>::UdpSocket;

        #[inline]
        async fn bind(&self, addr: &SocketAddr) -> IoResult<Self::UdpSocket> {
            self.$udp.bind(addr).await
        }
    }

    impl $($gens)* SleepProvider for $SomeMockRuntime {
        type SleepFuture = <$SleepProvider as SleepProvider>::SleepFuture;

        fn sleep(&self, dur: Duration) -> Self::SleepFuture {
            self.$sleep.sleep(dur)
        }
        fn now(&self) -> Instant {
            self.$sleep.now()
        }
        fn wallclock(&self) -> SystemTime {
            self.$sleep.wallclock()
        }
        fn block_advance<T: Into<String>>(&self, reason: T) {
            self.$sleep.block_advance(reason);
        }
        fn release_advance<T: Into<String>>(&self, reason: T) {
            self.$sleep.release_advance(reason);
        }
        fn allow_one_advance(&self, dur: Duration) {
            self.$sleep.allow_one_advance(dur);
        }
    }
} }

/// Prelude that must be imported to use [`impl_runtime!`](impl_runtime)
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
    pub(crate) use futures::task::{FutureObj, Spawn, SpawnError};
    pub(crate) use futures::Future;
    pub(crate) use std::io::Result as IoResult;
    pub(crate) use std::net::SocketAddr;
    pub(crate) use std::time::{Duration, Instant, SystemTime};
    pub(crate) use tor_rtcompat::{
        BlockOn, Runtime, SleepProvider, TcpProvider, TlsProvider, UdpProvider,
    };
}
