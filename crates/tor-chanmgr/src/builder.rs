//! Implement a concrete type to build channels.

use crate::Error;

use tor_linkspec::{ChanTarget, OwnedChanTarget};
use tor_llcrypto::pk;
use tor_rtcompat::{tls::TlsConnector, Runtime, TlsProvider};

use async_trait::async_trait;
use futures::task::SpawnExt;
use std::sync::Arc;

/// TLS-based channel builder.
///
/// This is a separate type so that we can keep our channel management
/// code network-agnostic.
pub(crate) struct ChanBuilder<R: Runtime> {
    /// Asynchronous runtime for TLS, TCP, spawning, and timeouts.
    runtime: R,
    /// Object to build TLS connections.
    tls_connector: <R as TlsProvider>::Connector,
}

impl<R: Runtime> ChanBuilder<R> {
    /// Construct a new ChanBuilder.
    pub(crate) fn new(runtime: R) -> Self {
        let tls_connector = runtime.tls_connector();
        ChanBuilder {
            runtime,
            tls_connector,
        }
    }
}

#[async_trait]
impl<R: Runtime> crate::mgr::ChannelFactory for ChanBuilder<R> {
    type Channel = tor_proto::channel::Channel;
    type BuildSpec = OwnedChanTarget;

    async fn build_channel(&self, target: &Self::BuildSpec) -> crate::Result<Arc<Self::Channel>> {
        use tor_rtcompat::SleepProviderExt;

        // TODO: make this an option.  And make a better value.
        let five_seconds = std::time::Duration::new(5, 0);

        // FIXME(eta): there doesn't need to be an `Arc` here; `Channel` implements `Clone`!
        self.runtime
            .timeout(five_seconds, self.build_channel_notimeout(target))
            .await?
            .map(Arc::new)
    }
}

impl<R: Runtime> ChanBuilder<R> {
    /// As build_channel, but don't include a timeout.
    async fn build_channel_notimeout(
        &self,
        target: &OwnedChanTarget,
    ) -> crate::Result<tor_proto::channel::Channel> {
        use tor_proto::channel::ChannelBuilder;
        use tor_rtcompat::tls::CertifiedConn;

        // 1. Negotiate the TLS connection.

        // TODO: This just uses the first address. Instead we could be smarter,
        // or use "happy eyeballs, or whatever.  Maybe we will want to
        // refactor as we do so?
        let addr = target
            .addrs()
            .get(0)
            .ok_or_else(|| Error::UnusableTarget("No addresses for chosen relay".into()))?;

        tracing::info!("Negotiating TLS with {}", addr);

        // TODO: add a random hostname here if it will be used for SNI?
        let tls = self
            .tls_connector
            .connect_unvalidated(addr, "ignored")
            .await?;

        let peer_cert = tls
            .peer_certificate()?
            .ok_or(Error::Internal("TLS connection with no peer certificate"))?;

        // 2. Set up the channel.
        let mut builder = ChannelBuilder::new();
        builder.set_declared_addr(*addr);
        let chan = builder.launch(tls).connect().await?;
        let now = self.runtime.wallclock();
        let chan = chan.check(target, &peer_cert, Some(now))?;
        let (chan, reactor) = chan.finish().await?;

        // 3. Launch a task to run the channel reactor.
        self.runtime.spawn(async {
            let _ = reactor.run().await;
        })?;
        Ok(chan)
    }
}

impl crate::mgr::AbstractChannel for tor_proto::channel::Channel {
    type Ident = pk::ed25519::Ed25519Identity;
    fn ident(&self) -> &Self::Ident {
        self.peer_ed25519_id()
    }
    fn is_usable(&self) -> bool {
        !self.is_closing()
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::{
        mgr::{AbstractChannel, ChannelFactory},
        Result,
    };
    use pk::ed25519::Ed25519Identity;
    use pk::rsa::RsaIdentity;
    use std::net::SocketAddr;
    use std::time::{Duration, SystemTime};
    use tor_proto::channel::Channel;
    use tor_rtcompat::{test_with_one_runtime, TcpListener};
    use tor_rtmock::{io::LocalStream, net::MockNetwork, MockSleepRuntime};

    // Make sure that the builder can build a real channel.  To test
    // this out, we set up a listener that pretends to have the right
    // IP, fake the current time, and use a canned response from
    // [`testing::msgs`] crate.
    #[test]
    fn build_ok() -> Result<()> {
        use crate::testing::msgs;
        let orport: SocketAddr = msgs::ADDR.parse().unwrap();
        let ed: Ed25519Identity = msgs::ED_ID.into();
        let rsa: RsaIdentity = msgs::RSA_ID.into();
        let client_addr = "192.0.2.17".parse().unwrap();
        let tls_cert = msgs::X509_CERT.into();
        let target = OwnedChanTarget::new(vec![orport], ed, rsa);
        let now = SystemTime::UNIX_EPOCH + Duration::new(msgs::NOW, 0);

        test_with_one_runtime!(|rt| async move {
            // Stub out the internet so that this connection can work.
            let network = MockNetwork::new();

            // Set up a client runtime with a given IP
            let client_rt = network
                .builder()
                .add_address(client_addr)
                .runtime(rt.clone());
            // Mock the current time too
            let client_rt = MockSleepRuntime::new(client_rt);

            // Set up a relay runtime with a different IP
            let relay_rt = network
                .builder()
                .add_address(orport.ip())
                .runtime(rt.clone());

            // open a fake TLS listener and be ready to handle a request.
            let lis = relay_rt.mock_net().listen_tls(&orport, tls_cert).unwrap();

            // Tell the client to believe in a different timestamp.
            client_rt.jump_to(now);

            // Create the channelbuilder that we want to test.
            let builder = ChanBuilder::new(client_rt);

            let (r1, r2): (Result<Arc<Channel>>, Result<LocalStream>) = futures::join!(
                async {
                    // client-side: build a channel!
                    builder.build_channel(&target).await
                },
                async {
                    // relay-side: accept the channel
                    // (and pretend to know what we're doing).
                    let (mut con, addr) = lis.accept().await?;
                    assert_eq!(client_addr, addr.ip());
                    crate::testing::answer_channel_req(&mut con).await?;
                    Ok(con)
                }
            );

            let chan = r1.unwrap();
            assert_eq!(chan.ident(), &ed);
            assert!(chan.is_usable());
            r2.unwrap();
            Ok(())
        })
    }

    // TODO: Write tests for timeout logic, once there is smarter logic.
}
