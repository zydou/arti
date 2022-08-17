//! Implement a concrete type to build channels.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use crate::{event::ChanMgrEventSender, Error};

use std::time::Duration;
use tor_error::{bad_api_usage, internal};
use tor_linkspec::{HasAddrs, HasRelayIds, OwnedChanTarget};
use tor_llcrypto::pk;
use tor_proto::channel::params::ChannelPaddingInstructionsUpdates;
use tor_rtcompat::{tls::TlsConnector, Runtime, TcpProvider, TlsProvider};

use async_trait::async_trait;
use futures::stream::FuturesUnordered;
use futures::task::SpawnExt;
use futures::StreamExt;
use futures::{FutureExt, TryFutureExt};

/// Time to wait between starting parallel connections to the same relay.
static CONNECTION_DELAY: Duration = Duration::from_millis(150);

/// TLS-based channel builder.
///
/// This is a separate type so that we can keep our channel management
/// code network-agnostic.
pub(crate) struct ChanBuilder<R: Runtime> {
    /// Asynchronous runtime for TLS, TCP, spawning, and timeouts.
    runtime: R,
    /// Used to update our bootstrap reporting status.
    event_sender: Mutex<ChanMgrEventSender>,
    /// Object to build TLS connections.
    tls_connector: <R as TlsProvider<R::TcpStream>>::Connector,
}

impl<R: Runtime> ChanBuilder<R> {
    /// Construct a new ChanBuilder.
    pub(crate) fn new(runtime: R, event_sender: ChanMgrEventSender) -> Self {
        let tls_connector = runtime.tls_connector();
        ChanBuilder {
            runtime,
            event_sender: Mutex::new(event_sender),
            tls_connector,
        }
    }
}

#[async_trait]
impl<R: Runtime> crate::mgr::ChannelFactory for ChanBuilder<R> {
    type Channel = tor_proto::channel::Channel;
    type BuildSpec = OwnedChanTarget;

    async fn build_channel(&self, target: &Self::BuildSpec) -> crate::Result<Self::Channel> {
        use tor_rtcompat::SleepProviderExt;

        // TODO: make this an option.  And make a better value.
        let five_seconds = std::time::Duration::new(5, 0);

        self.runtime
            .timeout(five_seconds, self.build_channel_notimeout(target))
            .await
            .map_err(|_| Error::ChanTimeout {
                peer: target.clone(),
            })?
    }
}

/// Connect to one of the addresses in `addrs` by running connections in parallel until one works.
///
/// This implements a basic version of RFC 8305 "happy eyeballs".
async fn connect_to_one<R: Runtime>(
    rt: &R,
    addrs: &[SocketAddr],
) -> crate::Result<(<R as TcpProvider>::TcpStream, SocketAddr)> {
    // We need *some* addresses to connect to.
    if addrs.is_empty() {
        return Err(Error::UnusableTarget(bad_api_usage!(
            "No addresses for chosen relay"
        )));
    }

    // Turn each address into a future that waits (i * CONNECTION_DELAY), then
    // attempts to connect to the address using the runtime (where i is the
    // array index). Shove all of these into a `FuturesUnordered`, polling them
    // simultaneously and returning the results in completion order.
    //
    // This is basically the concurrent-connection stuff from RFC 8305, ish.
    // TODO(eta): sort the addresses first?
    let mut connections = addrs
        .iter()
        .enumerate()
        .map(|(i, a)| {
            let delay = rt.sleep(CONNECTION_DELAY * i as u32);
            delay.then(move |_| {
                tracing::info!("Connecting to {}", a);
                rt.connect(a)
                    .map_ok(move |stream| (stream, *a))
                    .map_err(move |e| (e, *a))
            })
        })
        .collect::<FuturesUnordered<_>>();

    let mut ret = None;
    let mut errors = vec![];

    while let Some(result) = connections.next().await {
        match result {
            Ok(s) => {
                // We got a stream (and address).
                ret = Some(s);
                break;
            }
            Err((e, a)) => {
                // We got a failure on one of the streams. Store the error.
                // TODO(eta): ideally we'd start the next connection attempt immediately.
                tracing::warn!("Connection to {} failed: {}", a, e);
                errors.push((e, a));
            }
        }
    }

    // Ensure we don't continue trying to make connections.
    drop(connections);

    ret.ok_or_else(|| Error::ChannelBuild {
        addresses: errors.into_iter().map(|(e, a)| (a, Arc::new(e))).collect(),
    })
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
        {
            self.event_sender
                .lock()
                .expect("Lock poisoned")
                .record_attempt();
        }

        let (stream, addr) = connect_to_one(&self.runtime, target.addrs()).await?;
        let using_target = match target.restrict_addr(&addr) {
            Ok(v) => v,
            Err(v) => v,
        };

        let map_ioe = |action: &'static str| {
            move |ioe: io::Error| Error::Io {
                action,
                peer: addr,
                source: ioe.into(),
            }
        };

        {
            self.event_sender
                .lock()
                .expect("Lock poisoned")
                .record_tcp_success();
        }

        // TODO: add a random hostname here if it will be used for SNI?
        let tls = self
            .tls_connector
            .negotiate_unvalidated(stream, "ignored")
            .await
            .map_err(map_ioe("TLS negotiation"))?;

        let peer_cert = tls
            .peer_certificate()
            .map_err(map_ioe("TLS certs"))?
            .ok_or_else(|| Error::Internal(internal!("TLS connection with no peer certificate")))?;

        {
            self.event_sender
                .lock()
                .expect("Lock poisoned")
                .record_tls_finished();
        }

        // 2. Set up the channel.
        let mut builder = ChannelBuilder::new();
        builder.set_declared_addr(addr);
        let chan = builder
            .launch(
                tls,
                self.runtime.clone(), /* TODO provide ZST SleepProvider instead */
            )
            .connect(|| self.runtime.wallclock())
            .await
            .map_err(|e| Error::from_proto_no_skew(e, &using_target))?;
        let clock_skew = Some(chan.clock_skew()); // Not yet authenticated; can't use it till `check` is done.
        let now = self.runtime.wallclock();
        let chan = chan
            .check(target, &peer_cert, Some(now))
            .map_err(|source| match &source {
                tor_proto::Error::HandshakeCertsExpired { .. } => {
                    self.event_sender
                        .lock()
                        .expect("Lock poisoned")
                        .record_handshake_done_with_skewed_clock();
                    Error::Proto {
                        source,
                        peer: using_target,
                        clock_skew,
                    }
                }
                _ => Error::from_proto_no_skew(source, &using_target),
            })?;
        let (chan, reactor) = chan.finish().await.map_err(|source| Error::Proto {
            source,
            peer: target.clone(),
            clock_skew,
        })?;

        {
            self.event_sender
                .lock()
                .expect("Lock poisoned")
                .record_handshake_done();
        }

        // 3. Launch a task to run the channel reactor.
        self.runtime
            .spawn(async {
                let _ = reactor.run().await;
            })
            .map_err(|e| Error::from_spawn("channel reactor", e))?;
        Ok(chan)
    }
}

impl crate::mgr::AbstractChannel for tor_proto::channel::Channel {
    type Ident = pk::ed25519::Ed25519Identity;
    fn ident(&self) -> &Self::Ident {
        self.target()
            .ed_identity()
            .expect("This channel had an Ed25519 identity when we created it, but now it doesn't!?")
    }
    fn is_usable(&self) -> bool {
        !self.is_closing()
    }
    fn duration_unused(&self) -> Option<Duration> {
        self.duration_unused()
    }
    fn reparameterize(
        &mut self,
        updates: Arc<ChannelPaddingInstructionsUpdates>,
    ) -> tor_proto::Result<()> {
        self.reparameterize(updates)
    }
    fn engage_padding_activities(&self) {
        self.engage_padding_activities();
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
    use std::time::{Duration, SystemTime};
    use std::{net::SocketAddr, str::FromStr};
    use tor_proto::channel::Channel;
    use tor_rtcompat::{test_with_one_runtime, SleepProviderExt, TcpListener};
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

            // Create the channel builder that we want to test.
            let (snd, _rcv) = crate::event::channel();
            let builder = ChanBuilder::new(client_rt, snd);

            let (r1, r2): (Result<Channel>, Result<LocalStream>) = futures::join!(
                async {
                    // client-side: build a channel!
                    builder.build_channel(&target).await
                },
                async {
                    // relay-side: accept the channel
                    // (and pretend to know what we're doing).
                    let (mut con, addr) = lis.accept().await.expect("accept failed");
                    assert_eq!(client_addr, addr.ip());
                    crate::testing::answer_channel_req(&mut con)
                        .await
                        .expect("answer failed");
                    Ok(con)
                }
            );

            let chan = r1.unwrap();
            assert_eq!(chan.ident(), &ed);
            assert!(chan.is_usable());
            // In theory, time could pass here, so we can't just use
            // "assert_eq!(dur_unused, dur_unused2)".
            let dur_unused = Channel::duration_unused(&chan);
            let dur_unused_2 = AbstractChannel::duration_unused(&chan);
            let dur_unused_3 = Channel::duration_unused(&chan);
            assert!(dur_unused.unwrap() <= dur_unused_2.unwrap());
            assert!(dur_unused_2.unwrap() <= dur_unused_3.unwrap());

            r2.unwrap();
            Ok(())
        })
    }

    #[test]
    fn test_connect_one() {
        let client_addr = "192.0.1.16".parse().unwrap();
        // We'll put a "relay" at this address
        let addr1 = SocketAddr::from_str("192.0.2.17:443").unwrap();
        // We'll put nothing at this address, to generate errors.
        let addr2 = SocketAddr::from_str("192.0.3.18:443").unwrap();
        // Well put a black hole at this address, to generate timeouts.
        let addr3 = SocketAddr::from_str("192.0.4.19:443").unwrap();
        // We'll put a "relay" at this address too
        let addr4 = SocketAddr::from_str("192.0.9.9:443").unwrap();

        test_with_one_runtime!(|rt| async move {
            // Stub out the internet so that this connection can work.
            let network = MockNetwork::new();

            // Set up a client and server runtime with a given IP
            let client_rt = network
                .builder()
                .add_address(client_addr)
                .runtime(rt.clone());
            let server_rt = network
                .builder()
                .add_address(addr1.ip())
                .add_address(addr4.ip())
                .runtime(rt.clone());
            let _listener = server_rt.mock_net().listen(&addr1).await.unwrap();
            let _listener2 = server_rt.mock_net().listen(&addr4).await.unwrap();
            // TODO: Because this test doesn't mock time, there will actually be
            // delays as we wait for connections to this address to time out. It
            // would be good to use MockSleepProvider instead, once we figure
            // out how to make it both reliable and convenient.
            network.add_blackhole(addr3).unwrap();

            // No addresses? Can't succeed.
            let failure = connect_to_one(&client_rt, &[]).await;
            assert!(failure.is_err());

            // Connect to a set of addresses including addr1? That's a success.
            for addresses in [
                &[addr1][..],
                &[addr1, addr2][..],
                &[addr2, addr1][..],
                &[addr1, addr3][..],
                &[addr3, addr1][..],
                &[addr1, addr2, addr3][..],
                &[addr3, addr2, addr1][..],
            ] {
                let (_conn, addr) = connect_to_one(&client_rt, addresses).await.unwrap();
                assert_eq!(addr, addr1);
            }

            // Connect to a set of addresses including addr2 but not addr1?
            // That's an error of one kind or another.
            for addresses in [
                &[addr2][..],
                &[addr2, addr3][..],
                &[addr3, addr2][..],
                &[addr3][..],
            ] {
                let expect_timeout = addresses.contains(&addr3);
                let failure = rt
                    .timeout(
                        Duration::from_millis(300),
                        connect_to_one(&client_rt, addresses),
                    )
                    .await;
                if expect_timeout {
                    assert!(failure.is_err());
                } else {
                    assert!(failure.unwrap().is_err());
                }
            }

            // Connect to addr1 and addr4?  The first one should win.
            let (_conn, addr) = connect_to_one(&client_rt, &[addr1, addr4]).await.unwrap();
            assert_eq!(addr, addr1);
            let (_conn, addr) = connect_to_one(&client_rt, &[addr4, addr1]).await.unwrap();
            assert_eq!(addr, addr4);
        });
    }

    // TODO: Write tests for timeout logic, once there is smarter logic.
}
