//! Implement a concrete type to build channels over a transport.

use std::io;
use std::sync::{Arc, Mutex};

use crate::factory::{BootstrapReporter, ChannelFactory, IncomingChannelFactory};
use crate::transport::TransportImplHelper;
use crate::{Error, event::ChanMgrEventSender};

use async_trait::async_trait;
use std::time::Duration;
use tor_basic_utils::rand_hostname;
use tor_error::internal;
use tor_linkspec::{BridgeAddr, HasChanMethod, IntoOwnedChanTarget, OwnedChanTarget};
use tor_proto::channel::ChannelType;
use tor_proto::channel::kist::KistParams;
use tor_proto::channel::params::ChannelPaddingInstructionsUpdates;
use tor_proto::memquota::ChannelAccount;
use tor_rtcompat::SpawnExt;
use tor_rtcompat::{Runtime, TlsProvider, tls::TlsConnector};
use tracing::instrument;

#[cfg(feature = "relay")]
use {safelog::Sensitive, std::net::IpAddr, tor_proto::RelayIdentities};

/// TLS-based channel builder.
///
/// This is a separate type so that we can keep our channel management code
/// network-agnostic.
///
/// It uses a provided `TransportHelper` type to make a connection (possibly
/// directly over TCP, and possibly over some other protocol).  It then
/// negotiates TLS over that connection, and negotiates a Tor channel over that
/// TLS session.
///
/// This channel builder does not retry on failure, but it _does_ implement a
/// time-out.
pub struct ChanBuilder<R: Runtime, H: TransportImplHelper>
where
    R: tor_rtcompat::TlsProvider<H::Stream>,
{
    /// Asynchronous runtime for TLS, TCP, spawning, and timeouts.
    runtime: R,
    /// The transport object that we use to construct streams.
    transport: H,
    /// Object to build TLS connections.
    tls_connector: <R as TlsProvider<H::Stream>>::Connector,
    /// Relay identities needed for relay channels.
    #[cfg(feature = "relay")]
    identities: Option<Arc<RelayIdentities>>,
}

impl<R: Runtime, H: TransportImplHelper> ChanBuilder<R, H>
where
    R: TlsProvider<H::Stream>,
{
    /// Construct a new ChanBuilder.
    pub fn new(runtime: R, transport: H) -> Self {
        let tls_connector = <R as TlsProvider<H::Stream>>::tls_connector(&runtime);
        ChanBuilder {
            runtime,
            transport,
            tls_connector,
            #[cfg(feature = "relay")]
            identities: None,
        }
    }

    /// Set the relay identities and return itself.
    #[cfg(feature = "relay")]
    pub fn with_identities(mut self, ids: Arc<RelayIdentities>) -> Self {
        self.identities = Some(ids);
        self
    }

    /// Return the outbound channel type of this config.
    ///
    /// The channel type is used when creating outbound channels. Relays always initiate channels
    /// as "relay initiator" while client and bridges behave like a "client initiator".
    ///
    /// Important: The wrong channel type is returned if this is called before `with_identities()`
    /// is called.
    fn outbound_chan_type(&self) -> ChannelType {
        #[cfg(feature = "relay")]
        if self.identities.is_some() {
            return ChannelType::RelayInitiator;
        }
        // No relay built in, always client.
        ChannelType::ClientInitiator
    }
}

#[async_trait]
impl<R: Runtime, H: TransportImplHelper> ChannelFactory for ChanBuilder<R, H>
where
    R: tor_rtcompat::TlsProvider<H::Stream> + Send + Sync,
    H: Send + Sync,
{
    #[instrument(skip_all, level = "trace")]
    async fn connect_via_transport(
        &self,
        target: &OwnedChanTarget,
        reporter: BootstrapReporter,
        memquota: ChannelAccount,
    ) -> crate::Result<Arc<tor_proto::channel::Channel>> {
        use tor_rtcompat::SleepProviderExt;

        // TODO: make this an option.  And make a better value.
        let delay = if target.chan_method().is_direct() {
            std::time::Duration::new(5, 0)
        } else {
            std::time::Duration::new(10, 0)
        };

        self.runtime
            .timeout(delay, self.connect_no_timeout(target, reporter.0, memquota))
            .await
            .map_err(|_| Error::ChanTimeout {
                peer: target.to_logged(),
            })?
    }
}

#[async_trait]
impl<R: Runtime, H: TransportImplHelper> IncomingChannelFactory for ChanBuilder<R, H>
where
    R: tor_rtcompat::TlsProvider<H::Stream> + Send + Sync,
    H: Send + Sync,
{
    type Stream = H::Stream;

    #[cfg(feature = "relay")]
    async fn accept_from_transport(
        &self,
        peer: Sensitive<std::net::SocketAddr>,
        _my_addrs: Vec<IpAddr>,
        stream: Self::Stream,
        _memquota: ChannelAccount,
    ) -> crate::Result<Arc<tor_proto::channel::Channel>> {
        let map_ioe = |ioe, action| Error::Io {
            action,
            peer: Some(BridgeAddr::new_addr_from_sockaddr(peer.into_inner()).into()),
            source: ioe,
        };

        let _tls = self
            .tls_connector
            .negotiate_unvalidated(stream, "ignored")
            .await
            .map_err(|e| map_ioe(e.into(), "TLS negotiation"))?;

        // TODO RELAY: do handshake and build channel
        todo!();
    }
}

impl<R: Runtime, H: TransportImplHelper> ChanBuilder<R, H>
where
    R: tor_rtcompat::TlsProvider<H::Stream> + Send + Sync,
    H: Send + Sync,
{
    /// Perform the work of `connect_via_transport`, but without enforcing a timeout.
    ///
    /// Return a [`Channel`](tor_proto::channel::Channel) on success.
    #[instrument(skip_all, level = "trace")]
    async fn connect_no_timeout(
        &self,
        target: &OwnedChanTarget,
        event_sender: Arc<Mutex<ChanMgrEventSender>>,
        memquota: ChannelAccount,
    ) -> crate::Result<Arc<tor_proto::channel::Channel>> {
        use tor_rtcompat::tls::CertifiedConn;

        {
            event_sender.lock().expect("Lock poisoned").record_attempt();
        }

        // 1a. Negotiate the TCP connection or other stream.

        let (using_target, stream) = self.transport.connect(target).await?;
        let using_method = using_target.chan_method();
        let peer = using_method.target_addr();
        let peer_ref = &peer;

        let map_ioe = |action: &'static str| {
            let peer: Option<BridgeAddr> = peer_ref.as_ref().and_then(|peer| {
                let peer: Option<BridgeAddr> = peer.clone().into();
                peer
            });
            move |ioe: io::Error| Error::Io {
                action,
                peer: peer.map(Into::into),
                source: ioe.into(),
            }
        };

        {
            // TODO(nickm): At some point, it would be helpful to the
            // bootstrapping logic if we could distinguish which
            // transport just succeeded.
            event_sender
                .lock()
                .expect("Lock poisoned")
                .record_tcp_success();
        }

        // 1b. Negotiate TLS.

        let hostname = rand_hostname::random_hostname(&mut rand::rng());

        let tls = self
            .tls_connector
            .negotiate_unvalidated(stream, hostname.as_str())
            .await
            .map_err(map_ioe("TLS negotiation"))?;

        let peer_cert = tls
            .peer_certificate()
            .map_err(map_ioe("TLS certs"))?
            .ok_or_else(|| Error::Internal(internal!("TLS connection with no peer certificate")))?;

        {
            event_sender
                .lock()
                .expect("Lock poisoned")
                .record_tls_finished();
        }

        // Store this so we can log it in case we don't recognize it.
        let outbound_chan_type = self.outbound_chan_type();
        let chan = match outbound_chan_type {
            ChannelType::ClientInitiator => {
                // Get the client specific channel builder.
                let mut builder = tor_proto::ClientChannelBuilder::new();
                builder.set_declared_method(target.chan_method());

                builder
                    .launch(
                        tls,
                        self.runtime.clone(), /* TODO provide ZST SleepProvider instead */
                        memquota,
                    )
                    .connect(|| self.runtime.wallclock())
                    .await
                    .map_err(|e| Error::from_proto_no_skew(e, target))?
            }
            #[cfg(feature = "relay")]
            ChannelType::RelayInitiator => {
                let builder = tor_proto::RelayChannelBuilder::new();
                let identities = self
                    .identities
                    .as_ref()
                    .ok_or(internal!(
                        "Unable to build relay channel without identities"
                    ))?
                    .clone();

                // TODO(relay): Get the my_addrs from ChanBuilder or as function param.
                let my_addrs = Vec::new();
                builder
                    .launch(
                        tls,
                        self.runtime.clone(), /* TODO provide ZST SleepProvider instead */
                        identities,
                        my_addrs,
                        memquota,
                    )
                    .connect(|| self.runtime.wallclock())
                    .await
                    .map_err(|e| Error::from_proto_no_skew(e, &using_target))?
            }
            _ => {
                return Err(Error::Internal(internal!(
                    "Unusable channel type for outbound: {outbound_chan_type}",
                )));
            }
        };

        let clock_skew = Some(chan.clock_skew()); // Not yet authenticated; can't use it till `check` is done.
        let now = self.runtime.wallclock();
        let chan = chan
            .check(target, &peer_cert, Some(now))
            .map_err(|source| match &source {
                tor_proto::Error::HandshakeCertsExpired { .. } => {
                    event_sender
                        .lock()
                        .expect("Lock poisoned")
                        .record_handshake_done_with_skewed_clock();
                    Error::Proto {
                        source,
                        peer: using_target.to_logged(),
                        clock_skew,
                    }
                }
                _ => Error::from_proto_no_skew(source, &using_target),
            })?;
        let (chan, reactor) = chan.finish().await.map_err(|source| Error::Proto {
            source,
            peer: target.to_logged(),
            clock_skew,
        })?;

        {
            event_sender
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
    fn is_usable(&self) -> bool {
        !self.is_closing()
    }
    fn duration_unused(&self) -> Option<Duration> {
        self.duration_unused()
    }
    fn reparameterize(
        &self,
        updates: Arc<ChannelPaddingInstructionsUpdates>,
    ) -> tor_proto::Result<()> {
        tor_proto::channel::Channel::reparameterize(self, updates)
    }
    fn reparameterize_kist(&self, kist_params: KistParams) -> tor_proto::Result<()> {
        tor_proto::channel::Channel::reparameterize_kist(self, kist_params)
    }
    fn engage_padding_activities(&self) {
        tor_proto::channel::Channel::engage_padding_activities(self);
    }
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    use crate::{
        Result,
        mgr::{AbstractChannel, AbstractChannelFactory},
    };
    use futures::StreamExt as _;
    use std::net::SocketAddr;
    use std::time::{Duration, SystemTime};
    use tor_linkspec::{ChannelMethod, HasRelayIds, RelayIdType};
    use tor_llcrypto::pk::ed25519::Ed25519Identity;
    use tor_llcrypto::pk::rsa::RsaIdentity;
    use tor_proto::channel::Channel;
    use tor_proto::memquota::{ChannelAccount, SpecificAccount as _};
    use tor_rtcompat::{NetStreamListener, test_with_one_runtime};
    use tor_rtmock::{io::LocalStream, net::MockNetwork};

    #[allow(deprecated)] // TODO #1885
    use tor_rtmock::MockSleepRuntime;

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
        let target = OwnedChanTarget::builder()
            .addrs(vec![orport])
            .method(ChannelMethod::Direct(vec![orport]))
            .ed_identity(ed)
            .rsa_identity(rsa)
            .build()
            .unwrap();
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
            #[allow(deprecated)] // TODO #1885
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
            let transport = crate::transport::DefaultTransport::new(client_rt.clone());
            let builder = ChanBuilder::new(client_rt, transport);

            let (r1, r2): (Result<Arc<Channel>>, Result<LocalStream>) = futures::join!(
                async {
                    // client-side: build a channel!
                    builder
                        .build_channel(
                            &target,
                            BootstrapReporter::fake(),
                            ChannelAccount::new_noop(),
                        )
                        .await
                },
                async {
                    // relay-side: accept the channel
                    // (and pretend to know what we're doing).
                    let (mut con, addr) = lis
                        .incoming()
                        .next()
                        .await
                        .expect("Closed?")
                        .expect("accept failed");
                    assert_eq!(client_addr, addr.ip());
                    crate::testing::answer_channel_req(&mut con)
                        .await
                        .expect("answer failed");
                    Ok(con)
                }
            );

            let chan = r1.unwrap();
            assert_eq!(chan.identity(RelayIdType::Ed25519), Some((&ed).into()));
            assert!(chan.is_usable());
            // In theory, time could pass here, so we can't just use
            // "assert_eq!(dur_unused, dur_unused2)".
            let dur_unused = Channel::duration_unused(&chan);
            let dur_unused_2 = AbstractChannel::duration_unused(chan.as_ref());
            let dur_unused_3 = Channel::duration_unused(&chan);
            assert!(dur_unused.unwrap() <= dur_unused_2.unwrap());
            assert!(dur_unused_2.unwrap() <= dur_unused_3.unwrap());

            r2.unwrap();
            Ok(())
        })
    }

    // TODO: Write tests for timeout logic, once there is smarter logic.
}
