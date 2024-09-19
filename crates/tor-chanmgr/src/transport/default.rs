//! Implement the default transport, which opens TCP connections using a
//! happy-eyeballs style parallel algorithm.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use async_trait::async_trait;
use futures::{stream::FuturesUnordered, FutureExt, StreamExt, TryFutureExt};
use safelog::sensitive as sv;
use tor_error::bad_api_usage;
use tor_linkspec::{ChannelMethod, HasChanMethod, OwnedChanTarget};
use tor_rtcompat::{NetStreamProvider, Runtime};
use tracing::trace;

use crate::Error;

/// A default transport object that opens TCP connections for a
/// `ChannelMethod::Direct`.
///
/// It opens almost-simultaneous parallel TCP connections to each address, and
/// chooses the first one to succeed.
#[derive(Clone, Debug)]
pub(crate) struct DefaultTransport<R: Runtime> {
    /// The runtime that we use for connecting.
    runtime: R,
}

impl<R: Runtime> DefaultTransport<R> {
    /// Construct a new DefaultTransport
    pub(crate) fn new(runtime: R) -> Self {
        Self { runtime }
    }
}

#[async_trait]
impl<R: Runtime> crate::transport::TransportImplHelper for DefaultTransport<R> {
    type Stream = <R as NetStreamProvider>::Stream;

    /// Implements the transport: makes a TCP connection (possibly
    /// tunneled over whatever protocol) if possible.
    async fn connect(
        &self,
        target: &OwnedChanTarget,
    ) -> crate::Result<(OwnedChanTarget, Self::Stream)> {
        let direct_addrs: Vec<_> = match target.chan_method() {
            ChannelMethod::Direct(addrs) => addrs,
            #[allow(unreachable_patterns)]
            _ => {
                return Err(Error::UnusableTarget(bad_api_usage!(
                    "Used default transport implementation for an unsupported transport."
                )))
            }
        };

        trace!("Launching direct connection for {}", target);

        let (stream, addr) = connect_to_one(&self.runtime, &direct_addrs).await?;
        let mut using_target = target.clone();
        let _ignore = using_target.chan_method_mut().retain_addrs(|a| a == &addr);

        Ok((using_target, stream))
    }
}

/// Time to wait between starting parallel connections to the same relay.
static CONNECTION_DELAY: Duration = Duration::from_millis(150);

/// Connect to one of the addresses in `addrs` by running connections in parallel until one works.
///
/// This implements a basic version of RFC 8305 "happy eyeballs".
async fn connect_to_one<R: Runtime>(
    rt: &R,
    addrs: &[SocketAddr],
) -> crate::Result<(<R as NetStreamProvider>::Stream, SocketAddr)> {
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
                tracing::debug!("Connecting to {}", a);
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
                tor_error::warn_report!(e, "Connection to {} failed", sv(a));
                errors.push((e, a));
            }
        }
    }

    // Ensure we don't continue trying to make connections.
    drop(connections);

    ret.ok_or_else(|| Error::ChannelBuild {
        addresses: errors
            .into_iter()
            .map(|(e, a)| (sv(a), Arc::new(e)))
            .collect(),
    })
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
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use std::str::FromStr;

    use tor_rtcompat::{test_with_one_runtime, SleepProviderExt};
    use tor_rtmock::net::MockNetwork;

    use super::*;

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
}
