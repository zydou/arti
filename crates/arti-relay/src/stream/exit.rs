//! Exit streams

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr as _;
use std::time::Duration;

use futures::io::BufReader;
use tor_cell::relaycell::msg::{BeginFlags, Connected, End, EndReason};
use tor_error::warn_report;
use tor_proto::stream::{IncomingStream, IncomingStreamRequest};
use tor_rtcompat::Runtime;
use tor_rtcompat::SleepProviderExt as _;
use tracing::{debug, info, trace};

/// Handle an incoming exit stream.
///
/// This is expected to be called from a task dedicated to this stream,
/// so it may async-block (for example to establish the exit connection and proxy traffic).
/// It should not be used with a timeout.
pub(super) async fn handle_begin<R: Runtime>(
    runtime: R,
    incoming: IncomingStream,
) -> anyhow::Result<()> {
    let connect_options = Default::default();

    // It would be nice to have a better API on `IncomingStream`
    // so that we don't need this extra match.
    let msg = match incoming.request() {
        IncomingStreamRequest::Begin(msg) => msg,
        s => {
            return Err(anyhow::anyhow!(
                "unexpected stream request type {s:?}; should be unreachable"
            ));
        }
    };

    // TODO(relay): This is temporary. Remove this once we have exit policy support.
    // This is to help prevent us from accidentally running a public exit while we're testing.
    match std::env::var("ARTI_EXIT") {
        Ok(val) if val.trim() == "1" => {}
        _ => {
            info!("Rejecting incoming stream since `ARTI_EXIT` env variable is not set to '1'");
            return Ok(());
        }
    }

    // Assign these to local variables to ensure we use all of them.
    let (addr, port, flags) = (msg.addr(), msg.port(), msg.flags());

    if port == 0 {
        incoming
            .reject(End::new_with_reason(EndReason::EXITPOLICY))
            .await?;
        debug!("Rejecting incoming stream with 0 port");
        return Ok(());
    }

    // TODO(relay): It would be good to parse this in a more principled way.
    // More specifically, the parsing/decoding should probably be handled by `Begin` in tor-cell
    // that ensures that it's parsed according to the spec.
    // See https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/4421.
    let Ok(addr) = std::str::from_utf8(addr) else {
        incoming
            .reject(End::new_with_reason(EndReason::TORPROTOCOL))
            .await?;
        debug!("Rejecting incoming stream with non-utf8 address");
        return Ok(());
    };

    let exit_stream_fut = match IpAddr::from_str(addr) {
        Ok(addr) => {
            if addr.is_ipv4() && flags.contains(BeginFlags::IPV4_NOT_OKAY) {
                // TODO(relay): Should we use `NOROUTE` here?
                incoming.reject(End::new_misc()).await?;
                trace!(
                    "Rejecting incoming stream to IPv4 address since flags contains IPV4_NOT_OKAY",
                );
                return Ok(());
            }

            if addr.is_ipv6() && !flags.contains(BeginFlags::IPV6_OKAY) {
                // TODO(relay): Should we use `NOROUTE` here?
                incoming.reject(End::new_misc()).await?;
                trace!(
                    "Rejecting incoming stream to IPv6 address since flags did not contain IPV6_OKAY",
                );
                return Ok(());
            }

            // TODO(relay): Need to support an exit policy. Currently we allow exits to anywhere (except
            // basic loopback checks) for testing purposes.
            if addr.to_canonical().is_loopback() || addr.to_canonical().is_unspecified() {
                incoming
                    .reject(End::new_with_reason(EndReason::EXITPOLICY))
                    .await?;
                trace!("Rejecting incoming stream to loopback address");
                return Ok(());
            }

            let addr = SocketAddr::new(addr, port);

            let runtime = &runtime;
            async move { runtime.connect(&addr, &connect_options).await }
        }
        Err(_) => {
            // TODO(relay): Once we can look up hostnames,
            // we'll probably (maybe?) want to be able to do happy eyeballs with both addresses.
            // We should find a way to resuse our existing happy eyeballs code.
            // https://gitlab.torproject.org/tpo/core/arti/-/work_items/2510
            // TODO(relay): Need to take `BeginFlags::IPV6_PREFERRED` (and other flags) into account here.
            // https://spec.torproject.org/tor-spec/opening-streams.html
            todo!()
        }
    };

    // TODO(relay-tuning): timeout chosen arbitrarily
    let timeout = Duration::from_secs(30);
    let exit_stream = runtime.timeout(timeout, exit_stream_fut).await??;

    let tor_stream = incoming.accept_data(Connected::new_empty()).await?;

    // TODO(relay-tuning): copied from arti
    const STREAM_BUF_LEN: usize = 4096;
    let exit_stream = BufReader::with_capacity(STREAM_BUF_LEN, exit_stream);
    let tor_stream = BufReader::with_capacity(STREAM_BUF_LEN, tor_stream);

    let res = futures_copy::copy_buf_bidirectional(
        tor_stream,
        exit_stream,
        futures_copy::eof::Close,
        futures_copy::eof::Close,
    )
    .await;

    match res {
        Ok((tor_to_exit, exit_to_tor)) => {
            trace!(
                count_fwd = tor_to_exit,
                count_bwd = exit_to_tor,
                "Stream bidirectional copy finished",
            );
        }
        // TODO(relay): arti does something complicated here; see `report_proxy_error()`
        Err(e) => {
            warn_report!(e, "Error while proxying data on exit stream");
        }
    }

    Ok(())
}
