//! Exit streams

use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr as _;
use std::time::Duration;

use either::Either;
use futures::io::BufReader;
use tor_cell::relaycell::msg::{BeginFlags, Connected, End, EndReason};
use tor_error::warn_report;
use tor_proto::stream::{IncomingStream, IncomingStreamRequest};
use tor_rtcompat::SleepProviderExt as _;
use tor_rtcompat::{NetStreamProvider, Runtime, TimeoutError};
use tracing::{debug, info, trace};

use crate::stream::dns::resolver::{DnsResolver, RecordData};

/// Handle an incoming exit stream.
///
/// This is expected to be called from a task dedicated to this stream,
/// so it may async-block (for example to establish the exit connection and proxy traffic).
/// It should not be used with a timeout.
pub(super) async fn handle_begin<R: Runtime>(
    runtime: R,
    incoming: IncomingStream,
    resolver: DnsResolver,
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

    // A future for everything we want to include within the timeout.
    // Returns the TCP stream, and on error returns the END reason.
    let exit_stream_fut = match IpAddr::from_str(addr) {
        Ok(addr) => {
            let addr = SocketAddr::new(addr, port);
            let fut = connect_ip(&runtime, addr, flags, &connect_options);
            Either::Left(fut)
        }
        Err(_) => {
            let fut = connect_hostname(
                &runtime,
                addr.as_bytes(),
                port,
                flags,
                resolver,
                &connect_options,
            );
            Either::Right(fut)
        }
    };

    // TODO(relay-tuning): timeout chosen arbitrarily
    let timeout = Duration::from_secs(30);
    let exit_stream = match runtime.timeout(timeout, exit_stream_fut).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(end_reason)) => {
            incoming.reject(End::new_with_reason(end_reason)).await?;
            return Ok(());
        }
        Err(TimeoutError) => {
            incoming
                .reject(End::new_with_reason(EndReason::TIMEOUT))
                .await?;
            return Ok(());
        }
    };

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

/// For a BEGIN message containing the socket address and flags,
/// attempt to connect to the address.
async fn connect_ip<R: Runtime>(
    runtime: &R,
    addr: SocketAddr,
    flags: BeginFlags,
    connect_options: &<R as NetStreamProvider<SocketAddr>>::ConnectOptions,
) -> Result<<R as NetStreamProvider<SocketAddr>>::Stream, EndReason> {
    if addr.ip().is_ipv4() && flags.contains(BeginFlags::IPV4_NOT_OKAY) {
        trace!("Rejecting incoming stream to IPv4 address since flags contains IPV4_NOT_OKAY");
        // TODO(relay): Should we use `NOROUTE` here?
        return Err(EndReason::MISC);
    }

    if addr.ip().is_ipv6() && !flags.contains(BeginFlags::IPV6_OKAY) {
        trace!("Rejecting incoming stream to IPv6 address since flags did not contain IPV6_OKAY");
        // TODO(relay): Should we use `NOROUTE` here?
        return Err(EndReason::MISC);
    }

    // TODO(relay): Need to support an exit policy. Currently we allow exits to anywhere (except
    // basic loopback checks) for testing purposes.
    if addr.ip().to_canonical().is_loopback() || addr.ip().to_canonical().is_unspecified() {
        trace!("Rejecting incoming stream to loopback address");
        return Err(EndReason::EXITPOLICY);
    }

    match runtime.connect(&addr, connect_options).await {
        Ok(x) => Ok(x),
        Err(e) => Err(io_error_kind_to_end_reason(e.kind())),
    }
}

/// For a BEGIN message containing a hostname and flags,
/// attempt to connect to the hostname.
async fn connect_hostname<R: Runtime>(
    runtime: &R,
    hostname: &[u8],
    port: u16,
    _flags: BeginFlags,
    mut resolver: DnsResolver,
    connect_options: &<R as NetStreamProvider<SocketAddr>>::ConnectOptions,
) -> Result<<R as NetStreamProvider<SocketAddr>>::Stream, EndReason> {
    // TODO(relay): We should inspect the error type more closely here.
    // For example `LookupError::NonAsciiHostname` should probably result in a
    // `EndReason::TORPROTOCOL` instead.
    let answers = match resolver.resolve(hostname).await {
        Ok(x) => x,
        Err(e) => {
            // TODO: Use `trace_report!()` once it's usable with `LookupError`.
            trace!("Name resolution for exit stream failed: {e}");
            return Err(EndReason::RESOLVEFAILED);
        }
    };

    // Remove any hostname answers.
    // We could instead error if any answers were hostnames,
    // but I don't see a reason to do that.
    let mut answers = answers.iter().filter_map(|x| match x {
        RecordData::Ip(x) => Some(x),
        RecordData::Hostname(_) => None,
    });

    // TODO(relay): We probably (maybe?) want to be able to do happy eyeballs
    // with the first IPv4 and first IPv6 addresses listed.
    // We should find a way to resuse our existing happy eyeballs code.
    // https://gitlab.torproject.org/tpo/core/arti/-/work_items/2510
    // TODO(relay): Need to take `BeginFlags::IPV6_PREFERRED`
    // (and other flags) into account here.
    // https://spec.torproject.org/tor-spec/opening-streams.html

    // Until we implement the above TODOs, just take the first answer.
    // TODO(relay): Don't just use the first answer.
    let addr = match answers.next() {
        Some(ip) => ip,
        None => {
            trace!("Rejecting incoming stream since the domain resolution had no IP answers");
            return Err(EndReason::RESOLVEFAILED);
        }
    };

    let addr = SocketAddr::new(*addr, port);

    // TODO(relay): Need to support an exit policy. Currently we allow exits to anywhere (except
    // basic loopback checks) for testing purposes.
    if addr.ip().to_canonical().is_loopback() || addr.ip().to_canonical().is_unspecified() {
        trace!("Rejecting incoming stream to loopback address");
        return Err(EndReason::EXITPOLICY);
    }

    match runtime.connect(&addr, connect_options).await {
        Ok(x) => Ok(x),
        Err(e) => Err(io_error_kind_to_end_reason(e.kind())),
    }
}

/// For a TCP error, get the reason we should use in the END message.
fn io_error_kind_to_end_reason(e: ErrorKind) -> EndReason {
    // TODO(relay): Check if there are other error kinds to map to end reasons.
    match e {
        ErrorKind::ConnectionRefused => EndReason::CONNECTREFUSED,
        ErrorKind::ConnectionReset => EndReason::CONNRESET,
        _ => EndReason::MISC,
    }
}
