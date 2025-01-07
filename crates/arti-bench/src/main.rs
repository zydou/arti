//! A simple benchmarking utility for Arti.
//!
//! This works by establishing a simple TCP server, and having Arti connect back to it via
//! a `chutney` network of Tor nodes, benchmarking the upload and download bandwidth while doing so.

// @@ begin lint list maintained by maint/add_warning @@
#![allow(renamed_and_removed_lints)] // @@REMOVE_WHEN(ci_arti_stable)
#![allow(unknown_lints)] // @@REMOVE_WHEN(ci_arti_nightly)
#![warn(missing_docs)]
#![warn(noop_method_call)]
#![warn(unreachable_pub)]
#![warn(clippy::all)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::checked_conversions)]
#![warn(clippy::cognitive_complexity)]
#![deny(clippy::debug_assert_with_mut_call)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::expl_impl_clone_on_copy)]
#![deny(clippy::fallible_impl_from)]
#![deny(clippy::implicit_clone)]
#![deny(clippy::large_stack_arrays)]
#![warn(clippy::manual_ok_or)]
#![deny(clippy::missing_docs_in_private_items)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![deny(clippy::print_stderr)]
#![deny(clippy::print_stdout)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unchecked_duration_subtraction)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::mod_module_files)]
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
#![allow(clippy::result_large_err)] // temporary workaround for arti#587
#![allow(clippy::needless_raw_string_hashes)] // complained-about code is fine, often best
#![allow(clippy::needless_lifetimes)] // See arti#1765
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->
// This file uses `unwrap()` a fair deal, but this is fine in test/bench code
// because it's OK if tests and benchmarks simply crash if things go wrong.
#![allow(clippy::unwrap_used)]

use anyhow::{anyhow, Result};
use arti::cfg::ArtiCombinedConfig;
use arti_client::{IsolationToken, TorAddr, TorClient, TorClientConfig};
use clap::{value_parser, Arg, ArgAction};
use futures::StreamExt;
use rand::distributions::Standard;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::OsString;
use std::fmt;
use std::fmt::Formatter;
use std::future::Future;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::SystemTime;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_socks::tcp::Socks5Stream;
use tor_config::{ConfigurationSource, ConfigurationSources};
use tor_rtcompat::Runtime;
use tracing::info;

/// Generate a random payload of bytes of the given size
fn random_payload(size: usize) -> Vec<u8> {
    rand::thread_rng()
        .sample_iter(Standard)
        .take(size)
        .collect()
}

/// Timing information from the benchmarking server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerTiming {
    /// When the connection was accepted.
    accepted_ts: SystemTime,
    /// When the payload was successfully written to the client.
    copied_ts: SystemTime,
    /// When the server received the first byte from the client.
    first_byte_ts: SystemTime,
    /// When the server finished reading the client's payload.
    read_done_ts: SystemTime,
}

/// Timing information from the benchmarking client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientTiming {
    /// When the client's connection succeeded.
    started_ts: SystemTime,
    /// When the client received the first byte from the server.
    first_byte_ts: SystemTime,
    /// When the client finished reading the server's payload.
    read_done_ts: SystemTime,
    /// When the payload was successfully written to the server.
    copied_ts: SystemTime,
    /// The server's copy of the timing information.
    server: ServerTiming,
    /// The size of the payload downloaded from the server.
    download_size: usize,
    /// The size of the payload uploaded to the server.
    upload_size: usize,
}

/// A summary of benchmarking results, generated from `ClientTiming`.
#[derive(Debug, Copy, Clone, Serialize)]
pub struct TimingSummary {
    /// The time to first byte (TTFB) for the download benchmark.
    download_ttfb_sec: f64,
    /// The average download speed, in megabits per second.
    download_rate_megabit: f64,
    /// The time to first byte (TTFB) for the upload benchmark.
    upload_ttfb_sec: f64,
    /// The average upload speed, in megabits per second.
    upload_rate_megabit: f64,
}

impl fmt::Display for TimingSummary {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:.2} Mbit/s up (ttfb {:.2}ms), {:.2} Mbit/s down (ttfb {:.2}ms)",
            self.upload_rate_megabit,
            self.upload_ttfb_sec * 1000.0,
            self.download_rate_megabit,
            self.download_ttfb_sec * 1000.0
        )
    }
}

impl TimingSummary {
    /// Generate a `TimingSummary` from the `ClientTiming` returned by a benchmark run.
    pub fn generate(ct: &ClientTiming) -> Result<Self> {
        let download_ttfb = ct.first_byte_ts.duration_since(ct.server.accepted_ts)?;
        let download_time = ct.read_done_ts.duration_since(ct.first_byte_ts)?;
        let download_rate_bps = ct.download_size as f64 / download_time.as_secs_f64();

        let upload_ttfb = ct.server.first_byte_ts.duration_since(ct.read_done_ts)?;
        let upload_time = ct
            .server
            .read_done_ts
            .duration_since(ct.server.first_byte_ts)?;
        let upload_rate_bps = ct.upload_size as f64 / upload_time.as_secs_f64();

        Ok(Self {
            download_ttfb_sec: download_ttfb.as_secs_f64(),
            download_rate_megabit: download_rate_bps / 125_000.0,
            upload_ttfb_sec: upload_ttfb.as_secs_f64(),
            upload_rate_megabit: upload_rate_bps / 125_000.0,
        })
    }
}

/// How much should we be willing to read at a time?
const RECV_BUF_LEN: usize = 8192;

/// Run the timing routine
#[allow(clippy::cognitive_complexity)]
fn run_timing(mut stream: TcpStream, send: &Arc<[u8]>, receive: &Arc<[u8]>) -> Result<()> {
    let peer_addr = stream.peer_addr()?;
    let mut received = vec![0_u8; RECV_BUF_LEN];
    let expected_len = receive.len();
    let mut expected = receive.deref();
    let mut mismatch = false;
    let mut total_read = 0;

    info!("Accepted connection from {}", peer_addr);
    let accepted_ts = SystemTime::now();
    let mut data: &[u8] = send.deref();
    let copied = std::io::copy(&mut data, &mut stream)?;
    stream.flush()?;
    let copied_ts = SystemTime::now();
    assert_eq!(copied, send.len() as u64);
    info!("Copied {} bytes payload to {}.", copied, peer_addr);
    let read = stream.read(&mut received)?;
    if read == 0 {
        panic!("unexpected EOF");
    }
    let first_byte_ts = SystemTime::now();
    if received[0..read] != expected[0..read] {
        mismatch = true;
    }
    expected = &expected[read..];
    total_read += read;
    while total_read < expected_len {
        let read = stream.read(&mut received)?;
        if read == 0 {
            panic!("unexpected eof");
        }
        if received[0..read] != expected[0..read] {
            mismatch = true;
        }
        expected = &expected[read..];
        total_read += read;
    }
    let read_done_ts = SystemTime::now();
    info!("Received {} bytes payload from {}.", total_read, peer_addr);
    // Check we actually got what we thought we would get.
    if mismatch {
        panic!("Received data doesn't match expected; potential corruption?");
    }
    let st = ServerTiming {
        accepted_ts,
        copied_ts,
        first_byte_ts,
        read_done_ts,
    };
    serde_json::to_writer(&mut stream, &st)?;
    info!("Wrote timing payload to {}.", peer_addr);
    Ok(())
}

/// Runs the benchmarking TCP server, using the provided TCP listener and set of payloads.
fn serve_payload(
    listener: &TcpListener,
    send: &Arc<[u8]>,
    receive: &Arc<[u8]>,
) -> Vec<JoinHandle<Result<()>>> {
    info!("Listening for clients...");

    listener
        .incoming()
        .map(|stream| {
            let send = Arc::clone(send);
            let receive = Arc::clone(receive);
            std::thread::spawn(move || run_timing(stream?, &send, &receive))
        })
        .collect()
}

/// Runs the benchmarking client on the provided socket.
async fn client<S: AsyncRead + AsyncWrite + Unpin>(
    mut socket: S,
    send: Arc<[u8]>,
    receive: Arc<[u8]>,
) -> Result<ClientTiming> {
    // Do this potentially costly allocation before we do all the timing stuff.
    let mut received = vec![0_u8; receive.len()];
    let started_ts = SystemTime::now();

    let read = socket.read(&mut received).await?;
    if read == 0 {
        return Err(anyhow!("unexpected EOF"));
    }
    let first_byte_ts = SystemTime::now();
    socket.read_exact(&mut received[read..]).await?;
    let read_done_ts = SystemTime::now();
    info!("Received {} bytes payload.", received.len());
    let mut send_data = &send as &[u8];

    tokio::io::copy(&mut send_data, &mut socket).await?;
    socket.flush().await?;
    info!("Sent {} bytes payload.", send.len());
    let copied_ts = SystemTime::now();

    // Check we actually got what we thought we would get.
    if received != receive.deref() {
        panic!("Received data doesn't match expected; potential corruption?");
    }
    let mut json_buf = Vec::new();
    socket.read_to_end(&mut json_buf).await?;
    let server: ServerTiming = serde_json::from_slice(&json_buf)?;
    Ok(ClientTiming {
        started_ts,
        first_byte_ts,
        read_done_ts,
        copied_ts,
        server,
        download_size: receive.len(),
        upload_size: send.len(),
    })
}

#[allow(clippy::cognitive_complexity)]
fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let matches = clap::Command::new("arti-bench")
        .version(env!("CARGO_PKG_VERSION"))
        .author("The Tor Project Developers")
        .about("A simple benchmarking utility for Arti.")
        .arg(
            Arg::new("arti-config")
                .short('c')
                .long("arti-config")
                .action(ArgAction::Set)
                .required(true)
                .value_name("CONFIG")
                .value_parser(value_parser!(OsString))
                .help(
                    "Path to the Arti configuration to use (usually, a Chutney-generated config).",
                ),
        )
        .arg(
            Arg::new("num-samples")
                .short('s')
                .long("num-samples")
                .action(ArgAction::Set)
                .value_name("COUNT")
                .value_parser(value_parser!(usize))
                .default_value("3")
                .help("How many samples to take per benchmark run.")
        )
        .arg(
            Arg::new("num-streams")
                .short('p')
                .long("streams")
                .aliases(["num-parallel"])
                .action(ArgAction::Set)
                .value_name("COUNT")
                .value_parser(value_parser!(usize))
                .default_value("3")
                .help("How many simultaneous streams per circuit.")
        )
        .arg(
            Arg::new("num-circuits")
                .short('C')
                .long("num-circuits")
                .action(ArgAction::Set)
                .value_name("COUNT")
                .value_parser(value_parser!(usize))
                .default_value("1")
                .help("How many simultaneous circuits per run.")
        )
        .arg(
            Arg::new("output")
                .short('o')
                .action(ArgAction::Set)
                .value_name("/path/to/output.json")
                .help("A path to write benchmark results to, in JSON format.")
        )
        .arg(
            Arg::new("download-bytes")
                .short('d')
                .long("download-bytes")
                .action(ArgAction::Set)
                .value_name("SIZE")
                .value_parser(value_parser!(usize))
                .default_value("10485760")
                .help("How much fake payload data to generate for the download benchmark."),
        )
        .arg(
            Arg::new("upload-bytes")
                .short('u')
                .long("upload-bytes")
                .action(ArgAction::Set)
                .value_name("SIZE")
                .value_parser(value_parser!(usize))
                .default_value("10485760")
                .help("How much fake payload data to generate for the upload benchmark."),
        )
        .arg(
            Arg::new("socks-proxy")
                .long("socks5")
                .action(ArgAction::Set)
                .value_name("addr:port")
                .help("SOCKS5 proxy address for a node to benchmark through as well (usually a Chutney node). Optional."),
        )
        .get_matches();
    info!("Parsing Arti configuration...");
    let mut config_sources = ConfigurationSources::new_empty();
    matches
        .get_many::<OsString>("arti-config")
        .unwrap_or_default()
        .for_each(|f| {
            config_sources.push_source(
                ConfigurationSource::from_path(f),
                tor_config::sources::MustRead::MustRead,
            );
        });

    // TODO really we ought to get this from the arti configuration, or something.
    // But this is OK for now since we are a benchmarking tool.
    let mistrust = fs_mistrust::Mistrust::new_dangerously_trust_everyone();
    config_sources.set_mistrust(mistrust);

    let cfg = config_sources.load()?;
    let (_config, tcc) = tor_config::resolve::<ArtiCombinedConfig>(cfg)?;
    info!("Binding local TCP listener...");
    let listener = TcpListener::bind("0.0.0.0:0")?;
    let local_addr = listener.local_addr()?;
    let connect_addr = SocketAddr::new(IpAddr::from_str("127.0.0.1").unwrap(), local_addr.port());
    info!("Bound to {}.", local_addr);
    let upload_bytes = *matches.get_one::<usize>("upload-bytes").unwrap();
    let download_bytes = *matches.get_one::<usize>("download-bytes").unwrap();
    let samples = *matches.get_one::<usize>("num-samples").unwrap();
    let streams_per_circ = *matches.get_one::<usize>("num-streams").unwrap();
    let circs_per_sample = *matches.get_one::<usize>("num-circuits").unwrap();
    info!("Generating test payloads, please wait...");
    let upload_payload = random_payload(upload_bytes).into();
    let download_payload = random_payload(download_bytes).into();
    info!(
        "Generated payloads ({} upload, {} download)",
        upload_bytes, download_bytes
    );
    let up = Arc::clone(&upload_payload);
    let dp = Arc::clone(&download_payload);
    let _handle = std::thread::spawn(move || -> Result<()> {
        serve_payload(&listener, &dp, &up)
            .into_iter()
            .try_for_each(|handle| handle.join().expect("failed to join thread"))
    });

    let mut benchmark = Benchmark {
        connect_addr,
        samples,
        streams_per_circ,
        circs_per_sample,
        upload_payload,
        download_payload,
        runtime: tor_rtcompat::tokio::TokioNativeTlsRuntime::create()?,
        results: Default::default(),
    };

    benchmark.without_arti()?;
    if let Some(addr) = matches.get_one::<String>("socks-proxy") {
        benchmark.with_proxy(addr)?;
    }
    benchmark.with_arti(tcc)?;

    info!("Benchmarking complete.");

    for (ty, results) in benchmark.results.iter() {
        info!(
            "Information for benchmark type {:?} ({} samples taken):",
            ty, benchmark.samples
        );
        info!("  upload rate: {} Mbit/s", results.upload_rate_megabit);
        info!("download rate: {} Mbit/s", results.upload_rate_megabit);
        info!("    TTFB (up): {} msec", results.upload_ttfb_msec);
        info!("  TTFB (down): {} msec", results.download_ttfb_msec);
    }

    if let Some(output) = matches.get_one::<String>("output") {
        info!("Writing benchmark results to {}...", output);
        let file = std::fs::File::create(output)?;
        serde_json::to_writer(
            &file,
            &BenchmarkSummary {
                crate_version: env!("CARGO_PKG_VERSION").to_string(),
                results: benchmark.results,
            },
        )?;
    }

    Ok(())
}

/// A helper struct for running benchmarks
#[allow(clippy::missing_docs_in_private_items)]
struct Benchmark<R>
where
    R: Runtime,
{
    runtime: R,
    connect_addr: SocketAddr,
    samples: usize,
    streams_per_circ: usize,
    circs_per_sample: usize,
    upload_payload: Arc<[u8]>,
    download_payload: Arc<[u8]>,
    /// All benchmark results conducted, indexed by benchmark type.
    results: HashMap<BenchmarkType, BenchmarkResults>,
}

/// The type of benchmark conducted.
#[derive(Clone, Copy, Serialize, Deserialize, Hash, Debug, PartialEq, Eq)]
enum BenchmarkType {
    /// Use the benchmark server on its own, without using any proxy.
    ///
    /// This is useful to get an idea of how well the benchmarking utility performs on its own.
    RawLoopback,
    /// Benchmark via a SOCKS5 proxy (usually that of a chutney node).
    Socks,
    /// Benchmark via Arti.
    Arti,
}

#[derive(Clone, Serialize, Debug)]
/// Some information about a set of benchmark samples collected during multiple runs.
struct Statistic {
    /// The mean value of all samples.
    mean: f64,
    /// The low-median value of all samples.
    /// # Important note
    ///
    /// This is only the median if an odd number of samples were collected; otherwise,
    /// it is the `(number of samples / 2)`th sample after the samples are sorted.
    median: f64,
    /// The minimum sample observed.
    min: f64,
    /// The maximum sample observed.
    max: f64,
    /// The standard deviation of the set of samples.
    stddev: f64,
}

impl fmt::Display for Statistic {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let Statistic {
            mean,
            median,
            min,
            max,
            stddev,
        } = self;
        write!(
            f,
            "min/mean/median/max/stddev = {:>7.2}/{:>7.2}/{:>7.2}/{:>7.2}/{:>7.2}",
            min, mean, median, max, stddev
        )
    }
}

impl Statistic {
    /// Generate a summary of the provided `samples`.
    ///
    /// # Panics
    ///
    /// Panics if `samples` is empty.
    fn from_samples(mut samples: Vec<f64>) -> Self {
        let n_samples = samples.len();
        float_ord::sort(&mut samples);
        let mean = samples.iter().sum::<f64>() / n_samples as f64;
        // \Sigma (x_i - \mu)^2
        let samples_minus_mean_sum = samples.iter().map(|xi| (xi - mean).powf(2.0)).sum::<f64>();
        let stddev = (samples_minus_mean_sum / n_samples as f64).sqrt();
        Statistic {
            mean,
            median: samples[n_samples / 2],
            min: samples[0],
            max: samples[n_samples - 1],
            stddev,
        }
    }
}

/// A set of benchmark results for a given `BenchmarkType`, including information about averages.
#[derive(Clone, Serialize, Debug)]
struct BenchmarkResults {
    /// The type of benchmark conducted.
    ty: BenchmarkType,
    /// The number of times the benchmark was run.
    samples: usize,
    /// The number of concurrent streams per circuit used during the run.
    streams_per_circ: usize,
    /// The number of circuits used during the run.
    circuits: usize,
    /// The time to first byte (TTFB) for the download benchmark, in milliseconds.
    download_ttfb_msec: Statistic,
    /// The average download speed, in megabits per second.
    download_rate_megabit: Statistic,
    /// The time to first byte (TTFB) for the upload benchmark, in milliseconds.
    upload_ttfb_msec: Statistic,
    /// The average upload speed, in megabits per second.
    upload_rate_megabit: Statistic,

    /// The raw benchmark results.
    results_raw: Vec<TimingSummary>,
}

impl BenchmarkResults {
    /// Generate summarized benchmark results from raw run data.
    fn generate(
        ty: BenchmarkType,
        streams_per_circ: usize,
        circuits: usize,
        raw: Vec<TimingSummary>,
    ) -> Self {
        let download_ttfb_msecs = raw
            .iter()
            .map(|s| s.download_ttfb_sec * 1000.0)
            .collect::<Vec<_>>();
        let download_rate_megabits = raw
            .iter()
            .map(|s| s.download_rate_megabit)
            .collect::<Vec<_>>();
        let upload_ttfb_msecs = raw
            .iter()
            .map(|s| s.upload_ttfb_sec * 1000.0)
            .collect::<Vec<_>>();
        let upload_rate_megabits = raw
            .iter()
            .map(|s| s.upload_rate_megabit)
            .collect::<Vec<_>>();
        let samples = raw.len();
        BenchmarkResults {
            ty,
            samples,
            streams_per_circ,
            circuits,
            download_ttfb_msec: Statistic::from_samples(download_ttfb_msecs),
            download_rate_megabit: Statistic::from_samples(download_rate_megabits),
            upload_ttfb_msec: Statistic::from_samples(upload_ttfb_msecs),
            upload_rate_megabit: Statistic::from_samples(upload_rate_megabits),
            results_raw: raw,
        }
    }
}

/// A summary of all benchmarks conducted throughout the invocation of `arti-bench`.
///
/// Designed to be stored as an artifact and compared against other later runs.
#[derive(Clone, Serialize, Debug)]
struct BenchmarkSummary {
    /// The version of `arti-bench` used to generate the benchmark results.
    crate_version: String,
    /// All benchmark results conducted, indexed by benchmark type.
    results: HashMap<BenchmarkType, BenchmarkResults>,
}

impl<R: Runtime> Benchmark<R> {
    /// Run a type of benchmark (`ty`), performing `self.samples` benchmark
    /// runs, using `self.circs_per_sample` concurrent circuits, and
    /// `self.streams_per_circ` concurrent streams on each circuit.
    ///
    /// Uses `stream_generator`, function that returns futures that themselves
    /// generate streams, in order to obtain the required number of streams to
    /// run the test over.  The function takes an index of the current run.
    fn run<F, G, S, E>(&mut self, ty: BenchmarkType, mut stream_generator: F) -> Result<()>
    where
        F: FnMut(usize) -> G,
        G: Future<Output = Result<S, E>>,
        S: AsyncRead + AsyncWrite + Unpin,
        E: std::error::Error + Send + Sync + 'static,
    {
        let mut results = vec![];
        for n in 0..self.samples {
            let total_streams = self.streams_per_circ * self.circs_per_sample;
            let futures = (0..total_streams)
                .map(|_| {
                    let up = Arc::clone(&self.upload_payload);
                    let dp = Arc::clone(&self.download_payload);
                    let stream = stream_generator(n);
                    Box::pin(async move { client(stream.await?, up, dp).await })
                })
                .collect::<futures::stream::FuturesUnordered<_>>()
                .collect::<Vec<_>>();
            info!(
                "Benchmarking {:?} with {} connections, run {}/{}...",
                ty,
                self.streams_per_circ,
                n + 1,
                self.samples
            );
            let stats = self
                .runtime
                .block_on(futures)
                .into_iter()
                .map(|x| x.and_then(|x| TimingSummary::generate(&x)))
                .collect::<Result<Vec<_>>>()?;
            results.extend(stats);
        }
        let results =
            BenchmarkResults::generate(ty, self.streams_per_circ, self.circs_per_sample, results);
        self.results.insert(ty, results);
        Ok(())
    }

    /// Benchmark without Arti on loopback.
    fn without_arti(&mut self) -> Result<()> {
        let ca = self.connect_addr;
        self.run(BenchmarkType::RawLoopback, |_| {
            tokio::net::TcpStream::connect(ca)
        })
    }

    /// Benchmark through a SOCKS5 proxy at address `addr`.
    fn with_proxy(&mut self, addr: &str) -> Result<()> {
        let ca = self.connect_addr;
        let mut iso = StreamIsolationTracker::new(self.streams_per_circ);

        self.run(BenchmarkType::Socks, |run| {
            // Tor uses the username,password tuple of socks authentication do decide how to isolate streams.
            let iso_string = format!("{:?}", iso.next_in(run));
            async move {
                Socks5Stream::connect_with_password(addr, ca, &iso_string, &iso_string).await
            }
        })
    }

    /// Benchmark through Arti, using the provided `TorClientConfig`.
    fn with_arti(&mut self, tcc: TorClientConfig) -> Result<()> {
        info!("Starting Arti...");
        let tor_client = self.runtime.block_on(
            TorClient::with_runtime(self.runtime.clone())
                .config(tcc)
                .create_bootstrapped(),
        )?;

        let addr = TorAddr::dangerously_from(self.connect_addr)?;

        let mut iso = StreamIsolationTracker::new(self.streams_per_circ);

        self.run(BenchmarkType::Arti, |run| {
            let mut prefs = arti_client::StreamPrefs::new();
            prefs.set_isolation(iso.next_in(run));

            tor_client.connect(addr.clone())
        })
    }
}

/// Helper type: track a StreamIsolation token over a set of runs.
///
/// We want to return a new token every `streams_per_circ` calls for each run,
/// but always give a new token when a new run begins.
#[derive(Debug, Clone)]
struct StreamIsolationTracker {
    /// The number of streams to assign to each circuit.
    streams_per_circ: usize,
    /// The current run index.
    cur_run: usize,
    /// The stream index within the run that we expect on the _next_ call to `next_in`.
    next_stream: usize,
    /// The isolation token we're currently handing out.
    cur_token: IsolationToken,
}

impl StreamIsolationTracker {
    /// Construct a new StreamIsolationTracker.
    fn new(streams_per_circ: usize) -> Self {
        Self {
            streams_per_circ,
            cur_run: 0,
            next_stream: 0,
            cur_token: IsolationToken::new(),
        }
    }
    /// Return the isolation token to use for the next stream in the given
    /// `run`.  Requires that runs are not interleaved.
    fn next_in(&mut self, run: usize) -> IsolationToken {
        if run != self.cur_run {
            self.cur_run = run;
            self.next_stream = 0;
            self.cur_token = IsolationToken::new();
        } else if self.next_stream % self.streams_per_circ == 0 {
            self.cur_token = IsolationToken::new();
        }
        self.next_stream += 1;

        self.cur_token
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
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::StreamIsolationTracker;

    #[test]
    fn test_iso_tracker() {
        let mut tr = StreamIsolationTracker::new(2);
        let r1: Vec<_> = (0..9).map(|_| tr.next_in(0)).collect();
        let r2: Vec<_> = (0..6).map(|_| tr.next_in(1)).collect();
        assert_eq!(r1[0], r1[1]);
        assert_ne!(r1[1], r1[2]);
        assert_eq!(r1[2], r1[3]);
        assert_eq!(r2[0], r2[1]);
        assert_ne!(r2[1], r2[2]);
        assert!(!r1.contains(&r2[0]));
    }
}
