//! Tool for running an Arti client with unusual behavior or limitations.
//!
//! Example use:
//!
//! ```sh
//! $ cat ~/.arti_testing.toml
//! [storage]
//!
//! cache_dir = "${USER_HOME}/.arti_testing/cache"
//! state_dir = "${USER_HOME}/.arti_testing/state"
//!
//! $ ./target/debug/arti-testing bootstrap --config ~/.arti-testing.toml \
//!           --timeout 120 --expect=success
//! [...lots of logs]
//! Operation succeeded [as expected]
//! TCP stats: TcpCount { n_connect_attempt: 4, n_connect_ok: 2, n_accept: 0, n_bytes_send: 461102, n_bytes_recv: 3502811 }
//! Total events: Trace: 6943, Debug: 17, Info: 13, Warn: 0, Error: 0
//!
//! $ faketime '1 year ago' ./target/debug/arti-testing connect \
//!           --config ~/.arti-testing.toml
//!           --target www.torproject.org:80
//!           --timeout 60
//!           --expect=timeout
//! [...lots of logs...]
//! Timeout occurred [as expected]
//! TCP stats: TcpCount { n_connect_attempt: 3, n_connect_ok: 3, n_accept: 0, n_bytes_send: 10917, n_bytes_recv: 16704 }
//! Total events: Trace: 77, Debug: 21, Info: 10, Warn: 2, Error: 0
//! ```
//!
//! # TODO
//!
//! - More ways to break
//!   - make TCP connections fail only sporadically
//!   - make TLS fail
//!      - With wrong cert
//!      - Mysteriously
//!      - With complete junk
//!      - TLS succeeds, then sends nonsense
//!      - Authenticating with wrong ID.
//!   - Munge directory before using it
//!      - May require some dirmgr plug-in. :p
//!      - May require
//!
//! - More things to look at
//!   - do something on the connection
//!   - look at bootstrapping status and events
//!   - Make streams repeatedly on different circuits with some delay.
//! - Make sure we can replicate all/most test situations from arti#329
//! - Actually implement those tests.

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
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
#![allow(clippy::result_large_err)] // temporary workaround for arti#587
#![allow(clippy::needless_raw_string_hashes)] // complained-about code is fine, often best
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

#![allow(clippy::print_stderr)] // Allowed in this crate only.
#![allow(clippy::print_stdout)] // Allowed in this crate only.

mod config;
mod dirfilter;
mod rt;
mod traces;

use arti::ArtiCombinedConfig;
use arti_client::TorClient;
use futures::task::SpawnExt;
use rt::badtcp::BrokenTcpProvider;
use tor_config::ConfigurationSources;
use tor_dirmgr::filter::DirFilter;
use tor_rtcompat::{PreferredRuntime, Runtime, SleepProviderExt};

use anyhow::{anyhow, Result};
use tracing_subscriber::prelude::*;
//use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

/// A possible action for the tool to try to take
#[derive(Debug, Clone)]
enum Action {
    /// Bootstrap the client and exit.
    Bootstrap,
    /// Bootstrap the client, then try to connect to a target
    ///
    /// Exit when successful.
    Connect {
        /// The target address.
        target: String,
        /// How long to wait between attempts?  If None, exit on the first
        /// failure.
        retry_delay: Option<Duration>,
    },
}

/// What we expect to happen when we run a given job.
#[derive(Debug, Clone)]
enum Expectation {
    /// The operation should complete successfully.
    Success,
    /// The operation should terminate with an error.
    Failure,
    /// The operation should time out
    Timeout,
}

impl FromStr for Expectation {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "success" => Expectation::Success,
            "failure" => Expectation::Failure,
            "timeout" => Expectation::Timeout,
            _ => return Err(anyhow!("Unrecognized expectation {:?}", s)),
        })
    }
}

/// At what stage to install a kind of breakage
#[derive(Debug, Clone, PartialEq, Eq)]
enum BreakageStage {
    /// Create breakage while bootstrapping
    Bootstrap,
    /// Create breakage while connecting
    Connect,
}

impl FromStr for BreakageStage {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "bootstrap" => BreakageStage::Bootstrap,
            "connect" => BreakageStage::Connect,
            _ => return Err(anyhow!("unrecognized breakage stage {:?}", s)),
        })
    }
}

/// Describes how (if at all) to break TCP connection attempts
#[derive(Debug, Clone)]
struct TcpBreakage {
    /// What kind of breakage to install (if any)
    action: rt::badtcp::ConditionalAction,
    /// What stage to apply the breakage at.
    stage: BreakageStage,
    /// Delay (if any) after the start of the stage to apply breakage
    delay: Option<Duration>,
}

impl TcpBreakage {
    /// Apply the configured breakage to breakage_provider.  Use `main_runtime` to sleep if necessary.
    fn apply<R: Runtime, R2: Send + Sync + 'static>(
        &self,
        main_runtime: &R,
        breakage_provider: BrokenTcpProvider<R2>,
    ) {
        if let Some(delay) = self.delay {
            let rt_clone = main_runtime.clone();
            let action = self.action.clone();
            main_runtime
                .spawn(async move {
                    rt_clone.sleep(delay).await;
                    breakage_provider.set_action(action);
                })
                .expect("can't spawn.");
        } else {
            breakage_provider.set_action(self.action.clone());
        }
    }
}

/// Descriptions of an action to take, and what to expect as an outcome.
#[derive(Debug, Clone)]
struct Job {
    /// The action that the client should try to take
    action: Action,

    /// Describes how (if at all) to break the TCP connections.
    tcp_breakage: TcpBreakage,

    /// Describes how (if at all) to mess with directories.
    dir_filter: Arc<dyn DirFilter + 'static>,

    /// The tracing configuration for our console log.
    console_log: String,

    /// Where we're getting our configuration from.
    config: ConfigurationSources,

    /// What we expect to happen.
    expectation: Option<Expectation>,

    /// How long to wait for the action to succeed or fail.
    timeout: Duration,
}

impl Job {
    /// Make a new unbootstrapped client for this job.
    fn make_client<R: Runtime>(&self, runtime: R) -> Result<TorClient<R>> {
        let (_arti, tcc) = tor_config::resolve::<ArtiCombinedConfig>(self.config.load()?)?;
        let client = TorClient::with_runtime(runtime)
            .config(tcc)
            .dirfilter(self.dir_filter.clone())
            .create_unbootstrapped()?;
        Ok(client)
    }

    /// Run the body of a job.
    async fn run_job_inner<R: Runtime, R2: Send + Sync + Clone + 'static>(
        &self,
        broken_tcp: rt::badtcp::BrokenTcpProvider<R2>,
        client: TorClient<R>,
    ) -> Result<()> {
        if self.tcp_breakage.stage == BreakageStage::Bootstrap {
            self.tcp_breakage
                .apply(client.runtime(), broken_tcp.clone());
        }

        client.bootstrap().await?; // all jobs currently start with a bootstrap.

        match &self.action {
            Action::Bootstrap => {}
            Action::Connect {
                target,
                retry_delay,
            } => {
                if self.tcp_breakage.stage == BreakageStage::Connect {
                    self.tcp_breakage
                        .apply(client.runtime(), broken_tcp.clone());
                }

                loop {
                    let outcome = client.connect(target).await;
                    match (outcome, retry_delay) {
                        (Ok(_stream), _) => break,
                        (Err(e), None) => return Err(e.into()),
                        (Err(_e), Some(delay)) => client.runtime().sleep(*delay).await, // TODO log error
                    }
                }
            }
        }

        Ok(())
    }

    /// Run a provided job.
    ///
    /// TUDO Eventually this should come up with some kind of result that's meaningful.
    async fn run_job(&self) -> Result<()> {
        let runtime = PreferredRuntime::current()?;
        let broken_tcp = rt::badtcp::BrokenTcpProvider::new(
            runtime.clone(),
            rt::badtcp::ConditionalAction::default(),
        );
        // We put the counting TCP provider outside the one that breaks: we want
        // to know how many attempts to connect there are, and BrokenTcpProvider
        // eats the attempts that it fails without passing them down the stack.
        let counting_tcp = rt::count::Counting::new_zeroed(broken_tcp.clone());
        let runtime = tor_rtcompat::CompoundRuntime::new(
            runtime.clone(),
            runtime.clone(),
            runtime.clone(),
            counting_tcp.clone(),
            runtime.clone(),
            runtime,
        );
        let client = self.make_client(runtime)?;

        let outcome = client
            .clone()
            .runtime()
            .timeout(self.timeout, self.run_job_inner(broken_tcp.clone(), client))
            .await;

        let result = match (&self.expectation, outcome) {
            (Some(Expectation::Timeout), Err(tor_rtcompat::TimeoutError)) => {
                println!("Timeout occurred [as expected]");
                Ok(())
            }
            (Some(Expectation::Failure), Ok(Err(e))) => {
                println!("Got an error as [as expected]");
                println!("Error was: {}", e);
                Ok(())
            }
            (Some(Expectation::Success), Ok(Ok(()))) => {
                println!("Operation succeeded [as expected]");
                Ok(())
            }
            (Some(expectation), outcome) => Err(anyhow!(
                "Test failed. Expected {:?} but got: {:?}",
                expectation,
                outcome
            )),
            (None, outcome) => {
                // no expectation.
                println!("Outcome: {:?}", outcome);
                Ok(())
            }
        };

        println!("TCP stats: {:?}", counting_tcp.counts());

        result
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let job = config::parse_cmdline()?;

    let targets: tracing_subscriber::filter::Targets = job.console_log.parse()?;
    let console_layer = tracing_subscriber::fmt::Layer::default().with_filter(targets);
    let trace_count = Arc::new(traces::TraceCount::default());
    tracing_subscriber::registry()
        .with(console_layer)
        .with(traces::TraceCounter(trace_count.clone()))
        .init();

    let outcome = job.run_job().await;

    println!("Total events: {}", trace_count);

    outcome
}
