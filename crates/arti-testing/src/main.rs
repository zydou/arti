//! Tool for running an Arti client with unusual behavior or limitations.
//!
//! Example use:
//!
//! ```ignore
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
//! - make TCP connections fail
//! - do something on the connection
//! - look at bootstrapping status and events
//! - look at trace messages
//! - Make sure we can replicate all/most test situations from arti#329
//! - Actually implement those tests.

#![allow(dead_code)]
#![deny(missing_docs)]
#![warn(noop_method_call)]
#![deny(unreachable_pub)]
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
#![deny(clippy::missing_panics_doc)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::print_stderr)] // Allowed in this crate only.
#![allow(clippy::print_stdout)] // Allowed in this crate only.

mod config;
mod rt;
mod traces;

use arti_client::TorClient;
use arti_config::ArtiConfig;
use tor_rtcompat::{PreferredRuntime, Runtime, SleepProviderExt};

use anyhow::{anyhow, Result};
use tracing_subscriber::prelude::*;
//use std::path::PathBuf;
use std::convert::TryInto;
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

/// Descriptions of an action to take, and what to expect as an outcome.
#[derive(Debug, Clone)]
struct Job {
    /// The action that the client should try to take
    action: Action,

    /// The tracing configuration for our console log.
    console_log: String,

    /// Where we're getting our configuration from.
    config: arti_config::ConfigurationSources,

    /// What we expect to happen.
    expectation: Option<Expectation>,

    /// How long to wait for the action to succeed or fail.
    timeout: Duration,
}

impl Job {
    /// Make a new unbootstrapped client for this job.
    fn make_client<R: Runtime>(&self, runtime: R) -> Result<TorClient<R>> {
        let config: ArtiConfig = self.config.load()?.try_into()?;
        let client = TorClient::with_runtime(runtime)
            .config(config.tor_client_config()?)
            .create_unbootstrapped()?;
        Ok(client)
    }

    /// Run the body of a job.
    async fn run_job_inner<R: Runtime>(&self, client: TorClient<R>) -> Result<()> {
        client.bootstrap().await?; // all jobs currently start with a bootstrap.

        match &self.action {
            Action::Bootstrap => {}
            Action::Connect {
                target,
                retry_delay,
            } => {
                loop {
                    let outcome = client.connect(target).await;
                    match (outcome, retry_delay) {
                        (Ok(_stream), _) => break,
                        (Err(e), None) => return Err(e.into()),
                        (Err(_e), Some(delay)) => client.runtime().sleep(*delay).await, // XXXX log error
                    }
                }
            }
        }

        Ok(())
    }

    /// Run a provided job.
    ///
    /// XXXX Eventually this should come up with some kind of result that's meaningful.
    async fn run_job(&self) -> Result<()> {
        let runtime = PreferredRuntime::current()?;
        let tcp = rt::count::Counting::new_zeroed(runtime.clone());
        let runtime = tor_rtcompat::CompoundRuntime::new(
            runtime.clone(),
            runtime.clone(),
            tcp.clone(),
            runtime,
        );
        let client = self.make_client(runtime)?;

        let outcome = client
            .clone()
            .runtime()
            .timeout(self.timeout, self.run_job_inner(client))
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

        println!("TCP stats: {:?}", tcp.counts());

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
