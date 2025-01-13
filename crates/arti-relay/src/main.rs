//! A relay binary use to join the Tor network to relay anonymous communication.
//!
//! NOTE: This binary is still highly experimental as in in active development, not stable and
//! without any type of guarantee of running or even working.

mod cli;
mod config;
mod err;
mod relay;

use std::io::IsTerminal as _;

use anyhow::Context;
use clap::Parser;
use safelog::with_safe_logging_suppressed;
use tor_rtcompat::{PreferredRuntime, Runtime};
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::FmtSubscriber;

use crate::config::{base_resolver, TorRelayConfig, DEFAULT_LOG_LEVEL};
use crate::relay::TorRelay;

fn main() {
    // Will exit if '--help' used or there's a parse error.
    let cli = cli::Cli::parse();

    if let Err(e) = main_main(cli) {
        // TODO: Use arti_client's `HintableError` here (see `arti::main`)?
        // TODO: Why do we suppress safe logging, and squash the anyhow result into a single line?
        // TODO: Do we want to log the error?
        with_safe_logging_suppressed(|| tor_error::report_and_exit(e))
    }
}

/// The real main without the error formatting.
fn main_main(cli: cli::Cli) -> anyhow::Result<()> {
    // Register a basic stderr logger until we have enough info to configure the main logger.
    // Unlike arti, we enable timestamps for this pre-config logger.
    // TODO: Consider using timestamps with reduced-granularity (see `LogPrecision`).
    let level: tracing::metadata::Level = cli
        .global
        .log_level
        .map(Into::into)
        .unwrap_or(DEFAULT_LOG_LEVEL);
    let filter = EnvFilter::builder()
        .with_default_directive(level.into())
        .parse("")
        .expect("empty filter directive should be trivially parsable");
    FmtSubscriber::builder()
        .with_env_filter(filter)
        .with_ansi(std::io::stderr().is_terminal())
        .with_writer(|| {
            eprint!("arti-relay: ");
            std::io::stderr()
        })
        .finish()
        .init();

    match cli.command {
        cli::Commands::BuildInfo => {
            println!("Version: {}", env!("CARGO_PKG_VERSION"));
            // these are set by our build script
            println!("Features: {}", env!("BUILD_FEATURES"));
            println!("Profile: {}", env!("BUILD_PROFILE"));
            println!("Debug: {}", env!("BUILD_DEBUG"));
            println!("Optimization level: {}", env!("BUILD_OPT_LEVEL"));
            println!("Rust version: {}", env!("BUILD_RUSTC_VERSION"));
            println!("Target triple: {}", env!("BUILD_TARGET"));
            println!("Host triple: {}", env!("BUILD_HOST"));
        }
        cli::Commands::Run(args) => start_relay(args, cli.global)?,
    }

    Ok(())
}

/// Initialize and start the relay.
fn start_relay(_args: cli::RunArgs, global_args: cli::GlobalArgs) -> anyhow::Result<()> {
    let runtime = init_runtime().context("Failed to initialize the runtime")?;

    let mut cfg_sources = global_args
        .config()
        .context("Failed to get configuration sources")?;

    // A Mistrust object to use for loading our configuration.
    // Elsewhere, we use the value _from_ the configuration.
    let cfg_mistrust = if global_args.disable_fs_permission_checks {
        fs_mistrust::Mistrust::new_dangerously_trust_everyone()
    } else {
        fs_mistrust::MistrustBuilder::default()
            // By default, a `Mistrust` checks an environment variable.
            // We do not (at the moment) want this behaviour for relays:
            // https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/2699#note_3147502
            .ignore_environment()
            .build()
            .expect("default fs-mistrust should be buildable")
    };

    cfg_sources.set_mistrust(cfg_mistrust);

    let cfg = cfg_sources
        .load()
        .context("Failed to load configuration sources")?;
    let config =
        tor_config::resolve::<TorRelayConfig>(cfg).context("Failed to resolve configuration")?;

    // TODO: Configure a proper logger, not just a simple stderr logger.
    // TODO: We may want this to be the global logger, but if we use arti's `setup_logging` in the
    // future, it returns a `LogGuards` which we'd have no way of holding on to until the
    // application exits (see https://gitlab.torproject.org/tpo/core/arti/-/issues/1791).
    let filter = EnvFilter::builder()
        .parse(&config.logging.console)
        .with_context(|| {
            format!(
                "Failed to parse console logging directive {:?}",
                config.logging.console,
            )
        })?;
    let logger = tracing_subscriber::FmtSubscriber::builder()
        .with_env_filter(filter)
        .with_ansi(std::io::stderr().is_terminal())
        .with_writer(|| {
            eprint!("arti-relay: ");
            std::io::stderr()
        })
        .finish();
    let logger = tracing::Dispatch::new(logger);

    tracing::dispatcher::with_default(&logger, || {
        let path_resolver = base_resolver();
        let relay =
            TorRelay::new(runtime, &config, path_resolver).context("Failed to initialize relay")?;
        run_relay(relay)
    })?;

    Ok(())
}

/// Run the relay.
fn run_relay<R: Runtime>(_relay: TorRelay<R>) -> anyhow::Result<()> {
    Ok(())
}

/// Initialize a runtime.
///
/// Any commands that need a runtime should call this so that we use a consistent runtime.
fn init_runtime() -> std::io::Result<impl Runtime> {
    // Use the tokio runtime from tor_rtcompat unless we later find a reason to use tokio directly;
    // see https://gitlab.torproject.org/tpo/core/arti/-/work_items/1744
    PreferredRuntime::create()
}
