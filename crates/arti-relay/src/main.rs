//! A relay binary use to join the Tor network to relay anonymous communication.
//!
//! NOTE: This binary is still highly experimental as in in active development, not stable and
//! without any type of guarantee of running or even working.

mod cli;
mod config;
mod err;
mod relay;

use anyhow::Context;
use clap::Parser;
use safelog::with_safe_logging_suppressed;
use tor_rtcompat::{PreferredRuntime, Runtime};

use crate::cli::FS_DISABLE_PERMISSION_CHECKS_ENV_NAME;
use crate::config::{base_resolver, TorRelayConfig};
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
            .controlled_by_env_var_if_not_set(FS_DISABLE_PERMISSION_CHECKS_ENV_NAME)
            .build()
            .expect("default fs-mistrust should be buildable")
    };

    cfg_sources.set_mistrust(cfg_mistrust);

    let cfg = cfg_sources
        .load()
        .context("Failed to load configuration sources")?;
    let config =
        tor_config::resolve::<TorRelayConfig>(cfg).context("Failed to resolve configuration")?;

    let path_resolver = base_resolver();
    let _relay =
        TorRelay::new(runtime, &config, path_resolver).context("Failed to initialize relay")?;

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
