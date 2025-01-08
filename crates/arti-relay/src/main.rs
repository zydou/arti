//! A relay binary use to join the Tor network to relay anonymous communication.
//!
//! NOTE: This binary is still highly experimental as in in active development, not stable and
//! without any type of guarantee of running or even working.

mod cli;
mod config;
mod err;
mod relay;

use clap::Parser;
use safelog::with_safe_logging_suppressed;

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
    // use the tokio runtime from tor_rtcompat unless we later find a reason to use tokio directly;
    // see https://gitlab.torproject.org/tpo/core/arti/-/work_items/1744
    let runtime = tor_rtcompat::PreferredRuntime::create()?;

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
        cli::Commands::Run(_args) => {
            let config = TorRelayConfig::default();
            let path_resolver = base_resolver();
            let _relay = TorRelay::new(runtime, &config, path_resolver)?;
        }
    }

    Ok(())
}
