//! A relay binary use to join the Tor network to relay anonymous communication.
//!
//! NOTE: This binary is still highly experimental as in in active development, not stable and
//! without any type of guarantee of running or even working.

mod builder;
mod cli;
mod config;
mod err;
mod relay;

use clap::Parser;

use crate::relay::TorRelay;

fn main() -> anyhow::Result<()> {
    let cli = cli::Cli::parse();

    let runtime = create_runtime()?;

    match cli.command {
        cli::Commands::Run(_args) => {
            let _relay = TorRelay::with_runtime(runtime).create()?;
        }
    }

    Ok(())
}

/// Create the runtime for the relay.
fn create_runtime() -> std::io::Result<impl tor_rtcompat::Runtime> {
    // TODO(arti#1744): we may want to support multiple runtimes
    tor_rtcompat::PreferredRuntime::create()
}
