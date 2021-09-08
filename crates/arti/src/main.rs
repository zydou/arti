//! A minimal client for connecting to the tor network
//!
//! This crate is the primary command-line interface for
//! [Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
//! implement [Tor](https://www.torproject.org/) in Rust.
//! Many other crates in Arti depend on it.
//!
//! ⚠️**WARNING**: Arti is not yet a secure or complete Tor implementation!
//! If you use it, you should expect that it _will_ harm your privacy.
//! For now, if you have actual privacy or security needs, please use
//! the C implementation of Tor instead. ⚠️
//!
//! More documentation will follow as this program improves.  For now,
//! just know that it can run as a simple SOCKS proxy over the Tor network.
//! It will listen on port 9150 by default, but you can override this in
//! the configuration.
//!
//! # Command-line arguments
//!
//! (This is not stable; future versions will break this.)
//!
//! `-f <filename>` overrides the location to search for a
//! configuration file to the list of configuration file.  You can use
//! this multiple times: All files will be loaded and merged.
//!
//! `-c <key>=<value>` sets a configuration option to be applied after all
//! configuration files are loaded.
//!
//! # Configuration
//!
//! By default, `arti` looks for its configuration files in a
//! platform-dependent location.  That's `~/.config/arti/arti.toml` on
//! Unix. (TODO document OSX and Windows.)
//!
//! The configuration file is TOML.  (We do not guarantee its stability.)
//! For an example see [`arti_defaults.toml`](./arti_defaults.toml).
//!
//! # Compile-time features
//!
//! `tokio` (default): Use the tokio runtime library as our backend.
//!
//! `async-std`: Use the async-std runtime library as our backend.
//! This feature has no effect unless building with `--no-default-features`
//! to disable tokio.
//!
//! `static`: Try to link a single static binary.
//!
//! # Limitations
//!
//! There are many missing features.  Among them: there's no onion
//! service support yet. There's no anti-censorship support.  You
//! can't be a relay.  There isn't any kind of proxy besides SOCKS.
//! Resolve-over-SOCKS isn't implemented yet.
//!
//! See the [README
//! file](https://gitlab.torproject.org/tpo/core/arti/-/blob/main/README.md)
//! for a more complete list of missing features.

#![warn(missing_docs)]
#![deny(missing_docs)]
#![warn(noop_method_call)]
#![deny(unreachable_pub)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![deny(clippy::cast_lossless)]
#![warn(clippy::clone_on_ref_ptr)]
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
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]

mod exit;
mod proxy;

use std::sync::Arc;

use tor_circmgr::CircMgrConfig;
use tor_client::TorClient;
use tor_config::CfgPath;
use tor_dirmgr::{DirMgrConfig, DownloadScheduleConfig, NetworkConfig};
use tor_rtcompat::{Runtime, SpawnBlocking};

use anyhow::Result;
use argh::FromArgs;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::{info, warn};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, registry, EnvFilter};

#[derive(FromArgs, Debug, Clone)]
/// Connect to the Tor network, open a SOCKS port, and proxy
/// traffic.
///
/// This is a demo; you get no stability guarantee.
struct Args {
    /// override the default location(s) for the configuration file
    #[argh(option, short = 'f')]
    rc: Vec<String>,
    /// override a configuration option (uses toml syntax)
    #[argh(option, short = 'c')]
    cfg: Vec<String>,
}

/// Default options to use for our configuration.
const ARTI_DEFAULTS: &str = concat!(
    include_str!("./arti_defaults.toml"),
    include_str!("./authorities.toml"),
);

/// Structure to hold our configuration options, whether from a
/// configuration file or the command line.
///
/// NOTE: These are NOT the final options or their final layout.
/// Expect NO stability here.
#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct ArtiConfig {
    /// Port to listen on (at localhost) for incoming SOCKS
    /// connections.
    socks_port: Option<u16>,

    /// Whether to log to journald
    journald: bool,

    /// Filtering directives that determine tracing levels as described at
    /// <https://docs.rs/tracing-subscriber/0.2.20/tracing_subscriber/filter/struct.EnvFilter.html>
    ///
    /// You can override this setting with the environment variable ARTI_LOG.
    trace_filter: String,

    /// Information about the Tor network we want to connect to.
    network: NetworkConfig,

    /// Directories for storing information on disk
    storage: StorageConfig,

    /// Information about when and how often to download directory information
    download_schedule: DownloadScheduleConfig,

    /// Facility to override network parameters from the values set in the
    /// consensus.
    #[serde(default)]
    override_net_params: HashMap<String, i32>,

    /// Information about how to build paths through the network.
    path_rules: tor_circmgr::PathConfig,

    /// Information about how to retry requests for circuits.
    request_timing: tor_circmgr::RequestTiming,

    /// Information about how to expire circuits.
    circuit_timing: tor_circmgr::CircuitTiming,
}

/// Configuration for where information should be stored on disk.
///
/// This section is for read/write storage
#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    /// Location on disk for cached directory information
    cache_dir: CfgPath,
    /// Location on disk for less-sensitive persistent state information.
    state_dir: CfgPath,
}

impl ArtiConfig {
    /// Return a [`DirMgrConfig`] object based on the user's selected
    /// configuration.
    fn get_dir_config(&self) -> Result<DirMgrConfig> {
        let mut dircfg = tor_dirmgr::DirMgrConfigBuilder::new();
        dircfg.network_config(self.network.clone());
        dircfg.schedule_config(self.download_schedule.clone());
        dircfg.cache_path(&self.storage.cache_dir.path()?);
        for (k, v) in self.override_net_params.iter() {
            dircfg.override_net_param(k.clone(), *v);
        }
        dircfg.build()
    }

    /// Return a [`CircMgrConfig`] object based on the user's selected
    /// configuration.
    fn get_circ_config(&self) -> Result<CircMgrConfig> {
        let mut builder = tor_circmgr::CircMgrConfigBuilder::default();
        Ok(builder
            .set_path_config(self.path_rules.clone())
            .set_request_timing(self.request_timing.clone())
            .set_circuit_timing(self.circuit_timing.clone())
            .build()?)
    }
}

/// Run the main loop of the proxy.
async fn run<R: Runtime>(
    runtime: R,
    socks_port: u16,
    statecfg: PathBuf,
    dircfg: DirMgrConfig,
    circcfg: CircMgrConfig,
) -> Result<()> {
    use futures::FutureExt;
    futures::select!(
        r = exit::wait_for_ctrl_c().fuse() => r,
        r = async {
            let client =
                Arc::new(TorClient::bootstrap(runtime.clone(), statecfg, dircfg, circcfg).await?);
            proxy::run_socks_proxy(runtime, client, socks_port).await
        }.fuse() => r,
    )
}

/// Set up logging
fn setup_logging(config: &ArtiConfig) {
    let env_filter = match EnvFilter::try_from_env("ARTI_LOG") {
        Ok(f) => f,
        Err(_e) => EnvFilter::new(config.trace_filter.as_str()),
    };

    let registry = registry().with(fmt::Layer::default()).with(env_filter);

    #[cfg(feature = "journald")]
    if config.journald {
        if let Ok(journald) = tracing_journald::layer() {
            registry.with(journald).init();
            return;
        }
    }

    registry.init();
}

fn main() -> Result<()> {
    let args: Args = argh::from_env();
    let dflt_config = tor_config::default_config_file();

    let mut cfg = config::Config::new();
    cfg.merge(config::File::from_str(
        ARTI_DEFAULTS,
        config::FileFormat::Toml,
    ))?;
    tor_config::load(&mut cfg, &dflt_config, &args.rc, &args.cfg)?;

    let config: ArtiConfig = cfg.try_into()?;

    setup_logging(&config);

    let statecfg = config.storage.state_dir.path()?;
    let dircfg = config.get_dir_config()?;
    let circcfg = config.get_circ_config()?;

    let socks_port = match config.socks_port {
        Some(s) => s,
        None => {
            info!("Nothing to do: no socks_port configured.");
            return Ok(());
        }
    };

    #[cfg(feature = "tokio")]
    let runtime = tor_rtcompat::tokio::create_runtime()?;
    #[cfg(all(feature = "async-std", not(feature = "tokio")))]
    let runtime = tor_rtcompat::async_std::create_runtime()?;

    let rt_copy = runtime.clone();
    rt_copy.block_on(run(runtime, socks_port, statecfg, dircfg, circcfg))?;
    Ok(())
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn load_default_config() -> Result<()> {
        // TODO: this is duplicate code.
        let mut cfg = config::Config::new();
        cfg.merge(config::File::from_str(
            ARTI_DEFAULTS,
            config::FileFormat::Toml,
        ))?;

        let _parsed: ArtiConfig = cfg.try_into()?;
        Ok(())
    }
}
