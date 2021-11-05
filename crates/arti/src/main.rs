//! A minimal client for connecting to the tor network
//!
//! This crate is the primary command-line interface for
//! [Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
//! implement [Tor](https://www.torproject.org/) in Rust.
//! Many other crates in Arti depend on it.
//!
//! Note that Arti is a work in progress; although we've tried to
//! write all the critical security components, you probably shouldn't
//! use Arti in production until it's a bit more mature.
//!
//! More documentation will follow as this program improves.  For now,
//! just know that it can run as a simple SOCKS proxy over the Tor network.
//! It will listen on port 9150 by default, but you can override this in
//! the configuration.
//!
//! # Command-line interface
//!
//! (This is not stable; future versions will break this.)
//!
//! `arti` uses the [`clap`](https://docs.rs/clap/) crate for command-line
//! argument parsing; run `arti help` to get it to print its documentation.
//!
//! The only currently implemented subcommand is `arti proxy`; try
//! `arti help proxy` for a list of options you can pass to it.
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
#![deny(clippy::checked_conversions)]
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
// These are allowed in this crate only.
#![allow(clippy::print_stderr)]
#![allow(clippy::print_stdout)]

mod exit;
mod process;
mod proxy;

use std::sync::Arc;

use arti_client::{
    config::circ::{CircMgrConfig, CircMgrConfigBuilder},
    config::dir::{DirMgrConfig, DirMgrConfigBuilder, DownloadScheduleConfig, NetworkConfig},
    TorClient, TorClientConfig,
};
use tor_config::CfgPath;
use tor_rtcompat::{Runtime, SpawnBlocking};

use anyhow::Result;
use clap::{App, AppSettings, Arg, SubCommand};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::{info, warn};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, registry, EnvFilter};

/// Default options to use for our configuration.
const ARTI_DEFAULTS: &str = concat!(include_str!("./arti_defaults.toml"),);

/// Structure to hold our logging configuration options
#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
struct LoggingConfig {
    /// Filtering directives that determine tracing levels as described at
    /// <https://docs.rs/tracing-subscriber/0.2.20/tracing_subscriber/filter/struct.EnvFilter.html>
    ///
    /// You can override this setting with the -l, --log-level command line parameter.
    ///
    /// Example: "info,tor_proto::channel=trace"
    trace_filter: String,

    /// Whether to log to journald
    journald: bool,
}

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

    /// Logging configuration
    logging: LoggingConfig,

    /// Information about the Tor network we want to connect to.
    #[serde(default)]
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
    path_rules: arti_client::config::circ::PathConfig,

    /// Information about how to retry requests for circuits.
    request_timing: arti_client::config::circ::RequestTiming,

    /// Information about how to expire circuits.
    circuit_timing: arti_client::config::circ::CircuitTiming,

    /// Information about client address configuration parameters.
    addr_config: arti_client::config::ClientAddrConfig,
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
        let mut dircfg = DirMgrConfigBuilder::default();
        dircfg.network_config(self.network.clone());
        dircfg.schedule_config(self.download_schedule.clone());
        dircfg.cache_path(self.storage.cache_dir.path()?);
        for (k, v) in self.override_net_params.iter() {
            dircfg.override_net_param(k.clone(), *v);
        }
        Ok(dircfg.build()?)
    }

    /// Return a [`CircMgrConfig`] object based on the user's selected
    /// configuration.
    fn get_circ_config(&self) -> Result<CircMgrConfig> {
        let mut builder = CircMgrConfigBuilder::default();
        Ok(builder
            .path_config(self.path_rules.clone())
            .request_timing(self.request_timing.clone())
            .circuit_timing(self.circuit_timing.clone())
            .build()?)
    }
}

/// Run the main loop of the proxy.
async fn run<R: Runtime>(
    runtime: R,
    socks_port: u16,
    client_config: TorClientConfig,
) -> Result<()> {
    use futures::FutureExt;
    futures::select!(
        r = exit::wait_for_ctrl_c().fuse() => r,
        r = async {
            let client =
                Arc::new(TorClient::bootstrap(
                    runtime.clone(),
                    client_config,
                ).await?);
            proxy::run_socks_proxy(runtime, client, socks_port).await
        }.fuse() => r,
    )
}

/// As [`EnvFilter::new`], but print a message if any directive in the
/// log is invalid.
fn filt_from_str_verbose(s: &str, source: &str) -> EnvFilter {
    match EnvFilter::try_new(s) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("Problem in {}:", source);
            EnvFilter::new(s)
        }
    }
}

/// Set up logging
fn setup_logging(config: &ArtiConfig, cli: Option<&str>) {
    let env_filter =
        match cli.map(|s| filt_from_str_verbose(s, "--log-level command line parameter")) {
            Some(f) => f,
            None => filt_from_str_verbose(
                config.logging.trace_filter.as_str(),
                "trace_filter configuration option",
            ),
        };

    let registry = registry().with(fmt::Layer::default()).with(env_filter);

    if config.logging.journald {
        #[cfg(feature = "journald")]
        if let Ok(journald) = tracing_journald::layer() {
            registry.with(journald).init();
            return;
        }
        #[cfg(not(feature = "journald"))]
        warn!("journald logging was selected, but arti was built without journald support.");
    }

    registry.init();
}

fn main() -> Result<()> {
    let dflt_config = tor_config::default_config_file().unwrap_or_else(|| "./config.toml".into());

    let matches =
        App::new("Arti")
            .version(env!("CARGO_PKG_VERSION"))
            .author("The Tor Project Developers")
            .about("A Rust Tor implementation.")
            // HACK(eta): clap generates "arti [OPTIONS] <SUBCOMMAND>" for this usage string by
            //            default, but then fails to parse options properly if you do put them
            //            before the subcommand.
            //            We just declare all options as `global` and then require them to be
            //            put after the subcommand, hence this new usage string.
            .usage("arti <SUBCOMMAND> [OPTIONS]")
            .arg(
                Arg::with_name("config-files")
                    .short("c")
                    .long("config")
                    .takes_value(true)
                    .value_name("FILE")
                    .default_value_os(dflt_config.as_ref())
                    .multiple(true)
                    // NOTE: don't forget the `global` flag on all arguments declared at this level!
                    .global(true)
                    .help("Specify which config file(s) to read."),
            )
            .arg(
                Arg::with_name("option")
                    .short("o")
                    .takes_value(true)
                    .value_name("KEY=VALUE")
                    .multiple(true)
                    .global(true)
                    .help("Override config file parameters, using TOML-like syntax."),
            )
            .arg(
                Arg::with_name("loglevel")
                    .short("l")
                    .long("log-level")
                    .global(true)
                    .takes_value(true)
                    .value_name("LEVEL")
                    .help("Override the log level (usually one of 'trace', 'debug', 'info', 'warn', 'error')."),
            )
            .subcommand(
                SubCommand::with_name("proxy")
                    .about(
                        "Run Arti in SOCKS proxy mode, proxying connections through the Tor network.",
                    )
                    .arg(
                        Arg::with_name("socks-port")
                            .short("p")
                            .takes_value(true)
                            .value_name("PORT")
                            .help("Port to listen on for SOCKS connections (overrides the port in the config if specified).")
                    )
            )
            .setting(AppSettings::SubcommandRequiredElseHelp)
            .get_matches();

    let mut cfg = config::Config::new();
    cfg.merge(config::File::from_str(
        ARTI_DEFAULTS,
        config::FileFormat::Toml,
    ))?;

    let config_files = matches
        .values_of_os("config-files")
        // This shouldn't actually be possible given we specify a default.
        .expect("no config files provided")
        .into_iter()
        // The second value in this 2-tuple specifies whether the config file is "required" (as in,
        // failure to load it is an error). All config files that aren't the default are required.
        .map(|x| (PathBuf::from(x), x != dflt_config))
        .collect::<Vec<_>>();

    let additional_opts = matches
        .values_of("option")
        .map(|x| x.into_iter().map(ToOwned::to_owned).collect::<Vec<_>>())
        .unwrap_or_else(Vec::new);

    tor_config::load(&mut cfg, &config_files, additional_opts)?;

    let config: ArtiConfig = cfg.try_into()?;

    setup_logging(&config, matches.value_of("loglevel"));

    if let Some(proxy_matches) = matches.subcommand_matches("proxy") {
        let statecfg = config.storage.state_dir.path()?;
        let dircfg = config.get_dir_config()?;
        let circcfg = config.get_circ_config()?;
        let addrcfg = config.addr_config;

        let socks_port = match (proxy_matches.value_of("socks-port"), config.socks_port) {
            (Some(p), _) => p.parse().expect("Invalid port specified"),
            (None, Some(s)) => s,
            (None, None) => {
                warn!(
                "No SOCKS port set; specify -p PORT or use the `socks_port` configuration option."
            );
                return Ok(());
            }
        };

        info!(
            "Starting Arti {} in SOCKS proxy mode on port {}...",
            env!("CARGO_PKG_VERSION"),
            socks_port
        );

        let client_config = TorClientConfig::builder()
            .state_cfg(statecfg)
            .dir_cfg(dircfg)
            .circ_cfg(circcfg)
            .addr_cfg(addrcfg)
            .build()?;

        process::use_max_file_limit();

        #[cfg(feature = "tokio")]
        let runtime = tor_rtcompat::tokio::create_runtime()?;
        #[cfg(all(feature = "async-std", not(feature = "tokio")))]
        let runtime = tor_rtcompat::async_std::create_runtime()?;

        let rt_copy = runtime.clone();
        rt_copy.block_on(run(runtime, socks_port, client_config))?;
        Ok(())
    } else {
        panic!("Subcommand added to clap subcommand list, but not yet implemented")
    }
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
