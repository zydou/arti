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

//! `native-tls` -- Build with support for the `native_tls` TLS
//! backend. (default)
//!
//! `rustls` -- Build with support for the `rustls` TLS backend.
//!
//! `static` -- Link with static versions of your system dependencies,
//! including sqlite and/or openssl.  (⚠ Warning ⚠: this feature will
//! include a dependency on native-tls, even if you weren't planning
//! to use native-tls.  If you only want to build with a static sqlite
//! library, enable the `static-sqlite` feature.  We'll look for
//! better solutions here in the future.)
//!
//! `static-sqlite` -- Link with a static version of sqlite.
//!
//! `static-native-tls` -- Link with a static version of `native-tls`.
//! Enables `native-tls`.
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
#![warn(clippy::all)]
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
#![allow(clippy::print_stderr)] // Allowed in this crate only.
#![allow(clippy::print_stdout)] // Allowed in this crate only.
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]

mod exit;
mod process;
mod proxy;
mod trace;
mod watch_cfg;

use arti_client::{TorClient, TorClientConfig};
use arti_config::{default_config_file, ArtiConfig};
use tor_rtcompat::{BlockOn, Runtime};

use anyhow::{Context, Result};
use clap::{App, AppSettings, Arg, SubCommand};
use tracing::{info, warn};

use std::convert::TryInto;

/// Run the main loop of the proxy.
async fn run<R: Runtime>(
    runtime: R,
    socks_port: u16,
    config_sources: arti_config::ConfigurationSources,
    arti_config: arti_config::ArtiConfig,
    client_config: TorClientConfig,
) -> Result<()> {
    // Using OnDemand arranges that, while we are bootstrapping, incoming connections wait
    // for bootstrap to complete, rather than getting errors.
    use arti_client::BootstrapBehavior::OnDemand;
    use futures::FutureExt;
    let client = TorClient::with_runtime(runtime.clone())
        .config(client_config)
        .bootstrap_behavior(OnDemand)
        .create_unbootstrapped()?;
    if arti_config.application().watch_configuration() {
        watch_cfg::watch_for_config_changes(config_sources, arti_config, client.clone())?;
    }
    futures::select!(
        r = exit::wait_for_ctrl_c().fuse()
            => r.context("waiting for termination signal"),
        r = proxy::run_socks_proxy(runtime, client.clone(), socks_port).fuse()
            => r.context("SOCKS proxy failure"),
        r = async {
            client.bootstrap().await?;
            info!("Sufficiently bootstrapped; system SOCKS now functional.");
            futures::future::pending::<Result<()>>().await
        }.fuse()
            => r.context("bootstrap"),
    )
}

fn main() {
    main_main().unwrap_or_else(tor_error::report_and_exit);
}

/// Inner function to allow convenient error handling
fn main_main() -> Result<()> {
    // We describe a default here, rather than using `default()`, because the
    // correct behavior is different depending on whether the filename is given
    // explicitly or not.
    let mut config_file_help = "Specify which config file(s) to read.".to_string();
    if let Some(default) = arti_config::default_config_file() {
        config_file_help.push_str(&format!(" Defaults to {:?}", default));
    }

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
                    .multiple(true)
                    // NOTE: don't forget the `global` flag on all arguments declared at this level!
                    .global(true)
                    .help(&config_file_help),
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

    let cfg_sources = {
        let mut cfg_sources = arti_config::ConfigurationSources::new();

        let config_files = matches.values_of_os("config-files").unwrap_or_default();
        if config_files.len() == 0 {
            if let Some(default) = default_config_file() {
                cfg_sources.push_optional_file(default);
            }
        } else {
            config_files.for_each(|f| cfg_sources.push_file(f));
        }

        matches
            .values_of("option")
            .unwrap_or_default()
            .for_each(|s| cfg_sources.push_option(s));

        cfg_sources
    };

    let cfg = cfg_sources.load()?;

    let config: ArtiConfig = cfg.try_into().context("read configuration")?;

    let _log_guards = trace::setup_logging(config.logging(), matches.value_of("loglevel"))?;

    if let Some(proxy_matches) = matches.subcommand_matches("proxy") {
        let socks_port = match (
            proxy_matches.value_of("socks-port"),
            config.proxy().socks_port(),
        ) {
            (Some(p), _) => p.parse().expect("Invalid port specified"),
            (None, Some(s)) => s,
            (None, None) => {
                warn!(
                "No SOCKS port set; specify -p PORT or use the `socks_port` configuration option."
            );
                return Ok(());
            }
        };

        let client_config = config.tor_client_config()?;

        info!(
            "Starting Arti {} in SOCKS proxy mode on port {}...",
            env!("CARGO_PKG_VERSION"),
            socks_port
        );

        process::use_max_file_limit(&client_config);

        cfg_if::cfg_if! {
            if #[cfg(all(feature="tokio", feature="native-tls"))] {
            use tor_rtcompat::tokio::TokioNativeTlsRuntime as ChosenRuntime;
            } else if #[cfg(all(feature="tokio", feature="rustls"))] {
                use tor_rtcompat::tokio::TokioRustlsRuntime as ChosenRuntime;
            } else if #[cfg(all(feature="async-std", feature="native-tls"))] {
                use tor_rtcompat::tokio::TokioRustlsRuntime as ChosenRuntime;
            } else if #[cfg(all(feature="async-std", feature="rustls"))] {
                use tor_rtcompat::tokio::TokioRustlsRuntime as ChosenRuntime;
            }
        }

        let runtime = ChosenRuntime::create()?;

        let rt_copy = runtime.clone();
        rt_copy.block_on(run(runtime, socks_port, cfg_sources, config, client_config))?;
        Ok(())
    } else {
        panic!("Subcommand added to clap subcommand list, but not yet implemented")
    }
}
