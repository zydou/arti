//! A minimal command line program for connecting to the tor network
//!
//! (If you want a more general Tor client library interface, use [`arti_client`].)
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
//! platform-dependent location.
//!
//! | OS      | Configuration File                                 |
//! |---------|----------------------------------------------------|
//! | Unix    | `~/.config/arti/arti.toml`                         |
//! | macOS   | `~/Library/Application Support/arti/arti.toml`     |
//! | Windows | `\Users\<USERNAME>\AppData\Roaming\arti\arti.toml` |
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
//!
//! # Library for building command-line client
//!
//! This library crate contains code useful for making
//! a command line program similar to `arti`.
//! The API should not be considered stable.

#![warn(missing_docs)]
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

pub mod cfg;
pub mod dns;
pub mod exit;
pub mod logging;
pub mod process;
pub mod socks;
pub mod watch_cfg;

pub use cfg::{
    ApplicationConfig, ApplicationConfigBuilder, ArtiConfig, ArtiConfigBuilder, ProxyConfig,
    ProxyConfigBuilder, SystemConfig, SystemConfigBuilder,
};
pub use logging::{LoggingConfig, LoggingConfigBuilder};

use arti_client::{TorClient, TorClientConfig};
use arti_config::default_config_file;
use tor_rtcompat::{BlockOn, Runtime};

use anyhow::{Context, Result};
use clap::{App, AppSettings, Arg, SubCommand};
use tracing::{info, warn};

/// Shorthand for a boxed and pinned Future.
type PinnedFuture<T> = std::pin::Pin<Box<dyn futures::Future<Output = T>>>;

/// Run the main loop of the proxy.
///
/// # Panics
///
/// Currently, might panic if things go badly enough wrong
pub async fn run<R: Runtime>(
    runtime: R,
    socks_port: u16,
    dns_port: u16,
    config_sources: arti_config::ConfigurationSources,
    arti_config: ArtiConfig,
    client_config: TorClientConfig,
    fs_mistrust_disabled: bool,
) -> Result<()> {
    // Using OnDemand arranges that, while we are bootstrapping, incoming connections wait
    // for bootstrap to complete, rather than getting errors.
    use arti_client::BootstrapBehavior::OnDemand;
    use futures::FutureExt;
    let mut client_builder = TorClient::with_runtime(runtime.clone())
        .config(client_config)
        .bootstrap_behavior(OnDemand);
    if fs_mistrust_disabled {
        client_builder = client_builder.disable_fs_permission_checks();
    } else {
        client_builder = client_builder.enable_fs_permission_checks();
    }
    let client = client_builder.create_unbootstrapped()?;
    if arti_config.application().watch_configuration {
        watch_cfg::watch_for_config_changes(config_sources, arti_config, client.clone())?;
    }

    let mut proxy: Vec<PinnedFuture<(Result<()>, &str)>> = Vec::new();
    if socks_port != 0 {
        let runtime = runtime.clone();
        let client = client.isolated_client();
        proxy.push(Box::pin(async move {
            let res = socks::run_socks_proxy(runtime, client, socks_port).await;
            (res, "SOCKS")
        }));
    }

    if dns_port != 0 {
        let runtime = runtime.clone();
        let client = client.isolated_client();
        proxy.push(Box::pin(async move {
            let res = dns::run_dns_resolver(runtime, client, dns_port).await;
            (res, "DNS")
        }));
    }

    if proxy.is_empty() {
        // TODO change this message so it's not only about socks_port
        warn!("No proxy port set; specify -p PORT or use the `socks_port` configuration option.");
        return Ok(());
    }

    let proxy = futures::future::select_all(proxy).map(|(finished, _index, _others)| finished);
    futures::select!(
        r = exit::wait_for_ctrl_c().fuse()
            => r.context("waiting for termination signal"),
        r = proxy.fuse()
            => r.0.context(format!("{} proxy failure", r.1)),
        r = async {
            client.bootstrap().await?;
            info!("Sufficiently bootstrapped; system SOCKS now functional.");
            futures::future::pending::<Result<()>>().await
        }.fuse()
            => r.context("bootstrap"),
    )
}

/// Return true if the environment has been set up to disable FS mistrust.
//
// TODO(nickm): This is duplicate logic from arti_client config. When we make
// fs_mistrust configurable via deserialize, as a real part of our configuration
// logic, we should unify all this code.
fn fs_mistrust_disabled_via_env() -> bool {
    std::env::var_os("ARTI_FS_DISABLE_PERMISSION_CHECKS").is_some()
}

/// Inner function to allow convenient error handling
///
/// # Panics
///
/// Currently, might panic if wrong arguments are specified.
pub fn main_main() -> Result<()> {
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
                    .arg(
                        Arg::with_name("dns-port")
                            .short("d")
                            .takes_value(true)
                            .value_name("PORT")
                            .help("Port to listen on for DNS request (overrides the port in the config if specified).")
                    )
            )
            .setting(AppSettings::SubcommandRequiredElseHelp)
            .get_matches();

    let fs_mistrust_disabled = fs_mistrust_disabled_via_env();

    let mistrust = {
        // TODO: This is duplicate code from arti_client::config.  When we make
        // fs_mistrust configurable via deserialize, as a real part of our configuration
        // logic, we should unify this check.
        let mut mistrust = fs_mistrust::Mistrust::new();
        if fs_mistrust_disabled {
            mistrust.dangerously_trust_everyone();
        }
        mistrust
    };

    let cfg_sources = {
        let mut cfg_sources = arti_config::ConfigurationSources::new();

        let config_files = matches.values_of_os("config-files").unwrap_or_default();
        if config_files.len() == 0 {
            if let Some(default) = default_config_file() {
                match mistrust.verifier().require_file().check(&default) {
                    Ok(()) => {}
                    Err(fs_mistrust::Error::NotFound(_)) => {}
                    Err(e) => return Err(e.into()),
                }
                cfg_sources.push_optional_file(default);
            }
        } else {
            for f in config_files {
                mistrust.verifier().require_file().check(f)?;
                cfg_sources.push_file(f);
            }
        }

        matches
            .values_of("option")
            .unwrap_or_default()
            .for_each(|s| cfg_sources.push_option(s));

        cfg_sources
    };

    let cfg = cfg_sources.load()?;

    let config: ArtiConfig = cfg.try_into().context("read configuration")?;

    let _log_guards = logging::setup_logging(config.logging(), matches.value_of("loglevel"))?;

    if let Some(proxy_matches) = matches.subcommand_matches("proxy") {
        let socks_port = match (
            proxy_matches.value_of("socks-port"),
            config.proxy().socks_port,
        ) {
            (Some(p), _) => p.parse().expect("Invalid port specified"),
            (None, Some(s)) => s,
            (None, None) => 0,
        };

        let dns_port = match (proxy_matches.value_of("dns-port"), config.proxy().dns_port) {
            (Some(p), _) => p.parse().expect("Invalid port specified"),
            (None, Some(s)) => s,
            (None, None) => 0,
        };

        let client_config = config.tor_client_config()?;

        info!(
            "Starting Arti {} in SOCKS proxy mode on port {}...",
            env!("CARGO_PKG_VERSION"),
            socks_port
        );

        process::use_max_file_limit(&config);

        cfg_if::cfg_if! {
            if #[cfg(all(feature="tokio", feature="native-tls"))] {
            use tor_rtcompat::tokio::TokioNativeTlsRuntime as ChosenRuntime;
            } else if #[cfg(all(feature="tokio", feature="rustls"))] {
                use tor_rtcompat::tokio::TokioRustlsRuntime as ChosenRuntime;
            } else if #[cfg(all(feature="async-std", feature="native-tls"))] {
                use tor_rtcompat::async_std::AsyncStdNativeTlsRuntime as ChosenRuntime;
            } else if #[cfg(all(feature="async-std", feature="rustls"))] {
                use tor_rtcompat::async_std::AsyncStdRustlsRuntime as ChosenRuntime;
            }
        }

        let runtime = ChosenRuntime::create()?;

        let rt_copy = runtime.clone();
        rt_copy.block_on(run(
            runtime,
            socks_port,
            dns_port,
            cfg_sources,
            config,
            client_config,
            fs_mistrust_disabled,
        ))?;
        Ok(())
    } else {
        panic!("Subcommand added to clap subcommand list, but not yet implemented")
    }
}

/// Main program, callable directly from a binary crate's `main`
pub fn main() {
    main_main().unwrap_or_else(tor_error::report_and_exit);
}
