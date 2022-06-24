//! A minimal command line program for connecting to the tor network
//!
//! (If you want a more general Tor client library interface, use
//! [`arti_client`].)
//!
//! This crate is the primary command-line interface for
//! [Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to implement
//! [Tor](https://www.torproject.org/) in Rust. Many other crates in Arti depend
//! on it.
//!
//! Note that Arti is a work in progress; although we've tried to write all the
//! critical security components, you probably shouldn't use Arti in production
//! until it's a bit more mature.
//!
//! More documentation will follow as this program improves.  For now, just know
//! that it can run as a simple SOCKS proxy over the Tor network. It will listen
//! on port 9150 by default, but you can override this in the configuration.
//!
//! # Command-line interface
//!
//! (This is not stable; future versions will break this.)
//!
//! `arti` uses the [`clap`](https://docs.rs/clap/) crate for command-line
//! argument parsing; run `arti help` to get it to print its documentation.
//!
//! The only currently implemented subcommand is `arti proxy`; try `arti help
//! proxy` for a list of options you can pass to it.
//!
//! # Configuration
//!
//! By default, `arti` looks for its configuration files in a platform-dependent
//! location.
//!
//! | OS      | Configuration File                                 |
//! |---------|----------------------------------------------------|
//! | Unix    | `~/.config/arti/arti.toml`                         |
//! | macOS   | `~/Library/Application Support/arti/arti.toml`     |
//! | Windows | `\Users\<USERNAME>\AppData\Roaming\arti\arti.toml` |
//!
//! The configuration file is TOML.  (We do not guarantee its stability.) For an
//! example see [`arti_defaults.toml`](./arti_defaults.toml).
//!
//! # Compile-time features
//!
//! ## Additive features
//!
//! * `tokio` (default): Use the tokio runtime library as our backend.
//! * `async-std`: Use the async-std runtime library as our backend. This
//!   feature has no effect unless building with `--no-default-features` to
//!   disable tokio.
//! * `native-tls` -- Build with support for the `native_tls` TLS backend.
//!   (default)
//! * `journald` -- Build with support for logging to the `journald` logging
//!   backend (available as part of systemd.)
//!
//! * `full` -- Build with all features above, along with all stable additive
//!   features from other arti crates.  (This does not include experimental
//!   features. It also does not include features that select a particular
//!   implementation to the exclusion of another, or those that set a build
//!   flag.)
//!
//! * `rustls` -- build with the [rustls](https://github.com/rustls/rustls)
//!   TLS backend.  This is not included in `full`, since it uses the
//!   `ring` crate, which uses the old (3BSD/SSLEay) OpenSSL license, which may
//!   introduce licensing compatibility issues.
//!
//! ## Build-flag related features
//!
//! * `static` -- Link with static versions of your system dependencies,
//!   including sqlite and/or openssl.  (⚠ Warning ⚠: this feature will include
//!   a dependency on native-tls, even if you weren't planning to use
//!   native-tls.  If you only want to build with a static sqlite library,
//!   enable the `static-sqlite` feature.  We'll look for better solutions here
//!   in the future.)
//! * `static-sqlite` -- Link with a static version of sqlite.
//! * `static-native-tls` -- Link with a static version of `native-tls`. Enables
//!   `native-tls`.
//!
//! ## Cryptographic acceleration features
//!
//! Libraries should not enable these by default, since they replace one
//! implementation with another.
//!
//! * `accel-sha1-asm` -- Accelerate cryptography by using an assembly
//!   implementation of SHA1, if one is available.
//! * `accel-openssl` -- Accelerate cryptography by using openssl as a backend.
//!
//! ## Experimental features
//!
//!  Note that the APIs enabled by these features are NOT covered by semantic
//!  versioning guarantees: we might break them or remove them between patch
//!  versions.
//!
//! * `experimental` -- Build with all experimental features above, along with
//!   all experimental features from other arti crates.
//!
//! # Limitations
//!
//! There are many missing features.  Among them: there's no onion service
//! support yet. There's no anti-censorship support.  You can't be a relay.
//! There isn't any kind of proxy besides SOCKS.
//!
//! See the [README
//! file](https://gitlab.torproject.org/tpo/core/arti/-/blob/main/README.md) for
//! a more complete list of missing features.
//!
//! # Library for building command-line client
//!
//! This library crate contains code useful for making a command line program
//! similar to `arti`. The API should not be considered stable.

// @@ begin lint list maintained by maint/add_warning @@
#![cfg_attr(not(ci_arti_stable), allow(renamed_and_removed_lints))]
#![cfg_attr(not(ci_arti_nightly), allow(unknown_lints))]
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
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

// Overrides specific to this crate:
#![allow(clippy::print_stderr)]
#![allow(clippy::print_stdout)]

pub mod cfg;
pub mod dns;
pub mod exit;
pub mod logging;
pub mod process;
pub mod socks;
pub mod watch_cfg;

use std::fmt::Write;

pub use cfg::{
    ApplicationConfig, ApplicationConfigBuilder, ArtiCombinedConfig, ArtiConfig, ArtiConfigBuilder,
    ProxyConfig, ProxyConfigBuilder, SystemConfig, SystemConfigBuilder, ARTI_EXAMPLE_CONFIG,
};
pub use logging::{LoggingConfig, LoggingConfigBuilder};

use arti_client::config::{default_config_file, fs_permissions_checks_disabled_via_env};
use arti_client::{TorClient, TorClientConfig};
use safelog::with_safe_logging_suppressed;
use tor_config::ConfigurationSources;
use tor_rtcompat::{BlockOn, Runtime};

use anyhow::{Context, Error, Result};
use clap::{App, AppSettings, Arg, SubCommand};
use tracing::{info, warn};

/// Shorthand for a boxed and pinned Future.
type PinnedFuture<T> = std::pin::Pin<Box<dyn futures::Future<Output = T>>>;

/// Create a runtime for Arti to use.
fn create_runtime() -> std::io::Result<impl Runtime> {
    cfg_if::cfg_if! {
        if #[cfg(all(feature="tokio", feature="native-tls"))] {
        use tor_rtcompat::tokio::TokioNativeTlsRuntime as ChosenRuntime;
        } else if #[cfg(all(feature="tokio", feature="rustls"))] {
            use tor_rtcompat::tokio::TokioRustlsRuntime as ChosenRuntime;
        } else if #[cfg(all(feature="async-std", feature="native-tls"))] {
            use tor_rtcompat::async_std::AsyncStdNativeTlsRuntime as ChosenRuntime;
        } else if #[cfg(all(feature="async-std", feature="rustls"))] {
            use tor_rtcompat::async_std::AsyncStdRustlsRuntime as ChosenRuntime;
        } else {
            compile_error!("You must configure both an async runtime and a TLS stack. See doc/TROUBLESHOOTING.md for more.");
        }
    }
    ChosenRuntime::create()
}

/// Return a (non-exhaustive) array of enabled Cargo features, for version printing purposes.
fn list_enabled_features() -> &'static [&'static str] {
    // HACK(eta): We can't get this directly, so we just do this awful hack instead.
    // Note that we only list features that aren't about the runtime used, since that already
    // gets printed separately.
    &[
        #[cfg(feature = "journald")]
        "journald",
        #[cfg(feature = "static-sqlite")]
        "static-sqlite",
        #[cfg(feature = "static-native-tls")]
        "static-native-tls",
    ]
}

/// Run the main loop of the proxy.
///
/// # Panics
///
/// Currently, might panic if things go badly enough wrong
pub async fn run<R: Runtime>(
    runtime: R,
    socks_port: u16,
    dns_port: u16,
    config_sources: ConfigurationSources,
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
        warn!("No proxy port set; specify -p PORT (for `socks_port`) or -d PORT (for `dns_port`). Alternatively, use the `socks_port` or `dns_port` configuration option.");
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
    if let Ok(default) = default_config_file() {
        // If we couldn't resolve the default config file, then too bad.  If something
        // actually tries to use it, it will produce an error, but don't fail here
        // just for that reason.
        write!(config_file_help, " Defaults to {:?}", default).unwrap();
    }

    // We create the runtime now so that we can use its `Debug` impl to describe it for
    // the version string.
    let runtime = create_runtime()?;
    let features = list_enabled_features();
    let long_version = format!(
        "{}\nusing runtime: {:?}\noptional features: {}",
        env!("CARGO_PKG_VERSION"),
        runtime,
        if features.is_empty() {
            "<none>".into()
        } else {
            features.join(", ")
        }
    );

    let clap_app =
        App::new("Arti")
            .version(env!("CARGO_PKG_VERSION"))
            .long_version(&long_version as &str)
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
            .arg(
                Arg::with_name("disable-fs-permission-checks")
                    .long("disable-fs-permission-checks")
                    .takes_value(false)
                    .value_name("FILE")
                    .global(true)
                    .help("Don't check permissions on the files we use."),
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
            .setting(AppSettings::SubcommandRequiredElseHelp);

    // Tracing doesn't log anything when there is no subscriber set.  But we want to see
    // logging messages from config parsing etc.  We can't set the global default subscriber
    // because we can only set it once.  The other ways involve a closure.  So we have a
    // closure for all the startup code which runs *before* we set the logging properly.
    //
    // There is no cooked way to print our program name, so we do it like this.  This
    // closure is called to "make" a "Writer" for each message, so it runs at the right time:
    // before each message.
    let pre_config_logging_writer = || {
        // Weirdly, with .without_time(), tracing produces messages with a leading space.
        eprint!("arti:");
        std::io::stderr()
    };
    let pre_config_logging = tracing_subscriber::fmt()
        .without_time()
        .with_writer(pre_config_logging_writer)
        .finish();
    let pre_config_logging = tracing::Dispatch::new(pre_config_logging);
    let pre_config_logging_ret = tracing::dispatcher::with_default(&pre_config_logging, || {
        let matches = clap_app.get_matches();

        let fs_mistrust_disabled = fs_permissions_checks_disabled_via_env()
            | matches.is_present("disable-fs-permission-checks");

        // A Mistrust object to use for loading our configuration.  Elsewhere, we
        // use the value _from_ the configuration.
        let cfg_mistrust = if fs_mistrust_disabled {
            fs_mistrust::Mistrust::new_dangerously_trust_everyone()
        } else {
            fs_mistrust::Mistrust::new()
        };

        let cfg_sources = {
            let mut cfg_sources = ConfigurationSources::from_cmdline(
                default_config_file()?,
                matches.values_of_os("config-files").unwrap_or_default(),
                matches.values_of("option").unwrap_or_default(),
            );
            cfg_sources.set_mistrust(cfg_mistrust);
            cfg_sources
        };

        let cfg = cfg_sources.load()?;
        let (config, client_config) =
            tor_config::resolve::<ArtiCombinedConfig>(cfg).context("read configuration")?;

        let log_mistrust = if fs_mistrust_disabled {
            fs_mistrust::Mistrust::new_dangerously_trust_everyone()
        } else {
            client_config.fs_mistrust().clone()
        };

        Ok::<_, Error>((
            matches,
            cfg_sources,
            config,
            client_config,
            fs_mistrust_disabled,
            log_mistrust,
        ))
    })?;
    // Sadly I don't seem to be able to persuade rustfmt to format the two lists of
    // variable names identically.
    let (matches, cfg_sources, config, client_config, fs_mistrust_disabled, log_mistrust) =
        pre_config_logging_ret;

    let _log_guards = logging::setup_logging(
        config.logging(),
        &log_mistrust,
        matches.value_of("loglevel"),
    )?;

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

        info!(
            "Starting Arti {} in SOCKS proxy mode on port {}...",
            env!("CARGO_PKG_VERSION"),
            socks_port
        );

        process::use_max_file_limit(&config);

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
    main_main().unwrap_or_else(|e| with_safe_logging_suppressed(|| tor_error::report_and_exit(e)));
}
