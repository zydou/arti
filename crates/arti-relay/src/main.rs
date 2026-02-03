//! A relay binary use to join the Tor network to relay anonymous communication.
//!
//! NOTE: This binary is still highly experimental as in in active development, not stable and
//! without any type of guarantee of running or even working.
//!
//! ## Error handling
//!
//! We return [`anyhow::Error`] for functions whose errors will always result in an exit and don't
//! need to be handled individually.
//! When we do need to handle errors, functions should return a more comprehensive error type (for
//! example one created with `thiserror`).

// @@ begin lint list maintained by maint/add_warning @@
#![allow(renamed_and_removed_lints)] // @@REMOVE_WHEN(ci_arti_stable)
#![allow(unknown_lints)] // @@REMOVE_WHEN(ci_arti_nightly)
#![warn(missing_docs)]
#![warn(noop_method_call)]
#![warn(unreachable_pub)]
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
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![deny(clippy::print_stderr)]
#![deny(clippy::print_stdout)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unchecked_time_subtraction)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::mod_module_files)]
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
#![allow(clippy::result_large_err)] // temporary workaround for arti#587
#![allow(clippy::needless_raw_string_hashes)] // complained-about code is fine, often best
#![allow(clippy::needless_lifetimes)] // See arti#1765
#![allow(mismatched_lifetime_syntaxes)] // temporary workaround for arti#2060
#![deny(clippy::unused_async)]
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

mod cli;
mod client;
mod config;
mod relay;
mod tasks;
mod util;

use std::io::IsTerminal as _;

use anyhow::Context;
use clap::Parser;
use futures::FutureExt;
use safelog::with_safe_logging_suppressed;
use tor_rtcompat::SpawnExt;
use tor_rtcompat::tokio::TokioRustlsRuntime;
use tor_rtcompat::{Runtime, ToplevelRuntime};
use tracing::{debug, info, trace};
use tracing_subscriber::FmtSubscriber;
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::util::SubscriberInitExt;

use crate::config::{DEFAULT_LOG_LEVEL, TorRelayConfig, base_resolver};
use crate::relay::InertTorRelay;

fn main() {
    // Will exit if '--help' used or there's a parse error.
    let cli = cli::Cli::parse();

    if let Err(e) = main_main(cli) {
        // TODO: Use arti_client's `HintableError` here (see `arti::main`)?
        // TODO: Why do we suppress safe logging?
        // TODO: Do we want to log the error?
        // We use anyhow's error formatting here rather than `tor_error::report_and_exit` since the
        // latter seems to omit some error info and anyhow's error formatting is nicer.
        #[allow(clippy::print_stderr)]
        with_safe_logging_suppressed(|| {
            eprintln!("Error: {e:?}");
            // The 127 is copied from `tor_error::report_and_exit`.
            // It's unclear why 127 was chosen there.
            std::process::exit(127);
        });
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
        .with_writer(std::io::stderr)
        .finish()
        .init();

    match cli.command {
        #[allow(clippy::print_stdout)]
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
// Pass by value so that we don't need to clone fields, which keeps the code simpler.
#[allow(clippy::needless_pass_by_value)]
fn start_relay(_args: cli::RunArgs, global_args: cli::GlobalArgs) -> anyhow::Result<()> {
    // TODO: Warn (or exit?) if running as root; see 'arti::process::running_as_root()'.

    let mut cfg_sources = global_args
        .config()
        .context("Failed to get configuration sources")?;

    debug!(
        "Using override options: {}",
        util::iter_join(", ", cfg_sources.options()),
    );

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
        .with_writer(std::io::stderr)
        .finish();
    let logger = tracing::Dispatch::new(logger);

    tracing::dispatcher::with_default(&logger, || {
        let runtime = init_runtime().context("Failed to initialize the runtime")?;

        // Configure tor-log-ratelim early before we begin logging.
        tor_log_ratelim::install_runtime(runtime.clone())
            .context("Failed to initialze tor-log-ratelim")?;

        let path_resolver = base_resolver();
        let relay =
            InertTorRelay::new(config, path_resolver).context("Failed to initialize the relay")?;

        match mainloop(&runtime, run_relay(runtime.clone(), relay))? {
            MainloopStatus::Finished(Err(e)) => Err(e),
            MainloopStatus::CtrlC => {
                info!("Received a ctrl-c; stopping the relay");
                Ok(())
            }
        }
    })
}

/// A helper to drive a future using a runtime.
///
/// This calls `block_on` on the runtime.
/// The future will be cancelled on a ctrl-c event.
fn mainloop<T: Send + 'static>(
    runtime: &impl ToplevelRuntime,
    fut: impl Future<Output = T> + Send + 'static,
) -> anyhow::Result<MainloopStatus<T>> {
    trace!("Starting runtime");

    let rv = runtime.block_on(async {
        // Code running in 'block_on' runs slower than in a task (in tokio at least),
        // so the future is run on a task.
        let mut handle = runtime
            .spawn_with_handle(fut)
            .context("Failed to spawn task")?
            .fuse();

        futures::select!(
            // Signal handler is registered on the first poll.
            res = tokio::signal::ctrl_c().fuse() => {
                let () = res.context("Failed to listen for ctrl-c event")?;
                trace!("Received a ctrl-c");
                // Dropping the handle will cancel the task, so we do that explicitly here.
                drop(handle);
                Ok(MainloopStatus::CtrlC)
            }
            x = handle => Ok(MainloopStatus::Finished(x)),
        )
    });

    trace!("Finished runtime");
    rv
}

/// Run the relay.
///
/// This blocks until the relay stops.
async fn run_relay<R: Runtime>(
    runtime: R,
    inert_relay: InertTorRelay,
) -> anyhow::Result<void::Void> {
    let relay = inert_relay
        .init(runtime)
        .await
        .context("Failed to bootstrap")?;
    // This blocks until end of time or an error.
    relay.run().await
}

/// Initialize a runtime.
///
/// Any cli commands that need a runtime should call this so that we use a consistent runtime.
fn init_runtime() -> std::io::Result<impl ToplevelRuntime> {
    // Use the tokio runtime from tor_rtcompat unless we later find a reason to use tokio directly.
    // See https://gitlab.torproject.org/tpo/core/arti/-/work_items/1744.
    // Relays must use rustls as native-tls doesn't support
    // `CertifiedConn::export_keying_material()`.

    // Note: See comments in `tor_rtcompat::impls::rustls::RustlsProvider`
    // about choice of default crypto provider.
    let _idempotent_ignore =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    TokioRustlsRuntime::create()
}

/// The result of [`mainloop`].
enum MainloopStatus<T> {
    /// The result from the completed future.
    Finished(T),
    /// The future was cancelled due to a ctrl-c event.
    CtrlC,
}
