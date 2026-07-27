//! Arti consensus method plugin for C Tor
//!
//! Implements `authority-plugin.md` pursuant to `doc/dev/notes/dirauth-sketch.md`.
//!
//! This is the actual implementation.

use anyhow::Context as _;

use tor_dirauth::consensus;
use tor_error::ErrorReport as _;

mod utils;
use utils::FilenameOrStdio;

/// Options and arguments to plugin invocation
#[derive(Debug, clap::Parser)]
#[command(after_help =
//
"For details of semantics, exit status, input/output formats, etc., see the spec:
   arti-authority-plugin dump-spec
Latest version:
   https://gitlab.torproject.org/tpo/core/arti/-/blob/main/crates/arti-dirauth/authority-plugin.md
"
)]
struct CliArgs {
    /// Operation verb and its arguments
    #[command(subcommand)]
    op: CliOperation,
}

/// Operation verb and its arguments
#[derive(Debug, Clone, clap::Subcommand)]
enum CliOperation {
    /// `list-methods`, "mode 1"
    ListMethods {
        /// Output file
        #[arg(short = 'o')]
        output: FilenameOrStdio,
    },

    /// Print the specification to stdout, in markdown format
    //
    // This is to save us from having to document everything again here.
    // Instead, this can be regarded as part of the program's help output.
    // Our help output has a link to the rendered version in gitlab
    // (`after_help` attribute on `CliArgs`)
    DumpSpec {},
}

/// Top-level error - program exits with this, or `Ok(())`
#[derive(Debug, thiserror::Error)]
enum CliError {
    /// Invalid operation or usage
    #[error("invalid operation or usage")]
    InvalidInputs(#[source] anyhow::Error),

    /// Unsupported consensus method
    #[error("fall back to C Tor")]
    #[allow(dead_code)] // TODO DIRAUTH
    UnsupportedConsensusMethod(#[from] consensus::UnsupportedConsensusMethod),

    /// Operational error
    #[error("failed")]
    OperationalError(#[source] anyhow::Error),
}

//==================== implementations ====================

/// Actual implementation of the plugin's invocations
///
/// Split off for ease of testing.
fn plugin_impl(args: CliArgs) -> Result<(), CliError> {
    match args.op {
        CliOperation::ListMethods { output } => output.write(|w| {
            for m in consensus::SupportedConsensusMethod::iter_all() {
                writeln!(w, "{m}")?;
            }
            Ok(())
        }),

        CliOperation::DumpSpec {} => {
            print!("{}", include_str!("../authority-plugin.md"));
            Ok(())
        }
    }
}

/// Entrypoint for the Arti-in-C-Tor consensus method plugin
pub fn plugin_main() {
    match (|| {
        let args = <CliArgs as clap::Parser>::try_parse()
            .context("invalid arguments")
            .map_err(CliError::InvalidInputs)?;

        plugin_impl(args)
    })() {
        Ok(()) => {}
        Err(e) => {
            eprintln!("arti-authority-plugin: error: {}", e.report());
            std::process::exit(i32::from(e.exit_status()));
        }
    }
}

impl CliError {
    /// Exit status corresponding to this error, as per `authority-plugin.md`
    ///
    /// Returns `u8` because that's what Unix processes can exit,
    /// `std::process:exit`'s `i32` argument notwithstanding.
    fn exit_status(&self) -> u8 {
        use CliError as E;
        match self {
            E::InvalidInputs { .. } => 8,
            E::UnsupportedConsensusMethod { .. } => 10,
            E::OperationalError { .. } => 32,
        }
    }
}
