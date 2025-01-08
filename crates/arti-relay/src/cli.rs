use std::ffi::OsString;

use clap::{Args, Command, Parser, Subcommand, ValueEnum};

use crate::config::default_config_paths;

/// This macro exists only so that we can use the string literal in a `concat!` macro call.
/// You should generally use [`FS_DISABLE_PERMISSION_CHECKS_ENV_NAME`] instead.
macro_rules! fs_disable_permission_checks_env_name {
    () => {
        // TODO: this uses the environment variable "ARTI_FS_DISABLE_PERMISSION_CHECKS";
        // is this fine, or do we want an arti-relay-specific variable?
        "ARTI_FS_DISABLE_PERMISSION_CHECKS"
    };
}

/// The name of the environment variable that provides a default value for the
/// '--disable_fs_permission_checks' cli option.
pub(crate) const FS_DISABLE_PERMISSION_CHECKS_ENV_NAME: &str =
    fs_disable_permission_checks_env_name!();

/// A Rust Tor relay implementation.
#[derive(Clone, Debug, Parser)]
#[command(author = "The Tor Project Developers")]
#[command(version)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Commands,

    #[clap(flatten)]
    pub(crate) global: GlobalArgs,
}

/// Main subcommands.
#[derive(Clone, Debug, Subcommand)]
pub(crate) enum Commands {
    /// Run the relay.
    Run(RunArgs),
    /// Print build information.
    BuildInfo,
}

/// Global arguments for all commands.
// NOTE: `global = true` should be set for each field
#[derive(Clone, Debug, Args)]
pub(crate) struct GlobalArgs {
    /// Override the log level from the configuration.
    #[arg(long, short, global = true)]
    #[arg(value_name = "LEVEL")]
    pub(crate) log_level: Option<LogLevel>,

    /// Don't check permissions on the files we use.
    // clap has built-in support for environment variable defaults,
    // but fs-mistrust has its own environment variable evaluation rules
    // (see `fs_mistrust::Mistrust`).
    #[arg(long_help = concat!(
        "Don't check permissions on the files we use\n\n",
        "Overrides the '",
        fs_disable_permission_checks_env_name!(),
        "' environment variable and any configuration files if set.",
    ))]
    #[arg(long, global = true)]
    pub(crate) disable_fs_permission_checks: bool,

    /// Override config file parameters, using TOML-like syntax.
    #[arg(long = "option", short, global = true)]
    #[arg(value_name = "KEY=VALUE")]
    pub(crate) options: Vec<String>,

    /// Config files and directories to read.
    #[arg(long, short, global = true)]
    #[arg(value_name = "FILE")]
    // TODO: we don't want to unwrap here
    #[clap(default_values_t = default_config_paths().unwrap().into_iter().map(Into::into).map(CliOsString))]
    pub(crate) config: Vec<CliOsString>,
}

/// Arguments when running an Arti relay.
#[derive(Clone, Debug, Args)]
pub(crate) struct RunArgs {}

/// Log levels allowed by the cli.
#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Error => write!(f, "error"),
            Self::Warn => write!(f, "warn"),
            Self::Info => write!(f, "info"),
            Self::Debug => write!(f, "debug"),
            Self::Trace => write!(f, "trace"),
        }
    }
}

impl From<LogLevel> for tracing::metadata::Level {
    fn from(x: LogLevel) -> Self {
        match x {
            LogLevel::Error => Self::ERROR,
            LogLevel::Warn => Self::WARN,
            LogLevel::Info => Self::INFO,
            LogLevel::Debug => Self::DEBUG,
            LogLevel::Trace => Self::TRACE,
        }
    }
}

/// An [`OsString`] wrapper which implements `Display`; designed for use with the cli help text.
#[derive(Debug, Clone, Eq, PartialEq, derive_more::From)]
pub(crate) struct CliOsString(pub(crate) OsString);

impl std::fmt::Display for CliOsString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // we can't (and don't want to) write non-utf-8 bytes in the cli help output
        self.0.to_string_lossy().fmt(f)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn common_flags() {
        Cli::parse_from(["arti-relay", "build-info"]);
        Cli::parse_from(["arti-relay", "run"]);

        let cli = Cli::parse_from(["arti-relay", "--log-level", "warn", "run"]);
        assert_eq!(cli.global.log_level, Some(LogLevel::Warn));
        let cli = Cli::parse_from(["arti-relay", "run", "--log-level", "warn"]);
        assert_eq!(cli.global.log_level, Some(LogLevel::Warn));

        let cli = Cli::parse_from(["arti-relay", "--disable-fs-permission-checks", "run"]);
        assert!(cli.global.disable_fs_permission_checks);
        let cli = Cli::parse_from(["arti-relay", "run", "--disable-fs-permission-checks"]);
        assert!(cli.global.disable_fs_permission_checks);
    }

    #[test]
    fn clap_bug() {
        let cli = Cli::parse_from(["arti-relay", "-o", "foo=1", "run"]);
        assert_eq!(cli.global.options, vec!["foo=1"]);

        let cli = Cli::parse_from(["arti-relay", "-o", "foo=1", "-o", "bar=2", "run"]);
        assert_eq!(cli.global.options, vec!["foo=1", "bar=2"]);

        // this is https://github.com/clap-rs/clap/issues/3938
        // TODO: this is a footgun, and we should consider alternatives to clap's 'global' args
        let cli = Cli::parse_from(["arti-relay", "-o", "foo=1", "run", "-o", "bar=2"]);
        assert_eq!(cli.global.options, vec!["bar=2"]);
    }

    #[test]
    fn global_args_are_global() {
        let cmd = Command::new("test");
        let cmd = GlobalArgs::augment_args(cmd);

        // check that each argument in `GlobalArgs` has "global" set
        for arg in cmd.get_arguments() {
            assert!(
                arg.is_global_set(),
                "'global' must be set for {:?}",
                arg.get_long()
            );
        }
    }
}
