use std::ffi::OsString;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// A Rust Tor relay implementation.
#[derive(Clone, Debug, Parser)]
#[command(author = "The Tor Project Developers")]
#[command(version)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Commands,

    /// Override the log level from the configuration.
    #[arg(long, short, global = true)]
    #[arg(value_name = "LEVEL")]
    #[clap(default_value_t = LogLevel::Info)]
    pub(crate) log_level: LogLevel,

    /// Don't check permissions on the files we use.
    #[arg(long, global = true)]
    pub(crate) disable_fs_permission_checks: bool,

    /// Override config file parameters, using TOML-like syntax.
    #[arg(long = "option", short, global = true)]
    #[arg(value_name = "KEY=VALUE")]
    pub(crate) options: Vec<String>,

    /// Config file(s) to read.
    #[arg(long, short, global = true)]
    #[arg(value_name = "FILE")]
    #[clap(default_values_t = default_config_files().into_iter().map(CliOsString))]
    pub(crate) config: Vec<CliOsString>,
}

/// Main subcommands.
#[derive(Clone, Debug, Subcommand)]
pub(crate) enum Commands {
    /// Run the relay.
    Run(RunArgs),
    /// Print build information.
    BuildInfo,
}

/// Arguments when running an Arti relay.
#[derive(Clone, Debug, Args)]
pub(crate) struct RunArgs {}

/// Paths used for default configuration files.
fn default_config_files() -> Vec<OsString> {
    // TODO: these are temporary default paths
    vec![
        "~/.config/arti-relay/arti-relay.toml".into(),
        "~/.config/arti-relay/arti-relay.d/".into(),
    ]
}

/// Log levels allowed by the cli.
#[derive(Clone, Debug, Eq, PartialEq, ValueEnum)]
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
        assert_eq!(cli.log_level, LogLevel::Warn);
        let cli = Cli::parse_from(["arti-relay", "run", "--log-level", "warn"]);
        assert_eq!(cli.log_level, LogLevel::Warn);

        let cli = Cli::parse_from(["arti-relay", "--disable-fs-permission-checks", "run"]);
        assert!(cli.disable_fs_permission_checks);
        let cli = Cli::parse_from(["arti-relay", "run", "--disable-fs-permission-checks"]);
        assert!(cli.disable_fs_permission_checks);
    }

    #[test]
    fn clap_bug() {
        let cli = Cli::parse_from(["arti-relay", "-o", "foo=1", "run"]);
        assert_eq!(cli.options, vec!["foo=1"]);

        let cli = Cli::parse_from(["arti-relay", "-o", "foo=1", "-o", "bar=2", "run"]);
        assert_eq!(cli.options, vec!["foo=1", "bar=2"]);

        // this is https://github.com/clap-rs/clap/issues/3938
        // TODO: this is a footgun, and we should consider alternatives to clap's 'global' args
        let cli = Cli::parse_from(["arti-relay", "-o", "foo=1", "run", "-o", "bar=2"]);
        assert_eq!(cli.options, vec!["bar=2"]);
    }
}
