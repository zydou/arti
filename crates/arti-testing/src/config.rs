//! Reading configuration and command line issues in arti-testing.

use crate::rt::badtcp::ConditionalAction;
use crate::{Action, Job, TcpBreakage};

use anyhow::{Result, anyhow};
use clap::{Arg, ArgAction, Command, value_parser};
use std::ffi::OsString;
use std::str::FromStr;
use std::time::Duration;

use tor_config::{ConfigurationSource, ConfigurationSources};

/// Parse the command line into a Job description.
pub(crate) fn parse_cmdline() -> Result<Job> {
    let matches = Command::new("Arti testing tool")
        .version(env!("CARGO_PKG_VERSION"))
        .author("The Tor Project Developers")
        .about("Testing program for unusual arti behaviors")
        // HACK: see note in arti/src/main.rs
        .override_usage("arti-testing <SUBCOMMAND> [OPTIONS]")
        .arg(
            Arg::new("config-files")
                .short('c')
                .long("config")
                .action(ArgAction::Set)
                .value_name("FILE")
                .value_parser(value_parser!(OsString))
                .action(ArgAction::Append)
                .global(true),
        )
        .arg(
            Arg::new("option")
                .short('o')
                .action(ArgAction::Set)
                .value_name("KEY=VALUE")
                .action(ArgAction::Append)
                .global(true),
        )
        .arg(
            Arg::new("log")
                .short('l')
                .long("log")
                .action(ArgAction::Set)
                .value_name("FILTER")
                .default_value("debug")
                .global(true),
        )
        .arg(
            Arg::new("timeout")
                .long("timeout")
                .action(ArgAction::Set)
                .value_name("SECS")
                .value_parser(value_parser!(u64))
                .default_value("30")
                .global(true),
        )
        .arg(
            Arg::new("expect")
                .long("expect")
                .action(ArgAction::Set)
                .value_name("success|failure|timeout")
                .global(true),
        )
        .arg(
            Arg::new("tcp-failure")
                .long("tcp-failure")
                .action(ArgAction::Set)
                .value_name("none|timeout|error|blackhole")
                .global(true),
        )
        .arg(
            Arg::new("tcp-failure-on")
                .long("tcp-failure-on")
                .action(ArgAction::Set)
                .value_name("all|v4|v6|non443")
                .global(true),
        )
        .arg(
            Arg::new("tcp-failure-stage")
                .long("tcp-failure-stage")
                .action(ArgAction::Set)
                .value_name("bootstrap|connect")
                .global(true),
        )
        .arg(
            Arg::new("tcp-failure-delay")
                .long("tcp-failure-delay")
                .action(ArgAction::Set)
                .value_name("SECS")
                .global(true),
        )
        .arg(
            Arg::new("dir-filter")
                .long("dir-filter")
                .action(ArgAction::Set)
                .value_name("FILTER_NAME")
                .global(true),
        )
        .subcommand(
            Command::new("connect")
                .about("Try to bootstrap and connect to an address")
                .arg(
                    Arg::new("target")
                        .long("target")
                        .action(ArgAction::Set)
                        .value_name("ADDR:PORT")
                        .default_value("www.torproject.org:443"),
                )
                .arg(
                    Arg::new("retry")
                        .long("retry")
                        .action(ArgAction::Set)
                        .value_name("DELAY")
                        .value_parser(value_parser!(u64)),
                ),
        )
        .subcommand(Command::new("bootstrap").about("Try to bootstrap only"))
        .subcommand_required(true)
        .arg_required_else_help(true)
        .get_matches();

    let config = {
        // TODO: this is mostly duplicate code.
        let mut cfg_sources = ConfigurationSources::new_empty();

        let config_files = matches
            .get_many::<OsString>("config-files")
            .unwrap_or_default();

        if config_files.len() == 0 {
            // Not using the regular default here; we don't want interference
            // from the user's regular setup.
            // Maybe change this later on if we decide it's silly.
            return Err(anyhow!("Sorry, you need to give me a configuration file."));
        } else {
            config_files.for_each(|f| {
                cfg_sources.push_source(
                    ConfigurationSource::from_path(f),
                    tor_config::sources::MustRead::MustRead,
                );
            });
        }

        matches
            .get_many::<String>("option")
            .unwrap_or_default()
            .for_each(|s| cfg_sources.push_option(s));

        cfg_sources
    };

    let timeout = Duration::from_secs(
        *matches
            .get_one::<u64>("timeout")
            .expect("Failed to pick default timeout"),
    );

    let console_log = matches
        .get_one::<String>("log")
        .expect("Failed to get default log level")
        .clone();

    let expectation = matches
        .get_one::<String>("expect")
        .map(|s| crate::Expectation::from_str(s.as_str()))
        .transpose()?;

    let tcp_breakage = {
        let action = matches
            .get_one::<String>("tcp-failure")
            .unwrap_or(&"none".to_string())
            .parse()?;
        let stage = matches
            .get_one::<String>("tcp-failure-stage")
            .unwrap_or(&"bootstrap".to_string())
            .parse()?;
        let delay = matches
            .get_one::<String>("tcp-failure-delay")
            .map(|d| d.parse().map(Duration::from_secs))
            .transpose()?;
        let when = matches
            .get_one::<String>("tcp-failure-on")
            .unwrap_or(&"all".to_string())
            .parse()?;
        let action = ConditionalAction { action, when };

        TcpBreakage {
            action,
            stage,
            delay,
        }
    };

    let dir_filter = matches
        .get_one::<String>("dir-filter")
        .map(|s| crate::dirfilter::new_filter(s.as_str()))
        .transpose()?
        .unwrap_or_else(crate::dirfilter::nil_filter);

    let action = if let Some(_m) = matches.subcommand_matches("bootstrap") {
        Action::Bootstrap
    } else if let Some(matches) = matches.subcommand_matches("connect") {
        let target = matches
            .get_one::<String>("target")
            .expect("Failed to set default connect target")
            .clone();
        let retry_delay = matches
            .get_one::<u64>("retry")
            .map(|d| Duration::from_secs(*d));

        Action::Connect {
            target,
            retry_delay,
        }
    } else {
        return Err(anyhow!("No subcommand given?"));
    };

    Ok(Job {
        action,
        config,
        timeout,
        tcp_breakage,
        dir_filter,
        console_log,
        expectation,
    })
}
