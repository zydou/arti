//! Reading configuration and command line issues in arti-testing.

use crate::rt::badtcp::ConditionalAction;
use crate::{Action, Job, TcpBreakage};

use anyhow::{anyhow, Result};
use clap::{App, AppSettings, Arg, SubCommand};
use std::str::FromStr;
use std::time::Duration;

use tor_config::{ConfigurationSource, ConfigurationSources};

/// Helper: parse an optional string as a number of seconds.
fn int_str_to_secs(s: Option<&str>) -> Result<Option<Duration>> {
    match s {
        Some(s) => Ok(Some(Duration::from_secs(s.parse()?))),
        None => Ok(None),
    }
}

/// Parse the command line into a Job description.
pub(crate) fn parse_cmdline() -> Result<Job> {
    let matches = App::new("Arti testing tool")
        .version(env!("CARGO_PKG_VERSION"))
        .author("The Tor Project Developers")
        .about("Testing program for unusual arti behaviors")
        // HACK: see note in arti/src/main.rs
        .usage("arti-testing <SUBCOMMAND> [OPTIONS]")
        .arg(
            Arg::with_name("config-files")
                .short("c")
                .long("config")
                .takes_value(true)
                .value_name("FILE")
                .multiple(true)
                .global(true),
        )
        .arg(
            Arg::with_name("option")
                .short("o")
                .takes_value(true)
                .value_name("KEY=VALUE")
                .multiple(true)
                .global(true),
        )
        .arg(
            Arg::with_name("log")
                .short("l")
                .long("log")
                .takes_value(true)
                .value_name("FILTER")
                .global(true),
        )
        .arg(
            Arg::with_name("timeout")
                .long("timeout")
                .takes_value(true)
                .value_name("SECS")
                .global(true),
        )
        .arg(
            Arg::with_name("expect")
                .long("expect")
                .takes_value(true)
                .value_name("success|failure|timeout")
                .global(true),
        )
        .arg(
            Arg::with_name("tcp-failure")
                .long("tcp-failure")
                .takes_value(true)
                .value_name("none|timeout|error|blackhole")
                .global(true),
        )
        .arg(
            Arg::with_name("tcp-failure-on")
                .long("tcp-failure-on")
                .takes_value(true)
                .value_name("all|v4|v6|non443")
                .global(true),
        )
        .arg(
            Arg::with_name("tcp-failure-stage")
                .long("tcp-failure-stage")
                .takes_value(true)
                .value_name("bootstrap|connect")
                .global(true),
        )
        .arg(
            Arg::with_name("tcp-failure-delay")
                .long("tcp-failure-delay")
                .takes_value(true)
                .value_name("SECS")
                .global(true),
        )
        .arg(
            Arg::with_name("dir-filter")
                .long("dir-filter")
                .takes_value(true)
                .value_name("FILTER_NAME")
                .global(true),
        )
        .subcommand(
            SubCommand::with_name("connect")
                .about("Try to bootstrap and connect to an address")
                .arg(
                    Arg::with_name("target")
                        .long("target")
                        .takes_value(true)
                        .value_name("ADDR:PORT")
                        .required(true),
                )
                .arg(
                    Arg::with_name("retry")
                        .long("retry")
                        .takes_value(true)
                        .value_name("DELAY")
                        .required(false),
                ),
        )
        .subcommand(SubCommand::with_name("bootstrap").about("Try to bootstrap only"))
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .get_matches();

    let config = {
        // TODO: this is mostly duplicate code.
        let mut cfg_sources = ConfigurationSources::new_empty();

        let config_files = matches.values_of_os("config-files").unwrap_or_default();

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
            .values_of("option")
            .unwrap_or_default()
            .for_each(|s| cfg_sources.push_option(s));

        cfg_sources
    };

    let timeout =
        int_str_to_secs(matches.value_of("timeout"))?.unwrap_or_else(|| Duration::from_secs(30));

    let console_log = matches.value_of("log").unwrap_or("debug").to_string();

    let expectation = matches
        .value_of("expect")
        .map(crate::Expectation::from_str)
        .transpose()?;

    let tcp_breakage = {
        let action = matches.value_of("tcp-failure").unwrap_or("none").parse()?;
        let stage = matches
            .value_of("tcp-failure-stage")
            .unwrap_or("bootstrap")
            .parse()?;
        let delay = matches
            .value_of("tcp-failure-delay")
            .map(|d| d.parse().map(Duration::from_secs))
            .transpose()?;
        let when = matches
            .value_of("tcp-failure-on")
            .unwrap_or("all")
            .parse()?;
        let action = ConditionalAction { action, when };

        TcpBreakage {
            action,
            stage,
            delay,
        }
    };

    let dir_filter = matches
        .value_of("dir-filter")
        .map(crate::dirfilter::new_filter)
        .transpose()?
        .unwrap_or_else(crate::dirfilter::nil_filter);

    let action = if let Some(_m) = matches.subcommand_matches("bootstrap") {
        Action::Bootstrap
    } else if let Some(matches) = matches.subcommand_matches("connect") {
        let target = matches
            .value_of("target")
            .unwrap_or("www.torproject.org:443")
            .to_owned();
        let retry_delay = int_str_to_secs(matches.value_of("retry"))?;

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
