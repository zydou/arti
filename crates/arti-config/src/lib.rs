//! `arti-config`: Tools for configuration management in Arti
//!
//! # Overview
//!
//! This crate is part of
//! [Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
//! implement [Tor](https://www.torproject.org/) in Rust.
//!
//! It provides a client configuration tool using using `serde` and `config`,
//! plus extra features defined here for convenience.

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
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]

mod cmdline;
mod options;

pub use cmdline::CmdLine;
pub use options::{
    ArtiConfig, LoggingConfig, LoggingConfigBuilder, ProxyConfig, ProxyConfigBuilder,
};
use tor_config::CfgPath;

use std::path::{Path, PathBuf};

/// Load configuration into a a [`config::Config`] object from configuration files on disk (`files`),
/// and/or command-line arguments (`opts`).
///
/// `files` should be a list of TOML config file paths to read, with the boolean specifying whether
/// a failure to read this file should be an error or not.
///
/// `opts` are passed into a [`CmdLine`], and use the extended syntax of that mechanism.
pub fn load<P: AsRef<Path>>(
    files: &[(P, bool)],
    opts: Vec<String>,
) -> Result<config::Config, config::ConfigError> {
    let mut config = config::Config::new();
    config.merge(config::File::from_str(
        options::ARTI_DEFAULTS,
        config::FileFormat::Toml,
    ))?;
    load_mut(&mut config, files, opts)?;
    Ok(config)
}

/// As [`load()`], but load into a mutable `Config` object.
fn load_mut<P: AsRef<Path>>(
    cfg: &mut config::Config,
    files: &[(P, bool)],
    opts: Vec<String>,
) -> Result<(), config::ConfigError> {
    for (path, required) in files {
        // Not going to use File::with_name here, since it doesn't
        // quite do what we want.
        let f: config::File<_> = path.as_ref().into();
        cfg.merge(f.format(config::FileFormat::Toml).required(*required))?;
    }

    let mut cmdline = CmdLine::new();
    for opt in opts {
        cmdline.push_toml_line(opt);
    }
    cfg.merge(cmdline)?;

    Ok(())
}

/// Return a filename for the default user configuration file.
pub fn default_config_file() -> Option<PathBuf> {
    CfgPath::new("${ARTI_CONFIG}/arti.toml".into()).path().ok()
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use tempfile::tempdir;

    static EX_TOML: &str = "
[hello]
world = \"stuff\"
friends = 4242
";

    #[test]
    fn non_required_file() {
        let td = tempdir().unwrap();
        let dflt = td.path().join("a_file");
        let files = vec![(dflt, false)];
        let mut c = config::Config::new();
        load_mut(&mut c, &files, Default::default()).unwrap();
    }

    static EX2_TOML: &str = "
[hello]
world = \"nonsense\"
";

    #[test]
    fn both_required_and_not() {
        let td = tempdir().unwrap();
        let dflt = td.path().join("a_file");
        let cf = td.path().join("other_file");
        let mut c = config::Config::new();
        std::fs::write(&cf, EX2_TOML).unwrap();
        let files = vec![(dflt, false), (cf, true)];
        load_mut(&mut c, &files, Default::default()).unwrap();

        assert!(c.get_str("hello.friends").is_err());
        assert_eq!(c.get_str("hello.world").unwrap(), "nonsense".to_string());
    }

    #[test]
    fn load_two_files_with_cmdline() {
        let td = tempdir().unwrap();
        let cf1 = td.path().join("a_file");
        let cf2 = td.path().join("other_file");
        let mut c = config::Config::new();
        std::fs::write(&cf1, EX_TOML).unwrap();
        std::fs::write(&cf2, EX2_TOML).unwrap();
        let v = vec![(cf1, true), (cf2, true)];
        let v2 = vec!["other.var=present".to_string()];
        load_mut(&mut c, &v, v2).unwrap();

        assert_eq!(c.get_str("hello.friends").unwrap(), "4242".to_string());
        assert_eq!(c.get_str("hello.world").unwrap(), "nonsense".to_string());
        assert_eq!(c.get_str("other.var").unwrap(), "present".to_string());
    }

    #[test]
    fn check_default() {
        // We don't want to second-guess the directories crate too much
        // here, so we'll just make sure it does _something_ plausible.

        let dflt = default_config_file().unwrap();
        assert!(dflt.ends_with("arti.toml"));
    }
}
