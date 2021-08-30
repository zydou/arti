//! `tor-config`: Tools for configuration management in Arti
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
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]

mod cmdline;
mod path;
pub use cmdline::CmdLine;
pub use path::CfgPath;

use std::path::{Path, PathBuf};

/// Load a Config object based on a set of files and/or command-line
/// arguments.
///
/// The files should be toml; the command-line arguments have the extended
/// syntax of [`CmdLine`].
///
/// If `default_path` is present, and there is no list of files, then use a
/// default file if it exists.
//
// XXXX Add an error type for this crate.
pub fn load<'a, P1, C1, P2, C2>(
    cfg: &mut config::Config,
    default_path: &Option<P1>,
    files: C1,
    opts: C2,
) -> Result<(), config::ConfigError>
where
    P1: AsRef<Path> + 'a,
    C1: IntoIterator<Item = &'a P2>,
    P2: AsRef<Path> + 'a,
    C2: IntoIterator,
    C2::Item: AsRef<str>,
{
    let mut search_path = Vec::new();
    for f in files {
        search_path.push(f.as_ref());
    }
    let mut missing_ok = false;
    if search_path.is_empty() {
        if let Some(f) = default_path {
            // XXXX shouldn't be println, but no logs exist yet.
            println!("looking for default configuration in {:?}", f.as_ref());
            search_path.push(f.as_ref());
            missing_ok = true;
        }
    }

    for p in search_path {
        // Not going to use File::with_name here, since it doesn't
        // quite do what we want.
        let f: config::File<_> = p.into();
        cfg.merge(f.format(config::FileFormat::Toml).required(!missing_ok))?;
    }

    let mut cmdline = CmdLine::new();
    for opt in opts {
        cmdline.push_toml_line(opt.as_ref().to_string());
    }
    cfg.merge(cmdline)?;

    Ok(())
}

/// Return a filename for the default user configuration file.
pub fn default_config_file() -> Option<PathBuf> {
    CfgPath::new("${APP_CONFIG}/arti.toml".into()).path().ok()
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
    fn load_default() {
        let td = tempdir().unwrap();
        let dflt = td.path().join("a_file");
        let mut c = config::Config::new();
        let v: Vec<&'static str> = Vec::new();
        std::fs::write(&dflt, EX_TOML).unwrap();
        load(&mut c, &Some(dflt), &v, &v).unwrap();

        assert_eq!(c.get_str("hello.friends").unwrap(), "4242".to_string());
        assert_eq!(c.get_str("hello.world").unwrap(), "stuff".to_string());
    }

    static EX2_TOML: &str = "
[hello]
world = \"nonsense\"
";

    #[test]
    fn load_one_file() {
        let td = tempdir().unwrap();
        let dflt = td.path().join("a_file");
        let cf = td.path().join("other_file");
        let mut c = config::Config::new();
        std::fs::write(&dflt, EX_TOML).unwrap();
        std::fs::write(&cf, EX2_TOML).unwrap();
        let v = vec![cf];
        let v2: Vec<&'static str> = Vec::new();
        load(&mut c, &Some(dflt), &v, &v2).unwrap();

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
        let v = vec![cf1, cf2];
        let v2 = vec!["other.var=present"];
        let d: Option<String> = None;
        load(&mut c, &d, &v, &v2).unwrap();

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
