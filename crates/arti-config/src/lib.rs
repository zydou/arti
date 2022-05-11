//! `arti-config`: Tools for configuration management in Arti
//!
//! # Overview
//!
//! This crate is part of
//! [Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
//! implement [Tor](https://www.torproject.org/) in Rust.
//!
//! It provides a client configuration tool using `serde` and `config`,
//! plus extra features defined here for convenience.
//!
//! # ⚠ Stability Warning ⚠
//!
//! The design of this crate, and of the configuration system for
//! Arti, is likely to change significantly before the release of Arti
//! 1.0.0.  For more information see ticket [#285].
//!
//! [#285]: https://gitlab.torproject.org/tpo/core/arti/-/issues/285

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

mod cmdline;
mod options;

pub use cmdline::CmdLine;
pub use options::ARTI_DEFAULTS;

/// The synchronous configuration builder type we use.
///
/// (This is a type alias that config should really provide.)
type ConfigBuilder = config::builder::ConfigBuilder<config::builder::DefaultState>;

use std::path::{Path, PathBuf};

/// A description of where to find our configuration options.
#[derive(Clone, Debug, Default)]
pub struct ConfigurationSources {
    /// List of files to read (in order).
    files: Vec<(PathBuf, MustRead)>,
    /// A list of command-line options to apply after parsing the files.
    options: Vec<String>,
}

/// Rules for whether we should proceed if a configuration file is unreadable.
///
/// Some files (like the default configuration file) are okay to skip if they
/// aren't present. Others (like those specified on the command line) really
/// need to be there.
#[derive(Clone, Debug, Copy, Eq, PartialEq)]
enum MustRead {
    /// This file is okay to skip if it isn't present,
    TolerateAbsence,

    /// This file must be present and readable.
    MustRead,
}

impl ConfigurationSources {
    /// Create a new empty [`ConfigurationSources`].
    pub fn new_empty() -> Self {
        Self::default()
    }

    /// Establish a [`ConfigurationSources`] the usual way from a command line and defaults
    ///
    /// The caller should have parsed the program's command line, and extracted (inter alia)
    ///
    ///  * `config_files_options`: Paths of config file(s)
    ///  * `cmdline_toml_override_options`: Overrides ("key=value")
    ///
    /// The caller should also provide `default_config_file`, the default location of the
    /// configuration file.  This is used if no file(s) are specified on the command line.
    ///
    /// `mistrust` is used to check whether the configuration files have appropriate permissions.
    pub fn from_cmdline<F, O>(
        default_config_file: impl Into<PathBuf>,
        config_files_options: impl IntoIterator<Item = F>,
        cmdline_toml_override_options: impl IntoIterator<Item = O>,
        mistrust: &fs_mistrust::Mistrust,
    ) -> Result<Self, fs_mistrust::Error>
    where
        F: Into<PathBuf>,
        O: Into<String>,
    {
        let mut cfg_sources = ConfigurationSources::new_empty();

        let mut any_files = false;
        for f in config_files_options {
            let f = f.into();
            mistrust.verifier().require_file().check(&f)?;
            cfg_sources.push_file(f);
            any_files = true;
        }
        if !any_files {
            let default = default_config_file.into();
            match mistrust.verifier().require_file().check(&default) {
                Ok(()) => {}
                Err(fs_mistrust::Error::NotFound(_)) => {}
                Err(e) => return Err(e),
            }
            cfg_sources.push_optional_file(default);
        }

        for s in cmdline_toml_override_options {
            cfg_sources.push_option(s);
        }

        Ok(cfg_sources)
    }

    /// Add `p` to the list of files that we want to read configuration from.
    ///
    /// Configuration files are loaded and applied in the order that they are
    /// added to this object.
    ///
    /// If the listed file is absent, loading the configuration won't succeed.
    pub fn push_file(&mut self, p: impl Into<PathBuf>) {
        self.files.push((p.into(), MustRead::MustRead));
    }

    /// As `push_file`, but if the listed file can't be loaded, loading the
    /// configuration can still succeed.
    pub fn push_optional_file(&mut self, p: impl Into<PathBuf>) {
        self.files.push((p.into(), MustRead::TolerateAbsence));
    }

    /// Add `s` to the list of overridden options to apply to our configuration.
    ///
    /// Options are applied after all configuration files are loaded, in the
    /// order that they are added to this object.
    ///
    /// The format for `s` is as in [`CmdLine`].
    pub fn push_option(&mut self, option: impl Into<String>) {
        self.options.push(option.into());
    }

    /// Return an iterator over the files that we care about.
    pub fn files(&self) -> impl Iterator<Item = &Path> {
        self.files.iter().map(|(f, _)| f.as_path())
    }

    /// Load the configuration into a new [`config::Config`].
    pub fn load(&self) -> Result<config::Config, config::ConfigError> {
        let mut builder = config::Config::builder();
        builder = builder.add_source(config::File::from_str(
            options::ARTI_DEFAULTS,
            config::FileFormat::Toml,
        ));
        builder = add_sources(builder, &self.files, &self.options);
        builder.build()
    }
}

/// Add every file and commandline source to `builder`, returning a new
/// builder.
fn add_sources<P>(
    mut builder: ConfigBuilder,
    files: &[(P, MustRead)],
    opts: &[String],
) -> ConfigBuilder
where
    P: AsRef<Path>,
{
    for (path, must_read) in files {
        // Not going to use File::with_name here, since it doesn't
        // quite do what we want.
        let f: config::File<_, _> = path.as_ref().into();
        let required = must_read == &MustRead::MustRead;
        builder = builder.add_source(f.format(config::FileFormat::Toml).required(required));
    }

    let mut cmdline = CmdLine::new();
    for opt in opts {
        cmdline.push_toml_line(opt.clone());
    }
    builder = builder.add_source(cmdline);

    builder
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use arti_client::config::default_config_file;
    use tempfile::tempdir;

    static EX_TOML: &str = "
[hello]
world = \"stuff\"
friends = 4242
";

    /// Load from a set of files and option strings, without taking
    /// the arti defaults into account.
    fn load_nodefaults<P: AsRef<Path>>(
        files: &[(P, MustRead)],
        opts: &[String],
    ) -> Result<config::Config, config::ConfigError> {
        add_sources(config::Config::builder(), files, opts).build()
    }

    #[test]
    fn non_required_file() {
        let td = tempdir().unwrap();
        let dflt = td.path().join("a_file");
        let files = vec![(dflt, MustRead::TolerateAbsence)];
        load_nodefaults(&files, Default::default()).unwrap();
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
        std::fs::write(&cf, EX2_TOML).unwrap();
        let files = vec![(dflt, MustRead::TolerateAbsence), (cf, MustRead::MustRead)];
        let c = load_nodefaults(&files, Default::default()).unwrap();

        assert!(c.get_string("hello.friends").is_err());
        assert_eq!(c.get_string("hello.world").unwrap(), "nonsense".to_string());
    }

    #[test]
    fn load_two_files_with_cmdline() {
        let td = tempdir().unwrap();
        let cf1 = td.path().join("a_file");
        let cf2 = td.path().join("other_file");
        std::fs::write(&cf1, EX_TOML).unwrap();
        std::fs::write(&cf2, EX2_TOML).unwrap();
        let v = vec![(cf1, MustRead::TolerateAbsence), (cf2, MustRead::MustRead)];
        let v2 = vec!["other.var=present".to_string()];
        let c = load_nodefaults(&v, &v2).unwrap();

        assert_eq!(c.get_string("hello.friends").unwrap(), "4242".to_string());
        assert_eq!(c.get_string("hello.world").unwrap(), "nonsense".to_string());
        assert_eq!(c.get_string("other.var").unwrap(), "present".to_string());
    }

    #[test]
    fn check_default() {
        // We don't want to second-guess the directories crate too much
        // here, so we'll just make sure it does _something_ plausible.

        let dflt = default_config_file().unwrap();
        assert!(dflt.ends_with("arti.toml"));
    }
}
