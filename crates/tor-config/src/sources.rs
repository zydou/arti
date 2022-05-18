//! `ConfigurationSources`: Helper for handling configuration files
//!
//! This module provides [`ConfigurationSources`].
//!
//! This layer brings together the functionality of [`config::File`],
//! [`fs_mistrust`] and [`tor_config::cmdline`](crate::cmdline).
//!
//! A `ConfigurationSources` records a set of filenames of TOML files,
//! ancillary instructions for reading them,
//! and also a set of command line options.
//!
//! Usually, call [`ConfigurationSources::from_cmdline`],
//! perhaps [`set_mistrust`](ConfigurationSources::set_mistrust),
//! and finally [`load`](ConfigurationSources::load).
//! The resulting [`config::Config`] can then be deserialized.

use crate::CmdLine;

use config::ConfigError;

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
    /// We will check all files we read
    mistrust: fs_mistrust::Mistrust,
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
    ) -> Self
    where
        F: Into<PathBuf>,
        O: Into<String>,
    {
        let mut cfg_sources = ConfigurationSources::new_empty();

        let mut any_files = false;
        for f in config_files_options {
            let f = f.into();
            cfg_sources.push_file(f);
            any_files = true;
        }
        if !any_files {
            let default = default_config_file.into();
            cfg_sources.push_optional_file(default);
        }

        for s in cmdline_toml_override_options {
            cfg_sources.push_option(s);
        }

        cfg_sources
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

    /// Sets the filesystem permission mistrust
    pub fn set_mistrust(&mut self, mistrust: fs_mistrust::Mistrust) {
        self.mistrust = mistrust;
    }

    /// Reads the filesystem permission mistrust
    pub fn mistrust(&self) -> &fs_mistrust::Mistrust {
        &self.mistrust
    }

    /// Return an iterator over the files that we care about.
    pub fn files(&self) -> impl Iterator<Item = &Path> {
        self.files.iter().map(|(f, _)| f.as_path())
    }

    /// Load the configuration into a new [`config::Config`].
    pub fn load(&self) -> Result<config::Config, ConfigError> {
        let mut builder = config::Config::builder();
        builder = add_sources(builder, &self.mistrust, &self.files, &self.options)?;
        builder.build()
    }
}

/// Add every file and commandline source to `builder`, returning a new
/// builder.
fn add_sources<P>(
    mut builder: ConfigBuilder,
    mistrust: &fs_mistrust::Mistrust,
    files: &[(P, MustRead)],
    opts: &[String],
) -> Result<ConfigBuilder, ConfigError>
where
    P: AsRef<Path>,
{
    for (path, must_read) in files {
        let required = must_read == &MustRead::MustRead;

        match mistrust.verifier().require_file().check(&path) {
            Ok(()) => {}
            Err(fs_mistrust::Error::NotFound(_)) if !required => {}
            Err(e) => return Err(ConfigError::Foreign(e.into())),
        }

        // Not going to use File::with_name here, since it doesn't
        // quite do what we want.
        let f: config::File<_, _> = path.as_ref().into();
        builder = builder.add_source(f.format(config::FileFormat::Toml).required(required));
    }

    let mut cmdline = CmdLine::new();
    for opt in opts {
        cmdline.push_toml_line(opt.clone());
    }
    builder = builder.add_source(cmdline);

    Ok(builder)
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

    /// Load from a set of files and option strings, without taking
    /// the arti defaults into account.
    fn load_nodefaults<P: AsRef<Path>>(
        files: &[(P, MustRead)],
        opts: &[String],
    ) -> Result<config::Config, config::ConfigError> {
        let mistrust = fs_mistrust::Mistrust::new_dangerously_trust_everyone();

        add_sources(config::Config::builder(), &mistrust, files, opts)
            .unwrap()
            .build()
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
}
