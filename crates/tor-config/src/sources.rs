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
//!
//! If you want to watch for config file changes,
//! use [`ConfigurationSources::scan()`],
//! to obtain a [`FoundConfigFiles`],
//! start watching the paths returned by [`FoundConfigFiles::iter()`],
//! and then call [`FoundConfigFiles::load()`].
//! (This ordering starts watching the files before you read them,
//! which is necessary to avoid possibly missing changes.)

use std::{fs, io};

use crate::CmdLine;

use config::ConfigError;
use tor_basic_utils::IoErrorExt as _;

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

/// Configuration files and directories we found in the filesystem
///
/// Result of [`ConfigurationSources::scan`].
///
/// When loading configuration files and also watching for filesystem updates,
/// this type encapsulates all the actual filesystem objects that need watching.
#[derive(Debug)]
pub struct FoundConfigFiles<'srcs> {
    /// The things we found
    ///
    /// This includes both:
    ///  * Files which ought to be read
    ///  * Directories, which may or may not contain any currently-relevant files
    ///
    /// The directories are retained for the purpose of watching for config changes:
    /// we will want to detect files being created within them,
    /// so our caller needs to discover them (via [`FoundConfigFiles::iter()`]).
    files: Vec<FoundConfigFile>,

    /// Our parent, which contains details we need for `load`
    sources: &'srcs ConfigurationSources,
}

/// A configuration source file or directory, found or not found on the filesystem
#[derive(Debug, Clone)]
pub struct FoundConfigFile {
    /// The path of the (putative) object
    path: PathBuf,

    /// Were we expecting this to definitely exist
    must_read: MustRead,

    /// What happened when we looked for it
    ty: FoundType,
}

/// Was this filesystem object a file or a directory?
#[derive(Debug, Copy, Clone)]
enum FoundType {
    /// File
    File,
    /// Directory
    Dir,
}

impl FoundConfigFile {
    /// Get the path
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Was this a directory, when we found it ?
    pub fn was_dir(&self) -> bool {
        match self.ty {
            FoundType::Dir => true,
            FoundType::File => false,
        }
    }
}

impl AsRef<Path> for FoundConfigFile {
    fn as_ref(&self) -> &Path {
        self.path()
    }
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
    ///  * `config_files_options`: Paths of config file(s) (or directories of `.toml` files)
    ///  * `cmdline_toml_override_options`: Overrides ("key=value")
    ///
    /// The caller should also provide `default_config_file`, the default location of the
    /// configuration file.  This is used if no file(s) are specified on the command line.
    ///
    /// `mistrust` is used to check whether the configuration files have appropriate permissions.
    ///
    /// Configuration file locations that turn out to be directories,
    /// will be scanned for files whose name ends in `.toml`.
    /// All those files (if any) will be read (in lexical order by filename).
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

    /// Scan for files and load the configuration into a new [`config::Config`].
    ///
    /// This is a convenience method for [`scan()`](Self::scan)
    /// followed by [`files.load`].
    pub fn load(&self) -> Result<config::Config, ConfigError> {
        let files = self.scan()?;
        files.load()
    }

    /// Scan for configuration source files (including scanning any directories)
    pub fn scan(&self) -> Result<FoundConfigFiles, ConfigError> {
        let mut out = vec![];

        for &(ref found, must_read) in &self.files {
            let required = must_read == MustRead::MustRead;

            // Returns Err(error) if we shuold bail,
            // or Ok(()) if we should ignore the error and skip the file.
            let handle_io_error = |e: io::Error| {
                if e.kind() == io::ErrorKind::NotFound && !required {
                    Ok(())
                } else {
                    Err(ConfigError::Foreign(
                        anyhow::anyhow!(format!(
                            "unable to access config path: {:?}: {}",
                            &found, e
                        ))
                        .into(),
                    ))
                }
            };

            match fs::read_dir(&found) {
                Ok(dir) => {
                    out.push(FoundConfigFile {
                        path: found.clone(),
                        must_read,
                        ty: FoundType::Dir,
                    });
                    // Rebinding `found` avoids using the directory name by mistake.
                    let mut entries = vec![];
                    for found in dir {
                        // reuse map_io_err, which embeds the directory name,
                        // since if we have Err we don't have an entry name.
                        let found = match found {
                            Ok(y) => y,
                            Err(e) => {
                                handle_io_error(e)?;
                                continue;
                            }
                        };
                        let leaf = found.file_name();
                        let leaf: &Path = leaf.as_ref();
                        match leaf.extension() {
                            Some(e) if e == "toml" => {}
                            _ => continue,
                        }
                        entries.push(found.path());
                    }
                    entries.sort();
                    out.extend(entries.into_iter().map(|path| FoundConfigFile {
                        path,
                        must_read: MustRead::TolerateAbsence,
                        ty: FoundType::File,
                    }));
                }
                Err(e) if e.is_not_a_directory() => {
                    out.push(FoundConfigFile {
                        path: found.clone(),
                        must_read,
                        ty: FoundType::File,
                    });
                }
                Err(e) => handle_io_error(e)?,
            }
        }

        Ok(FoundConfigFiles {
            files: out,
            sources: self,
        })
    }
}

impl FoundConfigFiles<'_> {
    /// Iterate over the filesystem objects that the scan found
    //
    // This ought really to be `impl IntoIterator for &Self` but that's awkward without TAIT
    pub fn iter(&self) -> impl Iterator<Item = &FoundConfigFile> {
        self.files.iter()
    }

    /// Add every file and commandline source to `builder`, returning a new
    /// builder.
    fn add_sources(self, mut builder: ConfigBuilder) -> Result<ConfigBuilder, ConfigError> {
        for FoundConfigFile {
            path,
            must_read,
            ty,
        } in self.files
        {
            let required = must_read == MustRead::MustRead;

            match ty {
                FoundType::File => {}
                FoundType::Dir => continue,
            }

            match self
                .sources
                .mistrust
                .verifier()
                .permit_readable()
                .check(&path)
            {
                Ok(()) => {}
                Err(fs_mistrust::Error::NotFound(_)) if !required => {}
                Err(e) => return Err(ConfigError::Foreign(e.into())),
            }

            // Not going to use File::with_name here, since it doesn't
            // quite do what we want.
            let f: config::File<_, _> = path.into();
            builder = builder.add_source(f.format(config::FileFormat::Toml).required(required));
        }

        let mut cmdline = CmdLine::new();
        for opt in &self.sources.options {
            cmdline.push_toml_line(opt.clone());
        }
        builder = builder.add_source(cmdline);

        Ok(builder)
    }

    /// Load the configuration into a new [`config::Config`].
    pub fn load(self) -> Result<config::Config, ConfigError> {
        let mut builder = config::Config::builder();
        builder = self.add_sources(builder)?;
        builder.build()
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use itertools::Itertools;
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
        let files = files
            .iter()
            .map(|(p, m)| (p.as_ref().to_owned(), *m))
            .collect_vec();
        let options = opts.iter().cloned().collect_vec();
        ConfigurationSources {
            files,
            options,
            mistrust,
        }
        .load()
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
        assert_eq!(c.get_string("hello.world").unwrap(), "nonsense");
    }

    #[test]
    fn dir_with_some() {
        let td = tempdir().unwrap();
        let cf = td.path().join("1.toml");
        let d = td.path().join("extra.d");
        let df = d.join("2.toml");
        let xd = td.path().join("nonexistent.d");
        std::fs::create_dir(&d).unwrap();
        std::fs::write(&cf, EX_TOML).unwrap();
        std::fs::write(&df, EX2_TOML).unwrap();
        std::fs::write(d.join("not-toml"), "SYNTAX ERROR").unwrap();

        let files = vec![
            (cf, MustRead::MustRead),
            (d, MustRead::MustRead),
            (xd.clone(), MustRead::TolerateAbsence),
        ];
        let c = load_nodefaults(&files, Default::default()).unwrap();

        assert_eq!(c.get_string("hello.friends").unwrap(), "4242");
        assert_eq!(c.get_string("hello.world").unwrap(), "nonsense");

        let files = vec![(xd, MustRead::MustRead)];
        let e = load_nodefaults(&files, Default::default())
            .unwrap_err()
            .to_string();
        assert!(dbg!(e).contains("nonexistent.d"));
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

        assert_eq!(c.get_string("hello.friends").unwrap(), "4242");
        assert_eq!(c.get_string("hello.world").unwrap(), "nonsense");
        assert_eq!(c.get_string("other.var").unwrap(), "present");
    }

    #[test]
    fn from_cmdline() {
        // Try one with specified files
        let sources = ConfigurationSources::from_cmdline(
            "/etc/loid.toml",
            ["/family/yor.toml", "/family/anya.toml"],
            ["decade=1960", "snack=peanuts"],
        );
        let files: Vec<_> = sources
            .files
            .iter()
            .map(|file| file.0.to_str().unwrap())
            .collect();
        assert_eq!(files, vec!["/family/yor.toml", "/family/anya.toml"]);
        assert_eq!(sources.files[0].1, MustRead::MustRead);
        assert_eq!(
            &sources.options,
            &vec!["decade=1960".to_owned(), "snack=peanuts".to_owned()]
        );

        // Try once with default only.
        let sources = ConfigurationSources::from_cmdline(
            "/etc/loid.toml",
            Vec::<PathBuf>::new(),
            ["decade=1960", "snack=peanuts"],
        );
        assert_eq!(
            &sources.files,
            &vec![("/etc/loid.toml".into(), MustRead::TolerateAbsence)]
        );
    }
}
