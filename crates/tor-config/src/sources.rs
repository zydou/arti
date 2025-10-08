//! `ConfigurationSources`: Helper for handling configuration files
//!
//! This module provides [`ConfigurationSources`].
//!
//! This layer brings together the functionality of
//! our underlying configuration library,
//! [`fs_mistrust`] and [`tor_config::cmdline`](crate::cmdline).
//!
//! A `ConfigurationSources` records a set of filenames of TOML files,
//! ancillary instructions for reading them,
//! and also a set of command line options.
//!
//! Usually, call [`ConfigurationSources::from_cmdline`],
//! perhaps [`set_mistrust`](ConfigurationSources::set_mistrust),
//! and finally [`load`](ConfigurationSources::load).
//! The resulting [`ConfigurationTree`] can then be deserialized.
//!
//! If you want to watch for config file changes,
//! use [`ConfigurationSources::scan()`],
//! to obtain a [`FoundConfigFiles`],
//! start watching the paths returned by [`FoundConfigFiles::iter()`],
//! and then call [`FoundConfigFiles::load()`].
//! (This ordering starts watching the files before you read them,
//! which is necessary to avoid possibly missing changes.)

use std::ffi::OsString;
use std::{fs, io, sync::Arc};

use figment::Figment;
use void::ResultVoidExt as _;

use crate::err::ConfigError;
use crate::{CmdLine, ConfigurationTree};

use std::path::{Path, PathBuf};

/// A description of where to find our configuration options.
#[derive(Clone, Debug, Default)]
pub struct ConfigurationSources {
    /// List of files to read (in order).
    files: Vec<(ConfigurationSource, MustRead)>,
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
#[allow(clippy::exhaustive_enums)]
pub enum MustRead {
    /// This file is okay to skip if it isn't present,
    TolerateAbsence,

    /// This file must be present and readable.
    MustRead,
}

/// A configuration file or directory, for use by a `ConfigurationSources`
///
/// You can make one out of a `PathBuf`, examining its syntax like `arti` does,
/// using `ConfigurationSource::from_path`.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[allow(clippy::exhaustive_enums)]
pub enum ConfigurationSource {
    /// A plain file
    File(PathBuf),

    /// A directory
    Dir(PathBuf),

    /// A verbatim TOML file
    Verbatim(Arc<String>),
}

impl ConfigurationSource {
    /// Interpret a path (or string) as a configuration file or directory spec
    ///
    /// If the path syntactically specifies a directory
    /// (i.e., can be seen to be a directory without accessing the filesystem,
    /// for example because it ends in a directory separator such as `/`)
    /// it is treated as specifying a directory.
    pub fn from_path<P: Into<PathBuf>>(p: P) -> ConfigurationSource {
        use ConfigurationSource as CS;
        let p = p.into();
        if is_syntactically_directory(&p) {
            CS::Dir(p)
        } else {
            CS::File(p)
        }
    }

    /// Use the provided text as verbatim TOML, as if it had been read from disk.
    pub fn from_verbatim(text: String) -> ConfigurationSource {
        Self::Verbatim(Arc::new(text))
    }

    /// Return a reference to the inner `Path`, if there is one.
    pub fn as_path(&self) -> Option<&Path> {
        use ConfigurationSource as CS;
        match self {
            CS::File(p) | CS::Dir(p) => Some(p),
            CS::Verbatim(_) => None,
        }
    }
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
struct FoundConfigFile {
    /// The path of the (putative) object
    source: ConfigurationSource,

    /// Were we expecting this to definitely exist
    must_read: MustRead,
}

impl ConfigurationSources {
    /// Create a new empty [`ConfigurationSources`].
    pub fn new_empty() -> Self {
        Self::default()
    }

    /// Establish a [`ConfigurationSources`] the from an infallible command line and defaults
    ///
    /// Convenience method for if the default config file location(s) can be infallibly computed.
    pub fn from_cmdline<F, O>(
        default_config_files: impl IntoIterator<Item = ConfigurationSource>,
        config_files_options: impl IntoIterator<Item = F>,
        cmdline_toml_override_options: impl IntoIterator<Item = O>,
    ) -> Self
    where
        F: Into<PathBuf>,
        O: Into<String>,
    {
        ConfigurationSources::try_from_cmdline(
            || Ok(default_config_files),
            config_files_options,
            cmdline_toml_override_options,
        )
        .void_unwrap()
    }

    /// Establish a [`ConfigurationSources`] the usual way from a command line and defaults
    ///
    /// The caller should have parsed the program's command line, and extracted (inter alia)
    ///
    ///  * `config_files_options`: Paths of config file(s) (or directories of `.toml` files)
    ///  * `cmdline_toml_override_options`: Overrides ("key=value")
    ///
    /// The caller should also provide `default_config_files`,
    /// which returns the default locations of the configuration files.
    /// This used if no file(s) are specified on the command line.
    //
    // The other inputs are always used and therefore
    // don't need to be lifted into FnOnce() -> Result.
    ///
    /// `mistrust` is used to check whether the configuration files have appropriate permissions.
    ///
    /// `ConfigurationSource::Dir`s
    /// will be scanned for files whose name ends in `.toml`.
    /// All those files (if any) will be read (in lexical order by filename).
    pub fn try_from_cmdline<F, O, DEF, E>(
        default_config_files: impl FnOnce() -> Result<DEF, E>,
        config_files_options: impl IntoIterator<Item = F>,
        cmdline_toml_override_options: impl IntoIterator<Item = O>,
    ) -> Result<Self, E>
    where
        F: Into<PathBuf>,
        O: Into<String>,
        DEF: IntoIterator<Item = ConfigurationSource>,
    {
        let mut cfg_sources = ConfigurationSources::new_empty();

        let mut any_files = false;
        for f in config_files_options {
            let f = f.into();
            cfg_sources.push_source(ConfigurationSource::from_path(f), MustRead::MustRead);
            any_files = true;
        }
        if !any_files {
            for default in default_config_files()? {
                cfg_sources.push_source(default, MustRead::TolerateAbsence);
            }
        }

        for s in cmdline_toml_override_options {
            cfg_sources.push_option(s);
        }

        Ok(cfg_sources)
    }

    /// Add `src` to the list of files or directories that we want to read configuration from.
    ///
    /// Configuration files are loaded and applied in the order that they are
    /// added to this object.
    ///
    /// If the listed file is absent, loading the configuration won't succeed.
    pub fn push_source(&mut self, src: ConfigurationSource, must_read: MustRead) {
        self.files.push((src, must_read));
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

    /// All given override options.
    ///
    /// See [`push_option`](Self::push_option).
    pub fn options(&self) -> impl Iterator<Item = &String> + Clone {
        self.options.iter()
    }

    /// Sets the filesystem permission mistrust
    ///
    /// This value only indicates whether and how to check permissions
    /// on the configuration file itself.
    /// It *does not* specify whether and how to check permissions of the
    /// paths provided within.
    /// This is defined by the `storage.permissions.dangerously_trust_everyone` flag.
    pub fn set_mistrust(&mut self, mistrust: fs_mistrust::Mistrust) {
        self.mistrust = mistrust;
    }

    /// Reads the filesystem permission mistrust
    ///
    /// This value only indicates whether and how to check permissions
    /// on the configuration file itself.
    /// It *does not* specify whether and how to check permissions of the
    /// paths provided within.
    /// This is defined by the `storage.permissions.dangerously_trust_everyone` flag.
    pub fn mistrust(&self) -> &fs_mistrust::Mistrust {
        &self.mistrust
    }

    /// Scan for files and load the configuration into a new [`ConfigurationTree`].
    ///
    /// This is a convenience method for [`scan()`](Self::scan)
    /// followed by `files.load`.
    pub fn load(&self) -> Result<ConfigurationTree, ConfigError> {
        let files = self.scan()?;
        files.load()
    }

    /// Scan for configuration source files (including scanning any directories)
    pub fn scan(&self) -> Result<FoundConfigFiles, ConfigError> {
        let mut out = vec![];

        for &(ref source, must_read) in &self.files {
            let required = must_read == MustRead::MustRead;

            // Returns Err(error) if we should bail,
            // or Ok(()) if we should ignore the error and skip the file.
            let handle_io_error = |e: io::Error, p: &Path| {
                if e.kind() == io::ErrorKind::NotFound && !required {
                    Result::<_, crate::ConfigError>::Ok(())
                } else {
                    Err(crate::ConfigError::Io {
                        action: "reading",
                        path: p.to_owned(),
                        err: Arc::new(e),
                    })
                }
            };

            use ConfigurationSource as CS;
            match &source {
                CS::Dir(dirname) => {
                    let dir = match fs::read_dir(dirname) {
                        Ok(y) => y,
                        Err(e) => {
                            handle_io_error(e, dirname.as_ref())?;
                            continue;
                        }
                    };
                    out.push(FoundConfigFile {
                        source: source.clone(),
                        must_read,
                    });
                    // Rebinding `found` avoids using the directory name by mistake.
                    let mut entries = vec![];
                    for found in dir {
                        // reuse map_io_err, which embeds the directory name,
                        // since if we have Err we don't have an entry name.
                        let found = match found {
                            Ok(y) => y,
                            Err(e) => {
                                handle_io_error(e, dirname.as_ref())?;
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
                        source: CS::File(path),
                        must_read: MustRead::TolerateAbsence,
                    }));
                }
                CS::File(_) | CS::Verbatim(_) => {
                    out.push(FoundConfigFile {
                        source: source.clone(),
                        must_read,
                    });
                }
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
    pub fn iter(&self) -> impl Iterator<Item = &ConfigurationSource> {
        self.files.iter().map(|f| &f.source)
    }

    /// Add every file and commandline source to `builder`, returning a new
    /// builder.
    fn add_sources(self, mut builder: Figment) -> Result<Figment, ConfigError> {
        use figment::providers::Format;

        // Note that we're using `merge` here.  It causes later sources' options
        // to replace those in earlier sources, and causes arrays to be replaced
        // rather than extended.
        //
        // TODO #1337: This array behavior is not necessarily ideal for all
        // cases, but doing something smarter would probably require us to hack
        // figment-rs or toml.

        for FoundConfigFile { source, must_read } in self.files {
            use ConfigurationSource as CS;

            let required = must_read == MustRead::MustRead;

            let file = match source {
                CS::File(file) => file,
                CS::Dir(_) => continue,
                CS::Verbatim(text) => {
                    builder = builder.merge(figment::providers::Toml::string(&text));
                    continue;
                }
            };

            match self
                .sources
                .mistrust
                .verifier()
                .permit_readable()
                .check(&file)
            {
                Ok(()) => {}
                Err(fs_mistrust::Error::NotFound(_)) if !required => {
                    continue;
                }
                Err(e) => return Err(ConfigError::FileAccess(e)),
            }

            // We use file_exact here so that figment won't look in parent
            // directories if the target file can't be found.
            let f = figment::providers::Toml::file_exact(file);
            builder = builder.merge(f);
        }

        let mut cmdline = CmdLine::new();
        for opt in &self.sources.options {
            cmdline.push_toml_line(opt.clone());
        }
        builder = builder.merge(cmdline);

        Ok(builder)
    }

    /// Load the configuration into a new [`ConfigurationTree`].
    pub fn load(self) -> Result<ConfigurationTree, ConfigError> {
        let mut builder = Figment::new();
        builder = self.add_sources(builder)?;

        Ok(ConfigurationTree(builder))
    }
}

/// Does it end in a slash?  (Or some other way of saying this is a directory.)
fn is_syntactically_directory(p: &Path) -> bool {
    use std::path::Component as PC;

    match p.components().next_back() {
        None => false,
        Some(PC::Prefix(_)) | Some(PC::RootDir) | Some(PC::CurDir) | Some(PC::ParentDir) => true,
        Some(PC::Normal(_)) => {
            // Does it end in a slash?
            let l = p.components().count();

            // stdlib doesn't let us tell if the thing ends in a path separator.
            // components() normalises, so doesn't give us an empty component
            // But, if it ends in a path separator, adding a path component char will
            // mean adding a component.
            // This will work regardless of the path separator, on any platform where
            // paths naming directories are like those for files.
            // It would even work on some others, eg VMS.
            let mut appended = OsString::from(p);
            appended.push("a");
            let l2 = PathBuf::from(appended).components().count();
            l2 != l
        }
    }
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;
    use itertools::Itertools;
    use tempfile::tempdir;

    static EX_TOML: &str = "
[hello]
world = \"stuff\"
friends = 4242
";

    /// Make a ConfigurationSources (that doesn't include the arti defaults)
    fn sources_nodefaults<P: AsRef<Path>>(
        files: &[(P, MustRead)],
        opts: &[String],
    ) -> ConfigurationSources {
        let mistrust = fs_mistrust::Mistrust::new_dangerously_trust_everyone();
        let files = files
            .iter()
            .map(|(p, m)| (ConfigurationSource::from_path(p.as_ref()), *m))
            .collect_vec();
        let options = opts.iter().cloned().collect_vec();
        ConfigurationSources {
            files,
            options,
            mistrust,
        }
    }

    /// Load from a set of files and option strings, without taking
    /// the arti defaults into account.
    fn load_nodefaults<P: AsRef<Path>>(
        files: &[(P, MustRead)],
        opts: &[String],
    ) -> Result<ConfigurationTree, crate::ConfigError> {
        sources_nodefaults(files, opts).load()
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
        let d = td.path().join("extra.d/");
        let df = d.join("2.toml");
        let xd = td.path().join("nonexistent.d/");
        std::fs::create_dir(&d).unwrap();
        std::fs::write(&cf, EX_TOML).unwrap();
        std::fs::write(df, EX2_TOML).unwrap();
        std::fs::write(d.join("not-toml"), "SYNTAX ERROR").unwrap();

        let files = vec![
            (cf, MustRead::MustRead),
            (d, MustRead::MustRead),
            (xd.clone(), MustRead::TolerateAbsence),
        ];
        let c = sources_nodefaults(&files, Default::default());
        let found = c.scan().unwrap();

        assert_eq!(
            found
                .iter()
                .map(|p| p
                    .as_path()
                    .unwrap()
                    .strip_prefix(&td)
                    .unwrap()
                    .to_str()
                    .unwrap())
                .collect_vec(),
            &["1.toml", "extra.d", "extra.d/2.toml"]
        );

        let c = found.load().unwrap();

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
            [ConfigurationSource::from_path("/etc/loid.toml")],
            ["/family/yor.toml", "/family/anya.toml"],
            ["decade=1960", "snack=peanuts"],
        );
        let files: Vec<_> = sources
            .files
            .iter()
            .map(|file| file.0.as_path().unwrap().to_str().unwrap())
            .collect();
        assert_eq!(files, vec!["/family/yor.toml", "/family/anya.toml"]);
        assert_eq!(sources.files[0].1, MustRead::MustRead);
        assert_eq!(
            &sources.options,
            &vec!["decade=1960".to_owned(), "snack=peanuts".to_owned()]
        );

        // Try once with default only.
        let sources = ConfigurationSources::from_cmdline(
            [ConfigurationSource::from_path("/etc/loid.toml")],
            Vec::<PathBuf>::new(),
            ["decade=1960", "snack=peanuts"],
        );
        assert_eq!(
            &sources.files,
            &vec![(
                ConfigurationSource::from_path("/etc/loid.toml"),
                MustRead::TolerateAbsence
            )]
        );
    }

    #[test]
    fn dir_syntax() {
        let chk = |tf, s: &str| assert_eq!(tf, is_syntactically_directory(s.as_ref()), "{:?}", s);

        chk(false, "");
        chk(false, "1");
        chk(false, "1/2");
        chk(false, "/1");
        chk(false, "/1/2");

        chk(true, "/");
        chk(true, ".");
        chk(true, "./");
        chk(true, "..");
        chk(true, "../");
        chk(true, "/");
        chk(true, "1/");
        chk(true, "1/2/");
        chk(true, "/1/");
        chk(true, "/1/2/");
    }
}
