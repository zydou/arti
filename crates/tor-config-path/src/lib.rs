#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![doc = include_str!("../README.md")]
// @@ begin lint list maintained by maint/add_warning @@
#![allow(renamed_and_removed_lints)] // @@REMOVE_WHEN(ci_arti_stable)
#![allow(unknown_lints)] // @@REMOVE_WHEN(ci_arti_nightly)
#![warn(missing_docs)]
#![warn(noop_method_call)]
#![warn(unreachable_pub)]
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
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![deny(clippy::print_stderr)]
#![deny(clippy::print_stdout)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unchecked_duration_subtraction)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
#![allow(clippy::result_large_err)] // temporary workaround for arti#587
#![allow(clippy::needless_raw_string_hashes)] // complained-about code is fine, often best
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
#[cfg(feature = "expand-paths")]
use std::borrow::Cow;
#[cfg(feature = "expand-paths")]
use {
    directories::{BaseDirs, ProjectDirs},
    once_cell::sync::Lazy,
};

use tor_error::{ErrorKind, HasKind};

#[cfg(feature = "address")]
pub mod addr;

/// A path in a configuration file: tilde expansion is performed, along
/// with expansion of certain variables.
///
/// The supported variables are:
///   * `ARTI_CACHE`: an arti-specific cache directory.
///   * `ARTI_CONFIG`: an arti-specific configuration directory.
///   * `ARTI_SHARED_DATA`: an arti-specific directory in the user's "shared
///     data" space.
///   * `ARTI_LOCAL_DATA`: an arti-specific directory in the user's "local
///     data" space.
///   * `PROGRAM_DIR`: the directory of the currently executing binary.
///     See documentation for [`std::env::current_exe`] for security notes.
///   * `USER_HOME`: the user's home directory.
///
/// These variables are implemented using the `directories` crate, and
/// so should use appropriate system-specific overrides under the
/// hood. (Some of those overrides are based on environment variables.)
/// For more information, see that crate's documentation.
///
/// Alternatively, a `CfgPath` can contain literal `PathBuf`, which will not be expanded.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(transparent)]
pub struct CfgPath(PathInner);

/// Inner implementation of CfgPath
///
/// `PathInner` exists to avoid making the variants part of the public Rust API
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(untagged)]
enum PathInner {
    /// A path that should be used literally, with no expansion.
    Literal(LiteralPath),
    /// A path that should be expanded from a string using ShellExpand.
    Shell(String),
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
/// Inner implementation of PathInner:Literal
///
/// `LiteralPath` exists to arrange that `PathInner::Literal`'s (de)serialization
/// does not overlap with `PathInner::Shell`'s.
struct LiteralPath {
    /// The underlying `PathBuf`.
    literal: PathBuf,
}

/// An error that has occurred while expanding a path.
#[derive(thiserror::Error, Debug, Clone)]
#[non_exhaustive]
#[cfg_attr(test, derive(PartialEq))]
pub enum CfgPathError {
    /// The path contained a variable we didn't recognize.
    #[error("Unrecognized variable {0} in path")]
    UnknownVar(String),
    /// We couldn't construct a ProjectDirs object.
    #[error("Couldn't determine XDG Project Directories, needed to resolve a path; probably, unable to determine HOME directory")]
    NoProjectDirs,
    /// We couldn't construct a BaseDirs object.
    #[error("Can't construct base directories to resolve a path element")]
    NoBaseDirs,
    /// We couldn't find our current binary path.
    #[error("Can't find the path to the current binary")]
    NoProgramPath,
    /// We couldn't convert a string to a valid path on the OS.
    #[error("Invalid path string: {0:?}")]
    InvalidString(String),
    /// Variable interpolation (`$`) attempted, but not compiled in
    #[error("Variable interpolation $ is not supported (tor-config/expand-paths feature disabled)); $ must still be doubled")]
    VariableInterpolationNotSupported(String),
    /// Home dir interpolation (`~`) attempted, but not compiled in
    #[error("Home dir ~/ is not supported (tor-config/expand-paths feature disabled)")]
    HomeDirInterpolationNotSupported(String),
}

impl HasKind for CfgPathError {
    fn kind(&self) -> ErrorKind {
        use CfgPathError as E;
        use ErrorKind as EK;
        match self {
            E::UnknownVar(_) | E::InvalidString(_) => EK::InvalidConfig,
            E::NoProjectDirs | E::NoBaseDirs => EK::NoHomeDirectory,
            E::NoProgramPath => EK::InvalidConfig,
            E::VariableInterpolationNotSupported(_) | E::HomeDirInterpolationNotSupported(_) => {
                EK::FeatureDisabled
            }
        }
    }
}

impl CfgPath {
    /// Create a new configuration path
    pub fn new(s: String) -> Self {
        CfgPath(PathInner::Shell(s))
    }

    /// Construct a new `CfgPath` designating a literal not-to-be-expanded `PathBuf`
    pub fn new_literal<P: Into<PathBuf>>(path: P) -> Self {
        CfgPath(PathInner::Literal(LiteralPath {
            literal: path.into(),
        }))
    }

    /// Return the path on disk designated by this `CfgPath`.
    pub fn path(&self) -> Result<PathBuf, CfgPathError> {
        match &self.0 {
            PathInner::Shell(s) => expand(s),
            PathInner::Literal(LiteralPath { literal }) => Ok(literal.clone()),
        }
    }

    /// If the `CfgPath` is a string that should be expanded, return the (unexpanded) string,
    ///
    /// Before use, this string would have be to expanded.  So if you want a path to actually use,
    /// call `path` instead.
    ///
    /// Returns `None` if the `CfgPath` is a literal `PathBuf` not intended for expansion.
    pub fn as_unexpanded_str(&self) -> Option<&str> {
        match &self.0 {
            PathInner::Shell(s) => Some(s),
            PathInner::Literal(_) => None,
        }
    }

    /// If the `CfgPath` designates a literal not-to-be-expanded `Path`, return a reference to it
    ///
    /// Returns `None` if the `CfgPath` is a string which should be expanded, which is the
    /// usual case.
    pub fn as_literal_path(&self) -> Option<&Path> {
        match &self.0 {
            PathInner::Shell(_) => None,
            PathInner::Literal(LiteralPath { literal }) => Some(literal),
        }
    }
}

/// Helper: expand a directory given as a string.
#[cfg(feature = "expand-paths")]
fn expand(s: &str) -> Result<PathBuf, CfgPathError> {
    Ok(shellexpand::path::full_with_context(s, get_home, get_env)
        .map_err(|e| e.cause)?
        .into_owned())
}

/// Helper: convert a string to a path without expansion.
#[cfg(not(feature = "expand-paths"))]
fn expand(input: &str) -> Result<PathBuf, CfgPathError> {
    // We must still de-duplicate `$` and reject `~/`,, so that the behaviour is a superset
    if input.starts_with('~') {
        return Err(CfgPathError::HomeDirInterpolationNotSupported(input.into()));
    }

    let mut out = String::with_capacity(input.len());
    let mut s = input;
    while let Some((lhs, rhs)) = s.split_once('$') {
        if let Some(rhs) = rhs.strip_prefix('$') {
            // deduplicate the $
            out += lhs;
            out += "$";
            s = rhs;
        } else {
            return Err(CfgPathError::VariableInterpolationNotSupported(
                input.into(),
            ));
        }
    }
    out += s;
    Ok(out.into())
}

/// Shellexpand helper: return the user's home directory if we can.
#[cfg(feature = "expand-paths")]
fn get_home() -> Option<&'static Path> {
    base_dirs().ok().map(BaseDirs::home_dir)
}

/// Shellexpand helper: return the directory holding the currently executing program.
#[cfg(feature = "expand-paths")]
fn get_program_dir() -> Result<Option<PathBuf>, CfgPathError> {
    let binary = std::env::current_exe().map_err(|_| CfgPathError::NoProgramPath)?;
    Ok(binary.parent().map(ToOwned::to_owned))
}

/// Shellexpand helper: Expand a shell variable if we can.
#[cfg(feature = "expand-paths")]
fn get_env(var: &str) -> Result<Option<Cow<'static, Path>>, CfgPathError> {
    match var {
        "ARTI_CACHE" => Ok(Some(Cow::Borrowed(project_dirs()?.cache_dir()))),
        "ARTI_CONFIG" => Ok(Some(Cow::Borrowed(project_dirs()?.config_dir()))),
        "ARTI_SHARED_DATA" => Ok(Some(Cow::Borrowed(project_dirs()?.data_dir()))),
        "ARTI_LOCAL_DATA" => Ok(Some(Cow::Borrowed(project_dirs()?.data_local_dir()))),
        "PROGRAM_DIR" => Ok(get_program_dir()?.map(Cow::Owned)),
        "USER_HOME" => Ok(Some(Cow::Borrowed(base_dirs()?.home_dir()))),
        _ => Err(CfgPathError::UnknownVar(var.to_owned())),
    }
}

impl std::fmt::Display for CfgPath {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            PathInner::Literal(LiteralPath { literal }) => write!(fmt, "{:?} [exactly]", literal),
            PathInner::Shell(s) => s.fmt(fmt),
        }
    }
}

/// Return a ProjectDirs object for the Arti project.
#[cfg(feature = "expand-paths")]
fn project_dirs() -> Result<&'static ProjectDirs, CfgPathError> {
    /// lazy cell holding the ProjectDirs object.
    static PROJECT_DIRS: Lazy<Option<ProjectDirs>> =
        Lazy::new(|| ProjectDirs::from("org", "torproject", "Arti"));

    PROJECT_DIRS.as_ref().ok_or(CfgPathError::NoProjectDirs)
}

/// Return a UserDirs object for the current user.
#[cfg(feature = "expand-paths")]
fn base_dirs() -> Result<&'static BaseDirs, CfgPathError> {
    /// lazy cell holding the BaseDirs object.
    static BASE_DIRS: Lazy<Option<BaseDirs>> = Lazy::new(BaseDirs::new);

    BASE_DIRS.as_ref().ok_or(CfgPathError::NoBaseDirs)
}

#[cfg(all(test, feature = "expand-paths"))]
mod test {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn expand_no_op() {
        let p = CfgPath::new("Hello/world".to_string());
        assert_eq!(p.to_string(), "Hello/world".to_string());
        assert_eq!(p.path().unwrap().to_str(), Some("Hello/world"));

        let p = CfgPath::new("/usr/local/foo".to_string());
        assert_eq!(p.to_string(), "/usr/local/foo".to_string());
        assert_eq!(p.path().unwrap().to_str(), Some("/usr/local/foo"));
    }

    #[cfg(not(target_family = "windows"))]
    #[test]
    fn expand_home() {
        let p = CfgPath::new("~/.arti/config".to_string());
        assert_eq!(p.to_string(), "~/.arti/config".to_string());

        let expected = dirs::home_dir().unwrap().join(".arti/config");
        assert_eq!(p.path().unwrap().to_str(), expected.to_str());

        let p = CfgPath::new("${USER_HOME}/.arti/config".to_string());
        assert_eq!(p.to_string(), "${USER_HOME}/.arti/config".to_string());
        assert_eq!(p.path().unwrap().to_str(), expected.to_str());
    }

    #[cfg(target_family = "windows")]
    #[test]
    fn expand_home() {
        let p = CfgPath::new("~\\.arti\\config".to_string());
        assert_eq!(p.to_string(), "~\\.arti\\config".to_string());

        let expected = dirs::home_dir().unwrap().join(".arti\\config");
        assert_eq!(p.path().unwrap().to_str(), expected.to_str());

        let p = CfgPath::new("${USER_HOME}\\.arti\\config".to_string());
        assert_eq!(p.to_string(), "${USER_HOME}\\.arti\\config".to_string());
        assert_eq!(p.path().unwrap().to_str(), expected.to_str());
    }

    #[cfg(not(target_family = "windows"))]
    #[test]
    fn expand_cache() {
        let p = CfgPath::new("${ARTI_CACHE}/example".to_string());
        assert_eq!(p.to_string(), "${ARTI_CACHE}/example".to_string());

        let expected = project_dirs().unwrap().cache_dir().join("example");
        assert_eq!(p.path().unwrap().to_str(), expected.to_str());
    }

    #[cfg(target_family = "windows")]
    #[test]
    fn expand_cache() {
        let p = CfgPath::new("${ARTI_CACHE}\\example".to_string());
        assert_eq!(p.to_string(), "${ARTI_CACHE}\\example".to_string());

        let expected = project_dirs().unwrap().cache_dir().join("example");
        assert_eq!(p.path().unwrap().to_str(), expected.to_str());
    }

    #[test]
    fn expand_bogus() {
        let p = CfgPath::new("${ARTI_WOMBAT}/example".to_string());
        assert_eq!(p.to_string(), "${ARTI_WOMBAT}/example".to_string());

        assert!(matches!(p.path(), Err(CfgPathError::UnknownVar(_))));
        assert_eq!(
            &p.path().unwrap_err().to_string(),
            "Unrecognized variable ARTI_WOMBAT in path"
        );
    }

    #[test]
    fn literal() {
        let p = CfgPath::new_literal(PathBuf::from("${ARTI_CACHE}/literally"));
        // This doesn't get expanded, since we're using a literal path.
        assert_eq!(
            p.path().unwrap().to_str().unwrap(),
            "${ARTI_CACHE}/literally"
        );
        assert_eq!(p.to_string(), "\"${ARTI_CACHE}/literally\" [exactly]");
    }
}

#[cfg(test)]
mod test_serde {
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

    use std::ffi::OsString;
    use std::fmt::Debug;

    use derive_builder::Builder;
    use tor_config::load::TopLevel;
    use tor_config::{impl_standard_builder, ConfigBuildError};

    #[derive(Serialize, Deserialize, Builder, Eq, PartialEq, Debug)]
    #[builder(derive(Serialize, Deserialize, Debug))]
    #[builder(build_fn(error = "ConfigBuildError"))]
    struct TestConfigFile {
        p: CfgPath,
    }

    impl_standard_builder! { TestConfigFile: !Default }

    impl TopLevel for TestConfigFile {
        type Builder = TestConfigFileBuilder;
    }

    fn deser_json(json: &str) -> CfgPath {
        dbg!(json);
        let TestConfigFile { p } = serde_json::from_str(json).expect("deser json failed");
        p
    }
    fn deser_toml(toml: &str) -> CfgPath {
        dbg!(toml);
        let TestConfigFile { p } = toml::from_str(toml).expect("deser toml failed");
        p
    }
    fn deser_toml_cfg(toml: &str) -> CfgPath {
        dbg!(toml);
        let mut sources = tor_config::ConfigurationSources::new_empty();
        sources.push_source(
            tor_config::ConfigurationSource::from_verbatim(toml.to_string()),
            tor_config::sources::MustRead::MustRead,
        );
        let cfg = sources.load().unwrap();

        dbg!(&cfg);
        let TestConfigFile { p } = tor_config::load::resolve(cfg).expect("cfg resolution failed");
        p
    }

    #[test]
    fn test_parse() {
        fn desers(toml: &str, json: &str) -> Vec<CfgPath> {
            vec![deser_toml(toml), deser_toml_cfg(toml), deser_json(json)]
        }

        for cp in desers(r#"p = "string""#, r#"{ "p": "string" }"#) {
            assert_eq!(cp.as_unexpanded_str(), Some("string"));
            assert_eq!(cp.as_literal_path(), None);
        }

        for cp in desers(
            r#"p = { literal = "lit" }"#,
            r#"{ "p": {"literal": "lit"} }"#,
        ) {
            assert_eq!(cp.as_unexpanded_str(), None);
            assert_eq!(cp.as_literal_path(), Some(&*PathBuf::from("lit")));
        }
    }

    fn non_string_path() -> PathBuf {
        #[cfg(target_family = "unix")]
        {
            use std::os::unix::ffi::OsStringExt;
            return PathBuf::from(OsString::from_vec(vec![0x80_u8]));
        }

        #[cfg(target_family = "windows")]
        {
            use std::os::windows::ffi::OsStringExt;
            return PathBuf::from(OsString::from_wide(&[0xD800_u16]));
        }

        #[allow(unreachable_code)]
        // Cannot test non-Stringy Paths on this platform
        PathBuf::default()
    }

    fn test_roundtrip_cases<SER, S, DESER, E, F>(ser: SER, deser: DESER)
    where
        SER: Fn(&TestConfigFile) -> Result<S, E>,
        DESER: Fn(&S) -> Result<TestConfigFile, F>,
        S: Debug,
        E: Debug,
        F: Debug,
    {
        let case = |easy, p| {
            let input = TestConfigFile { p };
            let s = match ser(&input) {
                Ok(s) => s,
                Err(e) if easy => panic!("ser failed {:?} e={:?}", &input, &e),
                Err(_) => return,
            };
            dbg!(&input, &s);
            let output = deser(&s).expect("deser failed");
            assert_eq!(&input, &output, "s={:?}", &s);
        };

        case(true, CfgPath::new("string".into()));
        case(true, CfgPath::new_literal(PathBuf::from("nice path")));
        case(true, CfgPath::new_literal(PathBuf::from("path with ✓")));

        // Non-UTF-8 paths are really hard to serialize.  We allow the serializsaton
        // to fail, and if it does, we skip the rest of the round trip test.
        // But, if they did serialise, we want to make sure that we can deserialize.
        // Hence this test case.
        case(false, CfgPath::new_literal(non_string_path()));
    }

    #[test]
    fn roundtrip_json() {
        test_roundtrip_cases(
            |input| serde_json::to_string(&input),
            |json| serde_json::from_str(json),
        );
    }

    #[test]
    fn roundtrip_toml() {
        test_roundtrip_cases(|input| toml::to_string(&input), |toml| toml::from_str(toml));
    }

    #[test]
    fn roundtrip_mpack() {
        test_roundtrip_cases(
            |input| rmp_serde::to_vec(&input),
            |mpack| rmp_serde::from_slice(mpack),
        );
    }

    #[test]
    #[cfg(feature = "expand-paths")]
    fn program_dir() {
        let p = CfgPath::new("${PROGRAM_DIR}/foo".to_string());

        let mut this_binary = std::env::current_exe().unwrap();
        this_binary.pop();
        this_binary.push("foo");
        let expanded = p.path().unwrap();
        assert_eq!(expanded, this_binary);
    }

    #[test]
    #[cfg(not(feature = "expand-paths"))]
    fn rejections() {
        let chk_err = |s: &str, mke: &dyn Fn(String) -> CfgPathError| {
            let p = CfgPath::new(s.to_string());
            assert_eq!(p.path().unwrap_err(), mke(s.to_string()));
        };

        let chk_ok = |s: &str, exp| {
            let p = CfgPath::new(s.to_string());
            assert_eq!(p.path(), Ok(PathBuf::from(exp)));
        };

        chk_err(
            "some/${PROGRAM_DIR}/foo",
            &CfgPathError::VariableInterpolationNotSupported,
        );
        chk_err("~some", &CfgPathError::HomeDirInterpolationNotSupported);

        chk_ok("some$$foo$$bar", "some$foo$bar");
        chk_ok("no dollars", "no dollars");
    }
}
