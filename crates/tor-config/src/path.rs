//! A path type exposed from the configuration crate
//!
//! This type allows the user to specify paths as strings, with some
//! support for tab expansion and user directory support.

use std::path::{Path, PathBuf};

use directories::{BaseDirs, ProjectDirs};
use once_cell::sync::Lazy;
use serde::Deserialize;

/// A path in a configuration file: tilde expansion is performed, along
/// with expansion of certain variables.
///
/// The supported variables are:
///   * `APP_CACHE`: an arti-specific cache directory.
///   * `APP_CONFIG`: an arti-specific configuration directory.
///   * `APP_SHARED_DATA`: an arti-specific directory in the user's "shared
///     data" space.
///   * `APP_LOCAL_DATA`: an arti-specific directory in the user's "local
///     data" space.
///   * `USER_HOME`: the user's home directory.
///
/// These variables are implemented using the `directories` crate, and
/// so should use appropriate system-specific overrides under the
/// hood.
#[derive(Clone, Debug, Deserialize)]
#[serde(transparent)]
pub struct CfgPath(String);

/// An error that has occurred while expanding a path.
#[derive(thiserror::Error, Debug, Clone)]
#[non_exhaustive]
pub enum CfgPathError {
    /// The path contained a variable we didn't recognize.
    #[error("unrecognized variable {0}")]
    UnknownVar(String),
    /// We couldn't construct a ProjectDirs object.
    #[error("can't construct project directories")]
    NoProjectDirs,
    /// We couldn't construct a BaseDirs object.
    #[error("can't construct base directories")]
    NoBaseDirs,
    /// We couldn't convert a variable to UTF-8.
    ///
    /// (This is due to a limitation in the shellexpand crate, which should
    /// be fixed in the future.)
    #[error("can't convert value of {0} to UTF-8")]
    BadUtf8(String),
}

impl CfgPath {
    /// Create a new configuration path
    pub fn new(s: String) -> Self {
        CfgPath(s)
    }

    /// Return the path on disk designated by this `CfgPath`.
    #[cfg(feature = "expand-paths")]
    pub fn path(&self) -> Result<PathBuf, CfgPathError> {
        Ok(shellexpand::full_with_context(&self.0, get_home, get_env)
            .map_err(|e| e.cause)?
            .into_owned()
            .into())
    }

    /// Return the path on disk designated by this `CfgPath`.
    #[cfg(not(feature = "expand-paths"))]
    pub fn path(&self) -> Result<PathBuf, CfgPathError> {
        Ok(self.0.into())
    }
}

/// Shellexpand helper: return the user's home directory if we can.
#[cfg(feature = "expand-paths")]
fn get_home() -> Option<&'static Path> {
    base_dirs().ok().map(BaseDirs::home_dir)
}

/// Shellexpand helper: Expand a shell variable if we can.
#[cfg(feature = "expand-paths")]
fn get_env(var: &str) -> Result<Option<&'static str>, CfgPathError> {
    let path = match var {
        "APP_CACHE" => project_dirs()?.cache_dir(),
        "APP_CONFIG" => project_dirs()?.config_dir(),
        "APP_SHARED_DATA" => project_dirs()?.data_dir(),
        "APP_LOCAL_DATA" => project_dirs()?.data_local_dir(),
        "USER_HOME" => base_dirs()?.home_dir(),
        _ => return Err(CfgPathError::UnknownVar(var.to_owned())),
    };

    match path.to_str() {
        // Note that we never return Ok(None) -- an absent variable is
        // always an error.
        Some(s) => Ok(Some(s)),
        // Note that this error is necessary because shellexpand
        // doesn't currently handle OsStr.  In the future, that might
        // change.
        None => Err(CfgPathError::BadUtf8(var.to_owned())),
    }
}

impl std::fmt::Display for CfgPath {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(fmt)
    }
}

/// Return a ProjectDirs object for the Arti project.
#[cfg(feature = "expand-paths")]
fn project_dirs() -> Result<&'static ProjectDirs, CfgPathError> {
    /// lazy cell holding the ProjectDirs object.
    // Note: this must stay in sync with sane_defaults() in the
    // arti-client crate.
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

    #[test]
    fn expand_cache() {
        let p = CfgPath::new("${APP_CACHE}/example".to_string());
        assert_eq!(p.to_string(), "${APP_CACHE}/example".to_string());

        let expected = project_dirs().unwrap().cache_dir().join("example");
        assert_eq!(p.path().unwrap().to_str(), expected.to_str());
    }

    #[test]
    fn expand_bogus() {
        let p = CfgPath::new("${APP_WOMBAT}/example".to_string());
        assert_eq!(p.to_string(), "${APP_WOMBAT}/example".to_string());

        assert!(p.path().is_err());
    }
}
