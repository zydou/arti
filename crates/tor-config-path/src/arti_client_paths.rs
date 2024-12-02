//! Base paths for use with arti clients.
//!
//! This code is defined in `tor-config-path` rather than in `arti-client` so that other programs
//! (notably `arti-rpc-client-core`) can use it.

use std::{borrow::Cow, path::PathBuf};

use directories::ProjectDirs;
use once_cell::sync::Lazy;

use crate::{CfgPathError, CfgPathResolver};

/// A [`CfgPathResolver`] with the base variables configured for a `TorClientConfig`
/// in `arti-client`.
///
/// A `TorClientConfig` may set additional variables on its resolver.
///
/// This should only be used by `TorClient` users
/// and others that need to use the same variables.
/// Libraries should be written in a
/// resolver-agnostic way (shouldn't rely on resolving `ARTI_CONFIG` for example).
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
/// These variables are implemented using the [`directories`] crate, and
/// so should use appropriate system-specific overrides under the
/// hood. (Some of those overrides are based on environment variables.)
/// For more information, see that crate's documentation.
pub fn arti_client_base_resolver() -> CfgPathResolver {
    let arti_cache = project_dirs().map(|x| Cow::Owned(x.cache_dir().to_owned()));
    let arti_config = project_dirs().map(|x| Cow::Owned(x.config_dir().to_owned()));
    let arti_shared_data = project_dirs().map(|x| Cow::Owned(x.data_dir().to_owned()));
    let arti_local_data = project_dirs().map(|x| Cow::Owned(x.data_local_dir().to_owned()));
    let program_dir = get_program_dir().map(Cow::Owned);
    let user_home = crate::home().map(Cow::Borrowed);

    let mut resolver = CfgPathResolver::default();

    resolver.set_var("ARTI_CACHE", arti_cache);
    resolver.set_var("ARTI_CONFIG", arti_config);
    resolver.set_var("ARTI_SHARED_DATA", arti_shared_data);
    resolver.set_var("ARTI_LOCAL_DATA", arti_local_data);
    resolver.set_var("PROGRAM_DIR", program_dir);
    resolver.set_var("USER_HOME", user_home);

    resolver
}

/// Return the directory holding the currently executing program.
fn get_program_dir() -> Result<PathBuf, CfgPathError> {
    let binary = std::env::current_exe().map_err(|_| CfgPathError::NoProgramPath)?;
    let directory = binary.parent().ok_or(CfgPathError::NoProgramDir)?;
    Ok(directory.to_owned())
}

/// Return a ProjectDirs object for the Arti project.
fn project_dirs() -> Result<&'static ProjectDirs, CfgPathError> {
    /// lazy cell holding the ProjectDirs object.
    static PROJECT_DIRS: Lazy<Option<ProjectDirs>> =
        Lazy::new(|| ProjectDirs::from("org", "torproject", "Arti"));

    PROJECT_DIRS.as_ref().ok_or(CfgPathError::NoProjectDirs)
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
    use crate::CfgPath;

    fn cfg_variables() -> impl IntoIterator<Item = (&'static str, PathBuf)> {
        let list = [
            ("ARTI_CACHE", project_dirs().unwrap().cache_dir()),
            ("ARTI_CONFIG", project_dirs().unwrap().config_dir()),
            ("ARTI_SHARED_DATA", project_dirs().unwrap().data_dir()),
            ("ARTI_LOCAL_DATA", project_dirs().unwrap().data_local_dir()),
            ("PROGRAM_DIR", &get_program_dir().unwrap()),
            ("USER_HOME", crate::home().unwrap()),
        ];

        list.into_iter()
            .map(|(a, b)| (a, b.to_owned()))
            .collect::<Vec<_>>()
    }

    #[cfg(not(target_family = "windows"))]
    #[test]
    fn expand_variables() {
        let path_resolver = arti_client_base_resolver();

        for (var, val) in cfg_variables() {
            let p = CfgPath::new(format!("${{{var}}}/example"));
            assert_eq!(p.to_string(), format!("${{{var}}}/example"));

            let expected = val.join("example");
            assert_eq!(p.path(&path_resolver).unwrap().to_str(), expected.to_str());
        }

        let p = CfgPath::new("${NOT_A_REAL_VAR}/example".to_string());
        assert!(p.path(&path_resolver).is_err());
    }

    #[cfg(target_family = "windows")]
    #[test]
    fn expand_variables() {
        let path_resolver = arti_client_base_resolver();

        for (var, val) in cfg_variables() {
            let p = CfgPath::new(format!("${{{var}}}\\example"));
            assert_eq!(p.to_string(), format!("${{{var}}}\\example"));

            let expected = val.join("example");
            assert_eq!(p.path(&path_resolver).unwrap().to_str(), expected.to_str());
        }

        let p = CfgPath::new("${NOT_A_REAL_VAR}\\example".to_string());
        assert!(p.path(&path_resolver).is_err());
    }
}
