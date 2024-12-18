//! Functionality for disabling `fs-mistrust` checks based on configuration or
//! environment variables.

use std::env::{self, VarError};

/// Convenience type to indicate whether permission checks are disabled.
///
/// Used to avoid accidents with boolean meanings.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub(crate) enum Status {
    /// We should indeed run permission checks, and treat some users as untrusted.
    CheckPermissions,
    /// We should treat every user as trusted, and therefore disable (most)
    /// permissions checks.
    DisableChecks,
}

impl Status {
    /// Return true if this `Status` tells us to disable checks.
    pub(crate) fn disabled(self) -> bool {
        self == Status::DisableChecks
    }
}

/// An environment variable which, if set, will cause a us to trust all users
/// (and therefore, in effect, to disable all permissions checks.)
pub const GLOBAL_DISABLE_VAR: &str = "FS_MISTRUST_DISABLE_PERMISSIONS_CHECKS";

/// Value to configure when permission checks should be disabled.  This type is
/// set in the builder, and converted to a bool in the `Mistrust`.
#[derive(Clone, Default, Debug, Eq, PartialEq)]
pub(crate) enum Disable {
    /// Check a caller-provided environment variable, and honor it if it is set.
    /// If it is not set, fall back to checking
    /// `$FS_MISTRUST_DISABLE_PERMISSIONS_CHECKS`.
    OnUserEnvVar(String),
    /// Disable permissions checks if the value of
    /// `$FS_MISTRUST_DISABLE_PERMISSIONS_CHECKS` is something other than "false",
    /// "0", "no", etc..
    ///
    /// This is the default.
    #[default]
    OnGlobalEnvVar,
    /// Perform permissions checks regardless of any values in the environment.
    Never,
}

/// Convert the result of `std::env::var` to a boolean, if the variable is set.
///
/// Names that seem to say "don't disable" are treated as `Some(false)`.  Any
/// other value is treated as `Some(true)`.  (That is, we err on the side of
/// assuming that if you set a disable variable, you meant to disable.)
///
/// Absent environment vars, or those set to the empty string, are treated as
/// None.
#[allow(clippy::match_like_matches_macro)]
fn from_env_var_value(input: std::result::Result<String, VarError>) -> Option<Status> {
    // WARNING: This behaviour of the environment variable parsing/evaluation is considered
    // stable and should not be modified unless necessary.
    // This behaviour is part of the public interface of applications which use fs-mistrust,
    // so changing the behaviour of this function may result in a breaking change for applications.

    let mut s = match input {
        Ok(s) => s,
        Err(VarError::NotPresent) => return None,
        Err(VarError::NotUnicode(_)) => return Some(Status::DisableChecks),
    };

    s.make_ascii_lowercase();
    let s = s.trim();

    match s {
        "" => None,
        "0" | "no" | "never" | "false" | "n" => Some(Status::CheckPermissions),
        _ => Some(Status::DisableChecks),
    }
}

/// As `from_env_value`, but takes the name of the variable.
fn from_env_var(varname: &str) -> Option<Status> {
    from_env_var_value(env::var(varname))
}

impl Disable {
    /// Return true if, based on this [`Disable`] setting, and on the
    /// environment, we should disable permissions checking.
    pub(crate) fn should_disable_checks(&self) -> Status {
        match self {
            Disable::OnUserEnvVar(varname) => from_env_var(varname)
                .or_else(|| from_env_var(GLOBAL_DISABLE_VAR))
                .unwrap_or(Status::CheckPermissions),
            Disable::OnGlobalEnvVar => {
                from_env_var(GLOBAL_DISABLE_VAR).unwrap_or(Status::CheckPermissions)
            }
            Disable::Never => Status::CheckPermissions,
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
    #[test]
    fn from_val() {
        for word in ["yes", "1", "true", "certainly", "whatever"] {
            assert_eq!(
                from_env_var_value(Ok(word.into())),
                Some(Status::DisableChecks)
            );
        }

        for word in ["no", "0", "false", "NO", "Never", "n"] {
            assert_eq!(
                from_env_var_value(Ok(word.into())),
                Some(Status::CheckPermissions)
            );
        }

        assert_eq!(from_env_var_value(Ok("".into())), None);
        assert_eq!(from_env_var_value(Ok(" ".into())), None);

        assert_eq!(from_env_var_value(Err(VarError::NotPresent)), None);
        assert_eq!(
            from_env_var_value(Err(VarError::NotUnicode("".into()))),
            Some(Status::DisableChecks)
        );

        // see https://gitlab.torproject.org/tpo/core/arti/-/issues/1782
        assert_eq!(
            from_env_var_value(Ok(" false ".to_string())),
            Some(Status::CheckPermissions),
        );
    }
}
