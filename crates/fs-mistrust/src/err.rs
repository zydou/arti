//! Declare an Error type for `fs-mistrust`.

use std::path::Path;
use std::{path::PathBuf, sync::Arc};

use std::io::{Error as IoError, ErrorKind as IoErrorKind};

#[cfg(feature = "anon_home")]
use crate::anon_home::PathExt as _;

// Define a local-only version of anonymize_home so that we can define our errors
// unconditionally.
#[cfg(not(feature = "anon_home"))]
trait PathExt {
    /// A do-nothing extension function.
    fn anonymize_home(&self) -> &Path;
}
#[cfg(not(feature = "anon_home"))]
impl PathExt for Path {
    fn anonymize_home(&self) -> &Path {
        self
    }
}

/// An error returned while checking a path for privacy.
///
/// Note that this often means a necessary file *doesn't exist at all*.
///
/// When printing a `fs_mistrust::Error`, do not describe it as a "permissions error".
/// Describe it with less specific wording, perhaps "Problem accessing Thing".
///
/// The `Display` impl will give the details.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A target  (or one of its ancestors) was not found.
    #[error("File or directory {} not found", _0.anonymize_home())]
    NotFound(PathBuf),

    /// A target  (or one of its ancestors) had incorrect permissions.
    ///
    /// Only generated on unix-like systems.
    ///
    /// The first integer contains the current permission bits, and the second
    /// contains the permission bits which were incorrectly set.
    #[error("Incorrect permissions: {} is {}; must be {}",
            _0.anonymize_home(),
            format_access_bits(* .1, '='),
            format_access_bits(* .2, '-'))]
    BadPermission(PathBuf, u32, u32),

    /// A target  (or one of its ancestors) had an untrusted owner.
    ///
    /// Only generated on unix-like systems.
    ///
    /// The provided integer contains the user_id o
    #[error("Bad owner (UID {1}) on file or directory {}", _0.anonymize_home())]
    BadOwner(PathBuf, u32),

    /// A target (or one of its ancestors) had the wrong type.
    ///
    /// Ordinarily, the target may be anything at all, though you can override
    /// this with [`require_file`](crate::Verifier::require_file) and
    /// [`require_directory`](crate::Verifier::require_directory).
    #[error("Wrong type of file at {}", _0.anonymize_home())]
    BadType(PathBuf),

    /// We were unable to inspect the target or one of its ancestors.
    ///
    /// (Ironically, we might lack permissions to see if something's permissions
    /// are correct.)
    ///
    /// (The `std::io::Error` that caused this problem is wrapped in an `Arc` so
    /// that our own [`Error`] type can implement `Clone`.)
    #[error("Unable to access {}", _0.anonymize_home())]
    CouldNotInspect(PathBuf, #[source] Arc<IoError>),

    /// Multiple errors occurred while inspecting the target.
    ///
    /// This variant will only be returned if the caller specifically asked for
    /// it by calling [`all_errors`](crate::Verifier::all_errors).
    ///
    /// We will never construct an instance of this variant with an empty `Vec`.
    #[error("Multiple errors found")]
    Multiple(Vec<Box<Error>>),

    /// We've realized that we can't finish resolving our path without taking
    /// more than the maximum number of steps.  The likeliest explanation is a
    /// symlink loop.
    #[error("Too many steps taken or planned: Possible symlink loop?")]
    StepsExceeded,

    /// We can't find our current working directory, or we found it but it looks
    /// impossible.
    #[error("Problem finding current directory")]
    CurrentDirectory(#[source] Arc<IoError>),

    /// We tried to create a directory, and encountered a failure in doing so.
    #[error("Problem creating directory")]
    CreatingDir(#[source] Arc<IoError>),

    /// We found a problem while checking the contents of the directory.
    #[error("Problem in directory contents")]
    Content(#[source] Box<Error>),

    /// We were unable to inspect the contents of the directory
    ///
    /// This error is only present when the `walkdir` feature is enabled.
    #[cfg(feature = "walkdir")]
    #[error("Unable to list directory contents")]
    Listing(#[source] Arc<walkdir::Error>),

    /// Tried to use an invalid path with a [`CheckedDir`](crate::CheckedDir),
    #[error("Provided path was not valid for use with CheckedDir")]
    InvalidSubdirectory,

    /// We encountered an error while attempting an IO operation on a file.
    #[error("IO error on {} while attempting to {action}", filename.anonymize_home())]
    Io {
        /// The file that we were trying to modify or inspect
        filename: PathBuf,
        /// The action that failed.
        action: &'static str,
        /// The error that we got when trying to perform the operation.
        #[source]
        err: Arc<IoError>,
    },

    /// A field was missing when we tried to construct a
    /// [`Mistrust`](crate::Mistrust).
    #[error("Missing field when constructing Mistrust")]
    MissingField(#[from] derive_builder::UninitializedFieldError),

    /// A  group that we were configured to trust could not be found.
    #[error("Configured with nonexistent group: {0}")]
    NoSuchGroup(String),

    /// A user that we were configured to trust could not be found.
    #[error("Configured with nonexistent user: {0}")]
    NoSuchUser(String),

    /// Error accessing passwd/group databases or obtaining our uids/gids
    #[error("Error accessing passwd/group databases or obtaining our uids/gids")]
    PasswdGroupIoError(#[source] Arc<IoError>),
}

impl Error {
    /// Create an error from an IoError encountered while inspecting permissions
    /// on an object.
    pub(crate) fn inspecting(err: IoError, fname: impl Into<PathBuf>) -> Self {
        match err.kind() {
            IoErrorKind::NotFound => Error::NotFound(fname.into()),
            _ => Error::CouldNotInspect(fname.into(), Arc::new(err)),
        }
    }

    /// Create an error from an IoError encountered while performing IO (open,
    /// read, write) on an object.
    pub(crate) fn io(err: IoError, fname: impl Into<PathBuf>, action: &'static str) -> Self {
        match err.kind() {
            IoErrorKind::NotFound => Error::NotFound(fname.into()),
            _ => Error::Io {
                filename: fname.into(),
                action,
                err: Arc::new(err),
            },
        }
    }

    /// Return the path, if any, associated with this error.
    pub fn path(&self) -> Option<&Path> {
        Some(
            match self {
                Error::NotFound(pb) => pb,
                Error::BadPermission(pb, ..) => pb,
                Error::BadOwner(pb, _) => pb,
                Error::BadType(pb) => pb,
                Error::CouldNotInspect(pb, _) => pb,
                Error::Io { filename: pb, .. } => pb,
                Error::Multiple(_) => return None,
                Error::StepsExceeded => return None,
                Error::CurrentDirectory(_) => return None,
                Error::CreatingDir(_) => return None,
                Error::InvalidSubdirectory => return None,
                Error::Content(e) => return e.path(),
                #[cfg(feature = "walkdir")]
                Error::Listing(e) => return e.path(),
                Error::MissingField(_) => return None,
                Error::NoSuchGroup(_) => return None,
                Error::NoSuchUser(_) => return None,
                Error::PasswdGroupIoError(_) => return None,
            }
            .as_path(),
        )
    }

    /// Return true iff this error indicates a problem with filesystem
    /// permissions.
    ///
    /// (Other errors typically indicate an IO problem, possibly one preventing
    /// us from looking at permissions in the first place)
    pub fn is_bad_permission(&self) -> bool {
        match self {
            Error::BadPermission(..) | Error::BadOwner(_, _) | Error::BadType(_) => true,

            Error::NotFound(_)
            | Error::CouldNotInspect(_, _)
            | Error::StepsExceeded
            | Error::CurrentDirectory(_)
            | Error::CreatingDir(_)
            | Error::InvalidSubdirectory
            | Error::Io { .. }
            | Error::MissingField(_)
            | Error::NoSuchGroup(_)
            | Error::NoSuchUser(_)
            | Error::PasswdGroupIoError(_) => false,

            #[cfg(feature = "walkdir")]
            Error::Listing(_) => false,

            Error::Multiple(errs) => errs.iter().any(|e| e.is_bad_permission()),
            Error::Content(err) => err.is_bad_permission(),
        }
    }

    /// Return an iterator over all of the errors contained in this Error.
    ///
    /// If this is a singleton, the iterator returns only a single element.
    /// Otherwise, it returns all the elements inside the `Error::Multiple`
    /// variant.
    ///
    /// Does not recurse, since we do not create nested instances of
    /// `Error::Multiple`.
    pub fn errors<'a>(&'a self) -> impl Iterator<Item = &Error> + 'a {
        let result: Box<dyn Iterator<Item = &Error> + 'a> = match self {
            Error::Multiple(v) => Box::new(v.iter().map(|e| e.as_ref())),
            _ => Box::new(vec![self].into_iter()),
        };

        result
    }
}

impl std::iter::FromIterator<Error> for Option<Error> {
    fn from_iter<T: IntoIterator<Item = Error>>(iter: T) -> Self {
        let mut iter = iter.into_iter();

        let first_err = iter.next()?;

        if let Some(second_err) = iter.next() {
            let mut errors = Vec::with_capacity(iter.size_hint().0 + 2);
            errors.push(Box::new(first_err));
            errors.push(Box::new(second_err));
            errors.extend(iter.map(Box::new));
            Some(Error::Multiple(errors))
        } else {
            Some(first_err)
        }
    }
}

/// Convert the low 9 bits of `bits` into a unix-style string describing its
/// access permission. Insert `c` between the ugo and perm.
///
/// For example, 0o022, '+' becomes 'g+w,o+w'.
///
/// Used for generating error messages.
pub fn format_access_bits(bits: u32, c: char) -> String {
    let mut s = String::new();

    for (shift, prefix) in [(6, 'u'), (3, 'g'), (0, 'o')] {
        let b = (bits >> shift) & 7;
        if b != 0 {
            if !s.is_empty() {
                s.push(',');
            }
            s.push(prefix);
            s.push(c);
            for (bit, ch) in [(4, 'r'), (2, 'w'), (1, 'x')] {
                if b & bit != 0 {
                    s.push(ch);
                }
            }
        }
    }

    s
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
    fn bits() {
        assert_eq!(format_access_bits(0o777, '='), "u=rwx,g=rwx,o=rwx");
        assert_eq!(format_access_bits(0o022, '='), "g=w,o=w");
        assert_eq!(format_access_bits(0o022, '-'), "g-w,o-w");
        assert_eq!(format_access_bits(0o020, '-'), "g-w");
        assert_eq!(format_access_bits(0, ' '), "");
    }

    #[test]
    fn bad_perms() {
        assert_eq!(
            Error::BadPermission(PathBuf::from("/path"), 0o777, 0o022).to_string(),
            "Incorrect permissions: /path is u=rwx,g=rwx,o=rwx; must be g-w,o-w"
        );
    }
}
