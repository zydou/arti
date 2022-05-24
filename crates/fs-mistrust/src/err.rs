//! Declare an Error type for `fs-mistrust`.

use std::path::Path;
use std::{path::PathBuf, sync::Arc};

use std::io::{Error as IoError, ErrorKind as IoErrorKind};

/// An error returned while checking a path for privacy.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A target  (or one of its ancestors) was not found.
    #[error("File or directory {0} not found")]
    NotFound(PathBuf),

    /// A target  (or one of its ancestors) had incorrect permissions.
    ///
    /// Only generated on unix-like systems.
    ///
    /// The provided integer contains the `st_mode` bits which were incorrectly
    /// set.
    #[error("Incorrect permissions on file or directory {0}:  {}", format_access_bits(* .1))]
    BadPermission(PathBuf, u32),

    /// A target  (or one of its ancestors) had an untrusted owner.
    ///
    /// Only generated on unix-like systems.
    ///
    /// The provided integer contains the user_id o
    #[error("Bad owner (UID {1}) on file or directory {0}")]
    BadOwner(PathBuf, u32),

    /// A target (or one of its ancestors) had the wrong type.
    ///
    /// Ordinarily, the target may be anything at all, though you can override
    /// this with [`require_file`](crate::Verifier::require_file) and
    /// [`require_directory`](crate::Verifier::require_directory).
    #[error("Wrong type of file at {0}")]
    BadType(PathBuf),

    /// We were unable to inspect the target or one of its ancestors.
    ///
    /// (Ironically, we might lack permissions to see if something's permissions
    /// are correct.)
    ///
    /// (The `std::io::Error` that caused this problem is wrapped in an `Arc` so
    /// that our own [`Error`] type can implement `Clone`.)
    #[error("Unable to access {0}")]
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
    #[error("Invalid directory content")]
    Content(#[source] Box<Error>),

    /// We were unable to inspect the contents of the directory
    ///
    /// This error is only present when the `walkdir` feature is enabled.
    #[cfg(feature = "walkdir")]
    #[error("Unable to list directory")]
    Listing(#[source] Arc<walkdir::Error>),

    /// Tried to use an invalid path with a [`CheckedDir`](crate::CheckedDir),
    #[error("Path was not valid for use with CheckedDir.")]
    InvalidSubdirectory,

    /// We encountered an error while attempting an IO operation on a file.
    #[error("IO error on {0}")]
    Io(PathBuf, #[source] Arc<IoError>),

    /// We could not create an unused temporary path when trying to write a
    /// file.
    #[error("Could not name temporary file for {0}")]
    NoTempFile(PathBuf),

    /// A field was missing when we tried to construct a
    /// [`Mistrust`](crate::Mistrust).
    #[error("Missing field: {0}")]
    MissingField(#[from] derive_builder::UninitializedFieldError),

    /// A  group that we were configured to trust could not be found.
    #[error("No such group: {0}")]
    NoSuchGroup(String),

    /// A user that we were configured to trust could not be found.
    #[error("No such user: {0}")]
    NoSuchUser(String),
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
    pub(crate) fn io(err: IoError, fname: impl Into<PathBuf>) -> Self {
        match err.kind() {
            IoErrorKind::NotFound => Error::NotFound(fname.into()),
            _ => Error::Io(fname.into(), Arc::new(err)),
        }
    }

    /// Return the path, if any, associated with this error.
    pub fn path(&self) -> Option<&Path> {
        Some(
            match self {
                Error::NotFound(pb) => pb,
                Error::BadPermission(pb, _) => pb,
                Error::BadOwner(pb, _) => pb,
                Error::BadType(pb) => pb,
                Error::CouldNotInspect(pb, _) => pb,
                Error::Io(pb, _) => pb,
                Error::NoTempFile(pb) => pb,
                Error::Multiple(_) => return None,
                Error::StepsExceeded => return None,
                Error::CurrentDirectory(_) => return None,
                Error::CreatingDir(_) => return None,
                Error::InvalidSubdirectory => return None,
                Error::Content(e) => return e.path(),
                Error::Listing(e) => return e.path(),
                Error::MissingField(_) => return None,
                Error::NoSuchGroup(_) => return None,
                Error::NoSuchUser(_) => return None,
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
            Error::BadPermission(_, _) | Error::BadOwner(_, _) | Error::BadType(_) => true,

            Error::NotFound(_)
            | Error::CouldNotInspect(_, _)
            | Error::StepsExceeded
            | Error::CurrentDirectory(_)
            | Error::CreatingDir(_)
            | Error::Listing(_)
            | Error::InvalidSubdirectory
            | Error::Io(_, _)
            | Error::NoTempFile(_)
            | Error::MissingField(_)
            | Error::NoSuchGroup(_)
            | Error::NoSuchUser(_) => false,

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
/// access permission.
///
/// For example, 0o022 becomes 'g+w o+w'.
///
/// Used for generating error messages.
fn format_access_bits(bits: u32) -> String {
    let mut s = String::new();

    for (shift, prefix) in [(6, "u="), (3, "g="), (0, "o=")] {
        let b = (bits >> shift) & 7;
        if b != 0 {
            if !s.is_empty() {
                s.push(' ');
            }
            s.push_str(prefix);
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
    use super::*;

    #[test]
    fn bits() {
        assert_eq!(format_access_bits(0o777), "u=rwx g=rwx o=rwx");
        assert_eq!(format_access_bits(0o022), "g=w o=w");
        assert_eq!(format_access_bits(0o022), "g=w o=w");
        assert_eq!(format_access_bits(0o020), "g=w");
        assert_eq!(format_access_bits(0), "");
    }
}
