//! Module providing support for handling paths relative to a [`CheckedDir`].
//!
//! The underlying relative path of a [`RelKeyPath`] should not be manipulated directly.
//! Instead, prefer converting it to an absolute path using
//! [`checked_path`](RelKeyPath::checked_path) where possible.
//! You may also use the `checked_op` macro to call [`CheckedDir`] functions on the path.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fs_mistrust::CheckedDir;
use tor_error::{ErrorKind, HasKind};
use tor_key_forge::KeyType;

use crate::{ArtiPathUnavailableError, KeySpecifier};

/// The path of a key, relative to a [`CheckedDir`].
///
/// See the [module-level documentation](self) for a general overview.
#[derive(Debug, Clone)]
pub(super) struct RelKeyPath<'a> {
    /// The directory this path is relative to.
    dir: &'a CheckedDir,
    /// The relative path.
    path: PathBuf,
}

impl<'a> RelKeyPath<'a> {
    /// Create a new [`RelKeyPath`] representing an `ArtiPath`.
    ///
    /// Returns an error if `key_spec` does not have an `ArtiPath`.
    pub(super) fn arti(
        dir: &'a CheckedDir,
        key_spec: &dyn KeySpecifier,
        key_type: &KeyType,
    ) -> Result<Self, ArtiPathUnavailableError> {
        let arti_path: String = key_spec.arti_path()?.into();
        let mut path = PathBuf::from(arti_path);
        path.set_extension(key_type.arti_extension());
        Ok(Self { dir, path })
    }

    /// Create a new [`RelKeyPath`] from a `CheckedDir` and a relative path.
    #[cfg(feature = "ctor-keystore")]
    pub(super) fn from_parts(dir: &'a CheckedDir, path: PathBuf) -> Self {
        Self { dir, path }
    }

    /// Return the checked absolute path.
    pub(super) fn checked_path(&self) -> Result<PathBuf, FilesystemError> {
        let abs_path = self
            .dir
            .join(&self.path)
            .map_err(|err| FilesystemError::FsMistrust {
                action: FilesystemAction::Read,
                path: self.path.clone(),
                err: err.into(),
            })?;

        Ok(abs_path)
    }

    /// Return this as an unchecked relative path.
    pub(super) fn rel_path_unchecked(&self) -> &Path {
        &self.path
    }

    /// Return the [`CheckedDir`] of this `RelKeyPath`.
    pub(super) fn checked_dir(&self) -> &CheckedDir {
        self.dir
    }
}

pub(crate) use internal::checked_op;

/// Private module for reexporting the `checked_op` macro.
mod internal {
    /// Run operation `op` on a [`RelKeyPath`](super::RelKeyPath).
    ///
    /// `op` is an identifier that represents a [`CheckedDir`](fs_mistrust::CheckedDir) function.
    macro_rules! checked_op {
        ($op:ident, $relpath:expr $(, $arg:expr)* ) => {{
            $relpath.checked_dir().$op($relpath.rel_path_unchecked(),  $($arg,)* )
        }}
    }

    pub(crate) use checked_op;
}

/// An error that occurred while accessing the filesystem.
#[derive(thiserror::Error, Debug, Clone)]
pub(crate) enum FilesystemError {
    /// An IO error that occurred while accessing the filesystem.
    #[error("IO error on {path} while attempting to {action}")]
    Io {
        /// The action we were trying to perform.
        action: FilesystemAction,
        /// The path of the key we were trying to fetch.
        path: PathBuf,
        /// The underlying error.
        #[source]
        err: Arc<io::Error>,
    },

    /// Encountered an inaccessible path or invalid permissions.
    #[error("Inaccessible path or bad permissions on {path} while attempting to {action}")]
    FsMistrust {
        /// The action we were trying to perform.
        action: FilesystemAction,
        /// The path of the key we were trying to fetch.
        path: PathBuf,
        /// The underlying error.
        #[source]
        err: Arc<fs_mistrust::Error>,
    },

    /// An error due to encountering a directory or symlink at a key path.
    #[error("File at {0} is not a regular file")]
    NotARegularFile(PathBuf),
}

/// The action that caused a [`FilesystemError`].
#[derive(Copy, Clone, Debug, derive_more::Display)]
pub(crate) enum FilesystemAction {
    /// Filesystem key store initialization.
    Init,
    /// Filesystem read
    Read,
    /// Filesystem write
    Write,
    /// Filesystem remove
    Remove,
}

impl HasKind for FilesystemError {
    fn kind(&self) -> ErrorKind {
        use tor_persist::FsMistrustErrorExt as _;
        use FilesystemError as FE;

        match self {
            FE::Io { .. } => ErrorKind::KeystoreAccessFailed,
            FE::FsMistrust { err, .. } => err.keystore_error_kind(),
            FE::NotARegularFile(_) => ErrorKind::KeystoreCorrupted,
        }
    }
}
