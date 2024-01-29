//! Helper module for loading and storing via serde
//!
//! Utilities to load or store a serde-able object,
//! in JSON format,
//! to/from a disk file at a caller-specified filename.
//!
//! The caller is supposed to do any necessary locking.
//!
//! The entrypoints are methods on `[Target]`,
//! which the caller is supposed to construct.

use std::path::Path;

use fs_mistrust::CheckedDir;
use serde::{de::DeserializeOwned, Serialize};

use crate::err::ErrorSource;

/// Common arguments to load/store operations
pub(crate) struct Target<'r> {
    /// Directory
    pub(crate) dir: &'r CheckedDir,

    /// Filename relative to `dir`
    ///
    /// Might be a leafname; must be relative
    /// Should include the `.json` extension.
    pub(crate) rel_fname: &'r Path,
}

impl Target<'_> {
    /// Load and deserialize a `D` from the file specified by `self`
    ///
    /// Returns `None` if the file doesn't exist.
    pub(crate) fn load<D: DeserializeOwned>(&self) -> Result<Option<D>, ErrorSource> {
        let string = match self.dir.read_to_string(self.rel_fname) {
            Ok(string) => string,
            Err(fs_mistrust::Error::NotFound(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        Ok(Some(serde_json::from_str(&string)?))
    }

    /// Serialise and store an `S` to the file specified by `self`
    ///
    /// Concurrent readers (using `load`) will see either the old data,
    /// or the new data,
    /// not corruption or a mixture.
    ///
    /// Likewise, if something fails, the old data will remain.
    /// (But, we do *not* use `fsync`.)
    ///
    /// It is a serious bug to make several concurrent calls to `store`
    /// for the same file.
    /// That might result in corrupted files.
    ///
    /// See [`fs_mistrust::CheckedDir::write_and_replace`]
    /// for more details about the semantics.
    pub(crate) fn store<S: Serialize>(&self, val: &S) -> Result<(), ErrorSource> {
        let output = serde_json::to_string_pretty(val)?;

        self.dir.write_and_replace(self.rel_fname, output)?;

        Ok(())
    }

    /// Delete the file specified by `self`
    pub(crate) fn delete(&self) -> Result<(), ErrorSource> {
        self.dir.remove_file(self.rel_fname)?;

        Ok(())
    }
}
