//! Helper module for loading and storing via serde

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
    pub(crate) rel_fname: &'r Path,
}

impl Target<'_> {
    /// Load
    pub(crate) fn load<D: DeserializeOwned>(&self) -> Result<Option<D>, ErrorSource> {
        let string = match self.dir.read_to_string(self.rel_fname) {
            Ok(string) => string,
            Err(fs_mistrust::Error::NotFound(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        Ok(Some(serde_json::from_str(&string)?))
    }

    /// Store
    pub(crate) fn store<S: Serialize>(&self, val: &S) -> Result<(), ErrorSource> {
        let output = serde_json::to_string_pretty(val)?;

        self.dir.write_and_replace(self.rel_fname, output)?;

        Ok(())
    }
}
