//! The Tor directory mirror implementation.

use crate::err::BuilderError;
use std::path::PathBuf;

/// Core data type of a directory mirror.
#[derive(Debug)]
pub struct DirMirror {
    /// Access to the [`DirMirrorBuilder`].
    builder: DirMirrorBuilder,
}

/// Builder type for [`DirMirror`].
#[derive(Debug, Default)]
pub struct DirMirrorBuilder {
    /// The path to the SQLite database.
    db_path: Option<PathBuf>,
}

impl DirMirror {
    /// Returns a new [`DirMirrorBuilder`] with default values.
    pub fn builder() -> DirMirrorBuilder {
        DirMirrorBuilder::default()
    }
}

impl DirMirrorBuilder {
    /// Creates a new instance of a [`DirMirrorBuilder`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the path of the SQLite database to a path on the filesystem.
    pub fn set_db_path(mut self, db_path: PathBuf) -> Self {
        self.db_path = Some(db_path);
        self
    }

    /// Builds a [`DirMirror`] from a [`DirMirrorBuilder`].
    pub fn build(self) -> Result<DirMirror, BuilderError> {
        if self.db_path.is_none() {
            return Err(BuilderError::MissingField("db_path"));
        }

        Ok(DirMirror { builder: self })
    }
}
