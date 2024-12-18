//! Functionality for opening files while verifying their permissions.

#![allow(missing_docs, clippy::missing_docs_in_private_items, dead_code)]

use crate::CheckedDir;

/// Helper object for accessing a file on disk while checking the necessary permissions.
///
/// A `FileAccess` wraps a reference to a [`CheckedDir`],
/// but allows configuring the rules for accessing the files it opens.
pub struct FileAccess<'a> {
    /// Validator object that we use for checking file permissions.
    pub(crate) inner: Inner<'a>,
}

/// Inner object for checking file permissions.
///
/// XXXX This is an enum because we plan to allow having a Mistrust here instead;
/// XXXX we should add that support or flatten this enum.
pub(crate) enum Inner<'a> {
    CheckedDir(&'a CheckedDir),
}

impl<'a> FileAccess<'a> {
    pub(crate) fn from_checked_dir(checked_dir: &'a CheckedDir) -> Self {
        Self::from_inner(Inner::CheckedDir(checked_dir))
    }
    fn from_inner(inner: Inner<'a>) -> Self {
        Self { inner }
    }
}
