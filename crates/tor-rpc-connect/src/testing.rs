//! Helper functionality for writing tests within the `tor-rpc-connect` crate.

use std::{os::unix::fs::PermissionsExt, path::PathBuf};

use fs_mistrust::Mistrust;
use tempfile::TempDir;

/// Create a temporary secure directory.
///
/// Return a [`tempfile::TempDir`] object (which should be retained but ignored),
/// a path to a secure directory within that `TempDir`,
/// and a [`Mistrust`] that accepts that secure directory.
///
/// # Panics
///
/// Panics if any operation fails.  This function is for testing only.
#[allow(clippy::unwrap_used)]
pub(crate) fn tempdir() -> (TempDir, PathBuf, Mistrust) {
    let mut bld = tempfile::Builder::new();
    #[cfg(unix)]
    bld.permissions(PermissionsExt::from_mode(0o700));
    let tempdir = bld.tempdir().unwrap();
    let subdir = tempdir.as_ref().join("d");

    let mistrust = fs_mistrust::Mistrust::builder()
        .ignore_prefix(tempdir.as_ref().canonicalize().unwrap())
        .build()
        .unwrap();

    mistrust.make_directory(&subdir).unwrap();
    (tempdir, subdir, mistrust)
}
