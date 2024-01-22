#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![doc = include_str!("../README.md")]
// @@ begin lint list maintained by maint/add_warning @@
#![cfg_attr(not(ci_arti_stable), allow(renamed_and_removed_lints))]
#![cfg_attr(not(ci_arti_nightly), allow(unknown_lints))]
#![warn(missing_docs)]
#![warn(noop_method_call)]
#![warn(unreachable_pub)]
#![warn(clippy::all)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::checked_conversions)]
#![warn(clippy::cognitive_complexity)]
#![deny(clippy::debug_assert_with_mut_call)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::expl_impl_clone_on_copy)]
#![deny(clippy::fallible_impl_from)]
#![deny(clippy::implicit_clone)]
#![deny(clippy::large_stack_arrays)]
#![warn(clippy::manual_ok_or)]
#![deny(clippy::missing_docs_in_private_items)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![deny(clippy::print_stderr)]
#![deny(clippy::print_stdout)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
#![allow(clippy::result_large_err)] // temporary workaround for arti#587
#![allow(clippy::needless_raw_string_hashes)] // complained-about code is fine, often best
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

use std::path::Path;

/// A lock-file for which we hold the lock.
///
/// So long as this object exists, we hold the lock on this file.
/// When it is dropped, we will release the lock.
///
/// # Semantics
///
///  * Only one `LockFileGuard` can exist at one time
///    for any particular `path`.
///  * This applies across all tasks and threads in all programs;
///    other acquisitions of the lock in the same process are prevented.
///  * This applies across even separate machines, if `path` is on a shared filesystem.
///
/// # Restrictions
///
///  * **`path` must only be deleted (or renamed) via the APIs in this module**
///  * This restriction applies to all programs on the computer,
///    so for example automatic file cleaning with `find` and `rm` is forbidden.
///  * Cross-filesystem locking is broken on Linux before 2.6.12.
#[derive(Debug)]
pub struct LockFileGuard {
    /// A locked [`fslock::LockFile`].
    ///
    /// This `LockFile` instance will remain locked for as long as this
    /// LockFileGuard exists.
    _locked: fslock::LockFile,
}

impl LockFileGuard {
    /// Try to construct a new [`LockFileGuard`] representing a lock we hold on
    /// the file `path`.
    ///
    /// Blocks until we can get the lock.
    pub fn lock<P>(path: P) -> Result<Self, fslock::Error>
    where
        P: AsRef<Path>,
    {
        let path = path.as_ref();
        loop {
            let mut lockfile = fslock::LockFile::open(path)?;
            lockfile.lock()?;

            if os::lockfile_has_path(&lockfile, path)? {
                return Ok(Self { _locked: lockfile });
            }
        }
    }

    /// Try to construct a new [`LockFileGuard`] representing a lock we hold on
    /// the file `path`.
    ///
    /// Does not block; returns Ok(None) if somebody else holds the lock.
    pub fn try_lock<P>(path: P) -> Result<Option<Self>, fslock::Error>
    where
        P: AsRef<Path>,
    {
        let path = path.as_ref();
        let mut lockfile = fslock::LockFile::open(path)?;
        if lockfile.try_lock()? && os::lockfile_has_path(&lockfile, path)? {
            return Ok(Some(Self { _locked: lockfile }));
        }
        Ok(None)
    }
}

/*

   TODO: This requires AsFd and AsHandle implementations for `LockFile`.
   See https://github.com/brunoczim/fslock/pull/15

/// Helper module for unix metadata manipulation.
#[cfg(unix)]
mod os {
    use std::{path::Path, os::unix::fs::MetadataExt as _, os::fd::AsFd, fs::File};

    /// Return true if `lf` currently exists with the given `path`, and false otherwise.
    pub(crate) fn lockfile_has_path(lf: &fslock::LockFile, path: &Path) -> std::io::Result<bool> {
        let m1 = std::fs::metadata(path)?;
        // TODO: This does an unnecessary dup().
        let f_dup = File::from(lf.as_fd().try_clone_to_owned()?);
        let m2 = f_dup.metadata()?;

        Ok(m1.ino() == m2.ino() && m1.dev() == m2.dev())
    }
}

/// Helper module for windows metadata manipulation.
#[cfg(windows)]
mod os {
    use std::{path::Path, fs::Metadata, os::windows::fs::MetadataExt as _, std::os::windows::io::AsHandle, fs::File};

    /// Return true if `lf` currently exists with the given `path`, and false otherwise.
    ///
    /// ## Limitations
    ///
    /// This function only looks at `creation_time`, which is not a perfectly
    /// reliable check.  It should instead look at `volume_serial_number` and
    /// `file_index`, but those are not yet stable in Rust.
    ///
    pub(crate) fn lockfile_has_path(lf: &fslock::LockFile, path: &Path) -> std::io::Result<bool> {
        let m1 = std::fs::metadata(path)?;
        // TODO: This does an unnecessary DuplicateHandle().
        let f_dup = File::from(lf.as_handle().try_clone_to_owned()?);
        let m2 = f_dup.metadata()?;

       Ok(m1.creation_time() == m2.creation_time())
    }
}
*/

/// Helper module for defective metadata implementation
mod os {
    use std::path::Path;

    /// TODO: Remove this; it does nothing good.
    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn lockfile_has_path(_lf: &fslock::LockFile, _path: &Path) -> std::io::Result<bool> {
        Ok(true)
    }
}
