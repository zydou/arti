#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
// @@ begin lint list maintained by maint/add_warning @@
#![allow(renamed_and_removed_lints)] // @@REMOVE_WHEN(ci_arti_stable)
#![allow(unknown_lints)] // @@REMOVE_WHEN(ci_arti_nightly)
#![warn(missing_docs)]
#![warn(noop_method_call)]
#![warn(unreachable_pub)]
#![warn(clippy::all)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::checked_conversions)]
#![allow(clippy::cognitive_complexity)] // See arti#2556
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
#![deny(clippy::unchecked_time_subtraction)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::mod_module_files)]
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
#![allow(clippy::result_large_err)] // temporary workaround for arti#587
#![allow(clippy::needless_raw_string_hashes)] // complained-about code is fine, often best
#![allow(clippy::needless_lifetimes)] // See arti#1765
#![allow(mismatched_lifetime_syntaxes)] // temporary workaround for arti#2060
#![allow(clippy::collapsible_if)] // See arti#2342
#![deny(clippy::unused_async)]
#![deny(clippy::string_slice)] // See arti#2571
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

use std::{fs, path::Path};

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
    /// A [`File`](fs::File) with its exclusive lock held.
    ///
    /// This `File` instance will remain locked for as long as this
    /// LockFileGuard exists.
    locked_file: fs::File,
}

impl LockFileGuard {
    /// Try to open `path` with options suitable for using it as a lockfile,
    /// creating it as necessary.
    fn open<P>(path: P) -> Result<fs::File, std::io::Error>
    where
        P: AsRef<Path>,
    {
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
    }

    /// Try to construct a new [`LockFileGuard`] representing a lock we hold on
    /// the file `path`.
    ///
    /// Blocks until we can get the lock.
    pub fn lock<P>(path: P) -> Result<Self, std::io::Error>
    where
        P: AsRef<Path>,
    {
        let path = path.as_ref();
        loop {
            let file = Self::open(path)?;
            do_lock(&file)?;

            if os::lockfile_has_path(&file, path)? {
                return Ok(Self { locked_file: file });
            }
        }
    }

    /// Try to construct a new [`LockFileGuard`] representing a lock we hold on
    /// the file `path`.
    ///
    /// Does not block; returns Ok(None) if somebody else holds the lock.
    pub fn try_lock<P>(path: P) -> Result<Option<Self>, std::io::Error>
    where
        P: AsRef<Path>,
    {
        let path = path.as_ref();
        let file = Self::open(path)?;
        match do_try_lock(&file) {
            Ok(()) => {
                if os::lockfile_has_path(&file, path)? {
                    Ok(Some(Self { locked_file: file }))
                } else {
                    Ok(None)
                }
            }
            Err(fs::TryLockError::WouldBlock) => Ok(None),
            Err(fs::TryLockError::Error(e)) => Err(e),
        }
    }

    /// Try to delete the lock file that we hold.
    ///
    /// The provided `path` must be the same as was passed to `lock`.
    pub fn delete_lock_file<P>(self, path: P) -> Result<(), std::io::Error>
    where
        P: AsRef<Path>,
    {
        let path = path.as_ref();
        if os::lockfile_has_path(&self.locked_file, path)? {
            std::fs::remove_file(path)
        } else {
            Err(std::io::Error::other(MismatchedPathError {}))
        }
    }
}

impl Drop for LockFileGuard {
    // We pro-actively unlock the file rather than relying on drop of the File closing it.
    //
    // This is necessary on Unix because otherwise the following scenario is possible:
    //   0. The process has multiple threads
    //   1. Thread A executes fork (eg as part of spawn), and the child gets a copy of the fd,
    //   2. Thread B drops the `LockFileGuard` and calls close() on its copy of the fd
    //   3. Thread B tries to re-acquire the same lock with try_lock and fails
    //   4. Thread A closes the fd (via exec, or otherwise)
    // We want to prevent the error in step 3, which arises from a race which is possible
    // due to us violating the expected semantics of a guard (namely, that the lock is
    // synchronously released when the guard is dropped).
    #[allow(clippy::unnecessary_lazy_evaluations)] // we want to write the discarded error type
    fn drop(&mut self) {
        self.locked_file
            .unlock()
            // Ignore errors from unlock.  There shouldn't be any, but if there are we
            // don't have anything sensible we could do with them.
            .unwrap_or_else(|_: std::io::Error| ());
    }
}

/// Try to lock `f`, blocking if need be.
///
/// On non-android, this just calls [`fs::File::lock`].
#[cfg(not(target_os = "android"))]
fn do_lock(f: &fs::File) -> std::io::Result<()> {
    f.lock()
}

/// Try to lock `f`, without blocking.
///
/// On non-android, this just calls [`fs::File::try_lock`].
#[cfg(not(target_os = "android"))]
fn do_try_lock(f: &fs::File) -> Result<(), std::fs::TryLockError> {
    f.try_lock()
}

/// Try to lock `f`, blocking if need be.
///
/// On android, we need to use flock manually, since Rust (as of May 2026)
/// always returns "not implemented" for `lock()` and `try_lock()`.
///
/// See <https://github.com/rust-lang/rust/issues/148325>.
/// Apparently,
/// although there are filesystems (specifically FUSE filesystems)
/// where flock won't work, it will correctly report ENOSYS
/// on those filesystems.
//
// TODO MSRV ????: we can remove this once Rust supports file locking on Android
// at our MSRV.  As of May 2026, https://github.com/rust-lang/rust/pull/157038/
// seems like the likeliest MR for that, but it has not been merged.
#[cfg(target_os = "android")]
fn do_lock(f: &fs::File) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;

    let fd = f.as_raw_fd();
    // SAFETY: Since `f` is a file, it has a valid fd.
    let success = unsafe { libc::flock(fd, libc::LOCK_EX) } == 0;

    if success {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Try to lock `f`, without blocking.
///
/// On android, we need to use flock manually, since Rust (as of May 2026)
/// always returns "not implemented" for `lock()` and `try_lock()`.
///
/// See <https://github.com/rust-lang/rust/issues/148325>.
/// Apparently,
/// although there are filesystems (specifically FUSE filesystems)
/// where flock won't work, it will correctly report ENOSYS
/// on those filesystems.
//
// TODO MSRV ????: See 'TODO MSRV' on do_lock above.
#[cfg(target_os = "android")]
fn do_try_lock(f: &fs::File) -> Result<(), std::fs::TryLockError> {
    use std::os::fd::AsRawFd;

    let fd = f.as_raw_fd();
    // SAFETY: Since `f` is a file, it has a valid fd.
    let success = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } == 0;

    if success {
        Ok(())
    } else {
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::WouldBlock {
            Err(std::fs::TryLockError::WouldBlock)
        } else {
            Err(std::fs::TryLockError::Error(err))
        }
    }
}

/// An error that we return when the path given to `delete_lock_file` does not
/// match the file we have.
///
/// Since we wrap this in an `io::Error`, it doesn't need to be public or fancy.
#[derive(thiserror::Error, Debug, Clone)]
#[error("Called delete_lock_file with a mismatched path.")]
struct MismatchedPathError {}

/// Platform module for locking protocol on Unix.
///
/// ### Locking protocol on Unix
///
/// The lock is held by an open-file iff:
///
///  * that open-file holds an `flock` `LOCK_EX` lock; and
///  * the directory entry for `path` refers to the same file as the open-file
///
/// `path` may only refer to a plain file, or `ENOENT`.
/// If `path` refers to a file,
/// only the lockholder may cause it to no longer refer to that file.
///
/// In principle the open-file might be shared with subprocesses.
/// Even a naive program can safely and correctly inherit and hold the lock,
/// since the lockholder only needs to not close an fd.
/// However uncontrolled leaking of the fd into other processes is undesirable,
/// as it might cause delays or even deadlocks, if those processes' inheritors live too long.
/// In our Rust implementation we don't support sharing the held lock
/// with subprocesses or different process images (ie across exec);
/// we use `O_CLOEXEC`.
///
/// #### Locking algorithm
///
///  1. open the file with `O_CREAT|O_RDWR`
///  2. `flock LOCK_EX`
///  3. `fstat` the open-file and `lstat` the path
///  4. If the inode and device numbers don't match,
///     close the fd and go back to the start.
///  5. Now we hold the lock.
///
/// Proof sketch:
///
/// If we get to point 5, we see that at point 3, we had the lock.
/// No-one else could cause the conditions to become false
/// in the meantime:
/// no-one else ~~can~~ may make `path` refer to a different file
/// since they don't hold the lock.
/// And, no-one else can `flock` it since the kernel prevents
/// a conflicting lock.
/// So at step 5 we must still hold the lock.
///
/// #### Unlocking algorithm
///
///  1. Close the fd.
///  2. Now we no longer hold the lock and others can acquire it.
///
/// This drops the open-file and
/// leaves the lock available for another caller.
///
/// #### Deletion algorithm
///
///  0. The lock must already be held
///  1. `unlink` the file
///  2. close the fd
///  3. Now we no longer hold the lock and others can acquire it.
///
/// Step 1 atomically falsifies the lock-holding condition.
/// We are allowed to perform it because we hold the lock.
///
/// Concurrent lockers might open the old file,
/// which we are about to delete.
/// They will acquire their `flock` (locking step 2)
/// after we close (deletion step 2)
/// and then see that they have a stale file.
#[cfg(unix)]
mod os {
    use std::{fs::File, os::unix::fs::MetadataExt as _, path::Path};

    /// Return true if `lf` currently exists with the given `path`, and false otherwise.
    pub(crate) fn lockfile_has_path(lf: &File, path: &Path) -> std::io::Result<bool> {
        let m1 = std::fs::metadata(path)?;
        let m2 = lf.metadata()?;

        Ok(m1.ino() == m2.ino() && m1.dev() == m2.dev())
    }
}

/// Platform module for locking protocol on Windows.
///
/// The argument for correctness on Windows proceeds as for Unix, but with a
/// higher degree of uncertainty, since we are not sufficient Windows experts to
/// determine if our assumptions hold.
///
/// Here we assume as follows:
/// * When `File::open` calls `CreateFileW`, it gets a `HANDLE` to an open file.
///   As we use them, the `HANDLE` behaves
///   similarly to the "fd" in the Unix argument above,
///   and the open file behaves similarly to the "open-file".
///   * We assume that any differences that exist in their behavior do not
///     affect our correctness above.
/// * When `File::lock` calls `LockFileEx`, and it completes successfully,
///   we now have a lock on the file.
///   Only one lock can exist on a file at a time.
/// * When we compare members of `handle.metadata()` and `path.metadata()`,
///   the comparison will return equal if ~~and only if~~
///   the two files are truly the same.
///   * We rely on the property that a file cannot change its file_index while it is
///     open.
/// * Deleting the lock file will actually work, since `File::open` opened it with
///   FILE_SHARE_DELETE.  (This is the default according to the documentation
///   for `OpenOptionsExt::share_mode`.)
/// * When we delete the lock file, possibly-asynchronous ("deferred") deletion
///   definitely won't mean that the OS kernel violates our rule that no-one but the lockholder
///   is allowed to delete the file.
/// * The above is true even if someone with read
///   access to the file - eg the human user - opens it without the FILE_SHARE options.
/// * The same is true even if there is a virus scanner.
/// * The same is true even on a remote filesystem.
/// * If someone with read access to the file - eg the human user - opens it for reading
///   without FILE_SHARE options, the algorithm will still work and not fail
///   with a file sharing violation io error.
///   (Or, every program the user might use to randomly peer at files in arti's
///   state directory, including the equivalents of `grep -R` and backup programs,
///   will use suitable FILE_SHARE options.)
///   (If this assumption is false, the consequence is not data loss;
///   rather, arti would fall over.  So that would be tolerable if we don't
///   know how to do better, or if doing better is hard.)
#[cfg(windows)]
mod os {
    use std::{fs::File, mem::MaybeUninit, os::windows::io::AsRawHandle, path::Path};
    use windows_sys::Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx},
    };

    /// Use `GetFileInformationByHandleEx` to return a FILE_ID_INFO data for `f`.
    ///
    /// `GetFileInformationByHandleEx` is supported in Vista and later, so it
    /// should be fine here.  Unlike GetFileInformationByHandle, it gives
    /// 128-bit identifiers which are supposedly even more unique.
    fn get_id_info(f: &File) -> std::io::Result<FILE_ID_INFO> {
        let handle = f.as_raw_handle() as HANDLE;
        let mut info: MaybeUninit<FILE_ID_INFO> = MaybeUninit::uninit();
        let buffersize: u32 = std::mem::size_of::<FILE_ID_INFO>()
            .try_into()
            .expect("sizeof(FILE_ID_INFO) is ridiculously large");

        let info = unsafe {
            // SAFETY: Since `size` is the size of info, this will not write to
            // uninitialized memory.
            let rv = GetFileInformationByHandleEx(
                handle,
                FileIdInfo,
                info.as_mut_ptr() as _,
                buffersize,
            );

            if rv == 0 {
                return Err(std::io::Error::last_os_error());
            }

            // SAFETY: since rv was nonzero, this value is initialized.
            info.assume_init()
        };
        Ok(info)
    }

    /// Return true if `lf` currently exists with the given `path`, and false otherwise.
    pub(crate) fn lockfile_has_path(lf: &File, path: &Path) -> std::io::Result<bool> {
        let f2 = File::open(path)?;

        // Note: we would like to just use the MetadataExt methods for index and
        // volume serial number, but they are currently available only on
        // nightly: https://github.com/rust-lang/rust/issues/63010
        //
        // If they stabilize at our MSRV, _and_ the file ID is expanded to the
        // 128-bit version, we can use them here instead.

        let i1 = get_id_info(lf)?;
        let i2 = get_id_info(&f2)?;

        // This comparison is about the best we can do on Windows,
        // though there are caveats.
        //
        // See Raymond Chen's writeup at
        //   https://devblogs.microsoft.com/oldnewthing/20220128-00/?p=106201
        // and also see BurntSushi's caveats at
        //   https://github.com/BurntSushi/same-file/blob/master/src/win.rs
        Ok(i1.VolumeSerialNumber == i2.VolumeSerialNumber
            && i1.FileId.Identifier == i2.FileId.Identifier)
    }
}

/// Non-windows, non-unix implementation for lockfile_has_path.
///
/// For now, this implementation always reports an error.
/// It exists so that we can build (but not run) on wasm.
#[cfg(all(not(windows), not(unix)))]
mod os {
    use std::path::Path;

    /// Return true if `lf` currently exists with the given `path`, and false otherwise.
    pub(crate) fn lockfile_has_path(_lf: &std::fs::File, _path: &Path) -> std::io::Result<bool> {
        Err(std::io::Error::other(
            "fslock-guard does not support this operating system".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    #![allow(clippy::string_slice)] // See arti#2571
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use crate::LockFileGuard;
    use std::sync::Arc;
    use std::thread;
    use test_temp_dir::test_temp_dir;

    #[test]
    fn keep_lock_file_after_drop() {
        test_temp_dir!().used_by(|dir| {
            let file = dir.join("file");
            let flock_guard = LockFileGuard::lock(&file).unwrap();
            assert!(file.try_exists().unwrap());
            drop(flock_guard);
            assert!(file.try_exists().unwrap());
        });
    }

    #[test]
    fn delete_lock_file_if_requested() {
        test_temp_dir!().used_by(|dir| {
            let file = dir.join("file");
            let flock_guard = LockFileGuard::lock(&file).unwrap();
            assert!(file.try_exists().unwrap());
            assert!(flock_guard.delete_lock_file(&file).is_ok());
            assert!(!file.try_exists().unwrap());
        });
    }

    #[test]
    fn tight_loop() {
        let tmp = Arc::new(test_temp_dir!());

        // We make several threads in case there are any cross-thread interactions
        // that we're not aware of.  There shouldn't be.
        let threads = (0..10)
            .map(|i| {
                let tmp = tmp.clone();
                thread::spawn(move || {
                    tmp.used_by(|dir| {
                        let file = dir.join(format!("{i}"));
                        for _ in 0..1000 {
                            // Test that the lock is immediately re-requirable after drop.
                            let lock: LockFileGuard =
                                LockFileGuard::try_lock(&file).unwrap().unwrap();
                            drop(lock);
                        }
                    });
                })
            })
            .collect::<Vec<_>>();

        for t in threads {
            t.join().unwrap_or_else(|e| std::panic::resume_unwind(e));
        }
    }
}
