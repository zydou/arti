//! Filesystem + JSON implementation of StateMgr.

mod clean;

use crate::err::{Action, ErrorSource, Resource};
use crate::load_store;
use crate::{Error, LockStatus, Result, StateMgr};
use fs_mistrust::anon_home::PathExt as _;
use fs_mistrust::CheckedDir;
use serde::{de::DeserializeOwned, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tor_error::warn_report;
use tracing::info;

/// Implementation of StateMgr that stores state as JSON files on disk.
///
/// # Locking
///
/// This manager uses a lock file to determine whether it's allowed to
/// write to the disk.  Only one process should write to the disk at
/// a time, though any number may read from the disk.
///
/// By default, every `FsStateMgr` starts out unlocked, and only able
/// to read.  Use [`FsStateMgr::try_lock()`] to lock it.
///
/// # Limitations
///
/// 1. This manager only accepts objects that can be serialized as
///    JSON documents.  Some types (like maps with non-string keys) can't
///    be serialized as JSON.
///
/// 2. This manager normalizes keys to an fs-safe format before saving
///    data with them.  This keeps you from accidentally creating or
///    reading files elsewhere in the filesystem, but it doesn't prevent
///    collisions when two keys collapse to the same fs-safe filename.
///    Therefore, you should probably only use ascii keys that are
///    fs-safe on all systems.
///
/// NEVER use user-controlled or remote-controlled data for your keys.
#[cfg_attr(docsrs, doc(cfg(not(target_arch = "wasm32"))))]
#[derive(Clone, Debug)]
pub struct FsStateMgr {
    /// Inner reference-counted object.
    inner: Arc<FsStateMgrInner>,
}

/// Inner reference-counted object, used by `FsStateMgr`.
#[derive(Debug)]
struct FsStateMgrInner {
    /// Directory in which we store state files.
    statepath: CheckedDir,
    /// Lockfile to achieve exclusive access to state files.
    lockfile: Mutex<fslock::LockFile>,
}

impl FsStateMgr {
    /// Construct a new `FsStateMgr` to store data in `path`.
    ///
    /// This function will try to create `path` if it does not already
    /// exist.
    ///
    /// All files must be "private" according to the rules specified in `mistrust`.
    pub fn from_path_and_mistrust<P: AsRef<Path>>(
        path: P,
        mistrust: &fs_mistrust::Mistrust,
    ) -> Result<Self> {
        let path = path.as_ref();
        let dir = path.join("state");

        let statepath = mistrust
            .verifier()
            .check_content()
            .make_secure_dir(&dir)
            .map_err(|e| {
                Error::new(
                    e,
                    Action::Initializing,
                    Resource::Directory { dir: dir.clone() },
                )
            })?;
        let lockpath = statepath.join("state.lock").map_err(|e| {
            Error::new(
                e,
                Action::Initializing,
                Resource::Directory { dir: dir.clone() },
            )
        })?;

        let lockfile = Mutex::new(fslock::LockFile::open(&lockpath).map_err(|e| {
            Error::new(
                e,
                Action::Initializing,
                Resource::File {
                    container: dir,
                    file: "state.lock".into(),
                },
            )
        })?);

        Ok(FsStateMgr {
            inner: Arc::new(FsStateMgrInner {
                statepath,
                lockfile,
            }),
        })
    }
    /// Like from_path_and_mistrust, but do not verify permissions.
    ///
    /// Testing only.
    #[cfg(test)]
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::from_path_and_mistrust(
            path,
            &fs_mistrust::Mistrust::new_dangerously_trust_everyone(),
        )
    }

    /// Return a filename, relative to the top of this directory, to use for
    /// storing data with `key`.
    ///
    /// See "Limitations" section on [`FsStateMgr`] for caveats.
    fn rel_filename(&self, key: &str) -> PathBuf {
        (sanitize_filename::sanitize(key) + ".json").into()
    }
    /// Return the top-level directory for this storage manager.
    ///
    /// (This is the same directory passed to
    /// [`FsStateMgr::from_path_and_mistrust`].)
    pub fn path(&self) -> &Path {
        self.inner
            .statepath
            .as_path()
            .parent()
            .expect("No parent directory even after path.join?")
    }

    /// Remove old and/or obsolete items from this storage manager.
    ///
    /// Requires that we hold the lock.
    fn clean(&self, now: SystemTime) {
        for fname in clean::files_to_delete(self.inner.statepath.as_path(), now) {
            info!("Deleting obsolete file {}", fname.anonymize_home());
            if let Err(e) = std::fs::remove_file(&fname) {
                warn_report!(e, "Unable to delete {}", fname.anonymize_home(),);
            }
        }
    }

    /// Operate using a `load_store::Target` for `key` in this state dir
    fn with_load_store_target<T, F>(&self, key: &str, action: Action, f: F) -> Result<T>
    where
        F: FnOnce(load_store::Target<'_>) -> std::result::Result<T, ErrorSource>,
    {
        let rel_fname = self.rel_filename(key);
        f(load_store::Target {
            dir: &self.inner.statepath,
            rel_fname: &rel_fname,
        })
        .map_err(|source| Error::new(source, action, self.err_resource(key)))
    }

    /// Return a `Resource` object representing the file with a given key.
    fn err_resource(&self, key: &str) -> Resource {
        Resource::File {
            container: self.path().to_path_buf(),
            file: PathBuf::from("state").join(self.rel_filename(key)),
        }
    }

    /// Return a `Resource` object representing our lock file.
    fn err_resource_lock(&self) -> Resource {
        Resource::File {
            container: self.path().to_path_buf(),
            file: "state.lock".into(),
        }
    }
}

impl StateMgr for FsStateMgr {
    fn can_store(&self) -> bool {
        let lockfile = self
            .inner
            .lockfile
            .lock()
            .expect("Poisoned lock on state lockfile");
        lockfile.owns_lock()
    }
    fn try_lock(&self) -> Result<LockStatus> {
        let mut lockfile = self
            .inner
            .lockfile
            .lock()
            .expect("Poisoned lock on state lockfile");
        if lockfile.owns_lock() {
            Ok(LockStatus::AlreadyHeld)
        } else if lockfile
            .try_lock()
            .map_err(|e| Error::new(e, Action::Locking, self.err_resource_lock()))?
        {
            self.clean(SystemTime::now());
            Ok(LockStatus::NewlyAcquired)
        } else {
            Ok(LockStatus::NoLock)
        }
    }
    fn unlock(&self) -> Result<()> {
        let mut lockfile = self
            .inner
            .lockfile
            .lock()
            .expect("Poisoned lock on state lockfile");
        if lockfile.owns_lock() {
            lockfile
                .unlock()
                .map_err(|e| Error::new(e, Action::Unlocking, self.err_resource_lock()))?;
        }
        Ok(())
    }
    fn load<D>(&self, key: &str) -> Result<Option<D>>
    where
        D: DeserializeOwned,
    {
        self.with_load_store_target(key, Action::Loading, |t| t.load())
    }

    fn store<S>(&self, key: &str, val: &S) -> Result<()>
    where
        S: Serialize,
    {
        if !self.can_store() {
            return Err(Error::new(
                ErrorSource::NoLock,
                Action::Storing,
                Resource::Manager,
            ));
        }

        self.with_load_store_target(key, Action::Storing, |t| t.store(val))
    }
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
    use std::{collections::HashMap, time::Duration};

    #[test]
    fn simple() -> Result<()> {
        let dir = tempfile::TempDir::new().unwrap();
        let store = FsStateMgr::from_path(dir.path())?;

        assert_eq!(store.try_lock()?, LockStatus::NewlyAcquired);
        let stuff: HashMap<_, _> = vec![("hello".to_string(), "world".to_string())]
            .into_iter()
            .collect();
        store.store("xyz", &stuff)?;

        let stuff2: Option<HashMap<String, String>> = store.load("xyz")?;
        let nothing: Option<HashMap<String, String>> = store.load("abc")?;

        assert_eq!(Some(stuff), stuff2);
        assert!(nothing.is_none());

        assert_eq!(dir.path(), store.path());

        drop(store); // Do this to release the fs lock.
        let store = FsStateMgr::from_path(dir.path())?;
        let stuff3: Option<HashMap<String, String>> = store.load("xyz")?;
        assert_eq!(stuff2, stuff3);

        let stuff4: HashMap<_, _> = vec![("greetings".to_string(), "humans".to_string())]
            .into_iter()
            .collect();

        assert!(matches!(
            store.store("xyz", &stuff4).unwrap_err().source(),
            ErrorSource::NoLock
        ));

        assert_eq!(store.try_lock()?, LockStatus::NewlyAcquired);
        store.store("xyz", &stuff4)?;

        let stuff5: Option<HashMap<String, String>> = store.load("xyz")?;
        assert_eq!(Some(stuff4), stuff5);

        Ok(())
    }

    #[test]
    fn clean_successful() -> Result<()> {
        let dir = tempfile::TempDir::new().unwrap();
        let statedir = dir.path().join("state");
        let store = FsStateMgr::from_path(dir.path())?;

        assert_eq!(store.try_lock()?, LockStatus::NewlyAcquired);
        let fname = statedir.join("numbat.toml");
        let fname2 = statedir.join("quoll.json");
        std::fs::write(fname, "we no longer use toml files.").unwrap();
        std::fs::write(fname2, "{}").unwrap();

        let count = statedir.read_dir().unwrap().count();
        assert_eq!(count, 3); // two files, one lock.

        // Now we can make sure that "clean" actually removes the right file.
        store.clean(SystemTime::now() + Duration::from_secs(365 * 86400));
        let lst: Vec<_> = statedir.read_dir().unwrap().collect();
        assert_eq!(lst.len(), 2); // one file, one lock.
        assert!(lst
            .iter()
            .any(|ent| ent.as_ref().unwrap().file_name() == "quoll.json"));

        Ok(())
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn permissions() -> Result<()> {
        use std::fs::Permissions;
        use std::os::unix::fs::PermissionsExt;

        let ro_dir = Permissions::from_mode(0o500);
        let rw_dir = Permissions::from_mode(0o700);
        let unusable = Permissions::from_mode(0o000);

        let dir = tempfile::TempDir::new().unwrap();
        let statedir = dir.path().join("state");
        let store = FsStateMgr::from_path(dir.path())?;

        assert_eq!(store.try_lock()?, LockStatus::NewlyAcquired);
        let fname = statedir.join("numbat.toml");
        let fname2 = statedir.join("quoll.json");
        std::fs::write(fname, "we no longer use toml files.").unwrap();
        std::fs::write(&fname2, "{}").unwrap();

        // Make the store directory read-only and make sure that we can't delete from it.
        std::fs::set_permissions(&statedir, ro_dir).unwrap();
        store.clean(SystemTime::now() + Duration::from_secs(365 * 86400));
        let lst: Vec<_> = statedir.read_dir().unwrap().collect();
        if lst.len() == 2 {
            // We must be root.  Don't do any more tests here.
            return Ok(());
        }
        assert_eq!(lst.len(), 3); // We can't remove the file, but we didn't freak out. Great!
                                  // Try failing to read a mode-0 file.
        std::fs::set_permissions(&statedir, rw_dir).unwrap();
        std::fs::set_permissions(fname2, unusable).unwrap();

        let h: Result<Option<HashMap<String, u32>>> = store.load("quoll");
        assert!(h.is_err());
        assert!(matches!(h.unwrap_err().source(), ErrorSource::IoError(_)));

        Ok(())
    }

    #[test]
    fn locking() {
        let dir = tempfile::TempDir::new().unwrap();
        let store1 = FsStateMgr::from_path(dir.path()).unwrap();
        let store2 = FsStateMgr::from_path(dir.path()).unwrap();

        // Nobody has the lock; store1 will take it.
        assert_eq!(store1.try_lock().unwrap(), LockStatus::NewlyAcquired);
        assert_eq!(store1.try_lock().unwrap(), LockStatus::AlreadyHeld);
        assert!(store1.can_store());

        // store1 has the lock; store2 will try to get it and fail.
        assert!(!store2.can_store());
        assert_eq!(store2.try_lock().unwrap(), LockStatus::NoLock);
        assert!(!store2.can_store());

        // Store 1 will drop the lock.
        store1.unlock().unwrap();
        assert!(!store1.can_store());
        assert!(!store2.can_store());

        // Now store2 can get the lock.
        assert_eq!(store2.try_lock().unwrap(), LockStatus::NewlyAcquired);
        assert!(store2.can_store());
        assert!(!store1.can_store());
    }

    #[test]
    fn errors() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = FsStateMgr::from_path(dir.path()).unwrap();

        // file not found is not an error.
        let nonesuch: Result<Option<String>> = store.load("Hello");
        assert!(matches!(nonesuch, Ok(None)));

        // bad utf8 is an error.
        let file: PathBuf = ["state", "Hello.json"].iter().collect();
        std::fs::write(dir.path().join(&file), b"hello world \x00\xff").unwrap();
        let bad_utf8: Result<Option<String>> = store.load("Hello");
        assert!(bad_utf8.is_err());
        assert_eq!(
            bad_utf8.unwrap_err().to_string(),
            format!(
                "IO error while loading persistent data on {} in {}",
                file.to_string_lossy(),
                dir.path().anonymize_home(),
            ),
        );
    }
}
