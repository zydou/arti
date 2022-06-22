//! Filesystem + JSON implementation of StateMgr.

mod clean;

use crate::{load_error, store_error};
use crate::{Error, LockStatus, Result, StateMgr};
use fs_mistrust::CheckedDir;
use serde::{de::DeserializeOwned, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tracing::{info, warn};

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
/// 1) This manager only accepts objects that can be serialized as
/// JSON documents.  Some types (like maps with non-string keys) can't
/// be serialized as JSON.
///
/// 2) This manager normalizes keys to an fs-safe format before saving
/// data with them.  This keeps you from accidentally creating or
/// reading files elsewhere in the filesystem, but it doesn't prevent
/// collisions when two keys collapse to the same fs-safe filename.
/// Therefore, you should probably only use ascii keys that are
/// fs-safe on all systems.
///
/// NEVER use user-controlled or remote-controlled data for your keys.
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
        let statepath = path.join("state");

        let statepath = mistrust
            .verifier()
            .check_content()
            .make_secure_dir(statepath)?;
        let lockpath = statepath.join("state.lock")?;

        let lockfile = Mutex::new(fslock::LockFile::open(&lockpath)?);

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
            info!("Deleting obsolete file {}", fname.display());
            if let Err(e) = std::fs::remove_file(&fname) {
                warn!("Unable to delete {}: {}", fname.display(), e);
            }
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
        } else if lockfile.try_lock()? {
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
            lockfile.unlock()?;
        }
        Ok(())
    }
    fn load<D>(&self, key: &str) -> Result<Option<D>>
    where
        D: DeserializeOwned,
    {
        let rel_fname = self.rel_filename(key);

        let string = match self.inner.statepath.read_to_string(rel_fname) {
            Ok(string) => string,
            Err(fs_mistrust::Error::NotFound(_)) => return Ok(None),
            Err(fs_mistrust::Error::Io { err, .. }) => return Err(Error::IoError(err)),
            Err(e) => return Err(e.into()),
        };

        Ok(Some(serde_json::from_str(&string).map_err(load_error)?))
    }

    fn store<S>(&self, key: &str, val: &S) -> Result<()>
    where
        S: Serialize,
    {
        if !self.can_store() {
            return Err(Error::NoLock);
        }

        let rel_fname = self.rel_filename(key);

        let output = serde_json::to_string_pretty(val).map_err(store_error)?;

        self.inner.statepath.write_and_replace(rel_fname, output)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]
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

        assert!(matches!(store.store("xyz", &stuff4), Err(Error::NoLock)));

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
        std::fs::write(&fname, "we no longer use toml files.").unwrap();
        std::fs::write(&fname2, "{}").unwrap();

        // Make the store directory read-only and make sure that we can't delete from it.
        std::fs::set_permissions(&statedir, ro_dir)?;
        store.clean(SystemTime::now() + Duration::from_secs(365 * 86400));
        let lst: Vec<_> = statedir.read_dir().unwrap().collect();
        if lst.len() == 2 {
            // We must be root.  Don't do any more tests here.
            return Ok(());
        }
        assert_eq!(lst.len(), 3); // We can't remove the file, but we didn't freak out. Great!
                                  // Try failing to read a mode-0 file.
        std::fs::set_permissions(&statedir, rw_dir)?;
        std::fs::set_permissions(&fname2, unusable)?;

        let h: Result<Option<HashMap<String, u32>>> = store.load("quoll");
        assert!(h.is_err());
        assert!(matches!(h, Err(Error::IoError(_))));

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
}
