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
            fs_mistrust::Mistrust::new().dangerously_trust_everyone(),
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
    fn clean(&self) {
        for fname in clean::files_to_delete(self.inner.statepath.as_path(), SystemTime::now()) {
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
            self.clean();
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
    use std::collections::HashMap;

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
}
