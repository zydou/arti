//! `tor-persist`: Persistent data storage for use with Tor.
//!
//! This crate is part of
//! [Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
//! implement [Tor](https://www.torproject.org/) in Rust.
//!
//! For now, users should construct storage objects directly with (for
//! example) [`FsStateMgr::from_path()`], but use them primarily via the
//! interfaces of the [`StateMgr`] trait.

#![deny(missing_docs)]
#![warn(noop_method_call)]
#![deny(unreachable_pub)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![deny(clippy::cast_lossless)]
#![warn(clippy::clone_on_ref_ptr)]
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
#![deny(clippy::missing_panics_doc)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]

use serde::{de::DeserializeOwned, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[cfg(target_family = "unix")]
use std::os::unix::fs::DirBuilderExt;

/// Wrapper type for Results returned from this crate.
type Result<T> = std::result::Result<T, crate::Error>;

/// An object that can manage persistent state.
///
/// State is implemented as a simple key-value store, where the values
/// are objects that can be serialized and deserialized.
///
/// # Warnings
///
/// Current implementations may place additional limits on the types
/// of objects that can be stored.  This is not a great example of OO
/// design: eventually we should probably clarify that more.
pub trait StateMgr {
    /// Try to load the object with key `key` from the store.
    ///
    /// Return None if no such object exists.
    fn load<D>(&self, key: &str) -> Result<Option<D>>
    where
        D: DeserializeOwned;
    /// Try to save `val` with key `key` in the store.
    ///
    /// Replaces any previous value associated with `key`.
    fn store<S>(&self, key: &str, val: &S) -> Result<()>
    where
        S: Serialize;
    /// Return true if this is a read-write state manager.
    ///
    /// If it returns false, then attempts to `store` will fail with
    /// [`Error::NoLock`]
    fn can_store(&self) -> bool;

    /// Try to become a read-write state manager if possible, without
    /// blocking.
    ///
    /// This function will return `Ok(true)` if we now hold the lock,
    /// and `Ok(false)` if some other process holds the lock.
    fn try_lock(&self) -> Result<bool>;
}

/// Implementation of StateMgr that stores state as Toml files on disk.
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
/// 1) This manager only accepts objects that can be serialized as Toml
/// documents.  Some types (like strings or lists) serialize to Toml
/// types that cannot appear at the head of a document.  You'll be
/// able to store them, but reloading them later on will fail.
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
    statepath: PathBuf,
    /// Lockfile to achieve exclusive access to state files.
    lockfile: Mutex<fslock::LockFile>,
}

impl FsStateMgr {
    /// Construct a new `FsStateMgr` to store data in `path`.
    ///
    /// This function will try to create `path` if it does not already
    /// exist.
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let statepath = path.join("state");
        let lockpath = path.join("state.lock");

        {
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(target_family = "unix")]
            builder.mode(0o700);
            builder.recursive(true).create(&statepath)?;
        }

        let lockfile = Mutex::new(fslock::LockFile::open_excl(&lockpath)?);

        Ok(FsStateMgr {
            inner: Arc::new(FsStateMgrInner {
                statepath,
                lockfile,
            }),
        })
    }
    /// Return a filename to use for storing data with `key`.
    ///
    /// See "Limitations" section on [`FsStateMgr`] for caveats.
    fn filename(&self, key: &str) -> PathBuf {
        self.inner
            .statepath
            .join(sanitize_filename::sanitize(key) + ".toml")
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
    fn try_lock(&self) -> Result<bool> {
        let mut lockfile = self
            .inner
            .lockfile
            .lock()
            .expect("Poisoned lock on state lockfile");
        if lockfile.owns_lock() {
            Ok(true)
        } else {
            Ok(lockfile.try_lock()?)
        }
    }
    fn load<D>(&self, key: &str) -> Result<Option<D>>
    where
        D: DeserializeOwned,
    {
        let fname = self.filename(key);

        let string = match std::fs::read_to_string(fname) {
            Ok(s) => s,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    return Ok(None);
                } else {
                    return Err(e.into());
                }
            }
        };

        Ok(Some(toml::from_str(&string)?))
    }

    fn store<S>(&self, key: &str, val: &S) -> Result<()>
    where
        S: Serialize,
    {
        if !self.can_store() {
            return Err(Error::NoLock);
        }

        let fname = self.filename(key);

        let output = toml::ser::to_string(val)?;

        let fname_tmp = fname.with_extension("tmp");
        std::fs::write(&fname_tmp, (&output).as_bytes())?;
        std::fs::rename(fname_tmp, fname)?;

        Ok(())
    }
}

/// An error type returned from a persistent state manager.
#[derive(thiserror::Error, Debug, Clone)]
#[non_exhaustive]
pub enum Error {
    /// An IO error occurred.
    #[error("IO error")]
    IoError(#[source] Arc<std::io::Error>),

    /// Tried to save without holding an exclusive lock.
    #[error("Storage not locked")]
    NoLock,

    /// Unable to serialize data as TOML.
    #[error("Toml serialization error")]
    TomlWriteError(#[from] toml::ser::Error),

    /// Unable to deserialize data from TOML
    #[error("Toml deserialization error")]
    TomlReadError(#[from] toml::de::Error),
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error::IoError(Arc::new(e))
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

        assert!(store.try_lock()?);
        let stuff: HashMap<_, _> = vec![("hello".to_string(), "world".to_string())]
            .into_iter()
            .collect();
        store.store("xyz", &stuff)?;

        let stuff2: Option<HashMap<String, String>> = store.load("xyz")?;
        let nothing: Option<HashMap<String, String>> = store.load("abc")?;

        assert_eq!(Some(stuff), stuff2);
        assert!(nothing.is_none());

        drop(store); // Do this to release the fs lock.
        let store = FsStateMgr::from_path(dir.path())?;
        let stuff3: Option<HashMap<String, String>> = store.load("xyz")?;
        assert_eq!(stuff2, stuff3);

        let stuff4: HashMap<_, _> = vec![("greetings".to_string(), "humans".to_string())]
            .into_iter()
            .collect();

        assert!(matches!(store.store("xyz", &stuff4), Err(Error::NoLock)));

        assert!(store.try_lock()?);
        store.store("xyz", &stuff4)?;

        let stuff5: Option<HashMap<String, String>> = store.load("xyz")?;
        assert_eq!(Some(stuff4), stuff5);

        Ok(())
    }
}
