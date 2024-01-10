//! State helper utility
//!
//! All the methods in this module perform appropriate mistrust checks.
//!
//! All the methods arrange to ensure suitably-finegrained exclusive access.
//! "Read-only" or "shared" mode is not supported.
//!
//! ### Differences from `tor_persist::StorageHandle`
//!
//!  * Explicit provision is made for multiple instances of a single facility.
//!    For example, multiple hidden services,
//!    each with their own state, and own lock.
//!
//!  * Locking is mandatory, rather than optional -
//!    there is no "shared" mode.
//!    
//!  * Locked state is represented in the Rust type system.
//!    
//!  * We don't use traits to support multiple implementations.
//!    Platform support would be done in the future with `#[cfg]`.
//!    Testing is done by temporary directories (as currently with `tor_persist`).
//!
//!  * The serde-based `StorageHandle` requires `&mut` for writing.
//!    This ensures proper serialisation of 1. read-modify-write cycles
//!    and 2. use of the temporary file.
//!    Or to put it another way, we model `StorageHandle`
//!    as *containing* a `T` without interior mutability.
//!
//!  * There's a way to get a raw directory for filesystem operations
//!    (currently, will be used for IPT replay logs).
//!
//! ### Implied filesystem structure
//!
//! ```text
//! STATE_DIR/
//! STATE_DIR/KIND_INSTANCE/
//! STATE_DIR/KIND_INSTANCE/lock
//! STATE_DIR/KIND_INSTANCE/SLUG.json
//! STATE_DIR/KIND_INSTANCE/SLUG.new
//! STATE_DIR/KIND_INSTANCE/SLUG/
//!
//! eg
//!
//! STATE_DIR/hss_allium-cepa.lock
//! STATE_DIR/hss_allium-cepa/ipts.json
//! STATE_DIR/hss_allium-cepa/iptpub.json
//! STATE_DIR/hss_allium-cepa/iptreplay/
//! STATE_DIR/hss_allium-cepa/iptreplay/9aa9517e6901c280a550911d3a3c679630403db1c622eedefbdf1715297f795f.bin
//! ```
//!
//! (The lockfile is outside the instance directory to facilitate
//! concurrency-correct deletion.)
//!
//! ### Platforms without a filesystem
//!
//! The implementation and (in places) the documentation
//! is in terms of filesystems.
//! But, everything except `InstanceStateHandle::raw_subdir`
//! is abstract enough to implement some other way.
//!
//! If we wish to support such platforms, the approach is:
//!
//!  * Decide on an approach for `StorageHandle`
//!    and for each caller of `raw_subdir`.
//!
//!  * Figure out how the startup code will look.
//!    (Currently everything is in terms of `fs_mistrust` and filesystems.)
//!
//!  * Provide a version of this module with a compatible API
//!    in terms of whatever underlying facilities are available.
//!    Use `#[cfg]` to select it.
//!    Don't implement `raw_subdir`.
//!
//!  * Call sites using `raw_subdir` will no longer compile.
//!    Use `#[cfg]` at call sites to replace the `raw_subdir`
//!    with whatever is appropriate for the platform.

#![allow(unused_variables, dead_code)]
#![allow(unreachable_pub)] // TODO this module will hopefully move to tor-persist and be pub

use std::cell::Cell;
use std::fmt::Display;
use std::iter;
use std::marker::PhantomData;
use std::path::Path;
use std::time::Duration;

use derive_more::Into;
use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;
use void::Void;

use fs_mistrust::{CheckedDir, Mistrust};

/// TODO HSS remove
type Todo = Void;

use std::result::Result as StdResult;

/// [`Result`](StdResult) throwing a [`state_dir::Error`](enum@Error)
pub type Result<T> = StdResult<T, Error>;

/// The whole program's state directory
///
/// Representation of `[storage] state_dir` and `permissions`
/// from the Arti configuration.
///
/// This type does not embody any subpaths relating to
/// any particular facility within Arti.
///
/// Constructing a `StateDirectory` may involve filesystem permissions checks,
/// so ideally it would be created once per process for performance reasons.
///
/// Existence of a `StateDirectory` also does not imply exclusive access.
///
/// ### Use for caches
///
/// In principle this type and the methods and subtypes available
/// would be suitable for cache data as well as state data.
///
/// However the locking scheme does not tolerate random removal of files.
/// And cache directories are sometimes configured to point to locations
/// with OS-supplied automatic file cleaning.
/// That would not be correct,
/// since the automatic file cleaner might remove an in-use lockfile,
/// effectively unlocking the instance state
/// even while a process exists that thinks it still has the lock.
#[allow(clippy::missing_docs_in_private_items)] // TODO HSS remove
pub struct StateDirectory {
    path: Todo,
    mistrust: Todo,
}

/// The identity of an instance, within its kind
///
/// Instance identities are from a restricted character set,
/// since they are reified in the filesystem.
/// This applies to kinds and slugs, too.
///
/// When kind and instance identities, and slugs,
/// are passed into the methods in this module,
/// they are taken as a `Display`, for convenience,
/// and the syntax will be checked before use.
///
/// TODO HSS define the character set.
#[derive(Into)]
pub struct InstanceIdString(String);

/// Is an instance still relevant?
///
/// Returned by the `filter` callback to
/// [`expire_instances`](StateDirectory::expire_instances).
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[allow(clippy::exhaustive_enums)] // this is a boolean
pub enum Liveness {
    /// This instance is not interesting and could be expired, if it's been long enough
    Unused,
    /// This instance is still wanted
    Live,
}

impl StateDirectory {
    /// Create a new `StateDirectory` from a directory and mistrust configuration
    #[allow(clippy::needless_pass_by_value)] // TODO HSS remove
    fn new(state_dir: impl AsRef<Path>, mistrust: Mistrust) -> Result<Self> { todo!() }

    /// Acquires (creates and locks) a storage for an instance
    ///
    /// Ensures the existence and suitability of a subdirectory named `kind_identity`,
    /// and locks it for exclusive access.
    ///
    /// `kind` and `identity` have syntactic restrictions -
    /// see [`InstanceIdString`].
    fn acquire_instance(
        &self,
        kind: &dyn Display,
        identity: &dyn Display,
    ) -> Result<InstanceStateHandle> {
        todo!()
    }

    /// List the instances of a particular kind
    ///
    /// Returns the instance identities.
    ///
    /// (The implementation lists subdirectories named `kind_*`.)
    ///
    /// Concurrency:
    /// An instance which is not being removed or created will be
    /// listed (or not) according to whether it's present.
    /// But, in the presence of concurrent calls to `acquire_instance` and `delete`
    /// on different instances,
    /// is not guaranteed to provide a snapshot:
    /// serialisation is not guaranteed across different instances.
    fn list_instances(&self, kind: &dyn Display) -> impl Iterator<Item = Result<InstanceIdString>> {
        let _: &Void = &self.path;
        iter::empty()
    }

    /// Delete instances according to selections made by the caller
    ///
    /// Each instance is considered in two stages.
    ///
    /// Firstly, it is passed to `filter`.
    /// If `filter` returns `Live`,
    /// further consideration is skipped and the instance is retained.
    ///
    /// Secondly, the instance is Acquired
    /// (that is, its lock is taken)
    /// and the resulting `InstanceStateHandle` passed to `dispose`.
    /// `dispose` may choose to call `instance.delete()`.
    ///
    /// Concurrency:
    /// In the presence of multiple concurrent calls to `acquire_instance` and `delete`:
    /// `filter` may be called for an instance which is being created or deleted
    /// by another task.
    /// `dispose` will be properly serialised with other activities on the same instance,
    /// as implied by it receiving an `InstanceStateHandle`.
    ///
    /// Instances which have been acquired
    /// or modified more recently than `retain_unused_for`
    /// will not be offered to `dispose`.
    fn expire_instances(
        &self,
        kind: &str,
        // counting from last time make_instance was called,
        // or storage_handle.store, or raw_subdir
        retain_unused_for: Duration,
        filter: &mut dyn FnMut(String) -> Result<Liveness>,
        dispose: &mut dyn FnMut(InstanceStateHandle) -> Result<()>,
    ) -> Result<()> {
        todo!()
    }

    /// Tries to peek at something written by `StorageHandle::store`
    ///
    /// It is guaranteed that this will return either the `T` that was stored,
    /// or `None` if `store` was never called,
    /// or `StorageHandle::delete` was called
    ///
    /// So the operation is atomic, but there is no further synchronisation.
    //
    // Not sure if we need this, but it's logically permissible
    fn instance_peek_storage<T>(
        &self,
        kind: &dyn Display,
        identity: &dyn Display,
        slug: &dyn Display,
    ) -> Result<Option<T>> {
        todo!()
    }
}

/// State or cache directory for an instance of a facility
///
/// Implies exclusive access:
/// there is only one `InstanceStateHandle` at a time,
/// across any number of processes, tasks, and threads,
/// for the same instance.
///
/// But this type is `Clone` and the exclusive access is shared across all clones.
///
/// Users of the `InstanceStateHandle` must ensure that functions like
/// `storage_handle` and `raw_directory` are only called once with each `slug`.
/// (Typically, the slug is fixed, so this is straightforward.)
/// Violating this rule does not result in memory-unsafety,
/// but might result in incorrect operation due to concurrent filesystem access,
/// including possible data loss and corruption.
#[allow(clippy::missing_docs_in_private_items)] // TODO HSS remove
pub struct InstanceStateHandle {
    lock: Todo,
}

impl InstanceStateHandle {
    /// Obtain a [`StorageHandle`], usable for storing/retrieving a `T`
    ///
    /// `slug` has syntactic restrictions - see [`InstanceIdString`].
    fn storage_handle<T>(slug: &dyn Display) -> StorageHandle<T> { todo!() }

    /// Obtain a raw filesystem subdirectory, within the directory for this instance
    ///
    /// This API is unsuitable platforms without a filesystem accessible via `std::fs`.
    /// May therefore only be used within Arti for features
    /// where we're happy to not to support such platforms (eg WASM without WASI)
    /// without substantial further work.
    ///
    /// `slug` has syntactic restrictions - see [`InstanceIdString`].
    fn raw_subdir(slug: &dyn Display) -> CheckedDir { todo!() }

    /// Unconditionally delete this instance directory
    ///
    /// For expiry, use `StateDirectory::expire`,
    /// and then call this in the `dispose` method.
    ///
    /// Will return a `BadAPIUsage` if other clones of this `InstanceStateHandle` exist.
    fn delete(self) -> Result<()> {
        // use Arc::into_inner on the lock object,
        // to make sure we're actually the only surviving InstanceStateHandle
        todo!()
    }
}

/// A place in the state or cache directory, where we can load/store a serialisable type
///
/// Implies exclusive access.
///
/// Rust mutability-xor-sharing rules enforce proper synchronisation,
/// unless multiple `StorageHandle`s are created
/// using the same [`InstanceStateHandle`] and `slug`.
pub struct StorageHandle<T> {
    /// We're not sync, and we can load and store a `T`
    marker: PhantomData<Cell<T>>,
    /// Clone of the InstanceStateHandle's lock
    lock: Todo,
}

// Like tor_persist, but writing needs `&mut`
#[allow(clippy::missing_docs_in_private_items)] // TODO HSS remove
impl<T: Serialize + DeserializeOwned> StorageHandle<T> {
    pub fn delete(&mut self) -> Result<()> {
        todo!()
    }
    pub fn store(&mut self, v: &T) -> Result<()> {
        todo!()
    }
    pub fn load(&self) -> Result<Option<T>> {
        todo!()
    }
}

/// Error accessing persistent state
#[derive(Error, Clone, Debug)]
pub enum Error {
    // will gain variants for:
    //  mistrust error
    //  io::error
    //  serde error
    //  bug
    //
    // will contain information such as the fs path or bad parameters
}
