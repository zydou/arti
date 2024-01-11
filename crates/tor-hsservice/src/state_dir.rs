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
//!  * Locking (via filesystem locks) is mandatory, rather than optional -
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
use std::fmt;
use std::iter;
use std::marker::PhantomData;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use derive_more::{AsRef, Into};
use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;
use void::Void;

use fs_mistrust::{CheckedDir, Mistrust};
use tor_error::Bug;

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
/// This type is passed to each facility's constructor;
/// the facility implements [`InstanceIdentity`]
/// and calls [`acquire_instance`](StateDirectory::acquire_instance).
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

/// An instance of a facility that wants to save persistent state (caller-provided impl)
///
/// Each value of a type implementing `InstanceIdentity`
/// designates a specific instance of a specific facility.
///
/// For example, `HsNickname` implements `state_dir::InstanceIdentity`.
///
/// The kind and identity are strings from a restricted character set:
/// Only lowercase ASCII alphanumerics, `_` , and `+`, are permitted,
/// and the first character must be an ASCII alphanumeric.
///
/// (The output from `write_identity` will be converted to an [`InstanceIdString`].)
pub trait InstanceIdentity {
    /// Return the kind.  For example `hss` for a Tor Hidden Service.
    ///
    /// This must return a fixed string,
    /// since usually all instances represented the same Rust type
    /// are also the same kind.
    //
    // This precludes dynamically chosen instance kind identifiers.
    // If we ever want that, we'd need an InstanceKind trait that is implemented
    // not for actual instances, but for values representing a kind.
    fn kind() -> &'static str;

    /// Obtain identity
    ///
    /// The instance identity distinguishes different instances of the same kind.
    ///
    /// For example, for a Tor Hidden Service the identity is the nickname.
    //
    // Throws Bug rather than fmt::Error so that in case of problems we can dump a stack trace.
    fn write_identity(&self, f: &mut fmt::Formatter) -> StdResult<(), Bug>;
}

/// For a facility to be expired using [`purge_instances`](StateDirectory::purge_instances) (caller-provided impl)
///
/// A filter which decides which instances to delete,
/// and deletes them if appropriate.
///
/// See [`purge_instances`](StateDirectory::purge_instances) for full documentation.
pub trait InstancePurgeHandler {
    /// Can we tell by its name that this instance is still live ?
    fn name_filter(&mut self, identity: &InstanceIdString) -> Result<Liveness>;

    /// How long should we retain an unused instance for ?
    ///
    /// Many implementations won't need to use `identity`.
    /// To pass every possibly-unused instance
    /// through to `dispose`, return `Duration::ZERO`.
    fn retain_unused_for(&mut self, identity: &InstanceIdString) -> Result<Duration>;

    /// Decide whether to keep this instance
    ///
    /// When it has made its decision, `dispose` should
    /// either call [`delete`](InstanceStateHandle::delete),
    /// or simply drop `handle`.
    ///
    /// Called only after `name_filter` returned [`Liveness::PossiblyUnused`]
    /// and only if the instance has not been acquired or modified recently.
    ///
    /// `info` includes the instance name and other useful information
    /// such as the last modification time.
    fn dispose(&mut self, info: &InstancePurgeInfo, handle: InstanceStateHandle) -> Result<()>;
}

/// Information about an instance, passed to [`InstancePurgeHandler::dispose`]
#[derive(amplify::Getters)]
#[derive(AsRef)]
pub struct InstancePurgeInfo<'i> {
    /// The instance's identity string
    #[as_ref]
    identity: &'i InstanceIdString,

    /// When the instance state was last updated, according to the filesystem timestamps
    ///
    /// See `[InstanceStateHandle::purge_instances]`
    /// for details of what kinds of events count as modifications.
    last_modified: SystemTime,
}

/// String identifying an instance, within its kind
///
/// Instance identities are from a restricted character set.
/// See [`InstanceIdentity`].
#[derive(Into, derive_more::Display)]
pub struct InstanceIdString(String);

impl InstanceIdString {
    /// Obtain this `InstanceIdString` as a `&str`
    pub fn as_str(&self) -> &str {
        self.as_ref()
    }
}
impl AsRef<str> for InstanceIdString {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for InstanceIdString {
    // TODO this should probably be a general InvalidSlug from a lower-level Slug type
    type Error = Bug;
    fn try_from(s: String) -> StdResult<Self, Self::Error> {
        todo!()
    }
}

/// Types which can be used as a `slug`
///
/// "Slugs" are used to distinguish different pieces of state within an instance.
/// Typically, each call site that needs to provide an `impl Slug`
/// will provide a fixed `&'static str`.
///
/// Slugs have the same character set restrictions as kinds and instance identities;
/// see [`InstanceIdentity`].
/// (This is checked at runtime by the `state_dir` implementation.)
///
/// Slugs may not be the same as the reserved device filenames on Windows,
/// (eg, `con`, `lpr`).
/// (This is not checked by the `state_dir` implementation,
/// but violation of this rule will result in code that doesn't work at all on Windows.)
///
/// It is important that slugs are distinct within an instance.
/// Specifically,
/// each slug provided to a method on the same [`InstanceStateHandle`]
/// (or a clone of it)
/// must be different.
/// Violating this rule does not result in memory-unsafety,
/// but might result in incorrect operation due to concurrent filesystem access,
/// including possible data loss and corruption.
/// (Typically, the slug is fixed, and the [`StorageHandle`]s are usually
/// obtained during instance construction, so ensuring this is straightforward.)
// We could implement a runtime check for this by retaining a table of in-use slugs,
// possibly only with `cfg(debug_assertions)`.  However I think this isn't worth the code:
// it would involve an Arc<Mutex<SlugsInUseTable>> in InstanceStateHnndle and StorageHandle,
// and Drop impls to remove unused entries (and `raw_subdir` would have imprecise checking
// unless it returned a Drop newtype around CheckedDir).
pub trait Slug: ToString {}

impl<T: ToString + ?Sized> Slug for T {}

/// Is an instance still relevant?
///
/// Returned by [`InstancePurgeHandler::name_filter`].
///
/// See [`StateDirectory::purge_instances`] for details of the semantics.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[allow(clippy::exhaustive_enums)] // this is a boolean
pub enum Liveness {
    /// This instance is not known to be interesting
    ///
    /// It could be perhaps expired, if it's been long enough
    PossiblyUnused,
    /// This instance is still wanted
    Live,
}

impl StateDirectory {
    /// Create a new `StateDirectory` from a directory and mistrust configuration
    #[allow(clippy::needless_pass_by_value)] // TODO HSS remove
    pub fn new(state_dir: impl AsRef<Path>, mistrust: Mistrust) -> Result<Self> { todo!() }

    /// Acquires (creates and locks) a storage for an instance
    ///
    /// Ensures the existence and suitability of a subdirectory named `kind_identity`,
    /// and locks it for exclusive access.
    ///
    /// `kind` and `identity` have syntactic restrictions -
    /// see [`InstanceIdString`].
    pub fn acquire_instance<I: InstanceIdentity>(
        &self,
        identity: &I,
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
    #[allow(clippy::extra_unused_type_parameters)] // TODO HSS remove if possible
    pub fn list_instances<I: InstanceIdentity>(
        &self
    ) -> impl Iterator<Item = Result<InstanceIdString>> {
        let _: &Void = &self.path;
        iter::empty()
    }

    /// Delete instances according to selections made by the caller
    ///
    /// Each instance is considered in three stages.
    ///
    /// Firstly, it is passed to [`name_filter`](InstancePurgeHandler::name_filter).
    /// If `name_filter` returns `Live`,
    /// further consideration is skipped and the instance is retained.
    ///
    /// Secondly, the last time the instance was written to is calculated,
    // This must be done with the lock held, for correctness
    // but the lock must be acquired in a way that doesn't itself update the modification time.
    // On Unix this is straightforward because opening for write doesn't update the mtime.
    // If this is hard on another platform, we'll need a separate stamp file updated
    // by an explicit Acquire operation.
    // We should have a test to check that this all works as expected.
    /// and compared to the return value from
    /// [`retain_unused_for`](InstancePurgeHandler::retain_unused_for).
    /// Again, this might mean ensure the instance is retained.
    ///
    /// Thirdly, the resulting `InstanceStateHandle` is passed to
    /// [`dispose`](InstancePurgeHandler::dispose).
    /// `dispose` may choose to call `handle.delete()`,
    /// or simply drop the handle.
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
    ///
    /// The expiry time is reset by calls to `acquire_instance`,
    /// `StorageHandle::store` and `InstanceStateHandle::raw_subdir`;
    /// it *may* be reset by calls to `StorageHandle::delete`.
    pub fn purge_instances<I: InstancePurgeHandler>(
        &self,
        filter: &mut I,
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
    pub fn instance_peek_storage<I: InstanceIdentity, T>(
        &self,
        identity: &I,
        slug: &(impl Slug + ?Sized),
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
/// Users of the `InstanceStateHandle` must ensure that functions like
/// `storage_handle` and `raw_directory` are only called once with each `slug`.
/// (Typically, the slug is fixed, so this is straightforward.)
/// See [`Slug`] for more details.
#[allow(clippy::missing_docs_in_private_items)] // TODO HSS remove
pub struct InstanceStateHandle {
    flock_guard: Arc<Todo>,
}

impl InstanceStateHandle {
    /// Obtain a [`StorageHandle`], usable for storing/retrieving a `T`
    ///
    /// `slug` has syntactic restrictions - see [`InstanceIdString`].
    pub fn storage_handle<T>(&self, slug: &(impl Slug + ?Sized)) -> Result<StorageHandle<T>> { todo!() }

    /// Obtain a raw filesystem subdirectory, within the directory for this instance
    ///
    /// This API is unsuitable platforms without a filesystem accessible via `std::fs`.
    /// May therefore only be used within Arti for features
    /// where we're happy to not to support such platforms (eg WASM without WASI)
    /// without substantial further work.
    ///
    /// `slug` has syntactic restrictions - see [`InstanceIdString`].
    pub fn raw_subdir(&self, slug: &(impl Slug + ?Sized)) -> Result<CheckedDir> { todo!() }

    /// Unconditionally delete this instance directory
    ///
    /// For expiry, use `StateDirectory::purge_instances`,
    /// and then call this in the `dispose` method.
    ///
    /// Will return a `BadAPIUsage` if other clones of this `InstanceStateHandle` exist.
    pub fn delete(self) -> Result<()> {
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
    flock_guard: Arc<Todo>,
}

// Like tor_persist, but writing needs `&mut`
#[allow(missing_docs)] // TODO HSS remove
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
#[non_exhaustive]
pub enum Error {
    // will gain variants for:
    //  mistrust error
    //  io::error
    //  serde error
    //  bug
    //
    // will contain information such as the fs path or bad parameters
}
