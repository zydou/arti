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
//! STATE_DIR/KIND/INSTANCE/
//! STATE_DIR/KIND/INSTANCE/lock
//! STATE_DIR/KIND/INSTANCE/KEY.json
//! STATE_DIR/KIND/INSTANCE/KEY.new
//! STATE_DIR/KIND/INSTANCE/KEY/
//!
//! eg
//!
//! STATE_DIR/hss/allium-cepa.lock
//! STATE_DIR/hss/allium-cepa/ipts.json
//! STATE_DIR/hss/allium-cepa/iptpub.json
//! STATE_DIR/hss/allium-cepa/iptreplay/
//! STATE_DIR/hss/allium-cepa/iptreplay/9aa9517e6901c280a550911d3a3c679630403db1c622eedefbdf1715297f795f.bin
//! ```
//!
//! (The lockfile is outside the instance directory to facilitate
//! concurrency-correct deletion.)
//!
// Specifically:
//
// The situation where there is only the lockfile, is an out-of-course but legal one.
// Likewise, a lockfile plus a *partially* deleted instance state, is also legal.
// Having an existing directory without associated lockfile is forbidden,
// but if it should occur we handle it properly.
//
//! ### Comprehensive example
//!
//! ```
//! use std::{collections::HashSet, fmt, time::{Duration, SystemTime}};
//! use tor_error::{into_internal, Bug};
//! use tor_persist::slug::SlugRef;
//! use tor_persist::state_dir;
//! use state_dir::{InstanceIdentity, InstancePurgeHandler};
//! use state_dir::{InstancePurgeInfo, InstanceStateHandle, StateDirectory, StorageHandle};
//! #
//! # // fake up some things; we do this rather than using real ones
//! # // since this example will move, with the module, to a lower level crate.
//! # struct OnionService { }
//! # #[derive(derive_more::Display)] struct HsNickname(String);
//! # type Error = anyhow::Error;
//! # mod ipt_mgr { pub mod persist {
//! #     #[derive(serde::Serialize, serde::Deserialize)] pub struct StateRecord {}
//! # } }
//!
//! impl InstanceIdentity for HsNickname {
//!     fn kind() -> &'static str { "hss" }
//!     fn write_identity(&self, f: &mut fmt::Formatter) -> fmt::Result {
//!         write!(f, "{self}")
//!     }
//! }
//!
//! impl OnionService {
//!     fn new(
//!         nick: HsNickname,
//!         state_dir: &StateDirectory,
//!     ) -> Result<Self, Error> {
//!         let instance_state = state_dir.acquire_instance(&nick)?;
//!         let replay_log_dir = instance_state.raw_subdir("ipt_replay")?;
//!         let ipts_storage: StorageHandle<ipt_mgr::persist::StateRecord> =
//!             instance_state.storage_handle("ipts")?;
//!         // ..
//! #       Ok(OnionService { })
//!     }
//! }
//!
//! struct PurgeHandler<'h>(&'h HashSet<&'h str>, Duration);
//! impl InstancePurgeHandler for PurgeHandler<'_> {
//!     fn kind(&self) -> &'static str {
//!         <HsNickname as InstanceIdentity>::kind()
//!     }
//!     fn name_filter(&mut self, id: &SlugRef) -> state_dir::Result<state_dir::Liveness> {
//!         Ok(if self.0.contains(id.as_str()) {
//!             state_dir::Liveness::Live
//!         } else {
//!             state_dir::Liveness::PossiblyUnused
//!         })
//!     }
//!     fn age_filter(&mut self, id: &SlugRef, age: Duration)
//!              -> state_dir::Result<state_dir::Liveness>
//!     {
//!         Ok(if age > self.1 {
//!             state_dir::Liveness::PossiblyUnused
//!         } else {
//!             state_dir::Liveness::Live
//!         })
//!     }
//!     fn dispose(&mut self, _info: &InstancePurgeInfo, handle: InstanceStateHandle)
//!                -> state_dir::Result<()> {
//!         // here might be a good place to delete keys too
//!         handle.purge()
//!     }
//! }
//! pub fn expire_hidden_services(
//!     state_dir: &StateDirectory,
//!     currently_configured_nicks: &HashSet<&str>,
//!     retain_for: Duration,
//! ) -> Result<(), Error> {
//!     state_dir.purge_instances(
//!         SystemTime::now(),
//!         &mut PurgeHandler(currently_configured_nicks, retain_for),
//!     )?;
//!     Ok(())
//! }
//! ```
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

#![allow(unused_variables, unused_imports, dead_code)] // TODO HSS remove

use std::cell::Cell;
use std::collections::HashSet;
use std::fmt::{self, Display};
use std::fs::{self, DirEntry};
use std::io;
use std::iter;
use std::marker::PhantomData;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use derive_adhoc::{define_derive_adhoc, Adhoc};
use derive_more::{AsRef, Deref, Into};
use itertools::{chain, Itertools};
use serde::{de::DeserializeOwned, Serialize};
use void::Void;

use fs_mistrust::{CheckedDir, Mistrust};
use tor_error::ErrorReport as _;
use tor_error::{bad_api_usage, into_bad_api_usage, Bug};
use tracing::trace;

use crate::err::{Action, ErrorSource, Resource};
use crate::load_store;
use crate::slug::{self, BadSlug, Slug, SlugRef, TryIntoSlug};
pub use crate::Error;

define_derive_adhoc! {
    ContainsInstanceStateGuard =

    impl<$tgens> ContainsInstanceStateGuard for $ttype where $twheres {
        fn raw_lock_guard(&self) -> Arc<LockFileGuard> {
            self.flock_guard.clone()
        }
    }
}

/// Re-export of the lock guard type, as obtained via [`ContainsInstanceStateGuard`]
pub use fslock_guard::LockFileGuard;

/// TODO HSS remove
type Todo = Void;

use std::result::Result as StdResult;

use std::path::MAIN_SEPARATOR as PATH_SEPARATOR;

/// [`Result`](StdResult) throwing a [`state_dir::Error`](Error)
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
#[derive(Debug, Clone)]
pub struct StateDirectory {
    /// The actual directory, including mistrust config
    dir: CheckedDir,
}

/// An instance of a facility that wants to save persistent state (caller-provided impl)
///
/// Each value of a type implementing `InstanceIdentity`
/// designates a specific instance of a specific facility.
///
/// For example, `HsNickname` implements `state_dir::InstanceIdentity`.
///
/// The kind and identity are [`slug`]s.
pub trait InstanceIdentity {
    /// Return the kind.  For example `hss` for a Tor Hidden Service.
    ///
    /// This must return a fixed string,
    /// since usually all instances represented the same Rust type
    /// are also the same kind.
    ///
    /// The returned value must be valid as a [`slug`].
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
    ///
    /// The generated string must be valid as a [`slug`].
    /// If it is not, the functions in this module will throw `Bug` errors.
    /// (Returning `fmt::Error` will cause a panic, as is usual with the fmt API.)
    fn write_identity(&self, f: &mut fmt::Formatter) -> fmt::Result;
}

/// For a facility to be expired using [`purge_instances`](StateDirectory::purge_instances) (caller-provided impl)
///
/// A filter which decides which instances to delete,
/// and deletes them if appropriate.
///
/// See [`purge_instances`](StateDirectory::purge_instances) for full documentation.
pub trait InstancePurgeHandler {
    /// What kind to iterate over
    fn kind(&self) -> &'static str;

    /// Can we tell by its name that this instance is still live ?
    fn name_filter(&mut self, identity: &SlugRef) -> Result<Liveness>;

    /// Can we tell by recent modification that this instance is still live ?
    ///
    /// Many implementations won't need to use the `identity` parameter.
    ///
    /// ### Concurrency
    ///
    /// The `age` passed to this callback might
    /// sometimes not be the most recent modification time of the instance.
    /// But. before calling `dispose`, `purge_instances` will call this
    /// function at least once with a fully up-to-date modification time.
    fn age_filter(&mut self, identity: &SlugRef, age: Duration) -> Result<Liveness>;

    /// Decide whether to keep this instance
    ///
    /// When it has made its decision, `dispose` should
    /// either call [`delete`](InstanceStateHandle::purge),
    /// or simply drop `handle`.
    ///
    /// Called only after `name_filter` and `age_filter`
    /// both returned [`Liveness::PossiblyUnused`].
    ///
    /// `info` includes the instance name and other useful information
    /// such as the last modification time.
    ///
    /// Note that although the existence of `handle` implies
    /// there can be no other `InstanceStateHandle`s for this instance,
    /// the last modification time of this instance has *not* been updated,
    /// as it would be by [`acquire_instance`](StateDirectory::acquire_instance).
    fn dispose(&mut self, info: &InstancePurgeInfo, handle: InstanceStateHandle) -> Result<()>;
}

/// Information about an instance, passed to [`InstancePurgeHandler::dispose`]
#[derive(Debug, Clone, amplify::Getters, AsRef)]
pub struct InstancePurgeInfo<'i> {
    /// The instance's identity string
    #[as_ref]
    identity: &'i SlugRef,

    /// When the instance state was last updated, according to the filesystem timestamps
    ///
    /// See `[InstanceStateHandle::purge_instances]`
    /// for details of what kinds of events count as modifications.
    last_modified: SystemTime,
}

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

/// Objects that co-own a lock on an instance
///
/// Each type implementing this trait mutually excludes independently-acquired
/// [`InstanceStateHandle`]s, and anything derived from them
/// (including, therefore, `ContainsInstanceStateGuard` implementors
/// with independent provenance.)
pub trait ContainsInstanceStateGuard {
    /// Obtain a raw clone of the underlying filesystem lock
    ///
    /// This lock (and clones of it) will mutually exclude
    /// re-acquisition of the same instance.
    fn raw_lock_guard(&self) -> Arc<LockFileGuard>;
}

/// Instance identity string formatter, type-erased
type InstanceIdWriter<'i> = &'i dyn Fn(&mut fmt::Formatter) -> fmt::Result;

impl StateDirectory {
    /// Create a new `StateDirectory` from a directory and mistrust configuration
    pub fn new(state_dir: impl AsRef<Path>, mistrust: &Mistrust) -> Result<Self> {
        /// Implementation, taking non-generic path
        fn inner(path: &Path, mistrust: &Mistrust) -> Result<StateDirectory> {
            let resource = || Resource::Directory {
                dir: path.to_owned(),
            };
            let handle_err = |source| Error::new(source, Action::Initializing, resource());

            let dir = mistrust
                .verifier()
                .make_secure_dir(path)
                .map_err(handle_err)?;

            Ok(StateDirectory { dir })
        }
        inner(state_dir.as_ref(), mistrust)
    }

    /// Acquires (creates and locks) a storage for an instance
    ///
    /// Ensures the existence and suitability of a subdirectory named `kind/identity`,
    /// and locks it for exclusive access.
    pub fn acquire_instance<I: InstanceIdentity>(
        &self,
        identity: &I,
    ) -> Result<InstanceStateHandle> {
        /// Implementation, taking non-generic values for identity
        fn inner(
            sd: &StateDirectory,
            kind_str: &'static str,
            id_writer: InstanceIdWriter,
        ) -> Result<InstanceStateHandle> {
            sd.with_instance_path_pieces(kind_str, id_writer, |kind, id, resource| {
                let handle_err =
                    |action, source: ErrorSource| Error::new(source, action, resource());

                // Obtain (creating if necessary) a subdir for a Checked
                let make_secure_directory = |parent: &CheckedDir, subdir| {
                    let resource = || Resource::Directory {
                        dir: parent.as_path().join(subdir),
                    };
                    parent
                        .make_secure_directory(subdir)
                        .map_err(|source| Error::new(source, Action::Initializing, resource()))
                };

                // ---- obtain the lock ----

                let kind_dir = make_secure_directory(&sd.dir, kind)?;

                let lock_path = kind_dir
                    .join(format!("{id}.lock"))
                    .map_err(|source| handle_err(Action::Initializing, source.into()))?;

                let flock_guard = match LockFileGuard::try_lock(&lock_path) {
                    Ok(Some(y)) => {
                        trace!("locked {lock_path:?}");
                        y.into()
                    }
                    Err(source) => {
                        trace!("locking {lock_path:?}, error {}", source.report());
                        return Err(handle_err(Action::Locking, source.into()));
                    }
                    Ok(None) => {
                        trace!("locking {lock_path:?}, in use",);
                        return Err(handle_err(Action::Locking, ErrorSource::AlreadyLocked));
                    }
                };

                // ---- we have the lock, calculate the directory (creating it if need be) ----

                let dir = make_secure_directory(&kind_dir, id)?;

                touch_instance_dir(&dir)?;

                Ok(InstanceStateHandle { dir, flock_guard })
            })
        }

        inner(self, I::kind(), &|f| identity.write_identity(f))
    }

    /// Given a kind and id, obtain pieces of its path and call a "doing work" callback
    ///
    /// This function factors out common functionality needed by
    /// [`StateDirectory::acquire_instance`] and [StateDirectory::instance_peek_storage`],
    /// particularly relating to instance kind and id, and errors.
    ///
    /// `kind` and `id` are from an `InstanceIdentity`.
    fn with_instance_path_pieces<T>(
        self: &StateDirectory,
        kind_str: &'static str,
        id_writer: InstanceIdWriter,
        // fn call(kind: &SlugRef, id: &SlugRef, resource_for_error: &impl Fn) -> _
        call: impl FnOnce(&SlugRef, &SlugRef, &dyn Fn() -> Resource) -> Result<T>,
    ) -> Result<T> {
        /// Struct that impls `Display` for formatting an instance id
        //
        // This exists because we want implementors of InstanceIdentity to be able to
        // use write! to format their identity string.
        struct InstanceIdDisplay<'i>(InstanceIdWriter<'i>);

        impl Display for InstanceIdDisplay<'_> {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                (self.0)(f)
            }
        }
        let id_string = InstanceIdDisplay(id_writer).to_string();

        // Both we and caller use this for our error reporting
        let resource = || Resource::InstanceState {
            state_dir: self.dir.as_path().to_owned(),
            kind: kind_str.to_string(),
            identity: id_string.clone(),
        };

        let handle_bad_slug = |source| Error::new(source, Action::Initializing, resource());

        if kind_str.is_empty() {
            return Err(handle_bad_slug(BadSlug::EmptySlugNotAllowed));
        }
        let kind = SlugRef::new(kind_str).map_err(handle_bad_slug)?;
        let id = SlugRef::new(&id_string).map_err(handle_bad_slug)?;

        call(kind, id, &resource)
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
    ///
    /// It *is* guaranteed to list each instance only once.
    pub fn list_instances<I: InstanceIdentity>(&self) -> impl Iterator<Item = Result<Slug>> {
        self.list_instances_inner(I::kind())
    }

    /// List the instances of a kind, where the kind is supplied as a value
    ///
    /// Used by `list_instances` and `purge_instances`.
    ///
    /// *Includes* instances that exists only as a stale lockfile.
    #[allow(clippy::blocks_in_conditions)] // TODO #1176 this wants to be global
    #[allow(clippy::redundant_closure_call)] // false positive, re handle_err
    fn list_instances_inner(&self, kind: &'static str) -> impl Iterator<Item = Result<Slug>> {
        // We collect the output into these
        let mut out = HashSet::new();
        let mut errs = Vec::new();

        // Error handling

        let resource = || Resource::InstanceState {
            state_dir: self.dir.as_path().into(),
            kind: kind.into(),
            identity: "*".into(),
        };

        /// `fn handle_err!()(source: impl Into<ErrorSource>) -> Error`
        //
        // (Generic, so can't be a closure.  Uses local bindings, so can't be a fn.)
        macro_rules! handle_err { { } => {
            |source| Error::new(source, Action::Enumerating, resource())
        } }

        // Obtain an iterator of Result<DirEntry>
        match (|| {
            let kind = SlugRef::new(kind).map_err(handle_err!())?;
            self.dir.read_directory(kind).map_err(handle_err!())
        })() {
            Err(e) => errs.push(e),
            Ok(ents) => {
                for ent in ents {
                    match ent {
                        Err(e) => errs.push(handle_err!()(e)),
                        Ok(ent) => {
                            // Actually handle a directory entry!

                            let Some(id) = (|| {
                                // look for either ID or ID.lock
                                let id = ent.file_name();
                                let id = id.to_str()?; // ignore non-UTF-8
                                let id = id.strip_suffix(".lock").unwrap_or(id);
                                let id = SlugRef::new(id).ok()?; // ignore other things
                                Some(id.to_owned())
                            })() else {
                                continue;
                            };

                            out.insert(id);
                        }
                    }
                }
            }
        }

        chain!(errs.into_iter().map(Err), out.into_iter().map(Ok),)
    }

    /// Delete instances according to selections made by the caller
    ///
    /// Each instance is considered in three stages.
    ///
    /// Firstly, it is passed to [`name_filter`](InstancePurgeHandler::name_filter).
    /// If `name_filter` returns `Live`,
    /// further consideration is skipped and the instance is retained.
    ///
    /// Secondly, the last time the instance was written to is determined,
    // This must be done with the lock held, for correctness
    // but the lock must be acquired in a way that doesn't itself update the modification time.
    // On Unix this is straightforward because opening for write doesn't update the mtime.
    // If this is hard on another platform, we'll need a separate stamp file updated
    // by an explicit Acquire operation.
    // We should have a test to check that this all works as expected. XXXX
    /// and passed to
    /// [`age_filter`](InstancePurgeHandler::age_filter).
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
    /// The expiry time is reset by calls to `acquire_instance`,
    /// `StorageHandle::store` and `InstanceStateHandle::raw_subdir`;
    /// it *may* be reset by calls to `StorageHandle::delete`.
    ///
    /// Instances that are currently locked by another task will not be purged,
    /// but the expiry time is *not* reset by *unlocking* an instance
    /// (dropping the last clone of an `InstanceStateHandle`).
    ///
    /// ### Sequencing of `InstancePurgeHandler` callbacks
    ///
    /// Each instance will be processed
    /// (and callbacks made for it) at most once;
    /// and calls for different instances will not be interleaved.
    ///
    /// During the processing of a particular instance
    /// The callbacks will be made in order,
    /// progressing monotonically through the methods in the order listed.
    /// But `name_filter` and `age_filter` might each be called
    /// more than once for the same instance.
    // We don't actually call name_filter more than once.
    ///
    /// Between each stage,
    /// the purge implementation may discover that the instance
    /// ought not to be processed further.
    /// So returning `Liveness::PossiblyUnused` from a filter does not
    /// guarantee that the next callback will be made.
    pub fn purge_instances(
        &self,
        now: SystemTime,
        filter: &mut (dyn InstancePurgeHandler + '_),
    ) -> Result<()> {
        let kind = filter.kind();

        for id in self.list_instances_inner(kind) {
            let id = id?;
            self.with_instance_path_pieces(kind, &|f| write!(f, "{id}"), |kind, id, resource| {
                self.maybe_purge_instance(now, kind, id, resource, filter)
            })?;
        }

        Ok(())
    }

    /// Consider whether to purge an instance
    ///
    /// Performs all the necessary steps, including liveness checks,
    /// passing an InstanceStateHandle to filter.dispose,
    /// and deleting stale lockfiles without associated state.
    fn maybe_purge_instance(
        &self,
        now: SystemTime,
        kind: &SlugRef,
        id: &SlugRef,
        resource: &dyn Fn() -> Resource,
        filter: &mut (dyn InstancePurgeHandler + '_),
    ) -> Result<()> {
        /// If `$l` is `Liveness::Live`, returns early with `Ok(())`.
        macro_rules! check_liveness { { $l:expr } => {
            match $l {
                Liveness::Live => return Ok(()),
                Liveness::PossiblyUnused => {},
            }
        } }

        check_liveness!(filter.name_filter(id)?);

        let dir_path = self.dir.as_path().join(kind).join(id);

        // Checks whether it should be kept due to being recently modified.
        // None::<SystemTime> means the instance directory is ENOENT
        // (which must mean that the instance exists only as a stale lockfile).
        let mut age_check = || -> Result<(Liveness, Option<SystemTime>)> {
            let handle_io_error = |source| Error::new(source, Action::Enumerating, resource());

            // 1. stat the instance dir
            let md = match fs::metadata(&dir_path) {
                // If instance dir is ENOENT, treat as old (maybe there was just a lockfile)
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    return Ok((Liveness::PossiblyUnused, None))
                }
                other => other.map_err(handle_io_error)?,
            };
            let mtime = md.modified().map_err(handle_io_error)?;

            // 2. calculate the age
            let age = now.duration_since(mtime).unwrap_or(Duration::ZERO);

            // 3. do the age check
            let liveness = filter.age_filter(id, age)?;

            Ok((liveness, Some(mtime)))
        };

        // preliminary check, without locking yet
        check_liveness!(age_check()?.0);

        // ok we're probably doing to pass it to dispose (for possible deletion)

        let lock_path = dir_path.with_extension("lock");
        let flock_guard = match LockFileGuard::try_lock(&lock_path) {
            Ok(Some(y)) => {
                trace!("locked {lock_path:?} (for purge)");
                y
            }
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                // We couldn't open the lockfile due to ENOENT
                // (Presumably) a containing directory is gone, so we don't need to do anything.
                trace!("locking {lock_path:?} (for purge), not found");
                return Ok(());
            }
            Ok(None) => {
                // Someone else has it locked.  Skip purging it.
                trace!("locking {lock_path:?} (for purge), in use");
                return Ok(());
            }
            Err(source) => {
                trace!(
                    "locking {lock_path:?} (for purge), error {}",
                    source.report()
                );
                return Err(Error::new(source, Action::Locking, resource()));
            }
        };

        // recheck to see if anyone has updated it
        let (age, mtime) = age_check()?;
        check_liveness!(age);

        // We have locked it and the filters say to maybe purge it.

        match mtime {
            None => {
                // And it doesn't even exist!  All we have is a leftover lockfile.  Delete it.
                let lockfile_rsrc = || Resource::File {
                    container: lock_path.parent().expect("no /!").into(),
                    file: lock_path.file_name().expect("no /!").into(),
                };
                flock_guard
                    .delete_lock_file(&lock_path)
                    .map_err(|source| Error::new(source, Action::Deleting, lockfile_rsrc()))?;
            }
            Some(last_modified) => {
                // Construct a state handle.
                let dir = self
                    .dir
                    .make_secure_directory(format!("{kind}/{id}"))
                    .map_err(|source| Error::new(source, Action::Enumerating, resource()))?;
                let flock_guard = Arc::new(flock_guard);

                filter.dispose(
                    &InstancePurgeInfo {
                        identity: id,
                        last_modified,
                    },
                    InstanceStateHandle { dir, flock_guard },
                )?;
            }
        }

        Ok(())
    }

    /// Tries to peek at something written by [`StorageHandle::store`]
    ///
    /// It is guaranteed that this will return either the `T` that was stored,
    /// or `None` if `store` was never called,
    /// or `StorageHandle::delete` was called
    ///
    /// So the operation is atomic, but there is no further synchronisation.
    //
    // Not sure if we need this, but it's logically permissible
    pub fn instance_peek_storage<I: InstanceIdentity, T: DeserializeOwned>(
        &self,
        identity: &I,
        key: &(impl TryIntoSlug + ?Sized),
    ) -> Result<Option<T>> {
        self.with_instance_path_pieces(
            I::kind(),
            &|f| identity.write_identity(f),
            // This closure is generic over T, so with_instance_path_pieces will be too;
            // this isn't desirable (code bloat) but avoiding it would involves some contortions.
            |kind_slug: &SlugRef, id_slug: &SlugRef, _resource| {
                // Throwing this error here will give a slightly wrong Error for this Bug
                // (because with_instance_path_pieces has its own notion of Action & Resource)
                // but that seems OK.
                let key_slug = key.try_into_slug()?;

                let rel_fname = format!(
                    "{}{PATH_SEPARATOR}{}{PATH_SEPARATOR}{}.json",
                    kind_slug, id_slug, key_slug,
                );

                let target = load_store::Target {
                    dir: &self.dir,
                    rel_fname: rel_fname.as_ref(),
                };

                target
                    .load()
                    // This Resource::File isn't consistent with those from StorageHandle:
                    // StorageHandle's `container` is the instance directory;
                    // here `container` is the top-level `state_dir`,
                    // and `file` is `KIND+INSTANCE/STORAGE.json".
                    .map_err(|source| {
                        Error::new(
                            source,
                            Action::Loading,
                            Resource::File {
                                container: self.dir.as_path().to_owned(),
                                file: rel_fname.into(),
                            },
                        )
                    })
            },
        )
    }
}

/// State or cache directory for an instance of a facility
///
/// Implies exclusive access:
/// there is only one `InstanceStateHandle` at a time,
/// across any number of processes, tasks, and threads,
/// for the same instance.
///
/// # Key uniqueness and syntactic restrictions
///
/// Methods on `InstanceStateHandle` typically take a [`TryIntoSlug`].
///
/// **It is important that keys are distinct within an instance.**
///
/// Specifically:
/// each key provided to a method on the same [`InstanceStateHandle`]
/// (or a clone of it)
/// must be different.
/// Violating this rule does not result in memory-unsafety,
/// but might result in incorrect operation due to concurrent filesystem access,
/// including possible data loss and corruption.
/// (Typically, the key is fixed, and the [`StorageHandle`]s are usually
/// obtained during instance construction, so ensuring this is straightforward.)
///
/// There are also syntactic restrictions on keys.  See [slug].
// We could implement a runtime check for this by retaining a table of in-use keys,
// possibly only with `cfg(debug_assertions)`.  However I think this isn't worth the code:
// it would involve an Arc<Mutex<SlugsInUseTable>> in InstanceStateHnndle and StorageHandle,
// and Drop impls to remove unused entries (and `raw_subdir` would have imprecise checking
// unless it returned a Drop newtype around CheckedDir).
#[derive(Debug, Clone, Adhoc)]
#[derive_adhoc(ContainsInstanceStateGuard)]
pub struct InstanceStateHandle {
    /// The directory
    dir: CheckedDir,
    /// Lock guard
    flock_guard: Arc<LockFileGuard>,
}

impl InstanceStateHandle {
    /// Obtain a [`StorageHandle`], usable for storing/retrieving a `T`
    ///
    /// [`key` has syntactic and uniqueness restrictions.](InstanceStateHandle#key-uniqueness-and-syntactic-restrictions)
    pub fn storage_handle<T>(&self, key: &(impl TryIntoSlug + ?Sized)) -> Result<StorageHandle<T>> {
        /// Implementation, not generic over `slug` and `T`
        fn inner(
            ih: &InstanceStateHandle,
            key: StdResult<Slug, BadSlug>,
        ) -> Result<(CheckedDir, String, Arc<LockFileGuard>)> {
            let key = key?;
            let instance_dir = ih.dir.clone();
            let leafname = format!("{key}.json");
            let flock_guard = ih.flock_guard.clone();
            Ok((instance_dir, leafname, flock_guard))
        }

        let (instance_dir, leafname, flock_guard) = inner(self, key.try_into_slug())?;
        Ok(StorageHandle {
            instance_dir,
            leafname,
            marker: PhantomData,
            flock_guard,
        })
    }

    /// Obtain a raw filesystem subdirectory, within the directory for this instance
    ///
    /// This API is unsuitable platforms without a filesystem accessible via `std::fs`.
    /// May therefore only be used within Arti for features
    /// where we're happy to not to support such platforms (eg WASM without WASI)
    /// without substantial further work.
    ///
    /// [`key` has syntactic and uniqueness restrictions.](InstanceStateHandle#key-uniqueness-and-syntactic-restrictions)
    pub fn raw_subdir(&self, key: &(impl TryIntoSlug + ?Sized)) -> Result<InstanceRawSubdir> {
        /// Implementation, not generic over `slug`
        fn inner(
            ih: &InstanceStateHandle,
            key: StdResult<Slug, BadSlug>,
        ) -> Result<InstanceRawSubdir> {
            let key = key?;
            let irs = (|| {
                trace!("ensuring/using {:?}/{:?}", ih.dir.as_path(), key.as_str());
                let dir = ih.dir.make_secure_directory(&key)?;
                let flock_guard = ih.flock_guard.clone();
                Ok::<_, ErrorSource>(InstanceRawSubdir { dir, flock_guard })
            })()
            .map_err(|source| {
                Error::new(
                    source,
                    Action::Initializing,
                    Resource::Directory {
                        dir: ih.dir.as_path().join(key),
                    },
                )
            })?;
            touch_instance_dir(&ih.dir)?;
            Ok(irs)
        }
        inner(self, key.try_into_slug())
    }

    /// Unconditionally delete this instance directory
    ///
    /// For expiry, use `StateDirectory::purge_instances`,
    /// and then call this in the `dispose` method.
    ///
    /// Will return a `BadAPIUsage` if other clones of this `InstanceStateHandle` exist.
    ///
    /// ### Deletion is *not* atomic
    ///
    /// If a deletion operation doesn't complete for any reason
    /// (maybe it was interrupted, or there was a filesystem access problem),
    /// *part* of the instance contents may remain.
    ///
    /// After such an interrupted deletion,
    /// storage items ([`StorageHandle`]) are might each independently
    /// be deleted ([`load`](StorageHandle::load) returns `None`)
    /// or retained (`Some`).
    ///
    /// Deletion of the contents of raw subdirectories
    /// ([`InstanceStateHandle::raw_subdir`])
    /// is done with `std::fs::remove_dir_all`.
    /// If deletion is interrupted, the raw subdirectory may contain partial contents.
    //
    // In principle we could provide atomic deletion, but it would lead to instances
    // that were in "limbo": they exist, but wouldn't appear in list_instances,
    // and the deletion would need to be completed next time they were acquired
    // (or during a purge_instances run).
    //
    // In practice we expect that callers will not try to use a partially-deleted instance,
    // and that if they do they will fail with a "state corrupted" error, which would be fine.
    pub fn purge(self) -> Result<()> {
        let dir = self.dir.as_path();

        (|| {
            // use Arc::into_inner on the lock object,
            // to make sure we're actually the only surviving InstanceStateHandle
            let flock_guard = Arc::into_inner(self.flock_guard).ok_or_else(|| {
                bad_api_usage!(
 "InstanceStateHandle::purge called for {:?}, but other clones of the handle exist",
                    self.dir.as_path(),
                )
            })?;

            trace!("purging {:?} (and .lock)", dir);
            fs::remove_dir_all(dir)?;
            flock_guard.delete_lock_file(
                // dir.with_extension is right because the last component of dir
                // is KIND+ID which doesn't contain `.` so no extension will be stripped
                dir.with_extension("lock"),
            )?;

            Ok::<_, ErrorSource>(())
        })()
        .map_err(|source| {
            Error::new(
                source,
                Action::Deleting,
                Resource::Directory { dir: dir.into() },
            )
        })
    }
}

/// Touch an instance the state directory, `dir`, for expiry purposes
fn touch_instance_dir(dir: &CheckedDir) -> Result<()> {
    let dir = dir.as_path();
    let resource = || Resource::Directory { dir: dir.into() };

    filetime::set_file_mtime(dir, filetime::FileTime::now())
        .map_err(|source| Error::new(source, Action::Initializing, resource()))
}

/// A place in the state or cache directory, where we can load/store a serialisable type
///
/// Implies exclusive access.
///
/// Rust mutability-xor-sharing rules enforce proper synchronisation,
/// unless multiple `StorageHandle`s are created
/// using the same [`InstanceStateHandle`] and key.
#[derive(Adhoc, Debug)] // not Clone, to enforce mutability rules (see above)
#[derive_adhoc(ContainsInstanceStateGuard)]
pub struct StorageHandle<T> {
    /// The directory and leafname
    instance_dir: CheckedDir,
    /// `KEY.json`
    leafname: String,
    /// We can load and store a `T`.
    ///
    /// Invariant in `T`.  But we're `Sync` and `Send` regardless of `T`.
    /// (From the Table of PhantomData patterns in the Nomicon.)
    marker: PhantomData<fn(T) -> T>,
    /// Clone of the InstanceStateHandle's lock
    flock_guard: Arc<LockFileGuard>,
}

// Like tor_persist, but writing needs `&mut`
impl<T: Serialize + DeserializeOwned> StorageHandle<T> {
    /// Load this persistent state
    ///
    /// `None` means the state was most recently [`delete`](StorageHandle::delete)ed
    pub fn load(&self) -> Result<Option<T>> {
        self.with_load_store_target(Action::Loading, |t| t.load())
    }
    /// Store this persistent state
    pub fn store(&mut self, v: &T) -> Result<()> {
        // The renames will cause a directory mtime update
        self.with_load_store_target(Action::Storing, |t| t.store(v))
    }
    /// Delete this persistent state
    pub fn delete(&mut self) -> Result<()> {
        // Only counts as a recent modification if this state *did* exist
        self.with_load_store_target(Action::Deleting, |t| t.delete())
    }

    /// Operate using a `load_store::Target`
    fn with_load_store_target<R, F>(&self, action: Action, f: F) -> Result<R>
    where
        F: FnOnce(load_store::Target<'_>) -> std::result::Result<R, ErrorSource>,
    {
        f(load_store::Target {
            dir: &self.instance_dir,
            rel_fname: self.leafname.as_ref(),
        })
        .map_err(self.map_err(action))
    }

    /// Helper to convert an `ErrorSource` to an `Error`, if we were performing `action`
    fn map_err(&self, action: Action) -> impl FnOnce(ErrorSource) -> Error {
        let resource = self.err_resource();
        move |source| crate::Error::new(source, action, resource)
    }

    /// Return the proper `Resource` for reporting errors
    fn err_resource(&self) -> Resource {
        Resource::File {
            // TODO ideally we would remember what proportion of instance_dir
            // came from the original state_dir, so we can put state_dir in the container
            container: self.instance_dir.as_path().to_owned(),
            file: self.leafname.clone().into(),
        }
    }
}

/// Subdirectory within an instance's state, for raw filesystem operations
///
/// Dereferences to `fs_mistrust::CheckedDir` and can be used mostly like one.
/// Obtained from [`InstanceStateHandle::raw_subdir`].
///
/// Existence of this value implies exclusive access to the instance.
///
/// If you need to manage the lock, and the directory path, separately,
/// [`raw_lock_guard`](ContainsInstanceStateGuard::raw_lock_guard)
///  will help.
#[derive(Deref, Clone, Debug, Adhoc)]
#[derive_adhoc(ContainsInstanceStateGuard)]
pub struct InstanceRawSubdir {
    /// The actual directory, as a [`fs_mistrust::CheckedDir`]
    #[deref]
    dir: CheckedDir,
    /// Clone of the InstanceStateHandle's lock
    flock_guard: Arc<LockFileGuard>,
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;
    use serde::{Deserialize, Serialize};
    use std::fmt::Display;
    use std::io;
    use test_temp_dir::test_temp_dir;
    use tor_error::{into_internal, HasKind as _};
    use tracing_test::traced_test;

    use tor_error::ErrorKind as TEK;

    struct Garlic(Slug);

    impl InstanceIdentity for Garlic {
        fn kind() -> &'static str {
            "garlic"
        }
        fn write_identity(&self, f: &mut fmt::Formatter) -> fmt::Result {
            Display::fmt(&self.0, f)
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
    struct StoredData {
        some_value: i32,
    }

    fn mk_state_dir(dir: &Path) -> StateDirectory {
        StateDirectory::new(
            dir,
            &fs_mistrust::Mistrust::new_dangerously_trust_everyone(),
        )
        .unwrap()
    }

    #[test]
    #[traced_test]
    fn test_api() {
        test_temp_dir!().used_by(|dir| {
            let sd = mk_state_dir(dir);

            let garlic = Garlic("wild".try_into_slug().unwrap());

            let acquire_instance = || sd.acquire_instance(&garlic);

            let ih = acquire_instance().unwrap();
            let inst_path = dir.join("garlic/wild");
            assert!(fs::metadata(&inst_path).unwrap().is_dir());

            assert_eq!(
                acquire_instance().unwrap_err().kind(),
                TEK::LocalResourceAlreadyInUse,
            );

            let irsd = ih.raw_subdir("raw").unwrap();
            assert!(fs::metadata(irsd.as_path()).unwrap().is_dir());
            assert_eq!(irsd.as_path(), dir.join("garlic").join("wild").join("raw"));

            let mut sh = ih.storage_handle::<StoredData>("stored_data").unwrap();
            let storage_path = dir.join("garlic/wild/stored_data.json");

            let peek = || sd.instance_peek_storage(&garlic, "stored_data");

            let expect_load = |sh: &StorageHandle<_>, expect| {
                let check_loaded = |what, loaded: Result<Option<StoredData>>| {
                    assert_eq!(loaded.unwrap().as_ref(), expect, "{what}");
                };
                check_loaded("load", sh.load());
                check_loaded("peek", peek());
            };

            expect_load(&sh, None);

            let to_store = StoredData { some_value: 42 };
            sh.store(&to_store).unwrap();
            assert!(fs::metadata(storage_path).unwrap().is_file());

            expect_load(&sh, Some(&to_store));

            sh.delete().unwrap();

            expect_load(&sh, None);

            drop(sh);
            drop(irsd);
            ih.purge().unwrap();

            assert_eq!(peek().unwrap(), None);
            assert_eq!(
                fs::metadata(&inst_path).unwrap_err().kind(),
                io::ErrorKind::NotFound
            );
        });
    }
}
