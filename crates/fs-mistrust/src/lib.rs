//! # `fs-mistrust`: check whether file permissions are private.
//!
//! This crate provides a set of functionality to check the permissions on files
//! and directories to ensure that they are effectively private—that is, that
//! they are only readable or writable by trusted[^1] users.
//!
//! This kind of check can protect your users' data against misconfigurations,
//! such as cases where they've accidentally made their home directory
//! world-writable, or where they're using a symlink stored in a directory owned
//! by another user.
//!
//! The checks in this crate try to guarantee that, after a path has been shown
//! to be private, no action by a _non-trusted user_ can make that path private.
//! It's still possible for a _trusted user_ to change a path after it has been
//! checked.  Because of that, you may want to use other mechanisms if you are
//! concerned about time-of-check/time-of-use issues caused by _trusted_ users
//! altering the filesystem.
//!
//! Also see the [Limitations](#limitations) section below.
//!
//! [^1]: we define "trust" here in the computer-security sense of the word: a
//!      user is "trusted" if they have the opportunity to break our security
//!      guarantees.  For example, `root` on a Unix environment is "trusted",
//!      whether you actually trust them or not.
//!
//! ## What's so hard about checking permissions?
//!
//! Suppose that we want to know whether a given path can be read or modified by
//! an untrusted user. That's trickier than it sounds:
//!
//! * Even if the permissions on the file itself are correct, we also need to
//!   check the permissions on the directory holding it, since they might allow
//!   an untrusted user to replace the file, or change its permissions.  
//! * Similarly, we need to check the permissions on the parent of _that_
//!   directory, since they might let an untrusted user replace the directory or
//!   change _its_ permissions.  (And so on!)
//! * It can be tricky to define "a trusted user".  On Unix systems, we usually
//!   say that each user is trusted by themself, and that root (UID 0) is
//!   trusted.  But it's hard to say which _groups_ are trusted: even if a given
//!   group contains only trusted users today, there's no OS-level guarantee
//!   that untrusted users won't be added to that group in the future.
//! * Symbolic links add another layer of confusion.  If there are any symlinks
//!   in the path you're checking, then you need to check permissions on the
//!   directory containing the symlink, and then the permissions on the target
//!   path, _and all of its ancestors_ too.
//! * Many programs first canonicalize the path being checked, removing all
//!   `..`s and symlinks.  That's sufficient for telling whether the _final_
//!   file can be modified by an untrusted user, but not for whether the _path_
//!   can be modified by an untrusted user.  If there is a modifiable symlink in
//!   the middle of the path, or at any stage of the path resolution, somebody
//!   who can modify that symlink can change which file the path points to.
//! * Even if you have checked a directory as being writeable only by a trusted
//!   user, that doesn't mean that the objects _in_ that directory are only
//!   writeable by trusted users.  Those objects might be symlinks to some other
//!   (more writeable) place on the file system; or they might be accessible
//!   with hard links stored elsewhere on the file system.
//!
//! Different programs try to solve this problem in different ways, often with
//! very little rationale.  This crate tries to give a reasonable implementation
//! for file privacy checking and enforcement, along with clear justifications
//! in its source for why it behaves that way.
//!
//!
//! ## What we actually do
//!
//! To make sure that every step in the file resolution process is checked, we
//! emulate that process on our own.  We inspect each component in the provided
//! path, to see whether it is modifiable by an untrusted user.  If we encounter
//! one or more symlinks, then we resolve every component of the path added by
//! those symlink, until we finally reach the target.
//!
//! In effect, we are emulating `realpath` (or `fs::canonicalize` if you
//! prefer), and looking at the permissions on every part of the filesystem we
//! touch in doing so, to see who has permissions to change our target file or
//! the process that led us to it.
//!
//! For groups, we use the following heuristic: If there is a group with the
//! same name as the current user, and the current user belongs to that group,
//! we assume that group is trusted.  Otherwise, we treat all groups as
//! untrusted.
//!
//! ## Examples
//!
//! ### Simple cases
//!
//! Make sure that a directory is only readable or writeable by us (simple
//! case):
//!
//! ```no_run
//! use fs_mistrust::Mistrust;
//! match Mistrust::new().check_directory("/home/itchy/.local/hat-swap") {
//!     Ok(()) => println!("directory is good"),
//!     Err(e) => println!("problem with our hat-swap directory: {}", e),
//! }
//! ```
//!
//! As above, but create the directory, and its parents if they do not already
//! exist.
//!
//! ```
//! use fs_mistrust::Mistrust;
//! match Mistrust::new().make_directory("/home/itchy/.local/hat-swap") {
//!     Ok(()) => println!("directory exists (or was created without trouble"),
//!     Err(e) => println!("problem with our hat-swap directory: {}", e),
//! }
//! ```
//!
//! ### Configuring a [`Mistrust`]
//!
//! You can adjust the [`Mistrust`] object to change what it permits:
//!
//! ```no_run
//! # fn example() -> fs_mistrust::Result<()> {
//! use fs_mistrust::Mistrust;
//!
//! let my_mistrust = Mistrust::builder()
//!     // Assume that our home directory and its parents are all well-configured.
//!     .ignore_prefix("/home/doze/")
//!     // Assume that a given group will only contain trusted users.
//!     .trust_group(413)
//!     .build()?;
//! # Ok(())
//! # }
//! ```
//!
//! See [`Mistrust`] for more options.
//!
//! ### Using [`Verifier`] for more fine-grained checks
//!
//! For more fine-grained control over a specific check, you can use the
//! [`Verifier`] API.  Unlike [`Mistrust`], which generally you'll want to
//! configure for several requests, the changes in [`Verifier`] generally make
//! sense only for one request at a time.
//!
//! ```no_run
//! # fn example() -> fs_mistrust::Result<()> {
//! use fs_mistrust::Mistrust;
//! let mistrust = Mistrust::new();
//!
//! // Require that an object is a regular file; allow it to be world-
//! // readable.
//! mistrust
//!     .verifier()
//!     .permit_readable()
//!     .require_file()
//!     .check("/home/trace/.path_cfg")?;
//!
//! // Make sure that a directory _and all of its contents_ are private.
//! // Create the directory if it does not exist.
//! // Return an error object containing _all_ of the problems discovered.
//! mistrust
//!     .verifier()
//!     .require_directory()
//!     .check_content()
//!     .all_errors()
//!     .make_directory("/home/trace/private_keys/");
//! # Ok(())
//! # }
//! ```
//!
//! See [`Verifier`] for more options.
//!
//! ### Using [`CheckedDir`] for safety.
//!
//! You can use the [`CheckedDir`] API to ensure not only that a directory is
//! private, but that all of your accesses to its contents continue to verify
//! and enforce _their_ permissions.
//!
//! ```
//! # fn example() -> anyhow::Result<()> {
//! use fs_mistrust::{Mistrust, CheckedDir};
//! use std::fs::{File, OpenOptions};
//! let dir = Mistrust::new()
//!     .verifier()
//!     .secure_dir("/Users/clover/riddles")?;
//!
//! // You can use the CheckedDir object to access files and directories.
//! // All of these must be relative paths within the path you used to
//! // build the CheckedDir.
//! dir.make_directory("timelines")?;
//! let file = dir.open("timelines/vault-destroyed.md",
//!     OpenOptions::new().write(true).create(true))?;
//! // (... use file...)
//! # Ok(())
//! # }
//! ```
//!
//! ## Limitations
//!
//! As noted above, this crate only checks whether a path can be changed by
//! _non-trusted_ users.  After the path has been checked, a _trusted_ user can
//! still change its permissions.  (For example, the user could make their home
//! directory world-writable.)  This crate does not try to defend against _that
//! kind_ of time-of-check/time-of-use issue.
//!
//! We currently assume a fairly vanilla Unix environment: we'll tolerate other
//! systems, but we don't actually look at the details of any of these:
//!    * Windows security (ACLs, SecurityDescriptors, etc)
//!    * SELinux capabilities
//!    * POSIX (and other) ACLs.
//!
//! We use a somewhat inaccurate heuristic when we're checking the permissions
//! of items _inside_ a target directory (using [`Verifier::check_content`] or
//! [`CheckedDir`]): we continue to forbid untrusted-writeable directories and
//! files, but we still allow readable ones, even if we insisted that the target
//! directory itself was required to to be unreadable.  This is too permissive
//! in the case of readable objects with hard links: if there is a hard link to
//! the file somewhere else, then an untrusted user can read it.  It is also too
//! restrictive in the case of writeable objects _without_ hard links: if
//! untrusted users have no path to those objects, they can't actually write
//! them.
//!
//! On Windows, we accept all file permissions and owners.
//!
//! We don't check for mount-points and the privacy of filesystem devices
//! themselves.  (For example, we don't distinguish between our local
//! administrator and the administrator of a remote filesystem. We also don't
//! distinguish between local filesystems and insecure networked filesystems.)
//!
//! This code has not been audited for correct operation in a setuid
//! environment; there are almost certainly security holes in that case.
//!
//! This is fairly new software, and hasn't been audited yet.
//!
//! All of the above issues are considered "good to fix, if practical".
//!
//! ## Acknowledgements
//!
//! The list of checks performed here was inspired by the lists from OpenSSH's
//! [safe_path], GnuPG's [check_permissions], and Tor's [check_private_dir]. All
//! errors are my own.
//!
//! [safe_path]:
//!     https://github.com/openssh/openssh-portable/blob/master/misc.c#L2177
//! [check_permissions]:
//!     https://github.com/gpg/gnupg/blob/master/g10/gpg.c#L1551
//! [check_private_dir]:
//!     https://gitlab.torproject.org/tpo/core/tor/-/blob/main/src/lib/fs/dir.c#L70

// TODO: Stuff to add before this crate is ready....
//  - Test the absolute heck out of it.

// POSSIBLY TODO:
//  - Cache information across runs.

// @@ begin lint list maintained by maint/add_warning @@
#![cfg_attr(not(ci_arti_stable), allow(renamed_and_removed_lints))]
#![cfg_attr(not(ci_arti_nightly), allow(unknown_lints))]
#![deny(missing_docs)]
#![warn(noop_method_call)]
#![deny(unreachable_pub)]
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
#![deny(clippy::missing_panics_doc)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

mod dir;
mod disable;
mod err;
mod imp;
#[cfg(all(
    target_family = "unix",
    not(target_os = "ios"),
    not(target_os = "android")
))]
mod user;

#[cfg(test)]
pub(crate) mod testing;
pub mod walk;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::{
    fs::DirBuilder,
    path::{Path, PathBuf},
    sync::Arc,
};

pub use dir::CheckedDir;
pub use disable::GLOBAL_DISABLE_VAR;
pub use err::Error;

/// A result type as returned by this crate
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(all(
    target_family = "unix",
    not(target_os = "ios"),
    not(target_os = "android")
))]
pub use user::{TrustedGroup, TrustedUser};

/// Configuration for verifying that a file or directory is really "private".
///
/// By default, we mistrust everything that we can: we assume  that every
/// directory on the filesystem is potentially misconfigured.  This object can
/// be used to change that.
///
/// Once you have a working [`Mistrust`], you can call its "`check_*`" methods
/// directly, or use [`verifier()`](Mistrust::verifier) to configure a more
/// complicated check.
///  
/// See the [crate documentation](crate) for more information.
///
/// # TODO
///
/// *  support more kinds of trust configuration, including more trusted users,
///    trusted groups, multiple trusted directories, etc?
#[derive(Debug, Clone, derive_builder::Builder, Eq, PartialEq)]
#[cfg_attr(feature = "serde", builder(derive(Debug, Serialize, Deserialize)))]
#[cfg_attr(not(feature = "serde"), builder(derive(Debug)))]
#[builder(build_fn(error = "Error"))]
#[cfg_attr(feature = "serde", builder_struct_attr(serde(default)))]
pub struct Mistrust {
    /// If the user called [`MistrustBuilder::ignore_prefix`], what did they give us?
    ///
    /// (This is stored in canonical form.)
    #[builder(
        setter(into, strip_option),
        field(build = "canonicalize_opt_prefix(&self.ignore_prefix)?")
    )]
    ignore_prefix: Option<PathBuf>,

    /// Are we configured to disable all permission and ownership tests?
    ///
    /// (This field is present in the builder only.)
    #[builder(setter(custom), field(type = "Option<bool>", build = "()"))]
    dangerously_trust_everyone: (),

    /// Should we check the environment to decide whether to disable permission
    /// and ownership tests?
    ///
    /// (This field is present in the builder only.)
    #[builder(setter(custom), field(type = "Option<disable::Disable>", build = "()"))]
    #[cfg_attr(feature = "serde", builder_field_attr(serde(skip)))]
    disable_by_environment: (),

    /// Internal value combining `dangerously_trust_everyone` and
    /// `disable_by_environment` to decide whether we're doing permissions
    /// checks or not.
    #[builder(setter(custom), field(build = "self.should_be_enabled()"))]
    #[cfg_attr(feature = "serde", builder_field_attr(serde(skip)))]
    status: disable::Status,

    /// What user ID do we trust by default (if any?)
    #[cfg(all(
        target_family = "unix",
        not(target_os = "ios"),
        not(target_os = "android")
    ))]
    #[builder(
        setter(into),
        field(type = "TrustedUser", build = "self.trust_user.get_uid()?")
    )]
    trust_user: Option<u32>,

    /// What group ID do we trust by default (if any?)
    #[cfg(all(
        target_family = "unix",
        not(target_os = "ios"),
        not(target_os = "android")
    ))]
    #[builder(
        setter(into),
        field(type = "TrustedGroup", build = "self.trust_group.get_gid()?")
    )]
    trust_group: Option<u32>,
}

/// Compute the canonical prefix for a given path prefix.
///
/// The funny types here are used to please derive_builder.
#[allow(clippy::option_option)]
fn canonicalize_opt_prefix(prefix: &Option<Option<PathBuf>>) -> Result<Option<PathBuf>> {
    match prefix {
        Some(Some(path)) if path.as_os_str().is_empty() => Ok(None),
        Some(Some(path)) => Ok(Some(
            path.canonicalize()
                .map_err(|e| Error::inspecting(e, path))?,
        )),
        _ => Ok(None),
    }
    // TODO: Permit "not found?" .
}

impl MistrustBuilder {
    /// Configure this `Mistrust` to trust only the admin (root) user.
    ///
    /// By default, both the currently running user and the root user will be
    /// trusted.
    ///
    /// This option disables the default group-trust behavior as well.
    #[cfg(all(
        target_family = "unix",
        not(target_os = "ios"),
        not(target_os = "android")
    ))]
    pub fn trust_admin_only(&mut self) -> &mut Self {
        self.trust_user = TrustedUser::None;
        self.trust_group = TrustedGroup::None;
        self
    }

    /// Configure this `Mistrust` to trust no groups at all.
    ///
    /// By default, we trust the group (if any) with the same name as the
    /// current user if we are currently running as a member of that group.
    ///
    /// With this option set, no group is trusted, and and any group-readable or
    /// group-writable objects are treated the same as world-readable and
    /// world-writable objects respectively.
    #[cfg(all(
        target_family = "unix",
        not(target_os = "ios"),
        not(target_os = "android")
    ))]
    pub fn trust_no_group_id(&mut self) -> &mut Self {
        self.trust_group = TrustedGroup::None;
        self
    }

    /// Configure this `Mistrust` to trust every user and every group.
    ///
    /// With this option set, every file and directory is treated as having
    /// valid permissions: even world-writeable files are allowed.  File-type
    /// checks are still performed.
    ///
    /// This option is mainly useful to handle cases where you want to make
    /// these checks optional, and still use [`CheckedDir`] without having to
    /// implement separate code paths for the "checking on" and "checking off"
    /// cases.
    ///
    /// Setting this flag will supersede any value set in the environment.
    pub fn dangerously_trust_everyone(&mut self) -> &mut Self {
        self.dangerously_trust_everyone = Some(true);
        self
    }

    /// Remove any ignored prefix, restoring this [`MistrustBuilder`] to a state
    /// as if [`MistrustBuilder::ignore_prefix`] had not been called.
    pub fn remove_ignored_prefix(&mut self) -> &mut Self {
        self.ignore_prefix = Some(None);
        self
    }

    /// Configure this [`MistrustBuilder`] to become disabled based on the
    /// environment variable `var`.
    ///
    /// (If the variable is "false", "no", or "0", it will be treated as
    /// false; other values are treated as true.)
    ///
    /// If `var` is not set, then we'll look at
    /// `$FS_MISTRUST_DISABLE_PERMISSIONS_CHECKS`.
    pub fn controlled_by_env_var(&mut self, var: &str) -> &mut Self {
        self.disable_by_environment = Some(disable::Disable::OnUserEnvVar(var.to_string()));
        self
    }

    /// Like `controlled_by_env_var`, but do not override any previously set
    /// environment settings.
    ///
    /// (The `arti-client` wants this, so that it can inform a caller-supplied
    /// `MistrustBuilder` about its Arti-specific env var, but only if the
    /// caller has not already provided a variable of its own. Other code
    /// embedding `fs-mistrust` may want it too.)
    pub fn controlled_by_env_var_if_not_set(&mut self, var: &str) -> &mut Self {
        if self.disable_by_environment.is_none() {
            self.controlled_by_env_var(var)
        } else {
            self
        }
    }

    /// Configure this [`MistrustBuilder`] to become disabled based on the
    /// environment variable `$FS_MISTRUST_DISABLE_PERMISSIONS_CHECKS` only,
    ///
    /// (If the variable is "false", "no", "0", or "", it will be treated as
    /// false; other values are treated as true.)
    ///
    /// This is the default.
    pub fn controlled_by_default_env_var(&mut self) -> &mut Self {
        self.disable_by_environment = Some(disable::Disable::OnGlobalEnvVar);
        self
    }

    /// Configure this [`MistrustBuilder`] to never consult the environment to
    /// see whether it should be disabled.
    pub fn ignore_environment(&mut self) -> &mut Self {
        self.disable_by_environment = Some(disable::Disable::Never);
        self
    }

    /// Considering our settings, determine whether we should trust all users
    /// (and thereby disable our permission checks.)
    fn should_be_enabled(&self) -> disable::Status {
        // If we've disabled checks in our configuration, then that settles it.
        if self.dangerously_trust_everyone == Some(true) {
            return disable::Status::DisableChecks;
        }

        // Otherwise, we use our "disable_by_environment" setting to see whether
        // we should check the environment.
        self.disable_by_environment
            .as_ref()
            .unwrap_or(&disable::Disable::default())
            .should_disable_checks()
    }
}

impl Default for Mistrust {
    fn default() -> Self {
        MistrustBuilder::default()
            .build()
            .expect("Could not build default")
    }
}

/// An object used to perform a single check.
///
/// A `Verifier` is used when [`Mistrust::check_directory`] and
/// [`Mistrust::make_directory`] are not sufficient for your needs.
#[derive(Clone, Debug)]
#[must_use]
pub struct Verifier<'a> {
    /// The [`Mistrust`] that was used to create this verifier.
    mistrust: &'a Mistrust,

    /// Has the user called [`Verifier::permit_readable`]?
    readable_okay: bool,

    /// Has the user called [`Verifier::all_errors`]?
    collect_multiple_errors: bool,

    /// If the user called [`Verifier::require_file`] or
    /// [`Verifier::require_directory`], which did they call?
    enforce_type: Type,

    /// If true, we want to check all the contents of this directory as well as
    /// the directory itself.  Requires the `walkdir` feature.
    check_contents: bool,
}

/// A type of object that we have been told to require.
#[derive(Debug, Clone, Copy)]
enum Type {
    /// A directory.
    Dir,
    /// A regular file.
    File,
    /// A directory or a regular file.
    DirOrFile,
    /// Absolutely anything at all.
    Anything,
}

impl Mistrust {
    /// Return a new [`MistrustBuilder`].
    pub fn builder() -> MistrustBuilder {
        MistrustBuilder::default()
    }

    /// Initialize a new default `Mistrust`.
    ///
    /// By default:
    ///    *  we will inspect all directories that are used to resolve any path that is checked.
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a new `Mistrust` that trusts all users and all groups.
    ///
    /// (In effect, this `Mistrust` will have all of its permissions checks
    /// disabled, since if all users and groups are trusted, it doesn't matter
    /// what the permissions on any file and directory are.)
    pub fn new_dangerously_trust_everyone() -> Self {
        Self::builder()
            .dangerously_trust_everyone()
            .build()
            .expect("Could not construct a Mistrust")
    }

    /// Create a new [`Verifier`] with this configuration, to perform a single check.
    pub fn verifier(&self) -> Verifier<'_> {
        Verifier {
            mistrust: self,
            readable_okay: false,
            collect_multiple_errors: false,
            enforce_type: Type::DirOrFile,
            check_contents: false,
        }
    }

    /// Verify that `dir` is a directory that only trusted users can read from,
    /// list the files in,  or write to.
    ///
    /// If it is, and we can verify that, return `Ok(())`.  Otherwise, return
    /// the first problem that we encountered when verifying it.
    ///
    /// `m.check_directory(dir)` is equivalent to
    /// `m.verifier().require_directory().check(dir)`.  If you need different
    /// behavior, see [`Verifier`] for more options.
    pub fn check_directory<P: AsRef<Path>>(&self, dir: P) -> Result<()> {
        self.verifier().require_directory().check(dir)
    }

    /// As `check_directory`, but create the directory if needed.
    ///
    /// `m.check_directory(dir)` is equivalent to
    /// `m.verifier().make_directory(dir)`.  If you need different behavior, see
    /// [`Verifier`] for more options.
    pub fn make_directory<P: AsRef<Path>>(&self, dir: P) -> Result<()> {
        self.verifier().make_directory(dir)
    }

    /// Return true if this `Mistrust` object has been configured to trust all
    /// users.
    pub(crate) fn is_disabled(&self) -> bool {
        self.status.disabled()
    }
}

impl<'a> Verifier<'a> {
    /// Configure this `Verifier` to require that all paths it checks be
    /// files (not directories).
    pub fn require_file(mut self) -> Self {
        self.enforce_type = Type::File;
        self
    }

    /// Configure this `Verifier` to require that all paths it checks be
    /// directories.
    pub fn require_directory(mut self) -> Self {
        self.enforce_type = Type::Dir;
        self
    }

    /// Configure this `Verifier` to allow the paths that it checks to be
    /// filesystem objects of any type.
    ///
    /// By default, the final path (after resolving all links) must be a
    /// directory or a regular file, not (for example) a block device or a named
    /// pipe.
    pub fn permit_all_object_types(mut self) -> Self {
        self.enforce_type = Type::Anything;
        self
    }

    /// Configure this `Verifier` to permit the target files/directory to be
    /// _readable_ by untrusted users.
    ///
    /// By default, we assume that the caller wants the target file or directory
    /// to be only readable or writable by trusted users.  With this flag, we
    /// permit the target file or directory to be readable by untrusted users,
    /// but not writable.
    ///
    /// (Note that we always allow the _parent directories_ of the target to be
    /// readable by untrusted users, since their readability does not make the
    /// target readable.)
    pub fn permit_readable(mut self) -> Self {
        self.readable_okay = true;
        self
    }

    /// Tell this `Verifier` to accumulate as many errors as possible, rather
    /// than stopping at the first one.
    ///
    /// If a single error is found, that error will be returned.  Otherwise, the
    /// resulting error type will be [`Error::Multiple`].
    ///
    /// # Example
    ///
    /// ```
    /// # use fs_mistrust::Mistrust;
    /// if let Err(e) = Mistrust::new().verifier().all_errors().check("/home/gardenGnostic/.gnupg/") {
    ///    for error in e.errors() {
    ///       println!("{}", e)
    ///    }
    /// }
    /// ```
    pub fn all_errors(mut self) -> Self {
        self.collect_multiple_errors = true;
        self
    }

    /// Configure this verifier so that, after checking the directory, check all
    /// of its contents.
    ///
    /// Symlinks are not permitted; both files and directories are allowed. This
    /// option implies `require_directory()`, since only a directory can have
    /// contents.
    ///
    /// Requires that the `walkdir` feature is enabled.
    #[cfg(feature = "walkdir")]
    pub fn check_content(mut self) -> Self {
        self.check_contents = true;
        self.require_directory()
    }

    /// Check whether the file or directory at `path` conforms to the
    /// requirements of this `Verifier` and the [`Mistrust`] that created it.
    pub fn check<P: AsRef<Path>>(self, path: P) -> Result<()> {
        let path = path.as_ref();

        // This is the powerhouse of our verifier code:
        //
        // See the `imp` module for actual implementation logic.
        let mut error_iterator = self
            .check_errors(path.as_ref())
            .chain(self.check_content_errors(path.as_ref()));

        // Collect either the first error, or all errors.
        let opt_error: Option<Error> = if self.collect_multiple_errors {
            error_iterator.collect()
        } else {
            let next = error_iterator.next();
            drop(error_iterator); // so that "canonical" is no loner borrowed.
            next
        };

        if let Some(err) = opt_error {
            return Err(err);
        }

        Ok(())
    }
    /// Check whether `path` is a valid directory, and create it if it doesn't
    /// exist.
    ///
    /// Returns `Ok` if the directory already existed or if it was just created,
    /// and it conforms to the requirements of this `Verifier` and the
    /// [`Mistrust`] that created it.
    ///
    /// Return an error if:
    ///  * there was a permissions or ownership problem in the path or any of
    ///    its ancestors,
    ///  * there was a problem when creating the directory
    ///  * after creating the directory, we found that it had a permissions or
    ///    ownership problem.
    pub fn make_directory<P: AsRef<Path>>(mut self, path: P) -> Result<()> {
        self.enforce_type = Type::Dir;

        let path = path.as_ref();
        match self.clone().check(path) {
            Err(Error::NotFound(_)) => {}
            Err(other_error) => return Err(other_error),
            Ok(()) => return Ok(()), // no error; file exists.
        }

        // Looks like we got a "not found", so we're creating the path.
        let mut bld = DirBuilder::new();
        #[cfg(target_family = "unix")]
        {
            use std::os::unix::fs::DirBuilderExt;
            bld.mode(0o700);
        }
        bld.recursive(true)
            .create(path)
            .map_err(|e| Error::CreatingDir(Arc::new(e)))?;

        // We built the path!  But for paranoia's sake, check it again.
        self.check(path)
    }

    /// Check whether `path` is a directory conforming to the requirements of
    /// this `Verifier` and the [`Mistrust`] that created it.
    ///
    /// If it is, then return a new [`CheckedDir`] that can be used to securely access
    /// the contents of this directory.  
    pub fn secure_dir<P: AsRef<Path>>(self, path: P) -> Result<CheckedDir> {
        let path = path.as_ref();
        self.clone().require_directory().check(path)?;
        CheckedDir::new(&self, path)
    }

    /// Check whether `path` is a directory conforming to the requirements of
    /// this `Verifier` and the [`Mistrust`] that created it.
    ///
    /// If successful, then return a new [`CheckedDir`] that can be used to
    /// securely access the contents of this directory.  
    pub fn make_secure_dir<P: AsRef<Path>>(self, path: P) -> Result<CheckedDir> {
        let path = path.as_ref();
        self.clone().require_directory().make_directory(path)?;
        CheckedDir::new(&self, path)
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use testing::{Dir, LinkType};

    #[test]
    fn simple_cases() {
        let d = Dir::new();
        d.dir("a/b/c");
        d.dir("e/f/g");
        d.chmod("a", 0o755);
        d.chmod("a/b", 0o755);
        d.chmod("a/b/c", 0o700);
        d.chmod("e", 0o755);
        d.chmod("e/f", 0o777);
        d.link_rel(LinkType::Dir, "a/b/c", "d");

        let m = Mistrust::builder()
            .trust_no_group_id()
            // Ignore the permissions on /tmp/whatever-tempdir-gave-us
            .ignore_prefix(d.canonical_root())
            .build()
            .unwrap();
        // /a/b/c should be fine...
        m.check_directory(d.path("a/b/c")).unwrap();
        // /e/f/g should not.
        let e = m.check_directory(d.path("e/f/g")).unwrap_err();
        assert!(matches!(e, Error::BadPermission(_, 0o777, 0o022)));
        assert_eq!(e.path().unwrap(), d.path("e/f").canonicalize().unwrap());

        m.check_directory(d.path("d")).unwrap();
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn admin_only() {
        use std::os::unix::prelude::MetadataExt;

        let d = Dir::new();
        d.dir("a/b");
        d.chmod("a", 0o700);
        d.chmod("a/b", 0o700);

        if d.path("a/b").metadata().unwrap().uid() == 0 {
            // Nothing to do here; we _are_ root.
            return;
        }

        // With normal settings should be okay...
        let m = Mistrust::builder()
            .ignore_prefix(d.canonical_root())
            .build()
            .unwrap();
        m.check_directory(d.path("a/b")).unwrap();

        // With admin_only, it'll fail.
        let m = Mistrust::builder()
            .ignore_prefix(d.canonical_root())
            .trust_admin_only()
            .build()
            .unwrap();

        let err = m.check_directory(d.path("a/b")).unwrap_err();
        assert!(matches!(err, Error::BadOwner(_, _)));
        assert_eq!(err.path().unwrap(), d.path("a").canonicalize().unwrap());
    }

    #[test]
    fn want_type() {
        let d = Dir::new();
        d.dir("a");
        d.file("b");
        d.chmod("a", 0o700);
        d.chmod("b", 0o600);

        let m = Mistrust::builder()
            .ignore_prefix(d.canonical_root())
            .trust_no_group_id()
            .build()
            .unwrap();

        // If we insist stuff is its own type, it works fine.
        m.verifier().require_directory().check(d.path("a")).unwrap();
        m.verifier().require_file().check(d.path("b")).unwrap();

        // If we insist on a different type, we hit an error.
        let e = m
            .verifier()
            .require_directory()
            .check(d.path("b"))
            .unwrap_err();
        assert!(matches!(e, Error::BadType(_)));
        assert_eq!(e.path().unwrap(), d.path("b").canonicalize().unwrap());

        let e = m.verifier().require_file().check(d.path("a")).unwrap_err();
        assert!(matches!(e, Error::BadType(_)));
        assert_eq!(e.path().unwrap(), d.path("a").canonicalize().unwrap());

        // TODO: Possibly, make sure that a special file matches neither.
    }

    #[test]
    fn readable_ok() {
        let d = Dir::new();
        d.dir("a/b");
        d.file("a/b/c");
        d.chmod("a", 0o750);
        d.chmod("a/b", 0o750);
        d.chmod("a/b/c", 0o640);

        let m = Mistrust::builder()
            .ignore_prefix(d.canonical_root())
            .trust_no_group_id()
            .build()
            .unwrap();

        // These will fail, since the file or directory is readable.
        let e = m.verifier().check(d.path("a/b")).unwrap_err();
        assert!(matches!(e, Error::BadPermission(..)));
        assert_eq!(e.path().unwrap(), d.path("a/b").canonicalize().unwrap());
        let e = m.verifier().check(d.path("a/b/c")).unwrap_err();
        assert!(matches!(e, Error::BadPermission(..)));
        assert_eq!(e.path().unwrap(), d.path("a/b/c").canonicalize().unwrap());

        // Now allow readable targets.
        m.verifier().permit_readable().check(d.path("a/b")).unwrap();
        m.verifier()
            .permit_readable()
            .check(d.path("a/b/c"))
            .unwrap();
    }

    #[test]
    fn multiple_errors() {
        let d = Dir::new();
        d.dir("a/b");
        d.chmod("a", 0o700);
        d.chmod("a/b", 0o700);

        let m = Mistrust::builder()
            .ignore_prefix(d.canonical_root())
            .trust_no_group_id()
            .build()
            .unwrap();

        // Only one error occurs, so we get that error.
        let e = m
            .verifier()
            .all_errors()
            .check(d.path("a/b/c"))
            .unwrap_err();
        assert!(matches!(e, Error::NotFound(_)));
        assert_eq!(1, e.errors().count());

        // Introduce a second error...
        d.chmod("a/b", 0o770);
        let e = m
            .verifier()
            .all_errors()
            .check(d.path("a/b/c"))
            .unwrap_err();
        assert!(matches!(e, Error::Multiple(_)));
        let errs: Vec<_> = e.errors().collect();
        assert_eq!(2, errs.len());
        assert!(matches!(&errs[0], Error::BadPermission(..)));
        assert!(matches!(&errs[1], Error::NotFound(_)));
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn sticky() {
        let d = Dir::new();
        d.dir("a/b/c");
        d.chmod("a", 0o777);
        d.chmod("a/b", 0o755);
        d.chmod("a/b/c", 0o700);

        let m = Mistrust::builder()
            .ignore_prefix(d.canonical_root())
            .build()
            .unwrap();

        // `a` is world-writable, so the first check will fail.
        m.check_directory(d.path("a/b/c")).unwrap_err();

        // Now `a` is world-writable _and_ sticky, so the check should succeed.
        d.chmod("a", 0o777 | crate::imp::STICKY_BIT);

        m.check_directory(d.path("a/b/c")).unwrap();

        // Make sure we got the right definition!
        #[allow(clippy::useless_conversion)]
        {
            assert_eq!(crate::imp::STICKY_BIT, u32::from(libc::S_ISVTX));
        }
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn trust_gid() {
        use std::os::unix::prelude::MetadataExt;
        let d = Dir::new();
        d.dir("a/b");
        d.chmod("a", 0o770);
        d.chmod("a/b", 0o770);

        let m = Mistrust::builder()
            .ignore_prefix(d.canonical_root())
            .trust_no_group_id()
            .build()
            .unwrap();

        // By default, we shouldn't be accept this directory, since it is
        // group-writable.
        let e = m.check_directory(d.path("a/b")).unwrap_err();
        assert!(matches!(e, Error::BadPermission(..)));

        // But we can make the group trusted, which will make it okay for the
        // directory to be group-writable.
        let gid = d.path("a/b").metadata().unwrap().gid();
        let m = Mistrust::builder()
            .ignore_prefix(d.canonical_root())
            .trust_group(gid)
            .build()
            .unwrap();

        m.check_directory(d.path("a/b")).unwrap();

        // OTOH, if we made a _different_ group trusted, it'll fail.
        let m = Mistrust::builder()
            .ignore_prefix(d.canonical_root())
            .trust_group(gid ^ 1)
            .build()
            .unwrap();

        let e = m.check_directory(d.path("a/b")).unwrap_err();
        assert!(matches!(e, Error::BadPermission(..)));
    }

    #[test]
    fn make_directory() {
        let d = Dir::new();
        d.dir("a/b");

        let m = Mistrust::builder()
            .ignore_prefix(d.canonical_root())
            .build()
            .unwrap();

        #[cfg(target_family = "unix")]
        {
            // Try once with bad permissions.
            d.chmod("a", 0o777);
            let e = m.make_directory(d.path("a/b/c/d")).unwrap_err();
            assert!(matches!(e, Error::BadPermission(..)));

            // Now make the permissions correct.
            d.chmod("a", 0o0700);
            d.chmod("a/b", 0o0700);
        }

        // Make the directory!
        m.make_directory(d.path("a/b/c/d")).unwrap();

        // Make sure it exists and has good permissions.
        m.check_directory(d.path("a/b/c/d")).unwrap();

        // Try make_directory again and make sure _that_ succeeds.
        m.make_directory(d.path("a/b/c/d")).unwrap();
    }

    #[test]
    fn check_contents() {
        let d = Dir::new();
        d.dir("a/b/c");
        d.file("a/b/c/d");
        d.chmod("a", 0o700);
        d.chmod("a/b", 0o700);
        d.chmod("a/b/c", 0o755);
        d.chmod("a/b/c/d", 0o666);

        let m = Mistrust::builder()
            .ignore_prefix(d.canonical_root())
            .build()
            .unwrap();

        // A check should work...
        m.check_directory(d.path("a/b")).unwrap();

        // But we get an error if we check the contents.
        let e = m
            .verifier()
            .all_errors()
            .check_content()
            .check(d.path("a/b"))
            .unwrap_err();
        assert_eq!(1, e.errors().count());

        // We only expect an error on the _writable_ contents: the _readable_
        // a/b/c is okay.
        assert_eq!(e.path().unwrap(), d.path("a/b/c/d"));
    }

    #[test]
    fn trust_everyone() {
        let d = Dir::new();
        d.dir("a/b/c");
        d.file("a/b/c/d");
        d.chmod("a", 0o777);
        d.chmod("a/b", 0o777);
        d.chmod("a/b/c", 0o777);
        d.chmod("a/b/c/d", 0o666);

        let m = Mistrust::builder()
            .dangerously_trust_everyone()
            .build()
            .unwrap();

        // This is fine.
        m.check_directory(d.path("a/b/c")).unwrap();
        // This isn't a directory!
        let err = m.check_directory(d.path("a/b/c/d")).unwrap_err();
        assert!(matches!(err, Error::BadType(_)));

        // But it _is_ a file.
        m.verifier()
            .require_file()
            .check(d.path("a/b/c/d"))
            .unwrap();
    }

    #[test]
    fn default_mistrust() {
        // we can't test a mistrust without ignore_prefix, but we should make sure that we can build one.
        let _m = Mistrust::default();
    }

    // TODO: Write far more tests.
    // * Can there be a test for a failed readlink()?  I can't see an easy way
    //   to provoke that without trying to make a time-of-check/time-of-use race
    //   condition, since we stat the link before we call readlink on it.
    // * Can there be a test for a failing call to std::env::current_dir?  Seems
    //   hard to provoke without calling set_current_dir(), which isn't good
    //   manners in a test.
}
