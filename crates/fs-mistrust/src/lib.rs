//! # `fs-mistrust`: make sure that files are really private.
//!
//! This crates provides a set of functionality to check the permissions on
//! files and directories to ensure that they are effectively private—that is,
//! that they are only readable or writable by trusted[^1] users.
//!
//! That's trickier than it sounds:
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
//! [^1]: we define "trust" here in the computer-security sense of the word: a
//!      user is "trusted" if they have the opportunity to break our security
//!      guarantees.  For example, `root` on a Unix environment is "trusted",
//!      whether you actually trust them or not.
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
//! ## Limitations
//!
//! We currently assume a fairly vanilla Unix environment: we'll tolerate other
//! systems, but we don't actually look at the details of any of these:
//!    * Windows security (ACLs, SecurityDescriptors, etc)
//!    * SELinux capabilities
//!    * POSIX (and other) ACLs.
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
//  - Add a way to recursively check the contents of a directory.

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

mod dir;
mod err;
mod imp;
#[cfg(test)]
pub(crate) mod testing;
pub mod walk;

use std::{
    fs::DirBuilder,
    path::{Path, PathBuf},
    sync::Arc,
};

pub use dir::SecureDir;
pub use err::Error;

/// A result type as returned by this crate
pub type Result<T> = std::result::Result<T, Error>;

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
//
// TODO: Example.
#[derive(Debug, Clone)]
pub struct Mistrust {
    /// If the user called [`Mistrust::ignore_prefix`], what did they give us?
    ///
    /// (This is stored in canonical form.)
    ignore_prefix: Option<PathBuf>,

    /// What user ID do we trust by default (if any?)
    #[cfg(target_family = "unix")]
    trust_uid: Option<u32>,

    /// What group ID do we trust by default (if any?)
    #[cfg(target_family = "unix")]
    trust_gid: Option<u32>,
}

impl Default for Mistrust {
    fn default() -> Self {
        Self {
            ignore_prefix: None,
            #[cfg(target_family = "unix")]
            trust_uid: Some(unsafe { libc::getuid() }),
            #[cfg(target_family = "unix")]
            trust_gid: None,
        }
    }
}

/// An object used to perform a single check.
///
/// A `Verifier` is used when the default "check" methods (TODO) on [`Mistrust`]
/// are not sufficient for your needs.
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
    /// Initialize a new default `Mistrust`.
    ///
    /// By default:
    ///    *  we will inspect all directories that are used to resolve any path that is checked.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a path as an "ignored prefix" for all of our checks.
    ///
    /// Any path that is a part of this prefix will be _assumed_ to have valid
    /// permissions and ownership. For example, if you call
    /// `ignore_prefix("/u1/users")`, then we will not check `/`, `/u1`, or
    /// `/u1/users`.
    ///
    /// A typical use of this function is to ignore `${HOME}/..`.
    ///
    /// If this directory cannot be found or resolved, this function will return
    /// an error.
    pub fn ignore_prefix<P: AsRef<Path>>(&mut self, directory: P) -> Result<&mut Self> {
        let directory = directory
            .as_ref()
            .canonicalize()
            .map_err(|e| Error::inspecting(e, directory.as_ref()))?;
        // TODO: Permit "not found?" . Use "walkdir" to do a more tolerant canonicalization?
        self.ignore_prefix = Some(directory);
        Ok(self)
    }

    /// Configure this `Mistrust` to trust only the admin (root) user.
    ///
    /// By default, both the currently running user and the root user will be trusted.
    #[cfg(target_family = "unix")]
    pub fn trust_admin_only(&mut self) -> &mut Self {
        self.trust_uid = None;
        self
    }

    #[cfg(target_family = "unix")]
    /// Configure a trusted group ID for this `Mistrust`.
    ///
    /// If a group ID is considered "trusted", then any file or directory we
    /// inspect is allowed to be readable and writable by that group.
    ///
    /// By default, no group ID is trusted, and any group-readable or
    /// group-writable objects are treated the same as world-readable and
    /// world-writable objects respectively.
    ///
    /// Anybody who is a member (or becomes a member) of the provided group will
    /// be allowed to read and modify the verified files.
    pub fn trust_group_id(&mut self, gid: u32) -> &mut Self {
        self.trust_gid = Some(gid);
        self
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

        match opt_error {
            Some(err) => return Err(err),
            None => {}
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
    /// If it is, then return a new [`SecureDir`] that can be used to securely access
    /// the contents of this directory.  
    pub fn secure_dir<P: AsRef<Path>>(self, path: P) -> Result<SecureDir> {
        let path = path.as_ref();
        self.clone().require_directory().check(path)?;
        SecureDir::new(&self, path)
    }

    /// Check whether `path` is a directory conforming to the requirements of
    /// this `Verifier` and the [`Mistrust`] that created it.
    ///
    /// If successful, then return a new [`SecureDir`] that can be used to
    /// securely access the contents of this directory.  
    pub fn make_secure_dir<P: AsRef<Path>>(self, path: P) -> Result<SecureDir> {
        let path = path.as_ref();
        self.clone().require_directory().make_directory(path)?;
        SecureDir::new(&self, path)
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use testing::Dir;

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

        let mut m = Mistrust::new();
        // Ignore the permissions on /tmp/whatever-tempdir-gave-us
        m.ignore_prefix(d.canonical_root()).unwrap();
        // /a/b/c should be fine...
        m.check_directory(d.path("a/b/c")).unwrap();
        // /e/f/g should not.
        let e = m.check_directory(d.path("e/f/g")).unwrap_err();
        assert!(matches!(e, Error::BadPermission(_, 0o022)));
        assert_eq!(e.path().unwrap(), d.path("e/f").canonicalize().unwrap());
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

        let mut m = Mistrust::new();
        m.ignore_prefix(d.canonical_root()).unwrap();
        // With normal settings should be okay...
        m.check_directory(d.path("a/b")).unwrap();

        // With admin_only, it'll fail.
        m.trust_admin_only();
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

        let mut m = Mistrust::new();
        m.ignore_prefix(d.canonical_root()).unwrap();

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

        let mut m = Mistrust::new();
        m.ignore_prefix(d.canonical_root()).unwrap();

        // These will fail, since the file or directory is readable.
        let e = m.verifier().check(d.path("a/b")).unwrap_err();
        assert!(matches!(e, Error::BadPermission(_, _)));
        assert_eq!(e.path().unwrap(), d.path("a/b").canonicalize().unwrap());
        let e = m.verifier().check(d.path("a/b/c")).unwrap_err();
        assert!(matches!(e, Error::BadPermission(_, _)));
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

        let mut m = Mistrust::new();
        m.ignore_prefix(d.canonical_root()).unwrap();

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
        assert!(matches!(&errs[0], Error::BadPermission(_, _)));
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

        let mut m = Mistrust::new();
        m.ignore_prefix(d.canonical_root()).unwrap();

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

        let mut m = Mistrust::new();
        m.ignore_prefix(d.canonical_root()).unwrap();

        // By default, we shouldn't be accept this directory, since it is
        // group-writable.
        let e = m.check_directory(d.path("a/b")).unwrap_err();
        assert!(matches!(e, Error::BadPermission(_, _)));

        // But we can make the group trusted, which will make it okay for the
        // directory to be group-writable.
        let gid = d.path("a/b").metadata().unwrap().gid();
        m.trust_group_id(gid);
        m.check_directory(d.path("a/b")).unwrap();

        // OTOH, if we made a _different_ group trusted, it'll fail.

        m.trust_group_id(gid ^ 1);
        let e = m.check_directory(d.path("a/b")).unwrap_err();
        assert!(matches!(e, Error::BadPermission(_, _)));
    }

    #[test]
    fn make_directory() {
        let d = Dir::new();
        d.dir("a/b");

        let mut m = Mistrust::new();
        m.ignore_prefix(d.canonical_root()).unwrap();

        #[cfg(target_family = "unix")]
        {
            // Try once with bad permissions.
            d.chmod("a", 0o777);
            let e = m.make_directory(d.path("a/b/c/d")).unwrap_err();
            assert!(matches!(e, Error::BadPermission(_, _)));

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
        d.chmod("a/b/c/d", 0o644);

        let mut m = Mistrust::new();
        m.ignore_prefix(d.canonical_root()).unwrap();

        // A check should work...
        m.check_directory(d.path("a/b")).unwrap();

        // But we get errors if we check the contents.
        let e = m
            .verifier()
            .all_errors()
            .check_content()
            .check(d.path("a/b"))
            .unwrap_err();

        assert_eq!(2, e.errors().count());
    }

    // TODO: Write far more tests.
    // * Can there be a test for a failed readlink()?  I can't see an easy way
    //   to provoke that without trying to make a time-of-check/time-of-use race
    //   condition, since we stat the link before we call readlink on it.
    // * Can there be a test for a failing call to std::env::current_dir?  Seems
    //   hard to provoke without calling set_current_dir(), which isn't good
    //   manners in a test.
}
