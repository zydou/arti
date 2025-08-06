//! Implementation logic for `fs-mistrust`.

use std::{
    fs::{FileType, Metadata},
    path::Path,
};

#[cfg(target_family = "unix")]
use std::os::unix::prelude::MetadataExt;

use crate::{
    Error, Result, Type,
    walk::{PathType, ResolvePath},
};

/// Definition for the "sticky bit", which on Unix means that the contents of
/// directory may not be renamed, deleted, or otherwise modified by a non-owner
/// of those contents, even if the user has write permissions on the directory.
///
/// This is the usual behavior for /tmp: You can make your own directories in
/// /tmp, but you can't modify other people's.
///
/// (We'd use libc's version of `S_ISVTX`, but they vacillate between u16 and
/// u32 depending what platform you're on.)
#[cfg(target_family = "unix")]
pub(crate) const STICKY_BIT: u32 = 0o1000;

/// Helper: Box an iterator of errors.
fn boxed<'a, I: Iterator<Item = Error> + 'a>(iter: I) -> Box<dyn Iterator<Item = Error> + 'a> {
    Box::new(iter)
}

impl<'a> super::Verifier<'a> {
    /// Return an iterator of all the security problems with `path`.
    ///
    /// If the iterator is empty, then there is no problem with `path`.
    //
    // TODO: This iterator is not fully lazy; sometimes, calls to check_one()
    // return multiple errors when it would be better for them to return only
    // one (since we're ignoring errors after the first).  This might be nice
    // to fix in the future if we can do so without adding much complexity
    // to the code.  It's not urgent, since the allocations won't cost much
    // compared to the filesystem access.
    pub(crate) fn check_errors(&self, path: &Path) -> impl Iterator<Item = Error> + '_ + use<'_> {
        if self.mistrust.is_disabled() {
            // We don't want to walk the path in this case at all: we'll just
            // look at the last element.

            let meta = match path.metadata() {
                Ok(meta) => meta,
                Err(e) => return boxed(vec![Error::inspecting(e, path)].into_iter()),
            };
            let mut errors = Vec::new();
            self.check_type(path, PathType::Final, &meta, &mut errors);
            return boxed(errors.into_iter());
        }

        let rp = match ResolvePath::new(path) {
            Ok(rp) => rp,
            Err(e) => return boxed(vec![e].into_iter()),
        };

        // Filter to remove every path that is a prefix of ignore_prefix. (IOW,
        // if stop_at_dir is /home/arachnidsGrip, real_stop_at_dir will be
        // /home, and we'll ignore / and /home.)
        let should_retain = move |r: &Result<_>| match (r, &self.mistrust.ignore_prefix) {
            (Ok((p, _, _)), Some(ignore_prefix)) => !ignore_prefix.starts_with(p),
            (_, _) => true,
        };

        boxed(
            rp.filter(should_retain)
                // Finally, check the path for errors.
                //
                // See `check_one` below for a note on TOCTOU issues.
                .flat_map(move |r| match r {
                    Ok((path, path_type, metadata)) => {
                        self.check_one(path.as_path(), path_type, &metadata)
                    }
                    Err(e) => vec![e],
                }),
        )
    }

    /// If check_contents is set, return an iterator over all the errors in
    /// elements _contained in this directory_.
    #[cfg(feature = "walkdir")]
    pub(crate) fn check_content_errors(
        &self,
        path: &Path,
    ) -> impl Iterator<Item = Error> + '_ + use<'_> {
        use std::sync::Arc;

        if !self.check_contents || self.mistrust.is_disabled() {
            return boxed(std::iter::empty());
        }

        boxed(
            walkdir::WalkDir::new(path)
                .follow_links(false)
                .min_depth(1)
                .into_iter()
                .flat_map(move |ent| match ent {
                    Err(err) => vec![Error::Listing(Arc::new(err))],
                    Ok(ent) => match ent.metadata() {
                        Ok(meta) => self
                            .check_one(ent.path(), PathType::Content, &meta)
                            .into_iter()
                            .map(|e| Error::Content(Box::new(e)))
                            .collect(),
                        Err(err) => vec![Error::Listing(Arc::new(err))],
                    },
                }),
        )
    }

    /// Return an empty iterator.
    #[cfg(not(feature = "walkdir"))]
    pub(crate) fn check_content_errors(&self, _path: &Path) -> impl Iterator<Item = Error> + '_ {
        std::iter::empty()
    }

    /// Check a single `path` for conformance with this `Verifier`.
    ///
    /// Note that this result is only meaningful if all of the _ancestors_ of
    /// this path have been checked.  Otherwise, a non-trusted user could change
    /// where this path points after it has been checked.
    #[must_use]
    pub(crate) fn check_one(
        &self,
        path: &Path,
        path_type: PathType,
        meta: &Metadata,
    ) -> Vec<Error> {
        let mut errors = Vec::new();

        self.check_type(path, path_type, meta, &mut errors);
        #[cfg(target_family = "unix")]
        self.check_permissions(path, path_type, meta, &mut errors);
        errors
    }

    /// Check whether a given file has the correct type, and push an error into
    /// `errors` if not. Other inputs are as for `check_one`.
    fn check_type(
        &self,
        path: &Path,
        path_type: PathType,
        meta: &Metadata,
        errors: &mut Vec<Error>,
    ) {
        let want_type = match path_type {
            PathType::Symlink => {
                // There's nothing to check on a symlink encountered _while
                // looking up the target_; its permissions and ownership do not
                // actually matter.
                return;
            }
            PathType::Intermediate => Type::Dir,
            PathType::Final => self.enforce_type,
            PathType::Content => Type::DirOrFile,
        };

        if !want_type.matches(meta.file_type()) {
            errors.push(Error::BadType(path.into()));
        }
    }

    /// Check whether a given file has the correct ownership and permissions,
    /// and push errors into `errors` if not. Other inputs are as for
    /// `check_one`.
    ///
    /// On iOS, check permissions but assumes the owner is the current user.
    #[cfg(target_family = "unix")]
    fn check_permissions(
        &self,
        path: &Path,
        path_type: PathType,
        meta: &Metadata,
        errors: &mut Vec<Error>,
    ) {
        // We need to check that the owner is trusted, since the owner can
        // always change the permissions of the object.  (If we're talking
        // about a directory, the owner cah change the permissions and owner
        // of anything in the directory.)

        #[cfg(all(
            not(target_os = "ios"),
            not(target_os = "tvos"),
            not(target_os = "android")
        ))]
        {
            let uid = meta.uid();
            if uid != 0 && Some(uid) != self.mistrust.trust_user {
                errors.push(Error::BadOwner(path.into(), uid));
            }
        }

        // On Unix-like platforms, symlink permissions are ignored (and usually
        // not settable). Theoretically, the symlink owner shouldn't matter, but
        // it's less confusing to consistently require the right owner.
        if path_type == PathType::Symlink {
            return;
        }

        let mut forbidden_bits = if !self.readable_okay && path_type == PathType::Final {
            // If this is the target object, and it must not be readable, then
            // we forbid it to be group-rwx and all-rwx.
            //
            // (We allow _content_ to be globally readable even if readable_okay
            // is false, since we check that the Final directory is itself
            // unreadable.  This is okay unless the content has hard links: see
            // the Limitations section of the crate-level documentation.)
            0o077
        } else {
            // If this is the target object and it may be readable, or if this
            // is _any parent directory_ or any content, then we typically
            // forbid the group-write and all-write bits.  (Those are the bits
            // that would allow non-trusted users to change the object, or
            // change things around in a directory.)
            if meta.is_dir() && meta.mode() & STICKY_BIT != 0 && path_type == PathType::Intermediate
            {
                // This is an intermediate directory and this sticky bit is
                // set.  Thus, we don't care if it is world-writable or
                // group-writable, since only the _owner_  of a file in this
                // directory can move or rename it.
                0o000
            } else {
                // It's not a sticky-bit intermediate directory; actually
                // forbid 022.
                0o022
            }
        };
        // If we trust the GID, then we allow even more bits to be set.
        #[cfg(all(
            not(target_os = "ios"),
            not(target_os = "tvos"),
            not(target_os = "android")
        ))]
        if self.mistrust.trust_group == Some(meta.gid()) {
            forbidden_bits &= !0o070;
        }

        // Both iOS and Android have some directory on the path for application data directory
        // which is group writeable. However both system already offer some guarantees regarding
        // application data being kept away from other apps.
        //
        // iOS: https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemOverview/FileSystemOverview.html
        // > For security purposes, an iOS app’s interactions with the file system are limited
        // to the directories inside the app’s sandbox directory
        //
        // Android: https://developer.android.com/training/data-storage
        // > App-specific storage: [...] Use the directories within internal storage to save
        // sensitive information that other apps shouldn't access.
        #[cfg(any(target_os = "ios", target_os = "tvos", target_os = "android"))]
        {
            forbidden_bits &= !0o070;
        }

        let bad_bits = meta.mode() & forbidden_bits;
        if bad_bits != 0 {
            errors.push(Error::BadPermission(
                path.into(),
                meta.mode() & 0o777,
                bad_bits,
            ));
        }
    }
}

impl super::Type {
    /// Return true if this required type is matched by a given `FileType`
    /// object.
    fn matches(&self, have_type: FileType) -> bool {
        match self {
            Type::Dir => have_type.is_dir(),
            Type::File => have_type.is_file(),
            Type::DirOrFile => have_type.is_dir() || have_type.is_file(),
            Type::Anything => true,
        }
    }
}
