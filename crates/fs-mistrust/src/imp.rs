//! Implementation logic for `fs-mistrust`.

use std::{fs::Metadata, path::Path};

#[cfg(target_family = "unix")]
use std::os::unix::prelude::MetadataExt;

use crate::{
    walk::{PathType, ResolvePath},
    Error, Result, Type,
};

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
    pub(crate) fn check_errors(&self, path: &Path) -> impl Iterator<Item = Error> + '_ {
        /// Helper: Box an iterator.
        fn boxed<'a, I: Iterator<Item = Error> + 'a>(
            iter: I,
        ) -> Box<dyn Iterator<Item = Error> + 'a> {
            Box::new(iter)
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
                .flat_map(move |r| match r {
                    Ok((path, path_type, metadata)) => {
                        self.check_one(path.as_path(), path_type, &metadata)
                    }
                    Err(e) => vec![e],
                }),
        )
    }

    /// Check a single `path` for conformance with this `Concrete` mistrust.
    ///
    /// `position` is the position of the path within the ancestors of the
    /// target path.  If the `position` is 0, then it's the position of the
    /// target path itself. If `position` is 1, it's the target's parent, and so
    /// on.
    fn check_one(&self, path: &Path, path_type: PathType, meta: &Metadata) -> Vec<Error> {
        let mut errors = Vec::new();

        if path_type == PathType::Symlink {
            // There's nothing to check on a symlink; its permissions and
            // ownership do not actually matter.
            //
            // TODO: Make sure that is correct.
            return errors;
        }

        // Make sure that the object is of the right type (file vs directory).
        let want_type = if path_type == PathType::Final {
            self.enforce_type
        } else {
            // We make sure that everything at a higher level is a directory.
            Some(Type::Dir)
        };

        let have_type = meta.file_type();
        match want_type {
            Some(Type::Dir) if !have_type.is_dir() => {
                errors.push(Error::BadType(path.into()));
            }
            Some(Type::File) if !have_type.is_file() => {
                errors.push(Error::BadType(path.into()));
            }
            _ => {}
        }

        // If we are on unix, make sure that the owner and permissions are
        // acceptable.
        #[cfg(target_family = "unix")]
        {
            // We need to check that the owner is trusted, since the owner can
            // always change the permissions of the object.  (If we're talking
            // about a directory, the owner cah change the permissions and owner
            // of anything in the directory.)
            let uid = meta.uid();
            if uid != 0 && Some(uid) != self.mistrust.trust_uid {
                errors.push(Error::BadOwner(path.into(), uid));
            }
            let forbidden_bits = if !self.readable_okay && path_type == PathType::Final {
                // If this is the target object, and it must not be readable,
                // then we forbid it to be group-rwx and all-rwx.
                0o077
            } else {
                // If this is the target object and it may be readable, or if
                // this is _any parent directory_, then we only forbid the
                // group-write and all-write bits.  (Those are the bits that
                // would allow non-trusted users to change the object, or change
                // things around in a directory.)
                0o022
                // TODO: Handle sticky bit.
            };
            let bad_bits = meta.mode() & forbidden_bits;
            if bad_bits != 0 {
                errors.push(Error::BadPermission(path.into(), bad_bits));
            }
        }

        errors
    }
}
