//! An iterator to resolve and canonicalize a filename.

use crate::{Error, Result};
use std::{
    collections::HashMap,
    ffi::OsString,
    fs::Metadata,
    io,
    iter::FusedIterator,
    path::{Path, PathBuf},
    sync::Arc,
};

/// The type of a single path inspected by [`Verifier`](crate::Verifier).
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[allow(clippy::exhaustive_enums)]
pub(crate) enum PathType {
    /// This is indeed the final canonical path we were trying to resolve.
    Final,
    /// This is an intermediary canonical path.  It _should_ be a directory, but
    /// it might not be if the path resolution is about to fail.
    Intermediate,
    /// This is a symbolic link.
    Symlink,
    /// This is a file _inside_ the target directory.
    Content,
}

/// A single piece of a path.
///
/// We would use [`std::path::Component`] directly here, but we want an owned
/// type.
#[derive(Clone, Debug)]
struct Component {
    /// Is this a prefix of a windows path?
    ///
    /// We need to keep track of these, because we expect stat() to fail for
    /// them.
    #[cfg(target_family = "windows")]
    is_windows_prefix: bool,
    /// The textual value of the component.
    text: OsString,
}

/// Windows error code that we expect to get when calling stat() on a prefix.
#[cfg(target_family = "windows")]
const INVALID_FUNCTION: i32 = 1;

impl<'a> From<std::path::Component<'a>> for Component {
    fn from(c: std::path::Component<'a>) -> Self {
        #[cfg(target_family = "windows")]
        let is_windows_prefix = matches!(c, std::path::Component::Prefix(_));
        let text = c.as_os_str().to_owned();
        Component {
            #[cfg(target_family = "windows")]
            is_windows_prefix,
            text,
        }
    }
}

/// An iterator to resolve and canonicalize a filename, imitating the actual
/// filesystem's lookup behavior.
///
/// A `ResolvePath` looks up a filename by visiting all intermediate steps in
/// turn, starting from the root directory, and following symlinks.  It
/// suppresses duplicates.  Every path that it yields will _either_ be:
///   * A directory in canonical[^1] [^2] form.
///   * `dir/link` where dir is a directory in canonical form, and `link` is a
///     symlink in that directory.
///   * `dir/file` where dir is a directory in canonical form, and `file` is a
///     file in that directory.
///
/// [^1]: We define "canonical" in the same way as `Path::canonicalize`: a
///   canonical path is an absolute path containing no "." or ".." elements, and
///   no symlinks.
/// [^2]: Strictly speaking, this iterator on its own cannot guarantee that the
///   paths it yields are truly canonical.  or that they even represent the
///   target.  It is possible that in between checking one path and the next,
///   somebody will modify the first path to replace a directory with a symlink,
///   or replace one symlink with another. To get this kind of guarantee, you
///   have to use a [`Mistrust`](crate::Mistrust) to check the permissions on
///   the directories as you go.  Even then, your guarantee is conditional on
///   none of the intermediary directories having been changed by a trusted user
///   at the wrong time.
///   
///
/// # Implementation notes
///
/// Abstractly, at any given point, the directory that we're resolving looks
/// like `"resolved"/"remaining"`, where `resolved` is the part that we've
/// already looked at (in canonical form, with all symlinks resolved) and
/// `remaining` is the part that we're still trying to resolve.
///
/// We represent `resolved` as a nice plain PathBuf, and  `remaining` as a stack
/// of strings that we want to push on to the end of the path.  We initialize
/// the algorithm with `resolved` empty and `remaining` seeded with the path we
/// want to resolve.  Once there are no more parts to push, the path resolution
/// is done.
///
/// The following invariants apply whenever we are outside of the `next`
/// function:
///    * `resolved.join(remaining)` is an alias for our target path.
///    * `resolved` is in canonical form.
///    * Every ancestor of `resolved` is a key of `already_inspected`.
///
/// # Limitations
///
/// Because we're using `Path::metadata` rather than something that would use
/// `openat()` and `fstat()` under the hood, the permissions returned here are
/// potentially susceptible to TOCTOU issues.  In this crate we address these
/// issues by checking each yielded path immediately to make sure that only
/// _trusted_ users can change it after it is checked.
//
// TODO: This code is potentially of use outside this crate.  Maybe it should be
// public?
#[derive(Clone, Debug)]
pub(crate) struct ResolvePath {
    /// The path that we have resolved so far.  It is always[^1] an absolute
    /// path in canonical form: it contains no ".." or "." entries, and no
    /// symlinks.
    ///
    /// [^1]: See note on [`ResolvePath`] about time-of-check/time-of-use
    ///     issues.
    resolved: PathBuf,

    /// The parts of the path that we have _not yet resolved_.  The item on the
    /// top of the stack (that is, the end), is the next element that we'd like
    /// to add to `resolved`.
    ///
    /// This is in reverse order: later path components at the start of the `Vec` (bottom of stack)
    //
    // TODO: I'd like to have a more efficient representation of this; the
    // current one has a lot of tiny little allocations.
    stack: Vec<Component>,

    /// If true, we have encountered a nonrecoverable error and cannot yield any
    /// more items.
    ///
    /// We have a flag for this so that we know to stop when we've encountered
    /// an error for `lstat()` or `readlink()`: If we can't do those, we can't
    /// continue resolving the path.
    terminated: bool,

    /// How many more steps are we willing to take in resolving this path?  We
    /// decrement this by 1 every time we pop an element from the stack.  If we
    /// ever realize that we've run out of steps, we abort, since that's
    /// probably a symlink loop.
    steps_remaining: usize,

    /// A cache of the paths that we have already yielded to the caller.  We keep
    /// this cache so that we don't have to `lstat()` or `readlink()` any path
    /// more than once.  If the path was a symlink, then the value associated
    /// with it is the target of that symlink.  Otherwise, the value associated
    /// with it is None.
    already_inspected: HashMap<PathBuf, Option<PathBuf>>,
}

/// How many steps are we willing to take in resolving a path?
const MAX_STEPS: usize = 1024;

impl ResolvePath {
    /// Create a new empty ResolvePath.
    fn empty() -> Self {
        ResolvePath {
            resolved: PathBuf::new(),
            stack: Vec::new(),
            terminated: false,
            steps_remaining: MAX_STEPS,
            already_inspected: HashMap::new(),
        }
    }
    /// Construct a new `ResolvePath` iterator to resolve the provided `path`.
    pub(crate) fn new(path: impl AsRef<Path>) -> Result<Self> {
        let mut resolve = Self::empty();
        let path = path.as_ref();
        // The path resolution algorithm will _end_ with resolving the path we
        // were provided...
        push_prefix(&mut resolve.stack, path);
        // ...and if if the path is relative, we will first resolve the current
        // directory.
        if path.is_relative() {
            // This can fail, sadly.
            let cwd = std::env::current_dir().map_err(|e| Error::CurrentDirectory(Arc::new(e)))?;
            if !cwd.is_absolute() {
                // This should be impossible, but let's make sure.
                let ioe = io::Error::new(
                    io::ErrorKind::Other,
                    format!("Current directory {:?} was not absolute.", cwd),
                );
                return Err(Error::CurrentDirectory(Arc::new(ioe)));
            }
            push_prefix(&mut resolve.stack, cwd.as_ref());
        }

        Ok(resolve)
    }

    /// Consume this ResolvePath and return as much work as it was able to
    /// complete.
    ///
    /// If the path was completely resolved, then we return the resolved
    /// canonical path, and None.
    ///
    /// If the path was _not_ completely resolved (the loop terminated early, or
    /// ended with an error), we return the part that we were able to resolve,
    /// and a path that would need to be joined onto it to reach the intended
    /// destination.
    pub(crate) fn into_result(self) -> (PathBuf, Option<PathBuf>) {
        let remainder = if self.stack.is_empty() {
            None
        } else {
            Some(self.stack.into_iter().rev().map(|c| c.text).collect())
        };

        (self.resolved, remainder)
    }
}

/// Push the string representation of each component of `path` onto `stack`,
/// from last to first, so that the first component of `path` winds up on the
/// top of the stack.
///
/// (This is a separate function rather than a method for borrow-checker
/// reasons.)
fn push_prefix(stack: &mut Vec<Component>, path: &Path) {
    stack.extend(path.components().rev().map(|component| component.into()));
}

impl Iterator for ResolvePath {
    type Item = Result<(PathBuf, PathType, Metadata)>;

    fn next(&mut self) -> Option<Self::Item> {
        // Usually we'll return a value from our first attempt at this loop; we
        // only call "continue" if we encounter a path that we have already
        // given the caller.
        loop {
            // If we're fused, we're fused.  Nothing more to do.
            if self.terminated {
                return None;
            }
            // We will necessarily take at least `stack.len()` more steps: if we
            // don't have that many steps left, we cannot succeed.  Probably
            // this indicates a symlink loop, though it could also be a maze of
            // some kind.
            //
            // TODO: Arguably, we should keep taking steps until we run out, but doing
            // so might potentially lead to our stack getting huge.  This way we
            // keep the stack depth under control.
            if self.steps_remaining < self.stack.len() {
                self.terminated = true;
                return Some(Err(Error::StepsExceeded));
            }

            // Look at the next component on the stack...
            let next_part = match self.stack.pop() {
                Some(p) => p,
                None => {
                    // This is the successful case: we have finished resolving every component on the stack.
                    self.terminated = true;
                    return None;
                }
            };
            self.steps_remaining -= 1;

            // ..and add that component to our resolved path to see what we
            // should inspect next.
            let inspecting: std::borrow::Cow<'_, Path> = if next_part.text == "." {
                // Do nothing.
                self.resolved.as_path().into()
            } else if next_part.text == ".." {
                // We can safely remove the last part of our path: We know it is
                // canonical, so ".." will not give surprising results.  (If we
                // are already at the root, "PathBuf::pop" will do nothing.)
                self.resolved
                    .parent()
                    .unwrap_or(self.resolved.as_path())
                    .into()
            } else {
                // We extend our path.  This may _temporarily_ make `resolved`
                // non-canonical if next_part is the name of a symlink; we'll
                // fix that in a minute.
                //
                // This is the only thing that can ever make `resolved` longer.
                self.resolved.join(&next_part.text).into()
            };

            // Now "inspecting" is the path we want to look at.  Later in this
            // function, we should replace "self.resolved" with "inspecting" if we
            // find that "inspecting" is a good canonical path.

            match self.already_inspected.get(inspecting.as_ref()) {
                Some(Some(link_target)) => {
                    // We already inspected this path, and it is a symlink.
                    // Follow it, and loop.
                    //
                    // (See notes below starting with "This is a symlink!" for
                    // more explanation of what we're doing here.)
                    push_prefix(&mut self.stack, link_target.as_path());
                    continue;
                }
                Some(None) => {
                    // We've already inspected this path, and it's canonical.
                    // We told the caller about it once before, so we just loop.
                    self.resolved = inspecting.into_owned();
                    continue;
                }
                None => {
                    // We haven't seen this path before. Carry on.
                }
            }

            // Look up the lstat() of the file, to see if it's a symlink.
            let metadata = match inspecting.symlink_metadata() {
                Ok(m) => m,
                #[cfg(target_family = "windows")]
                Err(e)
                    if next_part.is_windows_prefix
                        && e.raw_os_error() == Some(INVALID_FUNCTION) =>
                {
                    // We expected an error here, and we got one. Skip over this
                    // path component and look at the next.
                    self.resolved = inspecting.into_owned();
                    continue;
                }
                Err(e) => {
                    // Oops: can't lstat.  Move the last component back on to the stack, and terminate.
                    self.stack.push(next_part);
                    self.terminated = true;
                    return Some(Err(Error::inspecting(e, inspecting)));
                }
            };

            if metadata.file_type().is_symlink() {
                // This is a symlink!
                //
                // We have to find out where it leads us...
                let link_target = match inspecting.read_link() {
                    Ok(t) => t,
                    Err(e) => {
                        // Oops: can't readlink.  Move the last component back on to the stack, and terminate.
                        self.stack.push(next_part);
                        self.terminated = true;
                        return Some(Err(Error::inspecting(e, inspecting)));
                    }
                };

                // We don't modify self.resolved here: we would be putting a
                // symlink onto it, and symlinks aren't canonical.  (If the
                // symlink is relative, then we'll continue resolving it from
                // its target on the next iteration.  If the symlink is
                // absolute, its first component will be "/" or the equivalent,
                // which will replace self.resolved.)
                push_prefix(&mut self.stack, link_target.as_path());
                self.already_inspected
                    .insert(inspecting.to_path_buf(), Some(link_target));
                // We yield the link name, not the value of resolved.
                return Some(Ok((inspecting.into_owned(), PathType::Symlink, metadata)));
            } else {
                // It's not a symlink: Therefore it is a real canonical
                // directory or file that exists.
                self.already_inspected
                    .insert(inspecting.to_path_buf(), None);
                self.resolved = inspecting.into_owned();
                let path_type = if self.stack.is_empty() {
                    PathType::Final
                } else {
                    PathType::Intermediate
                };
                return Some(Ok((self.resolved.clone(), path_type, metadata)));
            }
        }
    }
}

impl FusedIterator for ResolvePath {}

/*
   Not needed, but can be a big help with debugging.
impl std::fmt::Display for ResolvePath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let remaining: PathBuf = self.stack.iter().rev().collect();
        write!(f, "{{ {:?} }}/{{ {:?} }}", &self.resolved, remaining,)
    }
}
*/

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    use crate::testing;

    #[cfg(target_family = "unix")]
    use crate::testing::LinkType;

    /// Helper: skip `r` past the first occurrence of the path `p` in a
    /// successful return.
    fn skip_past(r: &mut ResolvePath, p: impl AsRef<Path>) {
        #[allow(clippy::manual_flatten)]
        for item in r {
            if let Ok((name, _, _)) = item {
                if name == p.as_ref() {
                    break;
                }
            }
        }
    }

    /// Helper: change the prefix on `path` (if any) to a verbatim prefix.
    ///
    /// We do this to match the output of `fs::canonicalize` on Windows, for
    /// testing.
    ///
    /// If this function proves to be hard-to-maintain, we should consider
    /// alternative ways of testing what it provides.
    fn make_prefix_verbatim(path: PathBuf) -> PathBuf {
        let mut components = path.components();
        if let Some(std::path::Component::Prefix(prefix)) = components.next() {
            use std::path::Prefix as P;
            let verbatim = match prefix.kind() {
                P::UNC(server, share) => {
                    let mut p = OsString::from(r"\\?\UNC\");
                    p.push(server);
                    p.push("/");
                    p.push(share);
                    p
                }
                P::Disk(disk) => format!(r"\\?\{}:", disk as char).into(),
                _ => return path, // original prefix is fine.
            };
            let mut newpath = PathBuf::from(verbatim);
            newpath.extend(components.map(|c| c.as_os_str()));
            newpath
        } else {
            path // nothing to do.
        }
    }

    #[test]
    fn simple_path() {
        let d = testing::Dir::new();
        let root = d.canonical_root();

        // Try resolving a simple path that exists.
        d.file("a/b/c");
        let mut r = ResolvePath::new(d.path("a/b/c")).unwrap();
        skip_past(&mut r, root);
        let mut so_far = root.to_path_buf();
        for (c, p) in Path::new("a/b/c").components().zip(&mut r) {
            let (p, pt, meta) = p.unwrap();
            if pt == PathType::Final {
                assert_eq!(c.as_os_str(), "c");
                assert!(meta.is_file());
            } else {
                assert_eq!(pt, PathType::Intermediate);
                assert!(meta.is_dir());
            }
            so_far.push(c);
            assert_eq!(so_far, p);
        }
        let (canonical, rest) = r.into_result();
        assert_eq!(canonical, d.path("a/b/c").canonicalize().unwrap());
        assert!(rest.is_none());

        // Same as above, starting from a relative path to the target.
        let mut r = ResolvePath::new(d.relative_root().join("a/b/c")).unwrap();
        skip_past(&mut r, root);
        let mut so_far = root.to_path_buf();
        for (c, p) in Path::new("a/b/c").components().zip(&mut r) {
            let (p, pt, meta) = p.unwrap();
            if pt == PathType::Final {
                assert_eq!(c.as_os_str(), "c");
                assert!(meta.is_file());
            } else {
                assert_eq!(pt, PathType::Intermediate);
                assert!(meta.is_dir());
            }
            so_far.push(c);
            assert_eq!(so_far, p);
        }
        let (canonical, rest) = r.into_result();
        let canonical = make_prefix_verbatim(canonical);
        assert_eq!(canonical, d.path("a/b/c").canonicalize().unwrap());
        assert!(rest.is_none());

        // Try resolving a simple path that doesn't exist.
        let mut r = ResolvePath::new(d.path("a/xxx/yyy")).unwrap();
        skip_past(&mut r, root);
        let (p, pt, _) = r.next().unwrap().unwrap();
        assert_eq!(p, root.join("a"));
        assert_eq!(pt, PathType::Intermediate);
        let e = r.next().unwrap();
        match e {
            Err(Error::NotFound(p)) => assert_eq!(p, root.join("a/xxx")),
            other => panic!("{:?}", other),
        }
        let (start, rest) = r.into_result();
        assert_eq!(start, d.path("a").canonicalize().unwrap());
        assert_eq!(rest.unwrap(), Path::new("xxx/yyy"));
    }

    #[test]
    #[cfg(target_family = "unix")]
    fn repeats() {
        let d = testing::Dir::new();
        let root = d.canonical_root();

        // We're going to try a path with ..s in it, and make sure that we only
        // get each given path once.
        d.dir("a/b/c/d");
        let mut r = ResolvePath::new(root.join("a/b/../b/../b/c/../c/d")).unwrap();
        skip_past(&mut r, root);
        let paths: Vec<_> = r.map(|item| item.unwrap().0).collect();
        assert_eq!(
            paths,
            vec![
                root.join("a"),
                root.join("a/b"),
                root.join("a/b/c"),
                root.join("a/b/c/d"),
            ]
        );

        // Now try a symlink to a higher directory, and make sure we only get
        // each path once.
        d.link_rel(LinkType::Dir, "../../", "a/b/c/rel_lnk");
        let mut r = ResolvePath::new(root.join("a/b/c/rel_lnk/b/c/d")).unwrap();
        skip_past(&mut r, root);
        let paths: Vec<_> = r.map(|item| item.unwrap().0).collect();
        assert_eq!(
            paths,
            vec![
                root.join("a"),
                root.join("a/b"),
                root.join("a/b/c"),
                root.join("a/b/c/rel_lnk"),
                root.join("a/b/c/d"),
            ]
        );

        // Once more, with an absolute symlink.
        d.link_abs(LinkType::Dir, "a", "a/b/c/abs_lnk");
        let mut r = ResolvePath::new(root.join("a/b/c/abs_lnk/b/c/d")).unwrap();
        skip_past(&mut r, root);
        let paths: Vec<_> = r.map(|item| item.unwrap().0).collect();
        assert_eq!(
            paths,
            vec![
                root.join("a"),
                root.join("a/b"),
                root.join("a/b/c"),
                root.join("a/b/c/abs_lnk"),
                root.join("a/b/c/d"),
            ]
        );

        // One more, with multiple links.
        let mut r = ResolvePath::new(root.join("a/b/c/abs_lnk/b/c/rel_lnk/b/c/d")).unwrap();
        skip_past(&mut r, root);
        let paths: Vec<_> = r.map(|item| item.unwrap().0).collect();
        assert_eq!(
            paths,
            vec![
                root.join("a"),
                root.join("a/b"),
                root.join("a/b/c"),
                root.join("a/b/c/abs_lnk"),
                root.join("a/b/c/rel_lnk"),
                root.join("a/b/c/d"),
            ]
        );

        // Last time, visiting the same links more than once.
        let mut r =
            ResolvePath::new(root.join("a/b/c/abs_lnk/b/c/rel_lnk/b/c/rel_lnk/b/c/abs_lnk/b/c/d"))
                .unwrap();
        skip_past(&mut r, root);
        let paths: Vec<_> = r.map(|item| item.unwrap().0).collect();
        assert_eq!(
            paths,
            vec![
                root.join("a"),
                root.join("a/b"),
                root.join("a/b/c"),
                root.join("a/b/c/abs_lnk"),
                root.join("a/b/c/rel_lnk"),
                root.join("a/b/c/d"),
            ]
        );
    }

    #[test]
    #[cfg(target_family = "unix")]
    fn looping() {
        let d = testing::Dir::new();
        let root = d.canonical_root();

        d.dir("a/b/c");
        // This file links to itself.  We should hit our loop detector and barf.
        d.link_rel(LinkType::File, "../../b/c/d", "a/b/c/d");
        let mut r = ResolvePath::new(root.join("a/b/c/d")).unwrap();
        skip_past(&mut r, root);
        assert_eq!(r.next().unwrap().unwrap().0, root.join("a"));
        assert_eq!(r.next().unwrap().unwrap().0, root.join("a/b"));
        assert_eq!(r.next().unwrap().unwrap().0, root.join("a/b/c"));
        assert_eq!(r.next().unwrap().unwrap().0, root.join("a/b/c/d"));
        assert!(matches!(
            r.next().unwrap().unwrap_err(),
            Error::StepsExceeded
        ));
        assert!(r.next().is_none());

        // These directories link to each other.
        d.link_rel(LinkType::Dir, "./f", "a/b/c/e");
        d.link_rel(LinkType::Dir, "./e", "a/b/c/f");
        let mut r = ResolvePath::new(root.join("a/b/c/e/413")).unwrap();
        skip_past(&mut r, root);
        assert_eq!(r.next().unwrap().unwrap().0, root.join("a"));
        assert_eq!(r.next().unwrap().unwrap().0, root.join("a/b"));
        assert_eq!(r.next().unwrap().unwrap().0, root.join("a/b/c"));
        assert_eq!(r.next().unwrap().unwrap().0, root.join("a/b/c/e"));
        assert_eq!(r.next().unwrap().unwrap().0, root.join("a/b/c/f"));
        assert!(matches!(
            r.next().unwrap().unwrap_err(),
            Error::StepsExceeded
        ));
        assert!(r.next().is_none());
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn unix_permissions() {
        use std::os::unix::prelude::PermissionsExt;

        let d = testing::Dir::new();
        let root = d.canonical_root();
        d.dir("a/b/c/d/e");
        d.chmod("a", 0o751);
        d.chmod("a/b", 0o711);
        d.chmod("a/b/c", 0o715);
        d.chmod("a/b/c/d", 0o000);

        let mut r = ResolvePath::new(root.join("a/b/c/d/e/413")).unwrap();
        skip_past(&mut r, root);
        let resolvable: Vec<_> = (&mut r)
            .take(4)
            .map(|item| {
                let (p, _, m) = item.unwrap();
                (
                    p.strip_prefix(root).unwrap().to_string_lossy().into_owned(),
                    m.permissions().mode() & 0o777,
                )
            })
            .collect();
        let expected = vec![
            ("a", 0o751),
            ("a/b", 0o711),
            ("a/b/c", 0o715),
            ("a/b/c/d", 0o000),
        ];
        for ((p1, m1), (p2, m2)) in resolvable.iter().zip(expected.iter()) {
            assert_eq!(p1, p2);
            assert_eq!(m1, m2);
        }

        if pwd_grp::getuid() == 0 {
            // We won't actually get a CouldNotInspect if we're running as root,
            // since root can read directories that are mode 000.
            return;
        }

        let err = r.next().unwrap();
        assert!(matches!(err, Err(Error::CouldNotInspect(_, _))));

        assert!(r.next().is_none());
    }

    #[test]
    fn past_root() {
        let d = testing::Dir::new();
        let root = d.canonical_root();
        d.dir("a/b");
        d.chmod("a", 0o700);
        d.chmod("a/b", 0o700);

        let root_as_relative: PathBuf = root
            .components()
            .filter(|c| matches!(c, std::path::Component::Normal(_)))
            .collect();
        let n = root.components().count();
        // Start with our the "root" directory of our Dir...
        let mut inspect_path = root.to_path_buf();
        // Then go way past the root of the filesystem
        for _ in 0..n * 2 {
            inspect_path.push("..");
        }
        // Then back down to the "root" directory of the dir..
        inspect_path.push(root_as_relative);
        // Then to a/b.
        inspect_path.push("a/b");

        let r = ResolvePath::new(inspect_path.clone()).unwrap();
        let final_path = r.last().unwrap().unwrap().0;
        assert_eq!(final_path, inspect_path.canonicalize().unwrap());
    }
}
