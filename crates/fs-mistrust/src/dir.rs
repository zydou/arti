//! Implement a wrapper for access to the members of a directory whose status
//! we've checked.

use std::{
    fs::{File, Metadata, OpenOptions},
    io,
    path::{Path, PathBuf},
};

use crate::{walk::PathType, Error, Mistrust, Result, Verifier};

/// A directory whose access properties we have verified, along with accessor
/// functions to access members of that directory.
///
/// The accessor functions will enforce that whatever security properties we
/// checked on the directory also apply to all of the members that we access
/// within the directory.
///
/// ## Limitations
///
/// Having a `CheckedDir` means only that, at the time it was created, we were
/// confident that no _untrusted_ user could access it inappropriately.  It is
/// still possible, after the `CheckedDir` is created, that a _trusted_ user can
/// alter its permissions, make its path point somewhere else, or so forth.
///
/// If this kind of time-of-use/time-of-check issue is unacceptable, you may
/// wish to look at other solutions, possibly involving `openat()` or related
/// APIs.
///
/// See also the crate-level [Limitations](crate#limitations) section.
#[derive(Debug, Clone)]
pub struct CheckedDir {
    /// The `Mistrust` object whose rules we apply to members of this directory.
    mistrust: Mistrust,
    /// The location of this directory, in its original form.
    location: PathBuf,
    /// The "readable_okay" flag that we used to create this CheckedDir.
    readable_okay: bool,
}

impl CheckedDir {
    /// Create a CheckedDir.
    pub(crate) fn new(verifier: &Verifier<'_>, path: &Path) -> Result<Self> {
        let mut mistrust = verifier.mistrust.clone();
        // Ignore the path that we already verified.  Since ignore_prefix
        // canonicalizes the path, we _will_ recheck the directory if it starts
        // pointing to a new canonical location.  That's probably a feature.
        //
        // TODO:
        //   * If `path` is a prefix of the original ignored path, this will
        //     make us ignore _less_.
        mistrust.ignore_prefix = crate::canonicalize_opt_prefix(&Some(Some(path.to_path_buf())))?;
        Ok(CheckedDir {
            mistrust,
            location: path.to_path_buf(),
            readable_okay: verifier.readable_okay,
        })
    }

    /// Construct a new directory within this CheckedDir, if it does not already
    /// exist.
    ///
    /// `path` must be a relative path to the new directory, containing no `..`
    /// components.
    pub fn make_directory<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let path = path.as_ref();
        self.check_path(path)?;
        self.verifier().make_directory(self.location.join(path))
    }

    /// Construct a new `CheckedDir` within this `CheckedDir`
    ///
    /// Creates the directory if it does not already exist.
    ///
    /// `path` must be a relative path to the new directory, containing no `..`
    /// components.
    pub fn make_secure_directory<P: AsRef<Path>>(&self, path: P) -> Result<CheckedDir> {
        let path = path.as_ref();
        self.make_directory(path)?;
        // TODO I think this rechecks parents, but it need not, since we already did that.
        self.verifier().secure_dir(self.location.join(path))
    }

    /// Create a new [`FileAccess`](crate::FileAccess) for reading or writing files within this directory.
    pub fn file_access(&self) -> crate::FileAccess<'_> {
        crate::FileAccess::from_checked_dir(self)
    }

    /// Open a file within this CheckedDir, using a set of [`OpenOptions`].
    ///
    /// `path` must be a relative path to the new directory, containing no `..`
    /// components.  We check, but do not create, the file's parent directories.
    /// We check the file's permissions after opening it.  If the file already
    /// exists, it must not be a symlink.
    ///
    /// If the file is created (and this is a unix-like operating system), we
    /// always create it with mode `600`, regardless of any mode options set in
    /// `options`.
    pub fn open<P: AsRef<Path>>(&self, path: P, options: &OpenOptions) -> Result<File> {
        self.file_access().open(path, options)
    }

    /// List the contents of a directory within this [`CheckedDir`].
    ///
    /// `path` must be a relative path, containing no `..` components.  Before
    /// listing the directory, we verify that that no untrusted user is able
    /// change its contents or make it point somewhere else.
    ///
    /// The return value is an iterator as returned by [`std::fs::ReadDir`].  We
    /// _do not_ check any properties of the elements of this iterator.
    pub fn read_directory<P: AsRef<Path>>(&self, path: P) -> Result<std::fs::ReadDir> {
        let path = self.verified_full_path(path.as_ref(), FullPathCheck::CheckPath)?;

        std::fs::read_dir(&path).map_err(|e| Error::io(e, path, "read directory"))
    }

    /// Remove a file within this [`CheckedDir`].
    ///
    /// `path` must be a relative path, containing no `..` components.
    ///
    /// Note that we ensure that the _parent_ of the file to be removed is
    /// unmodifiable by any untrusted user, but we do not check any permissions
    /// on the file itself, since those are irrelevant to removing it.
    pub fn remove_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        // We insist that the ownership and permissions on everything up to and
        // including the _parent_ of the path that we are removing have to be
        // correct.  (If it were otherwise, we could be tricked into removing
        // the wrong thing.)  But we don't care about the permissions on file we
        // are removing.
        let path = self.verified_full_path(path.as_ref(), FullPathCheck::CheckParent)?;

        std::fs::remove_file(&path).map_err(|e| Error::io(e, path, "remove file"))
    }

    /// Return a reference to this directory as a [`Path`].
    ///
    /// Note that this function lets you work with a broader collection of
    /// functions, including functions that might let you access or create a
    /// file that is accessible by non-trusted users.  Be careful!
    pub fn as_path(&self) -> &Path {
        self.location.as_path()
    }

    /// Return a new [`PathBuf`] containing this directory's path, with `path`
    /// appended to it.
    ///
    /// Return an error if `path` has any components that could take us outside
    /// of this directory.
    pub fn join<P: AsRef<Path>>(&self, path: P) -> Result<PathBuf> {
        let path = path.as_ref();
        self.check_path(path)?;
        Ok(self.location.join(path))
    }

    /// Read the contents of the file at `path` within this directory, as a
    /// String, if possible.
    ///
    /// Return an error if `path` is absent, if its permissions are incorrect,
    /// if it has any components that could take us outside of this directory,
    /// or if its contents are not UTF-8.
    pub fn read_to_string<P: AsRef<Path>>(&self, path: P) -> Result<String> {
        self.file_access().read_to_string(path)
    }

    /// Read the contents of the file at `path` within this directory, as a
    /// vector of bytes, if possible.
    ///
    /// Return an error if `path` is absent, if its permissions are incorrect,
    /// or if it has any components that could take us outside of this
    /// directory.
    pub fn read<P: AsRef<Path>>(&self, path: P) -> Result<Vec<u8>> {
        self.file_access().read(path)
    }

    /// Store `contents` into the file located at `path` within this directory.
    ///
    /// We won't write to `path` directly: instead, we'll write to a temporary
    /// file in the same directory as `path`, and then replace `path` with that
    /// temporary file if we were successful.  (This isn't truly atomic on all
    /// file systems, but it's closer than many alternatives.)
    ///
    /// # Limitations
    ///
    /// This function will clobber any existing files with the same name as
    /// `path` but with the extension `tmp`.  (That is, if you are writing to
    /// "foo.txt", it will replace "foo.tmp" in the same directory.)
    ///
    /// This function may give incorrect behavior if multiple threads or
    /// processes are writing to the same file at the same time: it is the
    /// programmer's responsibility to use appropriate locking to avoid this.
    pub fn write_and_replace<P: AsRef<Path>, C: AsRef<[u8]>>(
        &self,
        path: P,
        contents: C,
    ) -> Result<()> {
        self.file_access().write_and_replace(path, contents)
    }

    /// Return the [`Metadata`] of the file located at `path`.
    ///
    /// `path` must be a relative path, containing no `..` components.
    /// We check the file's parent directories,
    /// and the file's permissions.
    /// If the file exists, it must not be a symlink.
    ///
    /// Returns [`Error::NotFound`] if the file does not exist.
    ///
    /// Return an error if `path` is absent, if its permissions are incorrect[^1],
    /// if the permissions of any of its the parent directories are incorrect,
    /// or if it has any components that could take us outside of this directory.
    ///
    /// [^1]: the permissions are incorrect if the path is readable or writable by untrusted users
    pub fn metadata<P: AsRef<Path>>(&self, path: P) -> Result<Metadata> {
        let path = self.verified_full_path(path.as_ref(), FullPathCheck::CheckParent)?;

        let meta = path
            .symlink_metadata()
            .map_err(|e| Error::inspecting(e, &path))?;

        if meta.is_symlink() {
            // TODO: this is inconsistent with CheckedDir::open()'s behavior, which returns a
            // FilesystemLoop io error in this case (we can't construct such an error here, because
            // ErrorKind::FilesystemLoop is only available on nightly)
            let err = io::Error::new(
                io::ErrorKind::Other,
                format!("Path {:?} is a symlink", path),
            );
            return Err(Error::io(err, &path, "metadata"));
        }

        if let Some(error) = self
            .verifier()
            .check_one(path.as_path(), PathType::Content, &meta)
            .into_iter()
            .next()
        {
            Err(error)
        } else {
            Ok(meta)
        }
    }

    /// Create a [`Verifier`] with the appropriate rules for this
    /// `CheckedDir`.
    pub fn verifier(&self) -> Verifier<'_> {
        let mut v = self.mistrust.verifier();
        if self.readable_okay {
            v = v.permit_readable();
        }
        v
    }

    /// Helper: Make sure that the path `p` is a relative path that can be
    /// guaranteed to stay within this directory.
    ///
    /// (Specifically, we reject absolute paths, ".." items, and Windows path prefixes.)
    fn check_path(&self, p: &Path) -> Result<()> {
        use std::path::Component;
        // This check should be redundant, but let's be certain.
        if p.is_absolute() {
            return Err(Error::InvalidSubdirectory);
        }

        for component in p.components() {
            match component {
                Component::Prefix(_) | Component::RootDir | Component::ParentDir => {
                    return Err(Error::InvalidSubdirectory)
                }
                Component::CurDir | Component::Normal(_) => {}
            }
        }

        Ok(())
    }

    /// Check whether `p` is a valid relative path within this directory,
    /// verify its permissions or the permissions of its parent, depending on `check_type`,
    /// and return an absolute path for `p`.
    pub(crate) fn verified_full_path(
        &self,
        p: &Path,
        check_type: FullPathCheck,
    ) -> Result<PathBuf> {
        self.check_path(p)?;
        let full_path = self.location.join(p);
        let to_verify: &Path = match check_type {
            FullPathCheck::CheckPath => full_path.as_ref(),
            FullPathCheck::CheckParent => full_path.parent().unwrap_or_else(|| full_path.as_ref()),
        };
        self.verifier().check(to_verify)?;

        Ok(full_path)
    }
}

/// Type argument for [`CheckedDir::verified_full_path`].
#[derive(Clone, Copy, Debug)]
pub(crate) enum FullPathCheck {
    /// Check all elements of the path, including the final element.
    CheckPath,
    /// Check all elements of the path, not including the final element.
    CheckParent,
}

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
    use crate::testing::Dir;
    use std::io::Write;

    #[test]
    fn easy_case() {
        let d = Dir::new();
        d.dir("a/b/c");
        d.dir("a/b/d");
        d.file("a/b/c/f1");
        d.file("a/b/c/f2");
        d.file("a/b/d/f3");

        d.chmod("a", 0o755);
        d.chmod("a/b", 0o700);
        d.chmod("a/b/c", 0o700);
        d.chmod("a/b/d", 0o777);
        d.chmod("a/b/c/f1", 0o600);
        d.chmod("a/b/c/f2", 0o666);
        d.chmod("a/b/d/f3", 0o600);

        let m = Mistrust::builder()
            .ignore_prefix(d.canonical_root())
            .build()
            .unwrap();

        let sd = m.verifier().secure_dir(d.path("a/b")).unwrap();

        // Try make_directory.
        sd.make_directory("c/sub1").unwrap();
        #[cfg(target_family = "unix")]
        {
            let e = sd.make_directory("d/sub2").unwrap_err();
            assert!(matches!(e, Error::BadPermission(..)));
        }

        // Try opening a file that exists.
        let f1 = sd.open("c/f1", OpenOptions::new().read(true)).unwrap();
        drop(f1);
        #[cfg(target_family = "unix")]
        {
            let e = sd.open("c/f2", OpenOptions::new().read(true)).unwrap_err();
            assert!(matches!(e, Error::BadPermission(..)));
            let e = sd.open("d/f3", OpenOptions::new().read(true)).unwrap_err();
            assert!(matches!(e, Error::BadPermission(..)));
        }

        // Try creating a file.
        let mut f3 = sd
            .open("c/f-new", OpenOptions::new().write(true).create(true))
            .unwrap();
        f3.write_all(b"Hello world").unwrap();
        drop(f3);

        #[cfg(target_family = "unix")]
        {
            let e = sd
                .open("d/f-new", OpenOptions::new().write(true).create(true))
                .unwrap_err();
            assert!(matches!(e, Error::BadPermission(..)));
        }
    }

    #[test]
    fn bad_paths() {
        let d = Dir::new();
        d.dir("a");
        d.chmod("a", 0o700);

        let m = Mistrust::builder()
            .ignore_prefix(d.canonical_root())
            .build()
            .unwrap();

        let sd = m.verifier().secure_dir(d.path("a")).unwrap();

        let e = sd.make_directory("hello/../world").unwrap_err();
        assert!(matches!(e, Error::InvalidSubdirectory));
        let e = sd.metadata("hello/../world").unwrap_err();
        assert!(matches!(e, Error::InvalidSubdirectory));

        let e = sd.make_directory("/hello").unwrap_err();
        assert!(matches!(e, Error::InvalidSubdirectory));
        let e = sd.metadata("/hello").unwrap_err();
        assert!(matches!(e, Error::InvalidSubdirectory));

        sd.make_directory("hello/world").unwrap();
    }

    #[test]
    fn read_and_write() {
        let d = Dir::new();
        d.dir("a");
        d.chmod("a", 0o700);
        let m = Mistrust::builder()
            .ignore_prefix(d.canonical_root())
            .build()
            .unwrap();

        let checked = m.verifier().secure_dir(d.path("a")).unwrap();

        // Simple case: write and read.
        checked
            .write_and_replace("foo.txt", "this is incredibly silly")
            .unwrap();

        let s1 = checked.read_to_string("foo.txt").unwrap();
        let s2 = checked.read("foo.txt").unwrap();
        assert_eq!(s1, "this is incredibly silly");
        assert_eq!(s1.as_bytes(), &s2[..]);

        // Checked subdirectory
        let sub = "sub";
        let sub_checked = checked.make_secure_directory(sub).unwrap();
        assert_eq!(sub_checked.as_path(), checked.as_path().join(sub));

        // Trickier: write when the preferred temporary already has content.
        checked
            .open("bar.tmp", OpenOptions::new().create(true).write(true))
            .unwrap()
            .write_all("be the other guy".as_bytes())
            .unwrap();
        assert!(checked.join("bar.tmp").unwrap().try_exists().unwrap());

        checked
            .write_and_replace("bar.txt", "its hard and nobody understands")
            .unwrap();

        // Temp file should be gone.
        assert!(!checked.join("bar.tmp").unwrap().try_exists().unwrap());
        let s4 = checked.read_to_string("bar.txt").unwrap();
        assert_eq!(s4, "its hard and nobody understands");
    }

    #[test]
    fn read_directory() {
        let d = Dir::new();
        d.dir("a");
        d.chmod("a", 0o700);
        d.dir("a/b");
        d.file("a/b/f");
        d.file("a/c.d");
        d.dir("a/x");

        d.chmod("a", 0o700);
        d.chmod("a/b", 0o700);
        d.chmod("a/x", 0o777);
        let m = Mistrust::builder()
            .ignore_prefix(d.canonical_root())
            .build()
            .unwrap();

        let checked = m.verifier().secure_dir(d.path("a")).unwrap();

        assert!(matches!(
            checked.read_directory("/"),
            Err(Error::InvalidSubdirectory)
        ));
        assert!(matches!(
            checked.read_directory("b/.."),
            Err(Error::InvalidSubdirectory)
        ));
        let mut members: Vec<String> = checked
            .read_directory(".")
            .unwrap()
            .map(|ent| ent.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        members.sort();
        assert_eq!(members, vec!["b", "c.d", "x"]);

        let members: Vec<String> = checked
            .read_directory("b")
            .unwrap()
            .map(|ent| ent.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(members, vec!["f"]);

        #[cfg(target_family = "unix")]
        {
            assert!(matches!(
                checked.read_directory("x"),
                Err(Error::BadPermission(_, _, _))
            ));
        }
    }

    #[test]
    fn remove_file() {
        let d = Dir::new();
        d.dir("a");
        d.chmod("a", 0o700);
        d.dir("a/b");
        d.file("a/b/f");
        d.dir("a/b/d");
        d.dir("a/x");
        d.dir("a/x/y");
        d.file("a/x/y/z");

        d.chmod("a", 0o700);
        d.chmod("a/b", 0o700);
        d.chmod("a/x", 0o777);

        let m = Mistrust::builder()
            .ignore_prefix(d.canonical_root())
            .build()
            .unwrap();
        let checked = m.verifier().secure_dir(d.path("a")).unwrap();

        // Remove a file that is there, and then make sure it is gone.
        assert!(checked.read_to_string("b/f").is_ok());
        assert!(checked.metadata("b/f").unwrap().is_file());
        checked.remove_file("b/f").unwrap();
        assert!(matches!(
            checked.read_to_string("b/f"),
            Err(Error::NotFound(_))
        ));
        assert!(matches!(checked.metadata("b/f"), Err(Error::NotFound(_))));
        assert!(matches!(
            checked.remove_file("b/f"),
            Err(Error::NotFound(_))
        ));

        // Remove a file in a nonexistent subdirectory
        assert!(matches!(
            checked.remove_file("b/xyzzy/fred"),
            Err(Error::NotFound(_))
        ));

        // Remove a file in a directory whose permissions are too open.
        #[cfg(target_family = "unix")]
        {
            assert!(matches!(
                checked.remove_file("x/y/z"),
                Err(Error::BadPermission(_, _, _))
            ));
            assert!(matches!(
                checked.metadata("x/y/z"),
                Err(Error::BadPermission(_, _, _))
            ));
        }
    }

    #[test]
    #[cfg(target_family = "unix")]
    fn access_symlink() {
        use crate::testing::LinkType;

        let d = Dir::new();
        d.dir("a/b");
        d.file("a/b/f1");

        d.chmod("a/b", 0o700);
        d.chmod("a/b/f1", 0o600);
        d.link_rel(LinkType::File, "f1", "a/b/f1-link");

        let m = Mistrust::builder()
            .ignore_prefix(d.canonical_root())
            .build()
            .unwrap();

        let sd = m.verifier().secure_dir(d.path("a/b")).unwrap();

        assert!(sd.open("f1", OpenOptions::new().read(true)).is_ok());

        // Metadata returns an error if called on a symlink
        let e = sd.metadata("f1-link").unwrap_err();
        assert!(
            matches!(e, Error::Io { ref err, .. } if err.to_string().contains("is a symlink")),
            "{e:?}"
        );

        // Open returns an error if called on a symlink.
        let e = sd
            .open("f1-link", OpenOptions::new().read(true))
            .unwrap_err();
        assert!(
            matches!(e, Error::Io { ref err, .. } if err.to_string().contains("symbolic")), // Error is ELOOP.
            "{e:?}"
        );
    }
}
