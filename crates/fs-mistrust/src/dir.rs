//! Implement a wrapper for access to the members of a directory whose status
//! we've checked.

use std::{
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
};

use crate::{walk::PathType, Error, Mistrust, Result, Verifier};

#[cfg(target_family = "unix")]
use std::os::unix::fs::OpenOptionsExt;

/// A directory whose access properties we have verified, along with accessor
/// functions to access members of that directory.
///
/// The accessor functions will enforce that whatever security properties we
/// checked on the the directory also apply to all of the members that we access
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
        mistrust.ignore_prefix(path)?;
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
        let path = path.as_ref();
        self.check_path(path)?;
        let path = self.location.join(path);
        if let Some(parent) = path.parent() {
            self.verifier().check(parent)?;
        }

        #[allow(unused_mut)]
        let mut options = options.clone();

        #[cfg(target_family = "unix")]
        {
            // By default, create all files mode 600, no matter what
            // OpenOptions said.

            // TODO: Give some way to override this to 640 or 0644 if you
            //    really want to.
            options.mode(0o600);
            // Don't follow symlinks out of the secured directory.
            options.custom_flags(libc::O_NOFOLLOW);
        }

        let file = options
            .open(&path)
            .map_err(|e| Error::inspecting(e, &path))?;
        let meta = file.metadata().map_err(|e| Error::inspecting(e, &path))?;

        if let Some(error) = self
            .verifier()
            .check_one(path.as_path(), PathType::Content, &meta)
            .into_iter()
            .next()
        {
            Err(error)
        } else {
            Ok(file)
        }
    }

    /// Return a reference to this directory as a [`Path`].
    ///
    /// Note that this function lets you work with a broader collection of
    /// functions, including functions that might let you access or create a
    /// file that is accessible by non-trusted users.  Be careful!
    pub fn as_path(&self) -> &Path {
        self.location.as_path()
    }

    /// Helper: create a [`Verifier`] with the appropriate rules for this
    /// `CheckedDir`.
    fn verifier(&self) -> Verifier<'_> {
        let mut v = self.mistrust.verifier();
        if self.readable_okay {
            v = v.permit_readable();
        }
        v
    }

    /// Helper: Make sure that the path `p` is a relative path that can be
    /// guaranteed to stay within this directory.
    fn check_path(&self, p: &Path) -> Result<()> {
        use std::path::Component;
        if p.is_absolute() {}

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
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]
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

        let mut m = Mistrust::new();
        m.ignore_prefix(d.canonical_root()).unwrap();

        let sd = m.verifier().secure_dir(d.path("a/b")).unwrap();

        // Try make_directory.
        sd.make_directory("c/sub1").unwrap();
        #[cfg(target_family = "unix")]
        {
            let e = sd.make_directory("d/sub2").unwrap_err();
            assert!(matches!(e, Error::BadPermission(_, _)));
        }

        // Try opening a file that exists.
        let f1 = sd.open("c/f1", OpenOptions::new().read(true)).unwrap();
        drop(f1);
        #[cfg(target_family = "unix")]
        {
            let e = sd.open("c/f2", OpenOptions::new().read(true)).unwrap_err();
            assert!(matches!(e, Error::BadPermission(_, _)));
            let e = sd.open("d/f3", OpenOptions::new().read(true)).unwrap_err();
            assert!(matches!(e, Error::BadPermission(_, _)));
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
            assert!(matches!(e, Error::BadPermission(_, _)));
        }
    }

    #[test]
    fn bad_paths() {
        let d = Dir::new();
        d.dir("a");
        d.chmod("a", 0o700);

        let mut m = Mistrust::new();
        m.ignore_prefix(d.canonical_root()).unwrap();

        let sd = m.verifier().secure_dir(d.path("a")).unwrap();

        let e = sd.make_directory("hello/../world").unwrap_err();
        assert!(matches!(e, Error::InvalidSubdirectory));
        let e = sd.make_directory("/hello").unwrap_err();
        assert!(matches!(e, Error::InvalidSubdirectory));

        sd.make_directory("hello/world").unwrap();
    }
}
