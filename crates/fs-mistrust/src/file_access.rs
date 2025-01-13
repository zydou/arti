//! Functionality for opening files while verifying their permissions.

use std::{
    borrow::Cow,
    fs::{File, OpenOptions},
    io::{Read as _, Write},
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;

use crate::{dir::FullPathCheck, walk::PathType, CheckedDir, Error, Result, Verifier};

/// Helper object for accessing a file on disk while checking the necessary permissions.
///
/// You can use a `FileAccess` when you want to read or write a file,
/// while making sure that the file obeys the permissions rules of
/// an associated [`CheckedDir`] or [`Verifier`].
///
/// `FileAccess` is a separate type from `CheckedDir` and `Verifier`
/// so that you you can set options to control the behavior of how how files are opened.
///
/// Note: When we refer to a path "obeying the constraints" of this `FileAccess`,
/// we mean:
/// * If the `FileAccess` wraps a `CheckedDir`, the requirement that it is a relative path
///   containing no ".." elements,
///   or other elements that would take it outside the `CheckedDir`.
/// * If the `FileAccess` wraps a `Verifier`, there are no requirements.
pub struct FileAccess<'a> {
    /// Validator object that we use for checking file permissions.
    pub(crate) inner: Inner<'a>,
    /// If set, we create files with this mode.
    #[cfg(unix)]
    create_with_mode: Option<u32>,
}

/// Inner object for checking file permissions.
pub(crate) enum Inner<'a> {
    /// A CheckedDir backing this FileAccess.
    CheckedDir(&'a CheckedDir),
    /// A Verifier backing this FileAccess.
    Verifier(Verifier<'a>),
}

impl<'a> FileAccess<'a> {
    /// Create a new `FileAccess` to access files within CheckedDir,
    /// using default options.
    pub(crate) fn from_checked_dir(checked_dir: &'a CheckedDir) -> Self {
        Self::from_inner(Inner::CheckedDir(checked_dir))
    }
    /// Create a new `FileAccess` to access files anywhere on the filesystem,
    /// using default options.
    pub(crate) fn from_verifier(verifier: Verifier<'a>) -> Self {
        Self::from_inner(Inner::Verifier(verifier))
    }
    /// Create a new `FileAccess` from `inner`,
    /// using default options.
    fn from_inner(inner: Inner<'a>) -> Self {
        Self {
            inner,
            #[cfg(unix)]
            create_with_mode: None,
        }
    }
    /// Check path constraints on `path` and verify its permissions
    /// (or the permissions of its parent) according to `check_type`
    fn verified_full_path(&self, path: &Path, check_type: FullPathCheck) -> Result<PathBuf> {
        match &self.inner {
            Inner::CheckedDir(cd) => cd.verified_full_path(path, check_type),
            Inner::Verifier(v) => {
                let to_verify = match check_type {
                    FullPathCheck::CheckPath => path,
                    FullPathCheck::CheckParent => path.parent().unwrap_or(path),
                };
                v.check(to_verify)?;
                Ok(path.into())
            }
        }
    }
    /// Return a `Verifier` to use for checking permissions.
    fn verifier(&self) -> crate::Verifier {
        match &self.inner {
            Inner::CheckedDir(cd) => cd.verifier(),
            Inner::Verifier(v) => v.clone(),
        }
    }
    /// Return the location of `path` relative to this verifier.
    ///
    /// Fails if `path` does not obey the constraints of this `FileAccess`,
    /// but does not do any permissions checking.
    fn location_unverified<'b>(&self, path: &'b Path) -> Result<Cow<'b, Path>> {
        Ok(match self.inner {
            Inner::CheckedDir(cd) => cd.join(path)?.into(),
            Inner::Verifier(_) => path.into(),
        })
    }

    /// Configure this FileAccess: when used to crate a file,
    /// that file will be created with the provided unix permissions.
    ///
    /// (This only has an effect on unix, and has the effect of
    /// giving a newly created file mode 0644.  If this option
    /// is not set, newly created files have mode 0600.)
    pub fn create_with_mode(&mut self, mode: u32) -> &mut Self {
        #[cfg(unix)]
        {
            self.create_with_mode = Some(mode);
        }
        self
    }

    /// Open a file relative to this `FileAccess`, using a set of [`OpenOptions`].
    ///
    /// `path` must be a path to the new file, obeying the constraints of this `FileAccess`.
    /// We check, but do not create, the file's parent directories.
    /// We check the file's permissions after opening it.  
    ///
    /// If the file already exists, and this `FileAccess` is based on a `CheckedDir,
    /// the file must not be a symlink.
    ///
    /// If the file is created (and this is a unix-like operating system), we
    /// always create it with a mode based on [`create_with_mode()`](Self::create_with_mode),
    /// regardless of any mode set in `options`.
    /// If `create_with_mode()` wasn't called, we create the file with mode 600.
    pub fn open<P: AsRef<Path>>(&self, path: P, options: &OpenOptions) -> Result<File> {
        let follow_links = matches!(&self.inner, Inner::Verifier(_));

        // If we're following links, then we want to look at the whole path,
        // since the final element might be a link.  If so, we need to look at
        // where it is linking to, and validate that as well.
        let check_type = if follow_links {
            FullPathCheck::CheckPath
        } else {
            FullPathCheck::CheckParent
        };

        let path = match self.verified_full_path(path.as_ref(), check_type) {
            Ok(path) => path.into(),
            // We tolerate a not-found error if we're following links:
            // - If the final element of the path is what wasn't found, then we might create it
            //   ourselves when we open it.
            // - If an earlier element of the path wasn't found, we will get a second NotFound error
            //   when we try to open the file, which is okay.
            Err(Error::NotFound(_)) if follow_links => self.location_unverified(path.as_ref())?,
            Err(e) => return Err(e),
        };

        #[allow(unused_mut)]
        let mut options = options.clone();

        #[cfg(unix)]
        {
            let create_mode = self.create_with_mode.unwrap_or(0o600);
            options.mode(create_mode);
            // Don't follow symlinks out of a secure directory.
            if !follow_links {
                options.custom_flags(libc::O_NOFOLLOW);
            }
        }

        let file = options
            .open(&path)
            .map_err(|e| Error::io(e, path.as_ref(), "open file"))?;
        let meta = file
            .metadata()
            .map_err(|e| Error::inspecting(e, path.as_ref()))?;

        if let Some(error) = self
            .verifier()
            .check_one(path.as_ref(), PathType::Content, &meta)
            .into_iter()
            .next()
        {
            Err(error)
        } else {
            Ok(file)
        }
    }

    /// Read the contents of the file at `path` relative to this `FileAccess`, as a
    /// String, if possible.
    ///
    /// Return an error if `path` is absent, if its permissions are incorrect,
    /// if it does not obey the constraints of this `FileAccess`,
    /// or if its contents are not UTF-8.
    pub fn read_to_string<P: AsRef<Path>>(&self, path: P) -> Result<String> {
        let path = path.as_ref();
        let mut file = self.open(path, OpenOptions::new().read(true))?;
        let mut result = String::new();
        file.read_to_string(&mut result)
            .map_err(|e| Error::io(e, path, "read file"))?;
        Ok(result)
    }

    /// Read the contents of the file at `path` relative to this `FileAccess`, as a
    /// vector of bytes, if possible.
    ///
    /// Return an error if `path` is absent, if its permissions are incorrect,
    /// or if it does not obey the constraints of this `FileAccess`.
    pub fn read<P: AsRef<Path>>(&self, path: P) -> Result<Vec<u8>> {
        let path = path.as_ref();
        let mut file = self.open(path, OpenOptions::new().read(true))?;
        let mut result = Vec::new();
        file.read_to_end(&mut result)
            .map_err(|e| Error::io(e, path, "read file"))?;
        Ok(result)
    }

    /// Store `contents` into the file located at `path` relative to this `FileAccess`.
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
        let path = path.as_ref();
        let final_path = self.verified_full_path(path, FullPathCheck::CheckParent)?;

        let tmp_name = path.with_extension("tmp");
        // We remove the temporary file before opening it, if it's present: otherwise it _might_ be
        // a symlink to somewhere silly.
        let _ignore = std::fs::remove_file(&tmp_name);

        // TODO: The parent directory  verification performed by "open" here is redundant with that done in
        // `verified_full_path` above.
        let mut tmp_file = self.open(
            &tmp_name,
            OpenOptions::new().create(true).truncate(true).write(true),
        )?;

        // Write the data.
        tmp_file
            .write_all(contents.as_ref())
            .map_err(|e| Error::io(e, &tmp_name, "write to file"))?;
        // Flush and close.
        drop(tmp_file);

        // Replace the old file.
        std::fs::rename(
            // It's okay to use location_unverified here, since we already verified it when we
            // called `open`.
            self.location_unverified(tmp_name.as_path())?,
            final_path,
        )
        .map_err(|e| Error::io(e, path, "replace file"))?;
        Ok(())
    }
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

    use std::{fs, os::linux::fs::MetadataExt};

    use super::*;
    use crate::{testing::Dir, Mistrust};

    #[test]
    fn create_public_in_checked_dir() {
        let d = Dir::new();
        d.dir("a");

        d.chmod("a", 0o700);

        let m = Mistrust::builder()
            .ignore_prefix(d.canonical_root())
            .build()
            .unwrap();
        let checked = m.verifier().secure_dir(d.path("a")).unwrap();

        {
            let mut f = checked
                .file_access()
                .open(
                    "private-1.txt",
                    OpenOptions::new().write(true).create_new(true),
                )
                .unwrap();
            f.write_all(b"Hello world\n").unwrap();

            checked
                .file_access()
                .write_and_replace("private-2.txt", b"Hello world 2\n")
                .unwrap();
        }
        {
            let mut f = checked
                .file_access()
                .create_with_mode(0o640)
                .open(
                    "public-1.txt",
                    OpenOptions::new().write(true).create_new(true),
                )
                .unwrap();
            f.write_all(b"Hello wider world\n").unwrap();

            checked
                .file_access()
                .create_with_mode(0o644)
                .write_and_replace("public-2.txt", b"Hello wider world 2")
                .unwrap();
        }

        #[cfg(target_family = "unix")]
        {
            assert_eq!(
                fs::metadata(d.path("a/private-1.txt")).unwrap().st_mode() & 0o7777,
                0o600
            );
            assert_eq!(
                fs::metadata(d.path("a/private-2.txt")).unwrap().st_mode() & 0o7777,
                0o600
            );
            assert_eq!(
                fs::metadata(d.path("a/public-1.txt")).unwrap().st_mode() & 0o7777,
                0o640
            );
            assert_eq!(
                fs::metadata(d.path("a/public-2.txt")).unwrap().st_mode() & 0o7777,
                0o644
            );
        }
    }

    #[test]
    #[cfg(unix)]
    fn open_symlinks() {
        use crate::testing::LinkType;
        let d = Dir::new();
        d.dir("a");
        d.dir("a/b");
        d.dir("a/c");
        d.file("a/c/file1.txt");
        d.link_rel(LinkType::File, "../c/file1.txt", "a/b/present");
        d.link_rel(LinkType::File, "../c/file2.txt", "a/b/absent");
        d.chmod("a", 0o700);
        d.chmod("a/b", 0o700);
        d.chmod("a/c", 0o700);
        d.chmod("a/c/file1.txt", 0o600);

        let m = Mistrust::builder()
            .ignore_prefix(d.canonical_root())
            .build()
            .unwrap();

        // Try reading
        let contents = m.file_access().read(d.path("a/b/present")).unwrap();
        assert_eq!(
            &contents[..],
            &b"This space is intentionally left blank"[..]
        );
        let error = m.file_access().read(d.path("a/b/absent")).unwrap_err();
        assert!(matches!(error, Error::NotFound(_)));

        // Try writing.
        {
            let mut f = m
                .file_access()
                .open(
                    d.path("a/b/present"),
                    OpenOptions::new().write(true).truncate(true),
                )
                .unwrap();
            f.write_all(b"This is extremely serious!").unwrap();
        }
        let contents = m.file_access().read(d.path("a/b/present")).unwrap();
        assert_eq!(&contents[..], &b"This is extremely serious!"[..]);

        let contents = m.file_access().read(d.path("a/c/file1.txt")).unwrap();
        assert_eq!(&contents[..], &b"This is extremely serious!"[..]);
        {
            let mut f = m
                .file_access()
                .open(
                    d.path("a/b/absent"),
                    OpenOptions::new().create(true).write(true),
                )
                .unwrap();
            f.write_all(b"This is extremely silly!").unwrap();
        }
        let contents = m.file_access().read(d.path("a/c/file2.txt")).unwrap();
        assert_eq!(&contents[..], &b"This is extremely silly!"[..]);
    }
}
