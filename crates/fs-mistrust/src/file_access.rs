//! Functionality for opening files while verifying their permissions.

#![allow(missing_docs, clippy::missing_docs_in_private_items, dead_code)]

use std::{
    borrow::Cow,
    fs::{File, OpenOptions},
    io::{Read as _, Write},
    path::{Path, PathBuf},
};

use crate::{dir::FullPathCheck, walk::PathType, CheckedDir, Error, Result};

/// Helper object for accessing a file on disk while checking the necessary permissions.
///
/// A `FileAccess` wraps a reference to a [`CheckedDir`],
/// but allows configuring the rules for accessing the files it opens.
///
/// When we refer to a path "obeying the constraints" of this `FileAccess`,
/// we mean the requirement that it is a relative path containing no ".." elements,
/// or other elements that would take it outside the `CheckedDir`.
pub struct FileAccess<'a> {
    /// Validator object that we use for checking file permissions.
    pub(crate) inner: Inner<'a>,
}

/// Inner object for checking file permissions.
///
/// XXXX This is an enum because we plan to allow having a Mistrust here instead;
/// XXXX we should add that support or flatten this enum.
pub(crate) enum Inner<'a> {
    CheckedDir(&'a CheckedDir),
}

impl<'a> FileAccess<'a> {
    pub(crate) fn from_checked_dir(checked_dir: &'a CheckedDir) -> Self {
        Self::from_inner(Inner::CheckedDir(checked_dir))
    }
    fn from_inner(inner: Inner<'a>) -> Self {
        Self { inner }
    }
    /// Check path constraints on `path` and verify its permissions
    /// (or the permissions of its parent) according to `check_type`
    fn verified_full_path(&self, path: &Path, check_type: FullPathCheck) -> Result<PathBuf> {
        match self.inner {
            Inner::CheckedDir(cd) => cd.verified_full_path(path, check_type),
        }
    }
    /// Return a `Verifier` to use for checking permissions.
    fn verifier(&self) -> crate::Verifier {
        match self.inner {
            Inner::CheckedDir(cd) => cd.verifier(),
        }
    }
    /// Return the location of `path` relative to this verifier.
    ///
    /// Fails if `path` does not obey the constraints of this `FileAccess`,
    /// but does not do any permissions checking.
    fn location_unverified<'b>(&self, path: &'b Path) -> Result<Cow<'b, Path>> {
        Ok(match self.inner {
            Inner::CheckedDir(cd) => cd.join(path)?.into(),
        })
    }

    // XXXX correct this documentation.
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
        let path = self.verified_full_path(path.as_ref(), FullPathCheck::CheckParent)?;

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
            .map_err(|e| Error::io(e, &path, "open file"))?;
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

    // XXXX correct this documentation.
    /// Read the contents of the file at `path` within this directory, as a
    /// String, if possible.
    ///
    /// Return an error if `path` is absent, if its permissions are incorrect,
    /// if it has any components that could take us outside of this directory,
    /// or if its contents are not UTF-8.
    pub fn read_to_string<P: AsRef<Path>>(&self, path: P) -> Result<String> {
        let path = path.as_ref();
        let mut file = self.open(path, OpenOptions::new().read(true))?;
        let mut result = String::new();
        file.read_to_string(&mut result)
            .map_err(|e| Error::io(e, path, "read file"))?;
        Ok(result)
    }

    // XXXX correct this documentation.
    /// Read the contents of the file at `path` within this directory, as a
    /// vector of bytes, if possible.
    ///
    /// Return an error if `path` is absent, if its permissions are incorrect,
    /// or if it has any components that could take us outside of this
    /// directory.
    pub fn read<P: AsRef<Path>>(&self, path: P) -> Result<Vec<u8>> {
        let path = path.as_ref();
        let mut file = self.open(path, OpenOptions::new().read(true))?;
        let mut result = Vec::new();
        file.read_to_end(&mut result)
            .map_err(|e| Error::io(e, path, "read file"))?;
        Ok(result)
    }

    // XXXX correct this documentation.
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
        let path = path.as_ref();
        let final_path = self.verified_full_path(path, FullPathCheck::CheckParent)?;

        let tmp_name = path.with_extension("tmp");
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
