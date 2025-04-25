//! Testing support functions, to more easily make a bunch of directories and
//! links.
//!
//! This module is only built when compiling tests.

use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

#[cfg(target_family = "unix")]
use std::os::unix::{self, fs::PermissionsExt};

use crate::Mistrust;

/// A temporary directory with convenience functions to build items inside it.
#[derive(Debug)]
pub(crate) struct Dir {
    /// The temporary directory
    toplevel: tempfile::TempDir,
    /// Canonicalized path to the temporary directory
    canonical_root: PathBuf,
}

/// When creating a link, are we creating a directory link or a file link?
///
/// (These are the same on Unix, and different on windows.)
#[cfg(target_family = "unix")]
#[derive(Copy, Clone, Debug)]
pub(crate) enum LinkType {
    Dir,
    File,
}

impl Dir {
    /// Make a new temporary directory
    pub(crate) fn new() -> Self {
        let toplevel = tempfile::TempDir::new().expect("Can't get tempfile");
        let canonical_root = toplevel.path().canonicalize().expect("Can't canonicalize");

        Dir {
            toplevel,
            canonical_root,
        }
    }

    /// Return the canonical path of the directory's root.
    pub(crate) fn canonical_root(&self) -> &Path {
        self.canonical_root.as_path()
    }

    /// Return the path to the temporary directory's root relative to our working directory.
    pub(crate) fn relative_root(&self) -> PathBuf {
        let mut cwd = std::env::current_dir().expect("no cwd");
        let mut relative = PathBuf::new();
        // TODO(nickm): I am reasonably confident that this will not work
        // correctly on windows.
        while !self.toplevel.path().starts_with(&cwd) {
            assert!(cwd.pop());
            relative.push("..");
        }
        relative.join(
            self.toplevel
                .path()
                .strip_prefix(cwd)
                .expect("error computing common ancestor"),
        )
    }

    /// Return the path of `p` within this temporary directory.
    ///
    /// Requires that `p` is a relative path.
    pub(crate) fn path(&self, p: impl AsRef<Path>) -> PathBuf {
        let p = p.as_ref();
        assert!(p.is_relative());
        self.canonical_root.join(p)
    }

    /// Make a  directory at `p` within this temporary directory, creating
    /// parent directories as needed.
    ///
    /// Requires that `p` is a relative path.
    pub(crate) fn dir(&self, p: impl AsRef<Path>) {
        fs::create_dir_all(self.path(p)).expect("Can't create directory.");
    }

    /// Make a small file at `p` within this temporary directory, creating
    /// parent directories as needed.
    ///
    /// Requires that `p` is a relative path.
    pub(crate) fn file(&self, p: impl AsRef<Path>) {
        self.dir(p.as_ref().parent().expect("Tempdir had no parent"));
        let mut f = File::create(self.path(p)).expect("Can't create file");
        f.write_all(&b"This space is intentionally left blank"[..])
            .expect("Can't write");
    }

    /// Make a relative link from "original" to "link" within this temporary
    /// directory, where `original` is relative
    /// to the directory containing `link`, and `link` is relative to the temporary directory.
    #[cfg(target_family = "unix")]
    pub(crate) fn link_rel(
        &self,
        link_type: LinkType,
        original: impl AsRef<Path>,
        link: impl AsRef<Path>,
    ) {
        {
            let _ = link_type;
            unix::fs::symlink(original.as_ref(), self.path(link)).expect("Can't symlink");
        }

        // Windows does support symlinks but it requires elevated privileges. For more information,
        // please have a look at:
        // https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/create-symbolic-links
    }

    /// As `link_rel`, but create an absolute link.  `original` is now relative
    /// to the temporary directory.
    #[cfg(target_family = "unix")]
    pub(crate) fn link_abs(
        &self,
        link_type: LinkType,
        original: impl AsRef<Path>,
        link: impl AsRef<Path>,
    ) {
        self.link_rel(link_type, self.path(original), link);
    }

    /// Change the unix permissions of a file.
    ///
    /// Requires that `p` is a relative path.
    ///
    /// Does nothing on windows.
    pub(crate) fn chmod(&self, p: impl AsRef<Path>, mode: u32) {
        #[cfg(target_family = "unix")]
        {
            let perm = fs::Permissions::from_mode(mode);
            fs::set_permissions(self.path(p), perm).expect("can't chmod");
        }
        #[cfg(not(target_family = "unix"))]
        {
            let (_, _) = (p, mode);
        }
    }
}

/// A utility type to represent the different operations available for a MistrustBuilder.
#[derive(Debug)]
pub(crate) enum MistrustOp<'a> {
    IgnorePrefix(&'a Path),
    DangerouslyTrustEveryone(),
    TrustNoGroupId(),

    #[cfg(target_family = "unix")]
    TrustAdminOnly(),

    #[cfg(target_family = "unix")]
    TrustGroup(u32),
}

/// A convenience function to construct a Mistrust type using a set of given operations.
pub(crate) fn mistrust_build(ops: &[MistrustOp]) -> Mistrust {
    ops.iter()
        .fold(&mut Mistrust::builder(), |m, op| {
            match op {
                MistrustOp::IgnorePrefix(prefix) => m.ignore_prefix(prefix),

                MistrustOp::DangerouslyTrustEveryone() => m.dangerously_trust_everyone(),

                MistrustOp::TrustNoGroupId() => {
                    // We call `m.trust_no_group_id()` on platforms where it is available.
                    // Otherwise, we simply return `m` unmodified here.
                    #[cfg(all(
                        target_family = "unix",
                        not(target_os = "ios"),
                        not(target_os = "android"),
                        not(target_os = "tvos")
                    ))]
                    return m.trust_no_group_id();

                    #[cfg(not(all(
                        target_family = "unix",
                        not(target_os = "ios"),
                        not(target_os = "android"),
                        not(target_os = "tvos")
                    )))]
                    return m;
                }

                #[cfg(target_family = "unix")]
                MistrustOp::TrustAdminOnly() => {
                    #[cfg(all(
                        target_family = "unix",
                        not(target_os = "ios"),
                        not(target_os = "android")
                    ))]
                    return m.trust_admin_only();
                    #[cfg(not(all(
                        target_family = "unix",
                        not(target_os = "ios"),
                        not(target_os = "android")
                    )))]
                    return m;
                }

                #[cfg(target_family = "unix")]
                MistrustOp::TrustGroup(gid) => {
                    #[cfg(all(
                        target_family = "unix",
                        not(target_os = "ios"),
                        not(target_os = "android")
                    ))]
                    return m.trust_group(*gid);
                    #[cfg(not(all(
                        target_family = "unix",
                        not(target_os = "ios"),
                        not(target_os = "android")
                    )))]
                    return m;
                }
            }
        })
        .build()
        .expect("Unable to build Mistrust object")
}
