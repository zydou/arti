//! Code to remove obsolete and extraneous files from a filesystem-based state
//! directory.

use std::{
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use tor_basic_utils::PathExt as _;
use tor_error::warn_report;
use tracing::warn;

/// Return true if `path` looks like a filename we'd like to remove from our
/// state directory.
fn fname_looks_obsolete(path: &Path) -> bool {
    if let Some(extension) = path.extension() {
        if extension == "toml" {
            // We don't make toml files any more.  We migrated to json because
            // toml isn't so good for serializing arbitrary objects.
            return true;
        }
    }

    if let Some(stem) = path.file_stem() {
        if stem == "default_guards" {
            // This file type is obsolete and was removed around 0.0.4.
            return true;
        }
    }

    false
}

/// How old must an obsolete-looking file be before we're willing to remove it?
//
// TODO: This could someday be configurable, if there are in fact users who want
// to keep obsolete files around in their state directories for months or years,
// or who need to get rid of them immediately.
const CUTOFF: Duration = Duration::from_secs(4 * 24 * 60 * 60);

/// Return true if `entry` is very old relative to `now` and therefore safe to delete.
fn very_old(entry: &std::fs::DirEntry, now: SystemTime) -> std::io::Result<bool> {
    Ok(match now.duration_since(entry.metadata()?.modified()?) {
        Ok(age) => age > CUTOFF,
        Err(_) => {
            // If duration_since failed, this file is actually from the future, and so it definitely isn't older than the cutoff.
            false
        }
    })
}

/// Implementation helper for [`FsStateMgr::clean()`](super::FsStateMgr::clean):
/// list all files in `statepath` that are ready to delete as of `now`.
pub(super) fn files_to_delete(statepath: &Path, now: SystemTime) -> Vec<PathBuf> {
    let mut result = Vec::new();

    let dir_read_failed = |err: std::io::Error| {
        use std::io::ErrorKind as EK;
        match err.kind() {
            EK::NotFound => {}
            _ => warn_report!(
                err,
                "Failed to scan directory {} for obsolete files",
                statepath.display_lossy(),
            ),
        }
    };
    let entries = std::fs::read_dir(statepath)
        .map_err(dir_read_failed) // Result from fs::read_dir
        .into_iter()
        .flatten()
        .map_while(|result| result.map_err(dir_read_failed).ok()); // Result from dir.next()

    for entry in entries {
        let path = entry.path();
        let basename = entry.file_name();

        if fname_looks_obsolete(Path::new(&basename)) {
            match very_old(&entry, now) {
                Ok(true) => result.push(path),
                Ok(false) => {
                    warn!(
                        "Found obsolete file {}; will delete it when it is older.",
                        entry.path().display_lossy(),
                    );
                }
                Err(err) => {
                    warn_report!(
                        err,
                        "Found obsolete file {} but could not access its modification time",
                        entry.path().display_lossy(),
                    );
                }
            }
        }
    }

    result
}

#[cfg(all(test, not(miri) /* filesystem access */))]
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

    #[test]
    fn fnames() {
        let examples = vec![
            ("guards", false),
            ("default_guards.json", true),
            ("guards.toml", true),
            ("marzipan.toml", true),
            ("marzipan.json", false),
        ];

        for (name, obsolete) in examples {
            assert_eq!(fname_looks_obsolete(Path::new(name)), obsolete);
        }
    }

    #[test]
    fn age() {
        let dir = tempfile::TempDir::new().unwrap();

        let fname1 = dir.path().join("quokka");
        let now = SystemTime::now();
        std::fs::write(fname1, "hello world").unwrap();

        let mut r = std::fs::read_dir(dir.path()).unwrap();
        let ent = r.next().unwrap().unwrap();
        assert!(!very_old(&ent, now).unwrap());
        assert!(very_old(&ent, now + CUTOFF * 2).unwrap());
    }

    #[test]
    fn list() {
        let dir = tempfile::TempDir::new().unwrap();
        let now = SystemTime::now();

        let fname1 = dir.path().join("quokka.toml");
        std::fs::write(fname1, "hello world").unwrap();

        let fname2 = dir.path().join("wombat.json");
        std::fs::write(fname2, "greetings").unwrap();

        let removable_now = files_to_delete(dir.path(), now);
        assert!(removable_now.is_empty());

        let removable_later = files_to_delete(dir.path(), now + CUTOFF * 2);
        assert_eq!(removable_later.len(), 1);
        assert_eq!(removable_later[0].file_stem().unwrap(), "quokka");

        // Make sure we tolerate files written "in the future"
        let removable_earlier = files_to_delete(dir.path(), now - CUTOFF * 2);
        assert!(removable_earlier.is_empty());
    }

    #[test]
    fn absent() {
        let dir = tempfile::TempDir::new().unwrap();
        let dir2 = dir.path().join("subdir_that_doesnt_exist");
        let r = files_to_delete(&dir2, SystemTime::now());
        assert!(r.is_empty());
    }
}
