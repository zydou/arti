//! Code to remove obsolete and extraneous files from a filesystem-based state
//! directory.

use std::{
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use tracing::{info, warn};

/// Return true if `path` looks like a filename we'd like to remove from our
/// state directory.
fn fname_looks_deletable(path: &Path) -> bool {
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

/// How old must a file be before we're willing to remove it?
const CUTOFF: Duration = Duration::from_secs(4 * 24 * 60 * 60);

/// Return true if `entry` is very old relative to `now` and therefore safe to delete.
fn very_old(entry: &std::fs::DirEntry, now: SystemTime) -> bool {
    entry
        .metadata()
        .and_then(|m| m.modified())
        .ok()
        .and_then(|m| now.duration_since(m).ok())
        .map(|d| d > CUTOFF)
        == Some(true)
}

/// Implementation helper for [`FsStateMgr::clean()`](super::FsStateMgr::clean):
/// list all files in `statepath` that are ready to delete as of `now`.
pub(super) fn files_to_delete(statepath: &Path, now: SystemTime) -> Vec<PathBuf> {
    let mut result = Vec::new();
    for entry in std::fs::read_dir(statepath).into_iter().flatten().flatten() {
        let path = entry.path();
        if let Ok(basename) = path.strip_prefix(statepath) {
            if fname_looks_deletable(basename) {
                if very_old(&entry, now) {
                    info!("Deleting obsolete file {}", entry.path().display());
                    result.push(path);
                } else {
                    warn!(
                        "Found obsolete file {}; will delete it when it is older.",
                        entry.path().display(),
                    );
                }
            }
        }
    }

    result
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]
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

        for (name, deletable) in examples {
            assert_eq!(fname_looks_deletable(Path::new(name)), deletable);
        }
    }

    #[test]
    fn age() {
        let dir = tempfile::TempDir::new().unwrap();

        let fname1 = dir.path().join("quokka");
        let now = SystemTime::now();
        std::fs::write(&fname1, "hello world").unwrap();

        let mut r = std::fs::read_dir(dir.path()).unwrap();
        let ent = r.next().unwrap().unwrap();
        assert!(!very_old(&ent, now));
        assert!(very_old(&ent, now + CUTOFF * 2));
    }

    #[test]
    fn list() {
        let dir = tempfile::TempDir::new().unwrap();
        let now = SystemTime::now();

        let fname1 = dir.path().join("quokka.toml");
        std::fs::write(&fname1, "hello world").unwrap();

        let fname2 = dir.path().join("wombat.json");
        std::fs::write(&fname2, "greetings").unwrap();

        let removable_now = files_to_delete(dir.path(), now);
        assert!(removable_now.is_empty());

        let removable_later = files_to_delete(dir.path(), now + CUTOFF * 2);
        assert_eq!(removable_later.len(), 1);
        assert_eq!(removable_later[0].file_stem().unwrap(), "quokka");
    }
}
