//! Functionality for reading a connect point from a file,
//! and verifying that its permissions are correct.

use std::{
    collections::HashMap,
    fs, io,
    path::{Path, PathBuf},
    sync::Arc,
};

use crate::{ClientErrorAction, HasClientErrorAction, ParsedConnectPoint};
use fs_mistrust::{CheckedDir, Mistrust};

/// Helper: Individual member of the vector returned by [`ParsedConnectPoint::load_dir`]
type PathEntry = (PathBuf, Result<ParsedConnectPoint, LoadError>);

impl ParsedConnectPoint {
    /// Load all the connect files from a directory.
    ///
    /// The directory, and individual files loaded within it,
    /// must satisfy `mistrust`.
    ///
    /// Within a directory:
    ///   * only filenames ending with `.toml` are considered.
    ///   * on unix, filenames beginning with `.` are ignored.
    ///   * files are considered in lexicographic order.
    ///
    /// Use `options` as a set of per-file options
    /// mapping the names of files within `path`
    /// to rules for reading them.
    ///
    /// Return an iterator yielding, for each element of the directory,
    /// its filename, and a `ParsedConnectPoint` or an error.
    pub fn load_dir<'a>(
        path: &Path,
        mistrust: &Mistrust,
        options: &'a HashMap<PathBuf, LoadOptions>,
    ) -> Result<ConnPointIterator<'a>, LoadError> {
        let dir = match mistrust.verifier().permit_readable().secure_dir(path) {
            Ok(checked_dir) => checked_dir,
            Err(fs_mistrust::Error::BadType(_)) => return Err(LoadError::NotADirectory),
            Err(other) => return Err(other.into()),
        };

        // Okay, this is a directory.  List its contents...
        let mut entries: Vec<(PathBuf, fs::DirEntry)> = dir
            .read_directory(".")?
            .map(|res| {
                let dirent = res?;
                Ok::<_, io::Error>((dirent.file_name().into(), dirent))
            })
            .collect::<Result<Vec<_>, _>>()?;
        // ... and sort those contents by name.
        //
        // (We sort in reverse order so that ConnPointIterator can pop them off the end of the Vec.)
        entries.sort_unstable_by(|a, b| a.0.cmp(&b.0).reverse());

        Ok(ConnPointIterator {
            dir,
            entries,
            options,
        })
    }

    /// Load the file at `path` as a ParsedConnectPoint.
    ///
    /// It is an error if `path` does not satisfy `mistrust`.
    pub fn load_file(path: &Path, mistrust: &Mistrust) -> Result<ParsedConnectPoint, LoadError> {
        mistrust
            .verifier()
            .require_file()
            .permit_readable()
            .check(path)?;
        // We don't need to worry about TOCTOU here: we already verified that nobody untrusted can
        // change the permissions on `path`.

        // TODO RPC: This is possibly inconsistent wrt symlink behavior.

        Ok(fs::read_to_string(path)?.parse()?)
    }
}

/// Iterator returned by [`ParsedConnectPoint::load_dir()`]
#[derive(Debug)]
pub struct ConnPointIterator<'a> {
    /// Directory object used to read checked files.
    dir: CheckedDir,
    /// The entries of `dir`, sorted in _reverse_ lexicographic order,
    /// so that we can perform a forward iteration by popping items off the end.
    ///
    /// (We compute the `PathBuf`s in advance,
    /// since every call to `DirEntry::file_name()` allocates a string).
    entries: Vec<(PathBuf, fs::DirEntry)>,
    //// The `Options` map passed to `load_dir`.
    options: &'a HashMap<PathBuf, LoadOptions>,
}

impl<'a> Iterator for ConnPointIterator<'a> {
    type Item = PathEntry;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let (fname, entry) = self.entries.pop()?;
            if let Some(outcome) =
                load_dirent(&self.dir, &entry, fname.as_path(), self.options).transpose()
            {
                return Some((self.dir.as_path().join(fname), outcome));
            }
        }
    }
}

/// Helper for `load_dir`: Read the element listed as `entry` within `dir`.
///
/// This is a separate method to help make sure that we capture
/// every possible error while loading the file.
///
/// Return `Ok(None)` if we are skipping this `DirEntry`
/// without reading a ParsedConnectPoint.
fn load_dirent(
    dir: &CheckedDir,
    entry: &fs::DirEntry,
    name: &Path,
    overrides: &HashMap<PathBuf, LoadOptions>,
) -> Result<Option<ParsedConnectPoint>, LoadError> {
    let settings = overrides.get(name);
    if matches!(settings, Some(LoadOptions { disable: true })) {
        // We have been told to disable this entry: Skip.
        return Ok(None);
    }
    if name.extension() != Some("toml".as_ref()) {
        // Wrong extension: Skip.
        return Ok(None);
    }
    #[cfg(unix)]
    if name.to_string_lossy().starts_with('.') {
        // Unix-hidden file: skip.
        return Ok(None);
    }
    if !entry.file_type()?.is_file() {
        // Not a plain file: skip.
        // TODO RPC: Should we try to accept symlinks here? `CheckDir` will reject them by default.
        return Ok(None);
    }

    let contents = dir.read_to_string(name)?;
    Ok(Some(contents.parse()?))
}

/// Configured options for a single file within a directory.
#[derive(Clone, Debug)]
pub struct LoadOptions {
    /// If true, do not try to read the file.
    disable: bool,
}

/// An error encountered while trying to read a `ParsedConnectPoint`.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LoadError {
    /// We couldn't accesss the path.
    ///
    /// This can happen if permissions are wrong,
    /// the file doesn't exist, we encounter an IO error, or something similar.
    #[error("Problem accessing file or directory")]
    Access(#[from] fs_mistrust::Error),
    /// We encountered an IO error while trying to read the file or list the directory.
    #[error("IO error while loading a file or directory")]
    Io(#[source] Arc<io::Error>),
    /// We read a file, but it was not a valid TOML connect point.
    #[error("Unable to parse connect point")]
    Parse(#[from] crate::connpt::ParseError),
    /// We called `load_dir` on something other than a directory.
    #[error("not a directory")]
    NotADirectory,
}
impl From<io::Error> for LoadError {
    fn from(value: io::Error) -> Self {
        LoadError::Io(Arc::new(value))
    }
}
impl HasClientErrorAction for LoadError {
    fn client_action(&self) -> ClientErrorAction {
        use ClientErrorAction as A;
        use LoadError as E;
        match self {
            E::Access(error) => error.client_action(),
            E::Io(error) => crate::fs_error_action(error),
            E::Parse(error) => error.client_action(),
            E::NotADirectory => A::Abort,
        }
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

    use super::*;

    use assert_matches::assert_matches;
    use io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use crate::testing::tempdir;

    fn write(dir: &Path, fname: &str, mode: u32, content: &str) -> PathBuf {
        #[cfg(not(unix))]
        let _ = mode;

        let p: PathBuf = dir.join(fname);

        let mut f = fs::File::create(&p).unwrap();
        f.write_all(content.as_bytes()).unwrap();

        // We need to chmod manually, to override our umask.
        #[cfg(unix)]
        f.set_permissions(PermissionsExt::from_mode(mode)).unwrap();

        p
    }

    const EXAMPLE_1: &str = r#"
    [connect]
socket = "inet:[::1]:9191"
socket_canonical = "inet:[::1]:2020"

auth = { cookie = { path = "/home/user/.arti_rpc/cookie" } }
"#;

    const EXAMPLE_2: &str = r#"
[connect]
socket = "inet:[::1]:9000"
socket_canonical = "inet:[::1]:2000"

auth = { cookie = { path = "/home/user/.arti_rpc/cookie" } }
"#;

    const EXAMPLE_3: &str = r#"
[connect]
socket = "inet:[::1]:413"
socket_canonical = "inet:[::1]:612"

auth = { cookie = { path = "/home/user/.arti_rpc/cookie" } }
"#;

    /// Kludge: use Debug to assert that two ParsedConnectPoints are equal.
    fn assert_conn_pt_eq(a: &ParsedConnectPoint, b: &ParsedConnectPoint) {
        assert_eq!(format!("{:?}", a), format!("{:?}", b));
    }
    /// Kludge: use Debug to assert that two ParsedConnectPoints are unequal.
    fn assert_conn_pt_ne(a: &ParsedConnectPoint, b: &ParsedConnectPoint) {
        assert_ne!(format!("{:?}", a), format!("{:?}", b));
    }

    /// Various tests for load cases that don't depend on fs_mistrust checking or permissions.
    #[test]
    fn load_normally() {
        let (_tmpdir, dir, m) = tempdir();

        let fname1 = write(dir.as_ref(), "01-file.toml", 0o600, EXAMPLE_1);
        let fname2 = write(dir.as_ref(), "02-file.toml", 0o600, EXAMPLE_2);
        // Invalid toml should cause an Err to appear in the result.
        let _fname3 = write(dir.as_ref(), "03-junk.toml", 0o600, "not toml at all");
        // Doesn't end with toml, should get skipped.
        let _not_dot_toml = write(dir.as_ref(), "README.config", 0o600, "skip me");
        // Should get skipped on unix.
        #[cfg(unix)]
        let _dotfile = write(dir.as_ref(), ".foo.toml", 0o600, "also skipped");

        // we don't recurse; create a file in a subdir to demonstrate this.
        let subdirname = dir.join("subdir");
        m.make_directory(&subdirname).unwrap();
        let _in_subdir = write(subdirname.as_ref(), "hello.toml", 0o600, EXAMPLE_1);

        let connpt1: ParsedConnectPoint = EXAMPLE_1.parse().unwrap();
        let connpt2: ParsedConnectPoint = EXAMPLE_2.parse().unwrap();

        // Try "load_file"
        let p = ParsedConnectPoint::load_file(fname1.as_ref(), &m).unwrap();
        assert_conn_pt_eq(&p, &connpt1);
        assert_conn_pt_ne(&p, &connpt2);

        // Try "load_file" on a directory.
        let err = ParsedConnectPoint::load_file(dir.as_ref(), &m).unwrap_err();
        assert_matches!(err, LoadError::Access(fs_mistrust::Error::BadType(_)));

        // Try "load_dir" on a file.
        let err = ParsedConnectPoint::load_dir(fname2.as_ref(), &m, &HashMap::new()).unwrap_err();
        assert_matches!(err, LoadError::NotADirectory);

        // Try "load_dir" on a directory.
        let v: Vec<_> = ParsedConnectPoint::load_dir(dir.as_ref(), &m, &HashMap::new())
            .unwrap()
            .collect();
        assert_eq!(v.len(), 3);
        assert_eq!(v[0].0.file_name().unwrap().to_str(), Some("01-file.toml"));
        assert_conn_pt_eq(v[0].1.as_ref().unwrap(), &connpt1);
        assert_eq!(v[1].0.file_name().unwrap().to_str(), Some("02-file.toml"));
        assert_conn_pt_eq(v[1].1.as_ref().unwrap(), &connpt2);
        assert_eq!(v[2].0.file_name().unwrap().to_str(), Some("03-junk.toml"));
        assert_matches!(&v[2].1, Err(LoadError::Parse(_)));

        // Try load_dir with `options`.
        let options: HashMap<_, _> = [
            (
                PathBuf::from("01-file.toml"),
                LoadOptions { disable: false },
            ), // Doesn't actually do anything.
            (PathBuf::from("02-file.toml"), LoadOptions { disable: true }),
        ]
        .into_iter()
        .collect();
        let v: Vec<_> = ParsedConnectPoint::load_dir(dir.as_ref(), &m, &options)
            .unwrap()
            .collect();
        assert_eq!(v.len(), 2);
        assert_conn_pt_eq(v[0].1.as_ref().unwrap(), &connpt1);
        assert_matches!(&v[1].1, Err(LoadError::Parse(_)));
    }

    #[test]
    #[cfg(unix)]
    fn bad_permissions() {
        let (_tmpdir, dir, m) = tempdir();

        let fname1 = write(dir.as_ref(), "01-file.toml", 0o600, EXAMPLE_1);
        // World-writeable: no good.
        let fname2 = write(dir.as_ref(), "02-file.toml", 0o777, EXAMPLE_2);
        // Good file, to make sure we keep reading.
        let _fname3 = write(dir.as_ref(), "03-file.toml", 0o600, EXAMPLE_3);

        let connpt1: ParsedConnectPoint = EXAMPLE_1.parse().unwrap();
        let connpt3: ParsedConnectPoint = EXAMPLE_3.parse().unwrap();

        // We can still load a file with good permissions.
        let p = ParsedConnectPoint::load_file(fname1.as_ref(), &m).unwrap();
        assert_conn_pt_eq(&p, &connpt1);

        // Can't load file with bad permissions.
        let err: LoadError = ParsedConnectPoint::load_file(fname2.as_ref(), &m).unwrap_err();
        assert_matches!(
            err,
            LoadError::Access(fs_mistrust::Error::BadPermission(..))
        );

        // Reading directory gives us the file with good permissions, but not the other.
        let v: Vec<_> = ParsedConnectPoint::load_dir(dir.as_ref(), &m, &HashMap::new())
            .unwrap()
            .collect();
        assert_eq!(v.len(), 3);
        assert_conn_pt_eq(v[0].1.as_ref().unwrap(), &connpt1);
        assert_matches!(
            v[1].1.as_ref().unwrap_err(),
            LoadError::Access(fs_mistrust::Error::BadPermission(..))
        );
        assert_conn_pt_eq(v[2].1.as_ref().unwrap(), &connpt3);
    }

    // TODO: Check symlink behavior once it is specified
}
