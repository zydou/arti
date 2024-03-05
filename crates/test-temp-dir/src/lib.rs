#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![doc = include_str!("../README.md")]
// @@ begin lint list maintained by maint/add_warning @@
#![cfg_attr(not(ci_arti_stable), allow(renamed_and_removed_lints))]
#![cfg_attr(not(ci_arti_nightly), allow(unknown_lints))]
#![warn(missing_docs)]
#![warn(noop_method_call)]
#![warn(unreachable_pub)]
#![warn(clippy::all)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::checked_conversions)]
#![warn(clippy::cognitive_complexity)]
#![deny(clippy::debug_assert_with_mut_call)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::expl_impl_clone_on_copy)]
#![deny(clippy::fallible_impl_from)]
#![deny(clippy::implicit_clone)]
#![deny(clippy::large_stack_arrays)]
#![warn(clippy::manual_ok_or)]
#![deny(clippy::missing_docs_in_private_items)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![deny(clippy::print_stderr)]
#![deny(clippy::print_stdout)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unchecked_duration_subtraction)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
#![allow(clippy::result_large_err)] // temporary workaround for arti#587
#![allow(clippy::needless_raw_string_hashes)] // complained-about code is fine, often best
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

// We have a nonstandard test lint block
#![allow(clippy::print_stdout)]

use std::env::{self, VarError};
use std::fs;
use std::io::{self, ErrorKind};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context as _};
use derive_more::{Deref, DerefMut};
use educe::Educe;

/// The env var the user should set to control test temp dir handling
const RETAIN_VAR: &str = "TEST_TEMP_RETAIN";

/// Directory for a test to store temporary files
///
/// Automatically deleted (if appropriate) when dropped.
#[derive(Debug)]
#[non_exhaustive]
pub enum TestTempDir {
    /// An ephemeral directory
    Ephemeral(tempfile::TempDir),
    /// A directory which should persist after the test completes
    Persistent(PathBuf),
}

/// A `T` which relies on some temporary directory with lifetime `d`
///
/// Obtained from `TestTempDir::used_by`.
///
/// Using this type means that the `T` won't outlive the temporary directory.
/// (Typically, if it were to, things would malfunction.
/// There might even be security hazards!)
#[derive(Clone, Copy, Deref, DerefMut, Educe)]
#[educe(Debug(bound))]
pub struct TestTempDirGuard<'d, T> {
    /// The thing
    #[deref]
    #[deref_mut]
    thing: T,

    /// Placate the compiler
    ///
    /// We use a notional `()` since we don't want the compiler to infer drop glue.
    #[educe(Debug(ignore))]
    tempdir: PhantomData<&'d ()>,
}

impl TestTempDir {
    /// Obtain a temp dir named after our thread, and the module path `mod_path`
    ///
    /// Expects that the current thread name is the module path within the crate,
    /// followed by the test function name.
    /// (This is how Rust's builtin `#[test]` names its threads.)
    // This is also used by some other crates.
    // If it turns out not to be true, we'll end up panicking.
    //
    // This is rather a shonky approach.  We take it here for the following reasons:
    //
    // It is important that the persistent test output filename is stable,
    // even if the source code is edited.  For example, if we used the line number
    // of the macro call, editing the source would change the output filenames.
    // When the output filenames change willy-nilly, it is very easy to accidentally
    // look at an out-of-date filename containing out-of-date test data,
    // which can be very confusing.
    //
    // We could ask the user to supply a string, but we'd then need
    // some kind of contraption for verifying its uniqueness, since
    // non-unique test names would risk tests overwriting each others'
    // files, making for flaky or malfunctioning tests.
    //
    // So the test function name is the best stable identifier we have,
    // and the thread name is the only way we have of discovering it.
    // Happily this works with `cargo nextest` too.
    //
    // For the same reasons, it wouldn't be a good idea to fall back
    // from the stable name to some less stable but more reliably obtainable id.
    //
    // And, the code structure is deliberately arranged that we *always*
    // try to determine the test name, even if TEST_TEMP_RETAIN isn't set.
    // Otherwise a latent situation, where TEST_TEMP_RETAIN doesn't work, could develop.
    //
    /// And, expects that `mod_path` is the crate name,
    /// and then the module path within the crate.
    /// This is what Rust's builtin `module_path!` macro returns.
    ///
    /// The two instances of the module path within the crate must be the same!
    ///
    /// # Panics
    ///
    /// Panics if the thread name and `mod_path` do not correspond
    /// (see the [self](module-level documentation).)
    pub fn from_module_path_and_thread(mod_path: &str) -> TestTempDir {
        let path = (|| {
            let (crate_, m_mod) = mod_path
                .split_once("::")
                .ok_or_else(|| anyhow!("module path {:?} doesn't contain `::`", &mod_path))?;
            let thread = std::thread::current();
            let thread = thread.name().context("get current thread name")?;
            let (t_mod, fn_) = thread
                .rsplit_once("::")
                .ok_or_else(|| anyhow!("current thread name {:?} doesn't contain `::`", &thread))?;
            if m_mod != t_mod {
                return Err(anyhow!(
 "module path {:?} implies module name {:?} but thread name {:?} implies module name {:?}",
                    mod_path, m_mod, thread, t_mod
                ));
            }
            Ok::<_, anyhow::Error>(format!("{crate_}::{m_mod}::{fn_}"))
        })()
        .expect("unable to calculate complete test function path");

        Self::from_complete_item_path(&path)
    }

    /// Obtains a temp dir named after a complete item path
    ///
    /// The supplied `item_path` must be globally unique in the whole workspace,
    /// or it might collide with other tests from other crates.
    ///
    /// Handles the replacement of `::` with `:` on Windows.
    pub fn from_complete_item_path(item_path: &str) -> Self {
        let subdir = item_path;

        // Operating systems that can't have `::` in pathnames
        #[cfg(target_os = "windows")]
        let subdir = subdir.replace("::", ",");

        #[allow(clippy::needless_borrow)] // borrow not needed if we didn't rebind
        Self::from_stable_unique_subdir(&subdir)
    }

    /// Obtains a temp dir given a stable unique subdirectory name
    ///
    /// The supplied `subdir` must be globally unique
    /// across every test in the whole workspace,
    /// or it might collide with other tests.
    pub fn from_stable_unique_subdir(subdir: &str) -> Self {
        let retain = env::var(RETAIN_VAR);
        let retain = match &retain {
            Ok(y) => y,
            Err(VarError::NotPresent) => "0",
            Err(VarError::NotUnicode(_)) => panic!("{} not unicode", RETAIN_VAR),
        };
        let target: PathBuf = if retain == "0" {
            println!("test {subdir}: {RETAIN_VAR} not enabled, using ephemeral temp dir");
            let dir = tempfile::tempdir().expect("failed to create temp dir");
            return TestTempDir::Ephemeral(dir);
        } else if retain.starts_with('.') || retain.starts_with('/') {
            retain.into()
        } else if retain == "1" {
            let target = env::var_os("CARGO_TARGET_DIR").unwrap_or_else(|| "target".into());
            let mut dir = PathBuf::from(target);
            dir.push("test");
            dir
        } else {
            panic!("invalid value for {}: {:?}", RETAIN_VAR, retain)
        };

        let dir = {
            let mut dir = target;
            dir.push(subdir);
            dir
        };
        println!("test {subdir}, temp dir is {}", dir.display());
        match fs::remove_dir_all(&dir) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            other => other,
        }
        .expect("pre-remove temp dir");
        fs::create_dir_all(&dir).expect("create temp dir");
        TestTempDir::Persistent(dir)
    }

    /// Obtain a reference to the `Path` of this temp directory
    ///
    /// Prefer to use [`.used_by()`](TestTempDir::used_by) where possible.
    ///
    /// The lifetime of the temporary directory will not be properly represented
    /// by Rust lifetimes.  For example, calling
    /// `.to_owned()`[ToOwned::to_owned]
    /// will get a `'static` value,
    /// which doesn't represent the fact that the directory will go away
    /// when the `TestTempDir` is dropped.
    ///
    /// So the resulting value can be passed to functions which
    /// store the path for later use, and might later malfunction because
    /// the `TestTempDir` is dropped too earlier.
    pub fn as_path_untracked(&self) -> &Path {
        match self {
            TestTempDir::Ephemeral(t) => t.as_ref(),
            TestTempDir::Persistent(t) => t.as_ref(),
        }
    }

    /// Return a subdirectory, without lifetime tracking
    pub fn subdir_untracked(&self, subdir: &str) -> PathBuf {
        let mut r = self.as_path_untracked().to_owned();
        r.push(subdir);
        r
    }

    /// Obtain a `T` which uses paths in `self`
    ///
    /// Within `f`, construct `T` using the supplied filesystem path,
    /// which is the full path to the test's temporary directory.
    ///
    /// Do not store or copy the path anywhere other than the return value;
    /// such copies would not be protected by Rust lifetimes against early deletion.
    ///
    /// Rust lifetime tracking ensures that the temporary directory
    /// won't be cleaned up until the `T` is destroyed.
    #[allow(clippy::needless_lifetimes)] // explicit lifetimes for clarity (and symmetry)
    pub fn used_by<'d, T>(&'d self, f: impl FnOnce(&Path) -> T) -> TestTempDirGuard<'d, T> {
        let thing = f(self.as_path_untracked());
        TestTempDirGuard::with_path(thing, self.as_path_untracked())
    }

    /// Obtain a `T` which uses paths in a subdir of `self`
    ///
    /// The directory `subdir` will be created,
    /// within the test's temporary directory,
    /// if it doesn't already exist.
    ///
    /// Within `f`, construct `T` using the supplied filesystem path,
    /// which is the fuill path to the subdirectory.
    ///
    /// Do not store or copy the path anywhere other than the return value;
    /// such copies would not be protected by Rust lifetimes against early deletion.
    ///
    /// Rust lifetime tracking ensures that the temporary directory
    /// won't be cleaned up until the `T` is destroyed.
    pub fn subdir_used_by<'d, T>(
        &'d self,
        subdir: &str,
        f: impl FnOnce(PathBuf) -> T,
    ) -> TestTempDirGuard<'d, T> {
        self.used_by(|dir| {
            let dir = dir.join(subdir);

            match fs::create_dir(&dir) {
                Err(e) if e.kind() == ErrorKind::AlreadyExists => Ok(()),
                other => other,
            }
            .expect("create subdir");

            f(dir)
        })
    }
}

impl<'d, T> TestTempDirGuard<'d, T> {
    /// Obtain the inner `T`
    ///
    /// It is up to you to ensure that `T` doesn't outlive
    /// the temp directory used to create it.
    pub fn into_untracked(self) -> T {
        self.thing
    }

    /// Create from a `T` and a `&Path` with the right lifetime
    pub fn with_path(thing: T, _path: &'d Path) -> Self {
        Self::new_untracked(thing)
    }

    /// Create from a raw `T`
    ///
    /// The returned lifetime is unfounded!
    /// It is up to you to ensure that the inferred lifetime is correct!
    pub fn new_untracked(thing: T) -> Self {
        Self {
            thing,
            tempdir: PhantomData,
        }
    }
}

/// Obtain a `TestTempDir` for the current test
///
/// Must be called in the same thread as the actual `#[test]` entrypoint!
///
/// **`fn test_temp_dir() -> TestTempDir;`**
#[macro_export]
macro_rules! test_temp_dir { {} => {
    $crate::TestTempDir::from_module_path_and_thread(module_path!())
} }
