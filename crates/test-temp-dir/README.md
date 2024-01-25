Temp directories in tests

Improves on
[`tempdir`](https://docs.rs/tempfile/latest/tempfile/fn.tempdir.html)
by adding several new features for testing:

 * Allowing the user to cause the tests to use predictable paths
 * Allowing the user to cause the tests to leave their temporary directories behind
 * Helping ensure that test directories are not deleted
   before everything that uses them has been torn down
   (via Rust lifetimes)

The principal entrypoint is [`test_temp_dir!`]
which returns a [`TestTempDir`].

# Environment variables

The behaviour is influenced by `TEST_TEMP_RETAIN`:

 * `0` (or unset): use a temporary directory in `TMPDIR` or `/tmp`
   and try to delete it after the test completes
   (equivalent to using [`tempfile::TempDir`]).

 * `1`: use the directory `target/test/crate::module::function`.
   Delete and recreate it *on entry to the test*, but do not delete it afterwards.
   On Windows, `,` is used to replace `::` since `::` cannot appear in filenames.

 * Pathname starting with `/` or `.`: like `1`,
   but the supplied path is used instead of `target/test`.

# stdout printing

This is a crate for use in tests.
When invoked, it will print a message to stdout about the test directory.

# Hazards of too-early deletion of temporary directories

When using raw [`tempfile`], or the `untracked` methods in this crate,
it is easy to write test cases where the temporary directory might be deleted
while paths referring to it are still stored and ready for use
(for example in objects such as `tor_keymgr::KeyMgr` or from `tor_persist`).

Consequences would include the tests trying to refer to the now-deleted directory;
in principle, this might even constitute a vulnerability,
since an attacker might be able to replace the deleted directory with malicious data,
and then the test case might read it!

The problem might even go undetected if the test case is such that
"file not found" counts as a pass.

This can only happen if the [`TempDir`](tempfile::TempDir)
or [`TestTempDir`] object is dropped too early.
The principal APIs in this crate use Rust lifetimes to help prevent that:
the temporary directory path is not directly accessible in `'static` form.

# Panics

This is a crate for use in tests.
Most error conditions will cause a panic.

# Other crates

 * **[`tempfile`](https://lib.rs/crates/tempfile)**:
   Underlying facility for raw temporary directories
   with auto-deletion;
   dependency of this crate.

 * **[`temp_testdir`](https://lib.rs/crates/temp_testdir)**:
   Similar to this crate, but rather less sophisticated.
   Doesn't have the lifetime-based API,
   and has less predictable filenames.
