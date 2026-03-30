# Arti CLI tests

This is a [`trycmd`]-based test suite for the arti CLI.

Each testable subcommand has a corresponding directory in `testcases`:
```
tests
├── cli_tests
│   ├── hsc.rs                 # hsc non-trycmd cli test
│   ├── hss.rs                 # hss non-trycmd cli test
│   ├── keys.rs                # keys non-trycmd cli test
│   ├── main.rs
│   ├── runner.rs              # trycmd test runner
│   └── ...                    # utils
├── README.md
└── testcases
    ├── hsc                    # hsc trycmd test run when only "hsc" extra feature is provided
    │   ├── help.stderr        # expected stderr for the "help" test
    │   ├── help.stdout        # expected stdout for the "help" test
    │   ├── help.toml          # hsc "help" test
    │   └── hsc.in             # test inputs and CWD
    ├── hsc-common             # hsc trycmd test run when either only "hsc" or other extra
    │   │                      # features are provided
    │   ├── hsc.md             # multiple hsc tests
    │   └── ...
    ├── hsc-extra              # hsc trycmd test run when extra features are provided
    │   └── ...
    ├── hss                    # hss trycmd tests
    │   ├── hss.in             # test inputs and CWD
    │   └── hss.md             # multiple hss tests
    └── ...
```

Each feature-dependent subcommand has a corresponding `<subcmd>-feature-missing`
test case, which tests that we output a hint about recompiling arti with the
necessary features (the feature-dependent tests are currently all skipped,
because we don't yet print helpful messages in such cases. See #1487).

Feature-dependent subcommands also provide test cases for specific scenarios,
such as when only the primary feature is enabled (e.g., `hsc`), when additional
features are enabled (e.g., `hsc-extra`), or when a common set of features is
used (e.g., `hsc-common`).

The tests can be written as [`*.trycmd`/`*.md` files], or in [`toml` format].
The `*md`-based tests can double as documentation, so they are often preferable
over the `toml` ones.

See the [`trycmd`] docs for more information.

> Note: [`trycmd`] is currently limited in functionality, when it is not
> possible to write an exhaustive test suite using [`trycmd`] it is possible
> to use [`assert_cmd`], and write the test inside the `cli_tests`'
> submodule `hsc.rs` (another submodule `hss.rs` will be created in
> the future if needed).

### Debugging

You can pass `-F trycmd/debug` to `cargo test` to debug `trycmd`'s behavior.`

[`trycmd`]: https://docs.rs/trycmd/latest/trycmd/
[`assert_cmd`]: https://docs.rs/assert_cmd/latest/assert_cmd/
[`*.trycmd`/`*.md` files]: https://docs.rs/trycmd/latest/trycmd/#trycmd
[`toml` format]: https://docs.rs/trycmd/latest/trycmd/#toml
