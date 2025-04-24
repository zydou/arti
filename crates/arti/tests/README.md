# Arti CLI tests

This is a [`trycmd`]-based test suite for the arti CLI.

Each testable subcommand has a corresponding directory in `testcases`:
```
tests
├── cli_tests
│   ├── hsc.rs                 # hsc non-trycmd cli test
│   ├── main.rs
│   └── runner.rs              # trycmd test runner
├── README.md
└── testcases
    ├── hsc
    │   ├── help.stderr        # expected stderr for the "help" test
    │   ├── help.stdout        # expected stdout for the "help" test
    │   ├── help.toml          # hsc "help" test
    │   ├── hsc.in             # test inputs and CWD
    │   └── hsc.md             # multiple hsc tests
    ├── hss                    # hss subcommand tests
    │   ├── hss.in             # test inputs and CWD
    │   └── hss.md             # multiple hss tests
    └── ...
```

Each feature-dependent subcommand has a corresponding `<subcmd>-feature-missing`
test case, which tests that we output a hint about recompiling arti with the
necessary features (the feature-dependent tests are currently all skipped,
because we don't yet print helpful messages in such cases. See #1487).

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
