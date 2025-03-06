### DEPRECATED: `MockSleepProvider` and `MockSleepRuntime` are marked `#[deprecated]`

These have known bugs (eg [#1036]) and can make it easy to write flaky tests.
They have been documented as deprecated since tor-rtmock 0.11.0 in
October 2023.  Now we formally mark them as `#[deprecated]`.

Use `MockExecutor` (and its `SimpleMockTimeProvider`) instead.
(That's a nontrivial change since the time mocking API is quite different.)

[#1036]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1036
