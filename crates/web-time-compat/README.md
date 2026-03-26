# web-time-compat

Small compatibility layer for [`web-time`].

Unlike [`web-time`], this crate does not require you to stop using
[`std::time::SystemTime`].
Instead, it provides an extension trait to replace the `now`
method of `SystemTime` types with a `get` method that works on
wasm32-unknown-unknown.

With `Instant`, it isn't possible to continue using `std::time::Instant`,
since that type is not interconvertible with `web_time::Instant`.  Instead,
we provide an extension trait to make it easier for you to make sure that you
are only using the version of Instant you want.

## How to use this crate

(This isn't the only way, but it's what we recommend.)

- Replace all references to `std::time::Instant` with `web_time_compat::Instant`.
- You may, if you like, also use `web_time_compat::{Duration, SystemTime}`.
  They are just aliases for the standard Duration and SystemTimetypes.
- Instead of `SystemTime::now()`, use `SystemTimeExt::get()`.
- Instead of `Instant::now()`, use `Instant::get()`.
- Add `std::time::SystemTime::now` and `std::time::Instant::now` to your
  [`disallowed-methods`] list in your `clippy.toml` file,
  to prevent them from being used accidentally.
- If you use any other time libraries (such as `time` or `chrono`), you may
  want to add their "now" methods to `disallowed-methods`, depending
  on whether you have configured them for wasm compatibility.

[`web-time`]: https://docs.rs/web-time/latest/web_time/
[`disallowed-methods`]: https://doc.rust-lang.org/stable/clippy/lint_configuration.html#disallowed-methods

----

License: MIT OR Apache-2.0
