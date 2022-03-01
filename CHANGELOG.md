### Notes

This file describes changes in Arti through the current release.  Once Arti
is more mature, and we start to version crates independently, we will
probably switch to using a separate changelog for each crate.

# Arti 0.1.0 — 1 Mar 2022

Arti 0.1.0 marks another important step towards stability, and the
completion of our 0.1.0 milestone.  With this milestone, we now consider
Arti ready for experimental embedding within other applications.

Additionally with this release, we're now ready to declare the
`arti_client` API more or less stable and supported.  (We're not
committing to never break it again in the future, but we'll try not to
do so without pretty good reasons.)  The 1.0.0 release, scheduled for
this September, will represent an even stronger API commitment.


### Breaking changes

- Our top-level `Error` type is now a mostly-opaque wrapper around an
  inner hidden `ErrorDetail` type.  (You can access `ErrorDetail` by
  enabling a feature, but it breaks your semver guarantees.) To
  distinguish among different kinds of `Error`s, we provide a supported
  (and hopefully stable) `ErrorKind` API that developers can use.
  ([!262], [!291], [!325], [#322], [#348])
- The interface to construct a `TorClient` instance has been completely
  replaced.  The new API should be stable, and prevent the need for
  additional breaking changes in the future. ([#350], [!364], [#326])
- Many smaller changes, too numerous to list.  (Starting _after_ this
  release, we will try be much more careful about breaking changes, and
  note them specifically here.)
- We no longer recommend the `static` feature flag; instead use
  `static-native-tls` or `static-sqlite` as appropriate. ([#302])

### New features

- The Arti client can now watch its configuration files to see if they change,
  and reconfigure itself when they do. This is controlled by a
  `watch_configuration` option, and is off-by-default. ([#270], [!280])
- Unused channels now expire after enough time has passed.  (This is
  mostly not needed on the client side, since relays also expire
  unused channels.) ([#41], [!273])
- You can now create an unbootstrapped TorClient object, so that you can
  observe its bootstrapping progress and/or bootstrap it
  at a later time.  ([#293], [!298])
- You can configure an unbootstrapped TorClient object to automatically
  bootstrap itself the first time it's used. ([!322])
- Arti now returns a webpage with an error message if you try to use its
  SOCKS proxy as an HTTP proxy ([!348])
- We now an [arti-hyper] crate for using Arti with the [hyper] HTTP
  library.  This is also good example code for showing how to integrate Arti
  with other tools. ([!342], [!355]]

### Major bugfixes

- Fixed a number of problems in the circuit Reactor implementation that
  could result in cell reordering, leading to relays closing our circuits
  because of protocol violations. ([!264], [!282])
- Fixed bugs that could cause strange behavior on shutdown or failure
  during circuit construction. ([#210], [#365], [!363], [!366], [!368])

### Infrastructure

- Numerous CI improvements.
- Numerous coverage-testing improvements.
- We renamed our shell and python scripts to remove their ".sh" and
  ".py" suffixes, so that we can more freely change their
  implementations in the future (if needed). ([#309])
- The `DirMgr` crate now uses an abstract `Store` trait to make it
  easier for us to implement new storage backends in the
  future. ([!345], [!317])

### Documentation and Examples

- Provide better sample code for `TorClient::connect`. ([!303])
- Provide an example for how to make a [lazy-initialized] `TorClient`
  object. ([#278], [!322])
- Provide an example for how to [override the default TCP-connect]
  implementation. ([!341], [!356])

### Cleanups, minor features, and minor bugfixes

- Stop using `:` as a path character; it's reserved on Windows. ([!277])
- Avoid returning junk data from over-long directory downloads ([!271])
- Implement Debug and Display for many more types.
- We no longer `deny(clippy::all)`; instead we only use
  `warn(clippy::all)` to prevent future clippy versions from breaking
  completely on our code. ([#338])
- As part of our `Error` refactoring and implementation of `ErrorKind`,
  we improved the Error objects in many individual crates for better
  accuracy and specificity.
- Fix a bug that caused us to flush our persistent state to disk too
  aggressively. ([#320], [!321])
- The `arti` proxy now starts listening on its SOCKS port immediately,
  rather than waiting for bootstrapping to complete. ([!333])


### Acknowledgments

Thanks to everybody who has contributed to this release, including
Daniel Schischkin, Dimitris Apostolou, Michael Prantl, tharvik, Trinity
Pointard, and Yuan Lyu.




[!262]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/262
[!264]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/264
[!271]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/271
[!273]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/273
[!277]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/277
[!280]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/280
[!282]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/282
[!291]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/291
[!298]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/298
[!303]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/303
[!317]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/317
[!321]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/321
[!322]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/322
[!325]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/325
[!333]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/333
[!341]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/341
[!342]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/342
[!345]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/345
[!348]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/348
[!355]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/355
[!356]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/356
[!363]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/363
[!364]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/364
[!366]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/366
[!368]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/368
[#41]: https://gitlab.torproject.org/tpo/core/arti/-/issues/41
[#210]: https://gitlab.torproject.org/tpo/core/arti/-/issues/210
[#270]: https://gitlab.torproject.org/tpo/core/arti/-/issues/270
[#278]: https://gitlab.torproject.org/tpo/core/arti/-/issues/278
[#293]: https://gitlab.torproject.org/tpo/core/arti/-/issues/293
[#302]: https://gitlab.torproject.org/tpo/core/arti/-/issues/302
[#309]: https://gitlab.torproject.org/tpo/core/arti/-/issues/309
[#320]: https://gitlab.torproject.org/tpo/core/arti/-/issues/320
[#322]: https://gitlab.torproject.org/tpo/core/arti/-/issues/322
[#326]: https://gitlab.torproject.org/tpo/core/arti/-/issues/326
[#338]: https://gitlab.torproject.org/tpo/core/arti/-/issues/338
[#348]: https://gitlab.torproject.org/tpo/core/arti/-/issues/348
[#350]: https://gitlab.torproject.org/tpo/core/arti/-/issues/350
[#365]: https://gitlab.torproject.org/tpo/core/arti/-/issues/365
[arti-hyper]: https://tpo.pages.torproject.net/core/doc/rust/arti_hyper/index.html
[hyper]: https://crates.io/crates/hyper
[lazy-initialized]: https://gitlab.torproject.org/tpo/core/arti/-/blob/main/crates/arti-client/examples/lazy-init.rs
[override the default TCP-connect]: https://gitlab.torproject.org/tpo/core/arti/-/blob/main/crates/arti-client/examples/hook-tcp.rs



# Arti 0.0.4 — 31 Jan 2022

This release adds support for bootstrap reporting and `rustls`,
improves several APIs, fixes a few bugs, and adds numerous smaller
features for future-proofing and correctness.

It breaks compatibility with previous releases, as is expected before
release 0.1.0 (scheduled March 2022).

### New features

- Add backends for exposing changes in bootstrap status, either to be
  queried by a function or read as a stream of events.  These APIs
  will become more useful once there is a way to actually get an
  un-bootstrapped `TorClient`. ([#96])
- `TorClient` now has a `clone_with_prefs` method to make a new client
  with a different set of default stream
  preferences. ([7ff16fc252c0121f6607], [#290]])
- Add a feature for telling a `TorClient` that every stream should be
  isolated on its own circuit. Please use this sparingly; it can be
  inefficient. ([!252])
- Convenience types for overriding parts of the behavior of an
  asynchronous  `Runtime`. ([!251])
- Optional support for `rustls` in place of `native_tls`. This is off
  by default; to turn it on, use the `rustls` feature, and construct
  your client using one of the `Runtime`s with `Rustls` in its name.
  ([!260], [#86])

### Breaking changes

- Significant refactoring of exports and constructor functions
  in the `arti-client` crate. ([!235])
- Change the persistence format used for guard information, to make it more
  future-proof. ([#176])
- Functions and types that used to refer to "Connections" now refer to
  "Streams" for consistency. ([!256])
- The types exported by the `tor-rtcompat` crate, and the functions
  used to create them, have been renamed for consistency. ([!263])
- The `Runtime` API has changed slightly, to avoid a conflict with
  newer versions of `async_executors`.  ([bf8fa66d36298561cc86])

### Major bugfixes

- Require authenticated SENDMEs when the relay supports them, and not
  otherwise. ([#294])
- Fix the default location for the cache files. (Previously, they were
  put into the state directory.) ([#297])

### Infrastructure

- Numerous improvements to coverage tooling. ([#248], [!221], [!269], [!253])
- Improvements to `arti-bench` reliability and usefulness. ([#292])
- Our CI now runs `shellcheck` on our shell scripts. ([#275])

### Documentation

- Build instructions for iOS. ([#132])
- Adopt a MSRV policy. ([#283])
- More information about troubleshooting the build process. ([#277])

### Cleanups, minor features, and minor bugfixes

- The `max_file_limit` setting is now configurable. ([#299])
- Fix an unreliable test. ([#276])
- Fix a test that would always fail when run after January 27. ([!268])
- Avoid possible incomplete reads and writes in Tor channel
  handshake. ([1d5a480f79e7d878ff], [!249]])
- Refactor some types to expose `Arc<>` less often. ([!236])
- Too many others to list!

### Acknowledgments

Thanks to everybody who has contributed to this release, including
Arturo Marquez, Daniel Eades, Daniel Schischkin, Jani Monoses, Neel
Chauhan, and Trinity Pointard.

[!221]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/221
[!235]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/235
[!236]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/236
[!249]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/249
[!251]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/251
[!252]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/252
[!253]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/253
[!256]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/256
[!260]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/260
[!263]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/263
[!268]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/268
[!269]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/269
[#86]: https://gitlab.torproject.org/tpo/core/arti/-/issues/86
[#96]: https://gitlab.torproject.org/tpo/core/arti/-/issues/96
[#132]: https://gitlab.torproject.org/tpo/core/arti/-/issues/132
[#176]: https://gitlab.torproject.org/tpo/core/arti/-/issues/176
[#248]: https://gitlab.torproject.org/tpo/core/arti/-/issues/248
[#276]: https://gitlab.torproject.org/tpo/core/arti/-/issues/276
[#277]: https://gitlab.torproject.org/tpo/core/arti/-/issues/277
[#283]: https://gitlab.torproject.org/tpo/core/arti/-/issues/283
[#290]: https://gitlab.torproject.org/tpo/core/arti/-/issues/290
[#292]: https://gitlab.torproject.org/tpo/core/arti/-/issues/292
[#294]: https://gitlab.torproject.org/tpo/core/arti/-/issues/294
[#297]: https://gitlab.torproject.org/tpo/core/arti/-/issues/297
[#299]: https://gitlab.torproject.org/tpo/core/arti/-/issues/299
[1d5a480f79e7d878ff]: https://gitlab.torproject.org/tpo/core/arti/-/commit/1d5a480f79e7d878ff291e6e8fc5225e17328919
[7ff16fc252c0121f6607]: https://gitlab.torproject.org/tpo/core/arti/-/commit/7ff16fc252c0121f660709a0dda9639eb7131d34
[bf8fa66d36298561cc86]: https://gitlab.torproject.org/tpo/core/arti/-/commit/bf8fa66d36298561cc868706f748049cec23f5eb


# Arti 0.0.3 — 11 Jan 2022

This release adds support for preemptive circuit construction, refactors
Arti's configuration code and behavior, and adds numerous smaller features
needed for a correct Tor client implementation.

It breaks compatibility with previous releases, as is expected before
release 0.1.0 (scheduled March 2022).

### New features

- Arti now builds preemptive circuits in order to anticipate the user's
  predicted needs.  This change matches Tor's behavior more closely, and
  should reduce latency for stream creation. ([!154])
- The configuration for a [`TorClient`] object can be changed while the
  client is running. ([!181])
- Guard selection now obeys family restrictions concerning exit nodes.
  ([!139])
- Better support for overriding the [`TcpProvider`] on an Arti client and
  having this change affect the [`TlsProvider`]. This helps with testing
  support, with cases where TCP streams must be constructed specially, etc.
  ([!166])
- We no longer consider a directory to be "complete" until we have
  microdescriptors for all of our primary guards. ([!220])

### Breaking changes

- Configuration files have been reorganized, and we have an all-new API for
  creating configuration objects. ([!135], [!137])
- A few unused types and functions have been removed. ([214c251e] etc)
- `CircMgr` now returns `ClientCirc` directly, not wrapped in an `Arc`.
  (ClientCirc instances are already cheap to clone.) ([!224])
- `TorClient` now has separate `connect` and `connect_with_prefs` methods.
  ([!229])
- Various other API refactorings and revisions. (Please remember that we plan
  to break backward compatibility with _every_ release between now and 0.1.0
  in early March.)

### Major bugfixes

- We fixed a bug in handling stream-level SENDMEs that would sometimes result
  in an Arti client sending too much data, causing the exit relay to close
  the circuit. ([!194])

### Infrastructure

- We now have an experimental benchmarking tool to compare Arti's performance
  with Tor's, when running over a chutney network. So far, we seem
  competitive, but we'll probably find cases where we underperform. ([!195])
- Our coverage tool now post-processes grcov's output to produce per-crate
  results. ([!163])
- Our integration test scripts are more robust to cases where the user has
  already configured a `CHUTNEY_PATH`. ([!168])
- We have lowered the required dependency versions in our Cargo.toml files
  so that each one is the lowest version that actually works with our code.
  ([!227])

### Cleanups, minor features, and minor bugfixes

- We store fewer needless fields from Tor directory documents. ([!151],
  [!165])
- We've gone through and converted _every_ `XXXX` comment in our code (which
  indicated a must-fix issue) into a ticket, or a `TODO`. ([#231])
- Our SOCKS code is much more careful about sending error messages if
  an error occurs before the SOCKS connection succeeds. ([!189])
- We no longer build non-directory circuits when the consensus is
  super-old. ([!90])
- We no longer consider timeouts to indicate that our circuits are all timing
  out unless we have seen _some_ recent incoming network traffic. ([!207])
- You can now configure logging to files, with support for rotating the
  files hourly or daily. You can have separate filters for each logging
  target. ([!222])
- Too many others to list!

### Acknowledgments

Thanks to everybody who has contributed to this release, including dagon,
Daniel Eades, Muhammad Falak R Wani, Neel Chauhan, Trinity Pointard, and
Yuan Lyu!

[!90]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/90
[!135]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/135
[!137]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/137
[!139]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/139
[!151]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/151
[!154]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/154
[!163]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/163
[!165]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/165
[!166]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/166
[!168]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/168
[!181]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/181
[!189]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/189
[!194]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/194
[!195]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/195
[!207]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/207
[!220]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/220
[!222]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/222
[!224]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/224
[!227]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/227
[!229]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/229
[#231]: https://gitlab.torproject.org/tpo/core/arti/-/issues/231
[214c251e]: https://gitlab.torproject.org/tpo/core/arti/-/commit/214c251e41a7583397cc5939b9447b89752ee323
[`TcpProvider`]: https://tpo.pages.torproject.net/core/doc/rust/tor_rtcompat/trait.TcpProvider.html
[`TlsProvider`]: https://tpo.pages.torproject.net/core/doc/rust/tor_rtcompat/trait.TlsProvider.html
[`TorClient`]: https://tpo.pages.torproject.net/core/doc/rust/arti_client/struct.TorClient.html


# Arti 0.0.2 — 30 Nov 2021

This release tries to move us towards a more permanent API, and sets the
stage for future work in performance evaluation and event reporting.

It breaks compatibility with previous releases, as is expected before
release 0.1.0 (scheduled March 2022).

### New features

- Warn if guard restrictions are too strict. ([#242])
- Optimistic data is now supported on streams, and used by default on
  directory requests. ([#23])
- Initial cut at a typed event framework. Not yet used, but will eventually
  take the role of Tor's "controller event" system.  ([#230])
- Large rewrite of configuration handling system, with more ergonomic
  builders for top-level configurations. ([#84])


### Breaking changes

- The `${APP_*}` path variables have been renamed to
  `${ARTI_*}`. ([efdd3275])
- The configuration file format has been substantially revised. ([#84])
- Most code that clients don't need is now behind a cargo feature. ([#124])
- Revised APIs in many other high-level crates.

### Documentation

- Many other improvements and rewrites.

### Infrastructure

- Update our `cargo-husky` scripts to better match our CI. ([!62])
- Use grcov, not tarpaulin. ([!136])

### Cleanups, minor features, and bugfixes

- Huge refactoring of the `tor-proto` crate to conform more closely to the
  reactor architecture, and reduce the need for locks. ([#205], [#217]).
- By default, `cargo build --release` now chooses a more aggressive set
  of optimization flags. ([!124])
  - Too many smaller fixes to list.

### Acknowledgments

Thanks to everybody who's contributed to this release, including dagon,
Daniel Eades, Dimitris Apostolou, Neel Chauhan, S0AndS0, Trinity Pointard,
and Yuan Lyu!

[#23]: https://gitlab.torproject.org/tpo/core/arti/-/issues/23
[#84]: https://gitlab.torproject.org/tpo/core/arti/-/issues/84
[#124]: https://gitlab.torproject.org/tpo/core/arti/-/issues/124
[#205]: https://gitlab.torproject.org/tpo/core/arti/-/issues/205
[#217]: https://gitlab.torproject.org/tpo/core/arti/-/issues/217
[#230]: https://gitlab.torproject.org/tpo/core/arti/-/issues/230
[#242]: https://gitlab.torproject.org/tpo/core/arti/-/issues/242
[!62]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/62
[!124]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/124
[!136]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/136
[efdd3275]: https://gitlab.torproject.org/tpo/core/arti/-/commit/efdd327569990cd9e4d7678bae2ac406baf7b1d5

# Arti 0.0.1 — 29 Oct 2021

This release attempts to be "free of known privacy holes". That
isn't to say that there are no remaining bugs, but rather that we've
implemented the missing features that we think are essential for
basic privacy.

### New features

- Guard relay support... ([#58])
  - ...with "Lightweight" path bias detection. ([#185])
- Circuit isolation API. ([#73], [!104])
- Circuit build timeout inference. ([#57])
- Persistent state on disk. ([#59])
- Allow multiple Arti instances to share directories. ([#194])
- Support for EnforceDistinctSubnets. ([#43])
- Configurable logging ([!68]) to journald. ([!73])
- Rejecting attempts to connect to internal addresses. ([#85])
- Support for Tor `RESOLVE` and `RESOLVE_PTR` [socks extensions]. ([#33])
- And too many others to list.

### Breaking changes

- Switched from `log` to `tracing`. ([#74])
- Renamed `arti-tor-client` to `arti-client`. ([#130])
- Stopped exposing `anyhow` errors. ([#165])
- CLI now uses `clap`, and uses subcommands. ([!109])
- Too many others to list.

### Documentation

- New top-level documentation for `arti-client`, with examples. ([!111])
- Many other improvements and rewrites.

### Infrastructure

- Reproducible builds for Linux ([!69]), Windows ([!70]), and OSX ([!86]).
- Support for static binaries. ([!69])
- Simple integration tests, using [chutney] ([!88]).

### Cleanups, minor features, and bugfixes

- Too many to list.

### Acknowledgments

Thanks to everybody who's contributed to this release, including Ben
Armstead, Daniel Eades, Dimitris Apostolou, Eugene Lomov, Felipe
Lema, Jani Monoses, Lennart Kloock, Neel Chauhan, S0AndS0, Smitty,
Trinity Pointard, Yuan Lyu, dagger, and rls!

[#33]: https://gitlab.torproject.org/tpo/core/arti/-/issues/33
[#43]: https://gitlab.torproject.org/tpo/core/arti/-/issues/43
[#57]: https://gitlab.torproject.org/tpo/core/arti/-/issues/57
[#58]: https://gitlab.torproject.org/tpo/core/arti/-/issues/58
[#59]: https://gitlab.torproject.org/tpo/core/arti/-/issues/59
[#73]: https://gitlab.torproject.org/tpo/core/arti/-/issues/73
[#74]: https://gitlab.torproject.org/tpo/core/arti/-/issues/74
[#85]: https://gitlab.torproject.org/tpo/core/arti/-/issues/85
[#130]: https://gitlab.torproject.org/tpo/core/arti/-/issues/130
[#165]: https://gitlab.torproject.org/tpo/core/arti/-/issues/165
[#185]: https://gitlab.torproject.org/tpo/core/arti/-/issues/185
[#194]: https://gitlab.torproject.org/tpo/core/arti/-/issues/194
[!68]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/68
[!69]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/69
[!70]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/70
[!73]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/73
[!86]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/86
[!88]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/88
[!104]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/104
[!109]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/109
[!111]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/111
[chutney]: https://gitlab.torproject.org/tpo/core/chutney
[socks extensions]: https://gitlab.torproject.org/tpo/core/torspec/-/blob/main/socks-extensions.txt

# Arti 0.0.0

Initial release, to reserve our crate names on crates.io.
