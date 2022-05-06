### Notes

This file describes changes in Arti through the current release.  Once Arti
is more mature, and we start to version crates independently, we may
switch to using a separate changelog for each crate.

# Arti 0.3.0 — 6 May 2022

Arti 0.3.0 includes several new features, including an improved
configuration builder API, improved detection and tolerance
of numerous network failure types, and several important bugfixes.

There are significant breaking changes in this release; please see
below.

### Breaking changes

Here are the main breaking changes visible from the arti-client crate.
Numerous other lower-level crates have breaking changes not noted here.

- We now require Rust 1.56 or later. This change enables us to use more
  recent versions of several of our dependencies, including a
  significantly faster `aes`.  ([!472])
- Some unused accessors have been removed from
  `tor-socksproto`. ([3103549cba603173])
- Our configuration logic and APIs have been significantly revised.
  Major changes are described below.  We expect that we're mostly
  done with breaking changes in this area, though we expect a few
  minor API breaks here in the next release.
  - Lists of objects, and contained configuration objects, are
    now constructed using a uniform pattern.
  - All of our config _builder_ types are now `Deserialize`; our
    configuration types themselves are not.
  - Various types are now more consistently constructed, which breaks
    some of the APIs.
  - Paths can now be given as "literal" paths, which will not be
    expanded.
  - Several options have been renamed for consistency.
  - For background see [#451], [!447], [!462], [!471], [!473], [!474],
    [!475], [!477], [!478], [!481], and [!487].

### New features

- Arti now tracks clock skew reports from the guard relays and
  fallback directories that we contact, and uses this information to
  infer whether our clock is actually skewed, and whether this skew is
  the likely cause of a failure to bootstrap. ([!450], [!455])
- We now remove obsolete files from our state directory. ([#282])
- More objects from `tor-dirmgr` are now exposed when the
  `experimental-api` feature is enabled. ([!463])
- Arti now has a feature to avoid logging certain sensitive information to
  persistent logs at level `info` or higher.  When safe logging is
  enabled (which it is, by default), the string `[scrubbed]` is printed
  in these contexts, rather than the sensitive information.
  At present, only target addresses are considered sensitive, though
  we aim to increase that information moving forward.  This feature can
  be disabled with the configuration option
  `storage.log_sensitive_information`.  ([#189], [!485])

### Major bugfixes

- Our circuit-build logic is now much more careful about which errors are
  retriable, and how long to wait between attempts. ([#421], [!443])
- Resolved a race condition that could cause internal errors to be
  erroneously reported during circuit construction. ([#427])
- Stop interpreting a successfully constructed circuit as meaning that a
  guard is working _as a directory_.  Even if it can build circuits, it
  may be unable to answer directory requests to our satisfaction
  ([b3e06b93b6a34922]).

### Infrastructure

- Our CI infrastructure now correctly detects (and reports!) failures
  from cargo-audit.  ([!452])

### Cleanups, minor features, and minor bugfixes

- We report more accurate and useful messages on failure to build a
  circuit. ([f7810d42eb953bf5])
- Avoid dropping information when reloading guards. ([#429])
- Arti now treats expired or not-yet-valid directory objects as an error
  condition, since they indicate that the directory cache (or the
  client) likely has a skewed clock. ([#431])
- We now back off on attempts to build preemptive circuits, if we find
  that those attempts are failing.  ([#437], [!456])
- As part of the configuration refactoring, we've extended the amount of
  our configuration builders that are auto-generated. ([!462])
- Improve handling of some integer overflows. ([!466])
- More unit tests throughout the code.

### Acknowledgments

Thanks to everybody who has contributed to this release, including
Christian Grigis, Dimitris Apostolou, Samanta Navarro, and
Trinity Pointard.

[!443]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/443
[!447]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/447
[!450]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/450
[!452]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/452
[!455]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/455
[!456]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/456
[!462]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/462
[!463]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/463
[!466]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/466
[!471]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/471
[!472]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/472
[!473]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/473
[!474]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/474
[!475]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/475
[!477]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/477
[!478]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/478
[!481]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/481
[!485]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/485
[!487]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/487
[#189]: https://gitlab.torproject.org/tpo/core/arti/-/issues/189
[#282]: https://gitlab.torproject.org/tpo/core/arti/-/issues/282
[#421]: https://gitlab.torproject.org/tpo/core/arti/-/issues/421
[#427]: https://gitlab.torproject.org/tpo/core/arti/-/issues/427
[#429]: https://gitlab.torproject.org/tpo/core/arti/-/issues/429
[#431]: https://gitlab.torproject.org/tpo/core/arti/-/issues/431
[#437]: https://gitlab.torproject.org/tpo/core/arti/-/issues/437
[#451]: https://gitlab.torproject.org/tpo/core/arti/-/issues/451
[3103549cba603173]: https://gitlab.torproject.org/tpo/core/arti/-/commit/3103549cba603173a5dc0aefa8f9c201d3d1a6e5
[b3e06b93b6a34922]: https://gitlab.torproject.org/tpo/core/arti/-/commit/b3e06b93b6a34922cd8d07f13aa8f265ae7e8af3
[f7810d42eb953bf5]: https://gitlab.torproject.org/tpo/core/arti/-/commit/f7810d42eb953bf57d9d777fc823087211350452





# Arti 0.2.0 — 1 Apr 2022

Arti 0.2.0 makes a large number of changes to Arti's code and
infrastructure for better configurability, lower memory usage, support
for running as a basic DNS resolver, improved stream isolation, better
behavior under network failures, and API support for a "dormant mode" to
suspend background activities.

### Breaking changes

Here are the main breaking changes visible from the arti-client crate.
Numerous other lower-level crates have breaking changes not noted here.

- Significant refactoring to our configuration handling logic and APIs.
  The goals here are:
      - To have the `ConfigBuilder` objects be the primary configuration
        objects, and simplify the handling of configuration at the
        `TorClient` and `arti` APIs.
      - To remove `arti-config` entirely, and fold its contents into
        `arti` or `arti-client` as appropriate.
      - To remove unnecessary ad-hoc accessor functions until they prove to be
        needed.

  This change is not done in this release; we expect to have more
  breakage in this area in our next release as well.  ([#314], [#371],
  [#372], [#374], [#396], [#418], [!391], [!401], [!417], [!421],
  [!423], [!425], [!427])
- The [`Runtime`] trait now includes (and requires) UDP support. (Part
  of [!390]'s support for DNS.)
- Stream isolation support is completely revised; see notes on isolation
  below.

### New features

- Experimental feature to allow the [`DirMgr`] to be replaced by
  a user-provided [`DirProvider`]. ([#267], [!318], [!347])
- Arti now tolerates IPv6-only environments, by using a basic form of
  the [RFC 8305] "happy eyeballs" algorithm to try connections to
  relays' IPv4 and IPv6 addresses in parallel. ([!382])
- New experimental APIs for modifying consensus objects ([!318], [!402])
- The `arti` crate now exists as a library, to better expose features
  like its top-level configuration logic. ([!403])
- Arti now supports a `dns_port` to relay A, AAAA, and PTR requests over
  the Tor network, like the C tor implementation's DnsPort. ([!390],
  [!408], [!409])
- Arti has a new full-featured [stream isolation API] that supports more
  complicated isolation rules, including user-supplied rules.  ([#150],
  [#414], [!377], [!418], [!420], [!429], [!434])
- Channel and Circuit objects now remember the peers that they used
  when they were constructed, and allow queries of this information as
  part of their API. ([#415])
- The logic for retrying failed guards has been revised to use
  the same decorrelated-jitter algorithm as directory requests, per
  [proposal 336]. ([cb103e04cf4d9853], part of [#407], [!426])
- When all our guards have failed, we no longer retry them all
  aggressively, but rather assume that our net connection is down and
  wait a while. ([eed1f06662366511], part of [#407], [!426])
- When running as a directory client, we now remember more information
  about the source of each request, so we can avoid caches that have
  failed. ([87a3f6b58a5e75f7])
- Experimental feature to install a "filter" for modifying incoming
  directory objects.  Used for testing, to observe client behavior when
  the directory is in an inconsistent or non-working state. ([#397], [!431])
- Arti now has initial support for a "Dormant Mode" where periodic events are
  suspended. Later, even more background tasks will be shut
  down. ([#90], [!429], [!436])
- Fallback directory caches are now handled with logic similar to guards,
  so we can avoid ones that aren't working, and simplify our logic for
  path construction.  As a fringe benefit, this unification means that
  we can now use our guards as directory caches even when we don't have
  an up-to-date consensus. ([#220], [#406], [!433])


### Infrastructure

- We have a new [`arti-testing`] crate (not published on crates.io) to
  perform various kinds of stress-testing on our implementation. It can
  simulate several kinds of failure and overload conditions; we've been
  using it to improve Arti's behavior when the network is broken or
  misbehaving. ([#397], [!378], [!392], [!442]; see also [#329])
- The [`arti-bench`] tool now constructs streams in parallel and
  supports isolated circuits, so we can
  stress-test the performance of a simulated busy client. ([#380], [!384])
- Reproducible build scripts now use Rust 1.59 and Alpine 3.15. ([#376],
  [!380])
- Improved messages from reproducible build script. ([#378], [!383])
- Scripts to launch chutney are now refactored and de-duplicated ([!396])

### Documentation and Examples

- Better documentation for default configuration paths. ([!386])
- Instructions for using Tor Browser with Arti on Windows. ([!388])
- Better instructions for building Arti on Windows. ([!389], [!393])
- Improved documentation for stress-testing Arti. ([!407])

### Cleanups, minor features, and minor bugfixes

- Use [`derive_more`] and [`educe`] (and simple built-in `derive`) in
  many places to simplify our code. ([!374], [!375])
- Use a [forked version of `shellexpand`] to provide correct behavior on
  Windows. ([!274], [!373])
- Avoid unnecessary `Arc::clone()`s in `arti-client` experimental
  APIs. ([#369], [!379])
- New [`tor-basic-utils`] crates for small pieces of low-level
  functionality.
- Small performance improvements to parsing and allocating directory objects,
  to improve start-up and download times. ([#377], [!381])
- Use significantly less memory (on the order of a few megabytes less per
  running client) to store directory objects. ([#384], [#385], [#386], [#387],
  [#388], [!389], [!398], [!415])
- Avoid allocating a backtrace object for each channel-creation
  attempt. ([#383], [!394])
- Always send an "If-Modified-Since" header on consensus requests, since
  we wouldn't want a consensus that was far too old. ([#403], [!412])
- Actually use the configuration for preemptive circuit construction.
  Previously, we missed a place where we needed to copy it.  (Part of [!417])
- Backend support for collecting clock skew information; not yet
  used. ([#405], [!410])
- Major refactoring for periodic events, to support an initial version of
  "dormant mode." ([!429])
- Remove most uses of `SystemTime::now`, in favor of calling the equivalent
  function on [`SleepProvider`]. ([#306], [!365])
- Several bugs in the logic for retrying directory downloads
  have been fixed, and several parameters have been tuned, to lead to
  better behavior under certain network failure conditions. ([!439])

### Acknowledgments

Thanks to everybody who has contributed to this release, including
Christian Grigis, Dimitris Apostolou, Lennart Kloock, Michael, solanav,
Steven Murdoch, and Trinity Pointard.

[!274]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/274
[!318]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/318
[!347]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/347
[!365]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/365
[!373]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/373
[!374]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/374
[!375]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/375
[!377]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/377
[!378]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/378
[!379]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/379
[!380]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/380
[!381]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/381
[!382]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/382
[!383]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/383
[!384]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/384
[!386]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/386
[!388]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/388
[!389]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/389
[!390]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/390
[!391]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/391
[!392]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/392
[!393]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/393
[!394]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/394
[!396]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/396
[!398]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/398
[!401]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/401
[!402]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/402
[!403]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/403
[!407]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/407
[!408]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/408
[!409]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/409
[!410]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/410
[!412]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/412
[!415]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/415
[!417]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/417
[!418]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/418
[!420]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/420
[!421]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/421
[!423]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/423
[!425]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/425
[!426]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/426
[!427]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/427
[!429]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/429
[!431]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/431
[!433]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/433
[!434]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/434
[!436]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/436
[!439]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/439
[!442]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/442
[#90]: https://gitlab.torproject.org/tpo/core/arti/-/issues/90
[#150]: https://gitlab.torproject.org/tpo/core/arti/-/issues/150
[#220]: https://gitlab.torproject.org/tpo/core/arti/-/issues/220
[#267]: https://gitlab.torproject.org/tpo/core/arti/-/issues/267
[#306]: https://gitlab.torproject.org/tpo/core/arti/-/issues/306
[#314]: https://gitlab.torproject.org/tpo/core/arti/-/issues/314
[#329]: https://gitlab.torproject.org/tpo/core/arti/-/issues/329
[#369]: https://gitlab.torproject.org/tpo/core/arti/-/issues/369
[#371]: https://gitlab.torproject.org/tpo/core/arti/-/issues/371
[#372]: https://gitlab.torproject.org/tpo/core/arti/-/issues/372
[#374]: https://gitlab.torproject.org/tpo/core/arti/-/issues/374
[#376]: https://gitlab.torproject.org/tpo/core/arti/-/issues/376
[#377]: https://gitlab.torproject.org/tpo/core/arti/-/issues/377
[#378]: https://gitlab.torproject.org/tpo/core/arti/-/issues/378
[#380]: https://gitlab.torproject.org/tpo/core/arti/-/issues/380
[#383]: https://gitlab.torproject.org/tpo/core/arti/-/issues/383
[#384]: https://gitlab.torproject.org/tpo/core/arti/-/issues/384
[#385]: https://gitlab.torproject.org/tpo/core/arti/-/issues/385
[#386]: https://gitlab.torproject.org/tpo/core/arti/-/issues/386
[#387]: https://gitlab.torproject.org/tpo/core/arti/-/issues/387
[#388]: https://gitlab.torproject.org/tpo/core/arti/-/issues/388
[#396]: https://gitlab.torproject.org/tpo/core/arti/-/issues/396
[#397]: https://gitlab.torproject.org/tpo/core/arti/-/issues/397
[#403]: https://gitlab.torproject.org/tpo/core/arti/-/issues/403
[#405]: https://gitlab.torproject.org/tpo/core/arti/-/issues/405
[#406]: https://gitlab.torproject.org/tpo/core/arti/-/issues/406
[#407]: https://gitlab.torproject.org/tpo/core/arti/-/issues/407
[#414]: https://gitlab.torproject.org/tpo/core/arti/-/issues/414
[#415]: https://gitlab.torproject.org/tpo/core/arti/-/issues/415
[#418]: https://gitlab.torproject.org/tpo/core/arti/-/issues/418
[87a3f6b58a5e75f7]: https://gitlab.torproject.org/tpo/core/arti/-/commit/87a3f6b58a5e75f7060a6797b8e1b33175fd5329
[cb103e04cf4d9853]: https://gitlab.torproject.org/tpo/core/arti/-/commit/cb103e04cf4d985333a6949f0fd646258dcedcd2
[eed1f06662366511]: https://gitlab.torproject.org/tpo/core/arti/-/commit/eed1f06662366511fe5fd15ac0ab0cb69497f2cf
[RFC 8305]: https://datatracker.ietf.org/doc/html/rfc8305
[`DirMgr`]: https://tpo.pages.torproject.net/core/doc/rust/tor_dirmgr/struct.DirMgr.html
[`DirProvider`]: https://tpo.pages.torproject.net/core/doc/rust/tor_dirmgr/trait.DirProvider.html
[`Runtime`]: https://tpo.pages.torproject.net/core/doc/rust/tor_rtcompat/trait.Runtime.html
[`SleepProvider`]: https://tpo.pages.torproject.net/core/doc/rust/tor_rtcompat/trait.SleepProvider.html
[`arti-bench`]: https://tpo.pages.torproject.net/core/doc/rust/arti_bench/index.html
[`arti-testing`]: https://tpo.pages.torproject.net/core/doc/rust/arti_testing/index.html
[`derive_more`]: https://docs.rs/derive_more/latest/derive_more/index.html
[`educe`]:  https://docs.rs/educe/latest/educe/
[`tor-basic-utils`]: https://tpo.pages.torproject.net/core/doc/rust/tor_basic_utils/index.html
[forked version of `shellexpand`]: https://crates.io/crates/shellexpand-fork
[proposal 336]: https://gitlab.torproject.org/tpo/core/torspec/-/blob/main/proposals/336-randomize-guard-retries.md
[stream isolation API]: https://tpo.pages.torproject.net/core/doc/rust/tor_circmgr/isolation/index.html










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
- We now provide an [arti-hyper] crate for using Arti with the [hyper] HTTP
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
