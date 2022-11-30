### Notes

This file describes changes in Arti through the current release.  Once Arti
is more mature, we may switch to using a separate changelog for each crate.

# Arti 1.1.0 — 30 November 2022

Arti 1.1.0 adds support for Tor's anticensorship features: Bridges
(unlisted relays), and Pluggable Transports (external tools to hide what
protocol you're using).

Use of these features can make Arti more effective at gaining access
to Tor, in spite of censorship (or breakage) between you the wider
public internet.

These features are still very new, so there are likely to be bugs,
and the user experience may not yet be optimal.  But we think the
security of these features is good enough for a general release.

### Breaking changes

- Arti now requires Rust 1.60 or later. This allows us to use a few new
  features, and to upgrade a few of our dependencies that had grown
  stale. See ["Minimum supported Rust Version" in `README.md`] for more
  information on our MSRV policy. ([#591], [#526], [#613], [#621], [!837])

### Breaking changes in lower level crates

- `SocksHandshake` has been renamed to `SocksProxyHandshake`, to
  distinguish it from `SocksClientHandshake`. ([b08073c2d43d7be5])
- Numerous changes to the bridge-related APIs introduced in 1.0.1.
  ([!758], [#600], [!759]], [!780])
- API changes to `tor-dirclient::Response`. ([!782])
- Netinfo cell constructors have been renamed. ([!793])
- The guard manager API no long accepts `NetDir` arguments to most of
  its methods; instead, it expects to be given a `NetDirProvider`.
  ([95a95076a77f4447])
- Move the responsibility for creating a GuardMgr to the `arti-client`
  crate. ([!850])
- Numerous other changes to lower-level APIs.

### New features

- Arti can now connect to bridges when compiled with the `bridge-client`
  feature.  (This is on by default in the `arti` binary.)
  As part of this feature, we have had to implement:
  - Configuration logic for bridges ([#599], [!744], [!745], [!767],
    [!781], [!780], [!783], [!826], [!874], [!877], [!881])
  - Data structures to keep track of relays based on possibly
    non-overlapping sets of keys ([!747], [!774], [!797], [!806])
  - Improved functionality for parsing router descriptors and integrating
    them with our list of bridges ([!755])
  - Large-scale refactoring of the channel-manager internals to handle
    bridges and relays while treating them as distinct. ([!773])
  - Code to download, store, and cache bridge descriptors. ([!782], [!795],
    [!810], [!820], [!827], [!828], [!831], [!834], [!845], [!851],)
  - Allow the guard manager to treat bridges as a kind of guard, and to
    treat bridge-lists and network directories as two kinds of a "universe"
    of possible guards.
    ([!785], [!808], [!815], [!832], [!840])
  - Support code to integrate directory management code with guard management
    code. ([!847], [!852])
  - More careful logging about changes in guard status. ([!869])
  - Logic to retire circuits when the bridge configuration changes.
    ([#650], [!880])

- Arti can now connect via pluggable transports when compiled with the `pt-client`
  feature.  (This is on by default in the `arti` binary.) This has
  required us to implement:

  - Configuration logic for pluggable transports ([!823])
  - The client side of the SOCKS protocol ([!746])
  - An abstraction mechanism to allow the `ChanMgr` code to delegate
    channel construction to caller-provided code. ([!769], [!771], [!887],
    [!888])
  - Integrating the SOCKS client code into the `ChanMgr` code. ([!776])
  - Launching pluggable transports and communicating with them using
    Tor's pluggable transport IPC protocol. ([#394], [!779], [!813])
  - Code to keep track of which pluggable transports are needed,
    and launch them on demand. ([!886], [!893])
  - Support code to integrate the pluggable transport manager with
    `arti-client`. ([#659])

- Paths in the configuration can now be configured using
  `${PROGRAM_DIR}`, which means "the directory containing the current
  executable".  ([#586], [!760])
- Some objects can now be marked as "Redactable". A "Redactable" object
  is one that can be displayed in the logs with some of its contents
  suppressed. For example, whereas a full IP might be "192.0.2.7",
  and a completely removed IP would be logged as "[scrubbed]",
  a redacted IP might be displayed as "192.x.x.x". ([#648], [!882])

### Testing

- We now use the [Shadow] discrete event simulator to test Arti against a
  simulated Tor network in our CI tests. ([#174], [!634])
- Fuzzing for SOCKS client implementations. ([dc55272602cbc9ff])
- Fuzzing for more types of cells ([c41305d1100d9685])
- Fuzzing for pluggable transport IPC ([!814])
- CI testing for more combinations of features. ([#303], [!775])
- CI testing for more targets. ([#585], [!844])
- Better reproducible builds, even on environments with small /dev/shm
  configured. ([#614], [!818])


### Cleanups, minor features, and bugfixes

- We now use the [`hostname-validator`] crate to check hostnames for
  correctness. ([!739])
- Now that we require a more recent Rust, we no longer need to duplicate
  all of our README.md files explicitly in our crate-level
  documentation. ([#603], [!768])
- A few small refactorings to avoid copying. ([!790], [!791])
- Refactor guard-manager code to make it harder to become confused about
  which sample a guard came from. ([19fdf196d89e670f])
- More robust conversion to `u16` at some places in `tor-cell`, to avoid
  future integer overflows. ([!803])
- Refactor our "flag event" to make it easier to (eventually) use in other
  crates. ([!804])
- Significant refactoring of our file-change watching code. ([#562], [!819])
- Upgrade to [`clap` v3] for our command-line option parsing. ([#616], [!830])
- Fix documentation for starting Tor Browser with Arti on Windows. ([!849])
- Allow empty lines at the end of a router descriptor. ([!857])
- Improve some error messages while parsing directory documents.
  ([#640], [!859])
- Internal refactoring in `ChanMgr` to better match current design. ([#606],
  [!864])
- Improve display output for describing relays as channel targets, to provide
  a more useful summary, and avoid displaying too much information about
  guards. ([#647], [!868])
- Better error reporting for some kinds of router descriptor parsing failures
  ([!870])



- Numerous typo and comment fixes.

HAVE REVIEWED THROUGH: b36a23cfd331aa5b3527fc825e5c867b97da97ab






# Arti 1.0.1 — 3 October  2022

Arti 1.0.1 fixes a few bugs in our previous releases.

This is a fairly small release: Members of our team have spent a lot of
September at a company meeting, on our vacations, and/or recovering from
COVID-19. The feature work we have managed to get done is
largely behind-the-scenes preparation for our anticensorship release,
which we now hope is coming in early November.

### Breaking changes

- The `Schedule::sleep()*` functions in `tor-rtcompat` now return a
  `Result`.  This change was part of the fix for part of [#572].

### New features

- Optionally expose an accessor to get the [`CircuitBuilder`] from a
  [`CircMgr`]. If you don't mind voiding your semver guarantees,
  you can enable this accessor with the `experimental-api` feature,
  and use it to build circuits using paths of your own creation.
  ([!738])
- We now apply our "safe logging" feature to the console as well, to
  avoid exposing sensitive information in our console log. ([#553],
  [!742])

### Major bugfixes

- Fixed a busy loop that could occur when dropping an Arti client, that
  would cause Arti to busy-loop and use too much CPU. ([#572], [!725])
- Fixed compilation when building with [`async-std`]. ([!723])

### Documentation

- Our high-level documentation has significantly tidied and revised for
  clarity and completeness. ([!717])
- We've updated our documentation for
  [how to use Arti with Tor Browser]. ([!719])

### Infrastructure

- Our reproducible builds now use Rust 1.63, and the code to make
  them has been cleaned up a bit. ([!716])

### Cleanups, minor features, and minor bugfixes

- Fix a test failure that would occur on some platforms depending
  on their inlining decisions. ([#570], [!727])
- Better listing of platforms that don't have [`getresuid()`], so
  that we can compile there without breaking. ([!728])
- Preliminary back-end support for encoding and decoding
  some messages in the onion service protocol. ([!714], [!735], [!736])
- Fixes for various newly implemented [Clippy] warnings. ([!729], [!749])
- The [`RouterDesc`] type now implements `Clone` and
  `Debug`. ([571e7f9556adf12d])
- Preliminary internal API designs for most of the logic needed
  to implement Tor's anticensorship features.  These APIs are unstable,
  and mostly not implemented yet, but they give us something to fill in.
  ([#543], [#558], [!740], [!743], [!748])

Thanks to everyone who has contributed to this release, including
Alexander Færøy, Trinity Pointard, and Yuan Lyu.

Also, our deep thanks to [Zcash Community Grants] for funding the development
of Arti 1.0.0!

[!714]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/714
[!716]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/716
[!717]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/717
[!719]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/719
[!723]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/723
[!725]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/725
[!727]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/727
[!728]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/728
[!729]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/729
[!735]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/735
[!736]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/736
[!738]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/738
[!740]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/740
[!742]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/742
[!743]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/743
[!748]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/748
[!749]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/749
[#543]: https://gitlab.torproject.org/tpo/core/arti/-/issues/543
[#553]: https://gitlab.torproject.org/tpo/core/arti/-/issues/553
[#558]: https://gitlab.torproject.org/tpo/core/arti/-/issues/558
[#570]: https://gitlab.torproject.org/tpo/core/arti/-/issues/570
[#572]: https://gitlab.torproject.org/tpo/core/arti/-/issues/572
[571e7f9556adf12d]: https://gitlab.torproject.org/tpo/core/arti/-/commit/571e7f9556adf12de8c8189ddbfc78c78a534a74
[Clippy]: https://github.com/rust-lang/rust-clippy
[Zcash Community Grants]: https://zcashcommunitygrants.org/
[`CircMgr`]: https://tpo.pages.torproject.net/core/doc/rust/tor_circmgr/struct.CircMgr.html
[`CircuitBuilder`]: https://tpo.pages.torproject.net/core/doc/rust/tor_circmgr/build/struct.CircuitBuilder.html
[`RouterDesc`]: https://tpo.pages.torproject.net/core/doc/rust/tor_netdoc/doc/routerdesc/struct.RouterDesc.html
[`async-std`]: https://docs.rs/async-std/latest/async_std/
[`getresuid()`]: https://man7.org/linux/man-pages/man2/getresgid.2.html
[how to use Arti with Tor Browser]: https://gitlab.torproject.org/tpo/core/arti/-/blob/main/crates/arti/README.md#using-arti-with-tor-browser



# Arti 1.0.0 — 1 September 2022

Arti 1.0.0 adds a final set of security features, clears up some
portability bugs, and addresses numerous other issues.

With this release, we are now ready to declare Arti *stable*: we are
relatively confident that Arti has the security features that it
needs for usage via the `arti` command-line proxy, or embedding via
the `arti-client` API.

In our next releases, we will focus on adding anticensorship
features similar to C tor, including support for connecting via
bridges and pluggable transports.


### Breaking changes

- Most of the APIs in the [`arti`] crate—the one providing our
  binary—are now hidden behind an `experimental-api` feature, to mark
  that they are unstable and unsupported.  If you need to embed `arti`
  in your application, please use the [`arti-client`] crate instead.
  ([#530], [!664])
- The `default_config_file` function has been replaced with
  `default_config_files`, since we now have both a default directory and a
  default file. ([!682])

### Breaking changes in lower-level crates

- New `params()` method in the [`NetDirProvider`] trait, to expose the
  latest parameters even when we don't have a complete directory.
  ([#528], [!658])
- Large refactoring on the traits that represent a relay's set
  of identities, to better support more identity types in the future,
  and to make sure we can support bridges with unknown Ed25519
  identities when we implement them. ([#428], [!662])
- Require that our `TcpStream` types implement `Send`. ([!675])

### New features

- Arti now implements Tor's channel padding feature, to make
  [netflow logs] less useful for traffic analysis. ([#62], [!657])
- Use [`zeroize`] more consistently across our code base. This tool
  clears various sensitive objects before they get dropped, for
  defense-in-depth against memory exposure. ([#254], [!655])
- Provide a "process hardening" feature (on by default) that uses
  [`secmem_proc`] to prevent low-privileged processes from inspecting
  our memory or our monitoring our execution. This is another
  defense-in-depth mechanism.  ([#364], [!672])
- Arti now rejects attempts to run as root.  You can override this with
  with `application.allow_running_as_root`. ([#523], [!688])
- Arti now rejects attempts to run in a setuid environment: this is not
  something we support. ([#523], [!689], [!691])
- We now support having an `arti.d` directory full of `.toml`
  configuration files, to be read in sorted order. ([#271], [#474],
  [#544], [!682], [!697])
- On Unix-like platforms, we now reload our configuration file when we
  receive a `HUP` signal.  ([#316], [!702])

### Major bugfixes

- Numerous fixes to our [`fs-mistrust`] crate for Android and iOS,
  including some that prevented it from building or working correctly.
  ([!667])
- The [`fs-mistrust`] crate now handles Windows prefixes correctly.
  Previously, it would try to read `C:`, and fail. ([!698])

### Infrastructure

- The `check_licenses` tool now works with the latest version of
  `cargo-license`. ([!674])
- Our continuous integration configuration now has support for building and
  testing Arti on Windows. ([#450], [!705])

### Documentation

- Our documentation is now much more careful about listing which Cargo
  features are required for any optional items. ([#541], [!681], [!706])
- Better documentation about our API stability and overall
  design. ([#522], [#531])
- Better documentation on the `DONE` stream-close condition. ([!677])

### Cleanups, minor features, and minor bugfixes

- The `dns_port` and `socks_port` options have been renamed to
  `dns_listen` and `socks_listen`. They now support multiple
  addresses. Backward compatibility with the old options is
  retained. ([#502], [!602])
- Renamed `.inc` files to end with `.rs`, to help analysis
  tools. ([#381], [!645])
- Backend support for some cell types that we'll need down the road when
  we implement onion services. ([!651], [!648])
- Switch to the once-again-maintained main branch of [`shellexpand`].
  ([!661])
- Use less storage on disk for descriptors, by expiring them more
  aggressively. ([#527], [!669])
- Backend support for RTT estimation, as needed for congestion-based
  flow-control. ([!525])
- Running as a DNS proxy can now be disabled at compile-time, by
  turning off the `dns-proxy` feature. ([#532])
- When a circuit fails for a reason that was not the fault of the
  Tor network, we no longer count it against our total number of
  permitted circuit failures. ([#517], [!676])
- Tests for older configuration file formats. ([!684])
- Our default log messages have been cleaned up a bit, to make them
  more useful. ([!692], [0f133de6b90e799d], [e8fcf2b0383f49a6])
- We use [`safelog`] in more places, to avoid logging information that
  could be useful if the logs were stolen or accidentally
  leaked. ([!687], [!693])
- Fix a race condition that could prevent us from noticing multiple
  configuration changes in rapid succession. ([#544],
  [a7bb3a73b4dfb0e8])
- Better errors on invalid escapes in our configuration files. (In toml,
  you can't say `"C:\Users"`; you have to escape it as `"C:\\Users"`.
  We now try to explain this.) ([#549], [!695])
- Improve reliability of a `fs-mistrust` test. ([!699])
- Various tests have been adjusted to work on Windows, or disabled on Windows
  because they were checking for Unix-only features.  ([#450], [#557],
  [!696], [!701])
- When displaying filenames in logs or error messages, we try to
  replace the user's home directory with `${HOME}` or `%UserProfile%` as
  appropriate, to reduce the frequency with which the username appears
  in the logs. ([#555], [!700])

### Testing

- Lengthen a timeout in a `tor-rtcompat` test, to make it more reliable.
  ([#515], [!644])

### Acknowledgments

Thanks to everyone who has contributed to this release, including
Alexander Færøy, Arturo Marquez, Dimitris Apostolou, Emptycup, FAMASoon,
Trinity Pointard, and Yuan Lyu.

Also, our deep thanks to [Zcash Community Grants] for funding the development
of Arti 1.0.0!

[!525]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/525
[!602]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/602
[!644]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/644
[!645]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/645
[!648]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/648
[!651]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/651
[!655]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/655
[!657]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/657
[!658]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/658
[!661]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/661
[!662]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/662
[!664]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/664
[!667]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/667
[!669]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/669
[!672]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/672
[!674]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/674
[!675]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/675
[!676]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/676
[!677]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/677
[!681]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/681
[!682]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/682
[!684]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/684
[!687]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/687
[!688]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/688
[!689]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/689
[!691]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/691
[!692]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/692
[!693]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/693
[!695]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/695
[!696]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/696
[!697]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/697
[!698]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/698
[!699]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/699
[!700]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/700
[!701]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/701
[!702]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/702
[!705]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/705
[!706]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/706
[#62]: https://gitlab.torproject.org/tpo/core/arti/-/issues/62
[#254]: https://gitlab.torproject.org/tpo/core/arti/-/issues/254
[#271]: https://gitlab.torproject.org/tpo/core/arti/-/issues/271
[#316]: https://gitlab.torproject.org/tpo/core/arti/-/issues/316
[#364]: https://gitlab.torproject.org/tpo/core/arti/-/issues/364
[#381]: https://gitlab.torproject.org/tpo/core/arti/-/issues/381
[#428]: https://gitlab.torproject.org/tpo/core/arti/-/issues/428
[#450]: https://gitlab.torproject.org/tpo/core/arti/-/issues/450
[#474]: https://gitlab.torproject.org/tpo/core/arti/-/issues/474
[#502]: https://gitlab.torproject.org/tpo/core/arti/-/issues/502
[#515]: https://gitlab.torproject.org/tpo/core/arti/-/issues/515
[#517]: https://gitlab.torproject.org/tpo/core/arti/-/issues/517
[#522]: https://gitlab.torproject.org/tpo/core/arti/-/issues/522
[#523]: https://gitlab.torproject.org/tpo/core/arti/-/issues/523
[#527]: https://gitlab.torproject.org/tpo/core/arti/-/issues/527
[#528]: https://gitlab.torproject.org/tpo/core/arti/-/issues/528
[#530]: https://gitlab.torproject.org/tpo/core/arti/-/issues/530
[#531]: https://gitlab.torproject.org/tpo/core/arti/-/issues/531
[#532]: https://gitlab.torproject.org/tpo/core/arti/-/issues/532
[#541]: https://gitlab.torproject.org/tpo/core/arti/-/issues/541
[#544]: https://gitlab.torproject.org/tpo/core/arti/-/issues/544
[#549]: https://gitlab.torproject.org/tpo/core/arti/-/issues/549
[#555]: https://gitlab.torproject.org/tpo/core/arti/-/issues/555
[#557]: https://gitlab.torproject.org/tpo/core/arti/-/issues/557
[0f133de6b90e799d]: https://gitlab.torproject.org/tpo/core/arti/-/commit/0f133de6b90e799d37fdcd9dc75f9f94acb6bb6c
[a7bb3a73b4dfb0e8]: https://gitlab.torproject.org/tpo/core/arti/-/commit/a7bb3a73b4dfb0e8e0f36994de3d31389d4997b9
[e8fcf2b0383f49a6]: https://gitlab.torproject.org/tpo/core/arti/-/commit/e8fcf2b0383f49a6d927cb094fdc00f766e82580
[`NetDirProvider`]: https://tpo.pages.torproject.net/core/doc/rust/tor_netdir/trait.NetDirProvider.html
[`arti-client`]: https://tpo.pages.torproject.net/core/doc/rust/arti_client/index.html
[`arti`]: https://tpo.pages.torproject.net/core/doc/rust/arti/index.html
[`fs-mistrust`]: https://tpo.pages.torproject.net/core/doc/rust/fs_mistrust/index.html
[`safelog`]: https://tpo.pages.torproject.net/core/doc/rust/safelog/index.html
[`secmem_proc`]: https://crates.io/crates/secmem-proc
[`shellexpand`]: https://crates.io/crates/shellexpand
[`zeroize`]: https://crates.io/crates/zeroize
[netflow logs]: https://en.wikipedia.org/wiki/NetFlow
[Zcash Community Grants]: https://zcashcommunitygrants.org/



# Arti 0.6.0 — 1 August 2022

Arti 0.6.0 fixes bugs, cleans up some messy internals, improves error
messages, and adds more preparation for future work in netflow padding.

(These notes summarize changes in all crates since Arti 0.5.0.)

### Breaking changes

- The `download_tolerance` configuration section has been renamed to
  `directory_tolerance`: It's not about tolerances at download time, but
  rather about how expired or premature a directory can be. The related
  `DirSkewTolerance` has also been renamed. ([#503], [!638])
- Several methods related to managing the [`Mistrust`] file-permissions
  object have been removed or changed, thanks to refactoring elsewhere.
  ([#483], [#640])

### Breaking changes in lower level crates

These changes should not break any code that only depends on the
[`arti_client`] APIs, but they will affect programs that use APIs from
lower-level crates to interact more closely with the Tor protocols.

- The `Error` types in all crates have been refactored to include far more
  accurate information about errors and their context.  This does not break
  the [`arti_client`] API, but it will affect anybody using lower-level
  crates. ([#323], [!614], [!616], [!619], [!620], [!625], [!628], [!638])
- The [`Writeable`] trait used to encode data, and related methods,
  are now fallible.  Previously they had no way to report errors.
  ([#513], [!623], [!640])
- The [`tor-cert`] APIs have been tweaked to support more compact
  internal representations and more idiomatic usage. ([#512], [!641],
  [!643]).
- The [`NetDirProvider`] API, and related APIs in [`tor-dirmgr`], have been
  changed to support returning network directories with varying timeliness
  requirements. ([#528], [!642])
- The [`fs-mistrust`] API no longer supports certain operations related to
  unix groups, when built on iOS. ([!652])

### New features

- The internal [`tor-cert`] API now supports generating Tor-compatible
  certificates. ([#511], [!611])
- Improved API support for circuit handshakes that include external
  encrypted data, such as [`ntor-v3`] and [`hs-ntor`]. ([!618])

### Major bugfixes

- Fix a bug that prevented Arti from storing consensus files on
  Windows. Previously, we had generated filenames containing a colon, which
  Windows treats as a reserved character. ([#516], [!627])
- Fix compilation on iOS.  Our dependency on the [`rust-users`] crate
  had broken our ability to work correctly there. ([#519], [!652])

### Infrastructure

- Our license checker now tolerates complicated licenses with nested boolean
  expressions, by explicitly allow-listing the ones we like. ([!635])

### Cleanups, minor features, and minor bugfixes

- Upgrade to a newer version of [`base64ct`], and remove some work-around
  logic required for the older versions.  ([!608])
- Various typo fixes. ([!609], [!610], [!650])
- Upgrade to a pre-release version of
  [`x25519-dalek`] to avoid a hard dependency on an outdated version of
  [`zeroize`], so we can follow the latest version of the [`rsa`] crate.
  ([#448], [!612])
- Our client-global "dormant mode" flag is now published via a
  [`postage::watch`], which makes it easier to observe for changes. ([!632])
- Preliminary (unused) support for some onion-service-related cells.
  ([!626])
- The [`fs-mistrust`] crate can now use environment variables to be told to
  disable itself. This has allowed for simplifications elsewhere in our
  configuration logic. ([#483], [!630])
- Clean up an incorrect `--help` message. ([!633])

### Testing

- More tests for [`arti-hyper`]. ([!615])
- More tests for our undderlying base-64 implementation. ([!613])

### Acknowledgments

Thanks to everyone who has contributed to this release, including Arturo
Marquez, Dimitris Apostolou, `feelingnothing`, Jim Newsome, Richard
Pospesel, `spongechameleon`, Trinity Pointard, and Yuan Lyu.

[!608]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/608
[!609]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/609
[!610]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/610
[!611]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/611
[!612]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/612
[!613]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/613
[!614]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/614
[!615]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/615
[!616]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/616
[!618]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/618
[!619]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/619
[!620]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/620
[!623]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/623
[!625]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/625
[!626]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/626
[!627]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/627
[!628]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/628
[!630]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/630
[!632]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/632
[!633]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/633
[!635]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/635
[!638]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/638
[!640]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/640
[!641]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/641
[!642]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/642
[!643]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/643
[!650]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/650
[!652]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/652
[#323]: https://gitlab.torproject.org/tpo/core/arti/-/issues/323
[#448]: https://gitlab.torproject.org/tpo/core/arti/-/issues/448
[#483]: https://gitlab.torproject.org/tpo/core/arti/-/issues/483
[#503]: https://gitlab.torproject.org/tpo/core/arti/-/issues/503
[#511]: https://gitlab.torproject.org/tpo/core/arti/-/issues/511
[#512]: https://gitlab.torproject.org/tpo/core/arti/-/issues/512
[#513]: https://gitlab.torproject.org/tpo/core/arti/-/issues/513
[#516]: https://gitlab.torproject.org/tpo/core/arti/-/issues/516
[#519]: https://gitlab.torproject.org/tpo/core/arti/-/issues/519
[#528]: https://gitlab.torproject.org/tpo/core/arti/-/issues/528
[#640]: https://gitlab.torproject.org/tpo/core/arti/-/issues/640
[`Mistrust`]: https://tpo.pages.torproject.net/core/doc/rust/fs_mistrust/struct.Mistrust.html
[`NetDirProvider`]: https://tpo.pages.torproject.net/core/doc/rust/tor_netdir/trait.NetDirProvider.html
[`Writeable`]: https://tpo.pages.torproject.net/core/doc/rust/tor_bytes/trait.Writeable.html
[`arti-hyper`]: https://tpo.pages.torproject.net/core/doc/rust/arti_hyper/index.html
[`arti_client`]: https://tpo.pages.torproject.net/core/doc/rust/arti_client/index.html
[`base64ct`]: https://docs.rs/base64ct/latest/base64ct/
[`fs-mistrust`]: https://tpo.pages.torproject.net/core/doc/rust/fs_mistrust/index.html
[`hs-ntor`]: https://gitlab.torproject.org/tpo/core/torspec/-/blob/main/rend-spec-v3.txt#L1876
[`ntor-v3`]: https://gitlab.torproject.org/tpo/core/torspec/-/blob/main/proposals/332-ntor-v3-with-extra-data.md
[`postage::watch`]: https://docs.rs/postage/latest/postage/watch/index.html
[`rsa`]: https://docs.rs/rsa/latest/rsa/
[`rust-users`]: https://docs.rs/users/latest/users/
[`tor-cert`]: https://tpo.pages.torproject.net/core/doc/rust/tor_cert/index.html
[`tor-dirmgr`]: https://tpo.pages.torproject.net/core/doc/rust/tor_dirmgr/index.html
[`x25519-dalek`]: https://docs.rs/x25519-dalek/latest/x25519_dalek/
[`zeroize`]: https://docs.rs/zeroize/latest/zeroize/




# tor-dirmgr patch release 0.5.1 — 14 July 2022

On 14 July 2022, we put out a patch release (0.5.1) to `tor-dirmgr`, to fix
a bug that prevented Arti from storing consensus files on
Windows. Previously, we had generated filenames containing a colon, which
Windows treats as a reserved character.

Thanks to "@feelingnothing" for the bug report and the fix.



# Arti 0.5.0 — 24 Jun 2022

Arti 0.5.0 adds more cryptographic acceleration, a useful set of toplevel
build features, reachable-address filtering, detection for failed directory
downloads, and numerous cleanups.

Note that for the first time, we did _not_ have breaking changes in the
`arti-client` crate, so its version is staying at 0.4.1.

### Breaking changes

- The `NetDirProvider` trait now requires `Send` and
  `Sync`. ([2223398eb1670c15])
- The traits that make up `Runtime` now also require `Send` and
  `Sync`. ([3ba3b26842254cfd])
- The "journald" option for LoggingConfig now takes
  `Option<Into<String>>`. ([!582])
- (Various smaller breaking changes in lower-level crates.)

### New features

- We can now (optionally) use OpenSSL as our cryptography backend, for
  its better performance. To enable this, build with the `accel-openssl`
  feature. ([#441], [#442], [#493], [!550])
- We can now (optionally) use the assembly implementation of SHA1 in our
  cryptography backend, for its better performance.  To enable this,
  build with the `accel-sha1-asm` feature. ([#441], [!590])
- Our top-level crates (`arti` and `arti-client`) now have a `full`
  feature that enables _most_ of their optional features—but not those
  that are unstable, those that are testing-only, those that select a
  particular implementation or build flag, or those whose licenses may
  be incompatible with some downstream licenses. ([#499], [!584])
- We now notice when we get stuck when trying to bootstrap a directory,
  and report the problem as part of our blockage-detection API. ([#468],
  [!587])
- We support a `reachable_addrs` feature that allows the user to tell
  Arti that only some addresses and/or ports are reachable over the
  local network.  ([#491], [#93], [!583])
- Our configuration logic now handles "no such value" options (like
  using "0" to mean "no port") more consistently, warns about
  unrecognized options, and includes tests to be sure that the "default
  configuration" file really lists all of the defaults.  ([#457],
  [#480], [#488], [!582], [!589], [!594])

### Infrastructure

- Our shell scripts are now more robust to a few different runtime
  environments. ([!539], [!541])
- Our license-checking code is more accurate and careful. ([#462], [!559])
- The PRNG logic in our unit tests now uses reproducible seeds,
  so that we can better diagnose issues related to sometimes-failing
  tests. ([!561])

### Cleanups, minor features, and minor bugfixes

- The `fs-mistrust` crate now handles environments where
  `getgrouplist()` doesn't include the current GID. ([#487], [!548])
- `dns_port` now de-duplicates requests based on transaction
   ID. ([#441], [!535])
- `dns_port` returns more accurate errors in several cases. ([!564])
- More unit tests in various places. ([!551], [!562])
- We avoid initializing a `DataStream` if it would immediately be
  closed. ([!556])
- We return a more useful error message for incorrect file permissions
  ([!554])
- The directory manager code now uses a refactored timing backend that
  knows how to respect dormant mode. ([#497], [!571])
- Fix an unreliable test related to guard filtering. ([#491],
  [89f9e1decb7872d6])
- We now use a constant-time implementation of base-64
  decoding. ([#154], [!600])
- We now make sure that at least _some_ log messages can get reported
  before the logging is configured.  In particular, unknown
  configuration settings now generate warning messages on stderr when
  `arti` starts up.  ([!589])
- Many of our lower-level `Error` types have been refactored to give
  more accurate, useful, and best-practices-conformant messages.
  ([#323], [!598], [!601], [!604])

### Acknowledgments

Thanks to everybody who has contributed to this release, including
0x4ndy, Alex Xu, Arturo Marquez, Dimitris Apostolou, Michael McCune,
Neel Chauhan, Orhun Parmaksız, Steven Murdoch, and Trinity Pointard.

[!535]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/535
[!539]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/539
[!541]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/541
[!548]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/548
[!550]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/550
[!551]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/551
[!554]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/554
[!556]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/556
[!559]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/559
[!561]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/561
[!562]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/562
[!564]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/564
[!571]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/571
[!582]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/582
[!583]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/583
[!584]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/584
[!587]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/587
[!589]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/589
[!590]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/590
[!594]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/594
[!598]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/598
[!600]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/600
[!601]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/601
[!604]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/604
[#93]: https://gitlab.torproject.org/tpo/core/arti/-/issues/93
[#154]: https://gitlab.torproject.org/tpo/core/arti/-/issues/154
[#323]: https://gitlab.torproject.org/tpo/core/arti/-/issues/323
[#441]: https://gitlab.torproject.org/tpo/core/arti/-/issues/441
[#442]: https://gitlab.torproject.org/tpo/core/arti/-/issues/442
[#457]: https://gitlab.torproject.org/tpo/core/arti/-/issues/457
[#462]: https://gitlab.torproject.org/tpo/core/arti/-/issues/462
[#468]: https://gitlab.torproject.org/tpo/core/arti/-/issues/468
[#480]: https://gitlab.torproject.org/tpo/core/arti/-/issues/480
[#487]: https://gitlab.torproject.org/tpo/core/arti/-/issues/487
[#488]: https://gitlab.torproject.org/tpo/core/arti/-/issues/488
[#491]: https://gitlab.torproject.org/tpo/core/arti/-/issues/491
[#493]: https://gitlab.torproject.org/tpo/core/arti/-/issues/493
[#497]: https://gitlab.torproject.org/tpo/core/arti/-/issues/497
[#499]: https://gitlab.torproject.org/tpo/core/arti/-/issues/499
[2223398eb1670c15]: https://gitlab.torproject.org/tpo/core/arti/-/commit/2223398eb1670c159151bc9aae5fed346b88c904
[3ba3b26842254cfd]: https://gitlab.torproject.org/tpo/core/arti/-/commit/3ba3b26842254cfd9033ea37b44b746895bcbd02
[89f9e1decb7872d6]: https://gitlab.torproject.org/tpo/core/arti/-/commit/89f9e1decb7872d688d126fe41ab28b6bd0504a0



# Arti 0.4.0 — 27 May 2022

Arti 0.4.0 wraps up our changes to the configuration logic,
detects several kinds of unsafe filesystem configuration, and has a
refactored directory manager to help us tolerate far more kinds of broken
networks and invalid documents.

There are significant breaking changes in this release; please see
below.

### Breaking changes

- We've merged the last (we hope) of our breaking configuration changes.
  - Configuration and command-line loading is now handled consistently
    via the option-agnostic `tor-config` crate. ([!495], [!498])
  - We follow a uniform pattern where configuration objects are
    constructed from associated Builder types, and these Builders
    support [`serde`] traits, and everything provides a consistent
    API. ([!499], [!505], [!507])
  - The `arti-config` crate no longer exists: its functionality has been
    divided among `arti`, `arti-client`, and `tor-config`. ([!508])
  - The [`TorClientConfig`] object no longer implements
    `TryInto<DirMgrConfig>`.
  - The configuration logic now supports extensible configurations,
    where applications can add their own sections and keys without
    interfering with Arti, and unrecognized keys can still produce
    warnings. ([#459], [#417])
- The [`Runtime`] trait now also requires that `Debug` be implemented.
  ([!496])
- (Various smaller breaking changes in lower-level crates.)

### New features

- Arti now checks file permissions before starting up, and rejects
  configuration files, state files, and cache files if they can be modified
  by untrusted users. You can disable this feature with the
  `ARTI_FS_DISABLE_PERMISSION_CHECKS` environment variable.  ([#315],
  [#465], [!468], [!483], [!504], [!515])
- Arti now tolerates a much wider array of broken networks and
  installations when trying to bootstrap a working connection to the Tor
  network. This includes improved handling for skewed clocks,
  untimely documents, and invalid consensus documents.  ([#412], [#466],
  [#467], [!500], [!501], [!511])

### Major bugfixes

- Arti no longer exits or gets stuck when it has received a consensus
  with invalid signatures, or a consensus claiming to be signed with
  certificates that don't exist. ([#412], [#439], [!511])

### Infrastructure

- Clean up more effectively in chutney-based test
  scripts. ([ee9730cab4e4b21e])
- Nightly [coverage reports] are now generated and exported to gitlab
  pages. ([!489])
- We no longer include a dependency on [`cargo-husky`]: If you want to
  have [git hooks] in your local repository, you'll need to install your
  own. (See [CONTRIBUTING.md] for instructions.) ([!494])
- Our shell scripts are more uniform in their behaiour. ([!533])

### Documentation and Examples

- Better documentation for Cargo features. ([#445], [!496])
- Better explanation of what platforms and dependencies we support,
  and what "support" means anyway. ([#379], [!513])
- An advanced example of using the stream isolation feature for
  trickier behavior. ([#414], [!524])

### Cleanups, minor features, and minor bugfixes

- Use [`tinystr`] to hold relay nicknames; this should save a bit of
  memory. ([!405])
- Refactor the [`DirMgr`] crate's bootstrapping implementation to reduce
  amount of mutable state, reduce complexity, and reduce the amount of
  code that has to modify a running directory. ([!488])
- We only check the formatting of our backtraces on our target
  platforms, to better tolerate operating systems where Rust's
  backtraces don't correctly include function details. ([#455], [!512])
- [`DirMgr`] is now better at remembering the origin
  of a piece of directory information. ([ef2640acfaf9f873])
- Used a new [`Sink::prepare_send_from`] helper to simplify the
  implementation of Channel reactors. ([!514])
- The SOCKS code now sends correct error messages under more
  circumstances. ([#258], [!531])


### Acknowledgments

Thanks to everybody who has contributed to this release, including
Alex Xu, Dimitris Apostolou, Jim Newsome, Michael Mccune, and Trinity
Pointard.

[!405]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/405
[!468]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/468
[!483]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/483
[!488]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/488
[!489]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/489
[!494]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/494
[!495]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/495
[!496]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/496
[!498]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/498
[!499]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/499
[!500]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/500
[!501]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/501
[!504]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/504
[!505]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/505
[!507]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/507
[!508]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/508
[!511]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/511
[!512]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/512
[!513]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/513
[!514]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/514
[!515]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/515
[!524]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/524
[!531]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/531
[!533]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/533
[#258]: https://gitlab.torproject.org/tpo/core/arti/-/issues/258
[#315]: https://gitlab.torproject.org/tpo/core/arti/-/issues/315
[#379]: https://gitlab.torproject.org/tpo/core/arti/-/issues/379
[#412]: https://gitlab.torproject.org/tpo/core/arti/-/issues/412
[#414]: https://gitlab.torproject.org/tpo/core/arti/-/issues/414
[#417]: https://gitlab.torproject.org/tpo/core/arti/-/issues/417
[#439]: https://gitlab.torproject.org/tpo/core/arti/-/issues/439
[#445]: https://gitlab.torproject.org/tpo/core/arti/-/issues/445
[#455]: https://gitlab.torproject.org/tpo/core/arti/-/issues/455
[#459]: https://gitlab.torproject.org/tpo/core/arti/-/issues/459
[#465]: https://gitlab.torproject.org/tpo/core/arti/-/issues/465
[#466]: https://gitlab.torproject.org/tpo/core/arti/-/issues/466
[#467]: https://gitlab.torproject.org/tpo/core/arti/-/issues/467
[ee9730cab4e4b21e]: https://gitlab.torproject.org/tpo/core/arti/-/commit/ee9730cab4e4b21ec40d05becd4c9f54a92d7c29
[ef2640acfaf9f873]: https://gitlab.torproject.org/tpo/core/arti/-/commit/ef2640acfaf9f873ca3de5253aae93b5032e659a
[CONTRIBUTING.md]: https://gitlab.torproject.org/tpo/core/arti/-/blob/main/CONTRIBUTING.md
[`DirMgr`]: https://tpo.pages.torproject.net/core/doc/rust/tor_dirmgr/struct.DirMgr.html
[`Runtime`]: https://tpo.pages.torproject.net/core/doc/rust/tor_rtcompat/trait.Runtime.html
[`Sink::prepare_send_from`]: https://tpo.pages.torproject.net/core/doc/rust/tor_basic_utils/futures/trait.SinkExt.html#tymethod.prepare_send_from
[`TorConfig`]: https://tpo.pages.torproject.net/core/doc/rust/arti_client/config/struct.TorClientConfig.html
[`cargo-husky`]: https://github.com/rhysd/cargo-husky
[`serde`]: https://serde.rs/
[`tinystr`]: https://docs.rs/tinystr/latest/tinystr/
[coverage reports]: https://tpo.pages.torproject.net/core/arti/coverage/
[git hooks]: https://gitlab.torproject.org/tpo/core/arti/-/tree/main/maint



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
  we aim to protect more information moving forward.  This feature can
  be disabled with the configuration option
  `storage.log_sensitive_information`.  ([#189], [!485])

### Major bugfixes

- Our circuit-build logic is now much more careful about which errors are
  retriable, and how long to wait between attempts. ([#421], [!443])
- We resolved a race condition that could cause internal errors to be
  reported erroneously during circuit construction. ([#427])
- We no longer interpret a successful circuit as meaning that a
  guard is working _as a directory_.  Even if it can build circuits, it
  may be unable to answer directory requests to our satisfaction.
  ([b3e06b93b6a34922])

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
