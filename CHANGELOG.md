### Notes

This file describes changes in Arti through the current release.  Once Arti
is more mature, we may switch to using a separate changelog for each crate.

# Arti 1.2.0 — 4 March 2024

Arti 1.2.0 continues work on support for running onion services.
You can now launch an onion service and expect it to run,
although you may well encounter bugs.

We have fixed a number of bugs and security issues,
and have made the `onion-service-service` feature non-experimental.

In the next releases, we will focus on implementing
the missing security features and on improving stability.

Don't rely on this onion service implementation for security yet;
there are a number of [missing security features]
we will need to develop before we can recommend them
for actual use.

See [`doc/OnionService.md`] for instructions and caveats.

### Major bugfixes

- Empty DATA messages are a way to inject an undetected traffic signal, so we
  now reject empty DATA messages, and prevent them from being constructed
  through the [`tor-cell`] API.  This is tracked as [TROVE-2024-001].
  ([!1981], [#1269])

### Breaking changes in lower-level crates

- In [`tor-circmgr`], `Error::GuardNotUsable`, `Error::CircTimeout`,
  and `Error::Protocol` now contain the process-unique identifier of the circuit
  that caused the error. ([!2003])
- In [`tor-hsclient`], remove `HsClientNickname` and the nickname argument from
  `HsClientDescEncKeypairSpecifier::new`. ([!1998], [#1283])
- In [`tor-hsrproxy`], add a `String` representing the error message to
  `ProxyConfigError::UnrecognizedTargetType`,
  `ProxyConfigError::InvalidTargetAddr`, `ProxyConfigError::InvalidPort`
  ([!1973], [#1266])
- In [`tor-hsservice`], remove the unimplemented `max_concurrent_streams_per_circuit`
  configuration option from `OnionServiceConfigBuilder`.  We may implement and
  reinstate it in a future release. ([!1996])
- In [`tor-keymgr`], rename `KeyInfoExtractor` to `KeyPathInfoExtractor`.
  ([bd85bffd0a388f57])
- In [`tor-keymgr`], rename `{to,from}_component()` to `{to,from}_slug()`.
  ([1040df929f643a2f])

### Onion service development

- Improve the key manager APIs. ([!1952], [#1115])
- Add more context to [`tor-hsrproxy`] configuration error messages. ([!1973])
- Design an API for vanguards. ([!1970])
- Make the descriptor publisher conform with the specification, by periodically
  republishing the hidden service descriptor.  This fixes a serious reachability
  bug. ([!1971], [#1241], [#1280])
- Rotate old introduction point relays even if they are not working.
  ([72c021555e1095f1])
- Expire old on-disk introduction point state. ([!1977], [!1982], [#1198])
- Expose `HsNickname::new`. ([f3720ac2c0f16883])
- Design the client and service configuration, and a CLI subcommand, for hidden
  service client authorization. ([!1987])
- Improve the ergonomics of our key listing and removal APIs. ([!1988], [#1271])
- Include the `ArtiPath` in key path errors. ([!1960], [#1115])
- Improve circuit error logging by including the process-unique identifier of
  the circuit in error messages. ([!2003], [#1297])
- Improve status reporting from onion services. ([!1966], [#1083])
- Design an API for bandwidth rate limiting. ([!1965])
- Improve descriptor publisher error reporting. ([!1991])
- Remove the client nickname from onion service client key specifiers. ([!1998],
  [#1283])
- When reconfiguring an onion service, reject any changes that are inappropriate
  or would put the service in a bad state. ([!1996], [#1209])
- Remove the keystore directory configuration option, pending design work
  relating to RPC and multi-user Arti. ([!1995], [#1202])
- Mark `onion-service-service` and every feature it depends on as
  non-experimental. ([!1993], [#1182])
- Fix a bug that prevented the descriptor publisher from fully processing the
  results of publish tasks, causing it to republish the descriptor unnecessarily
  in some circumstances. ([!1983])

### Other major new features in our Rust APIs

- [`tor-persist`] now provides new `state_dir` APIs for instance iteration and
  expiry needed for onion service state expiry.  ([!1968], [#1163])

### Documentation and examples

- Fix the casing of our recognized key paths. ([1a900081e945679e])
- Minor updates to the release process. ([!1959], [!1963])
- Fix typos in the [`tor-guardmgr`] README. ([!1980])
- Reword the [`tor-keymgr`] README for clarity. ([489a2555f28daa6d])
- Update onion service documentation. ([!1994], [#1287])
- Clarify the onion service configuration instructions from
  `doc/OnionService.md`, remove unsupported "unix:" example ([!1972], [#1266])

### Testing

- Improve replay log fork test. ([!1974], [!2010], [#1264])
- In the introduction point manager tests, avoid reusing the RNG seed.
  ([b515baf27f194470])
- Our [Shadow] CI tests now use the latest versions of `shadow` and `tgen`, and
  no longer pull `libigraph` from bullseye. ([!1958])

### Cleanups, minor features, and bugfixes

- Allow overriding `cargo` in [`semver-checks`]. ([83c29b0d805f908e])
- Introduce a [`list_crates_publish`] script. ([b03e5d5e11c52faf])
- Fix compilation with musl. ([!1961], [#1264])
- Add `fixup-features` to the main workspace, make various improvements to
  `fixup-features`, `check_toposort`, `list_crates` ([!1969], [#1263])
- Use `std::default::Default` instead of [educe]'s `Default` in a number of
  places in preparation for the upgrade to educe 0.5. ([!1975], [#1257])
- Require the Fast and Stable flags as appropriate. ([!1976], [#1100])
- Refactor and improve error hinting in [`arti`] and [`arti-client`]. ([!1986],
  [#1165])
- Do not output ANSI escape codes when logging to file. ([!1999], [#1298])
- Upgrade our dependency on [curve25519-dalek] from 4.1.1 to 4.1.2 ([!2000])
- Upgrade to the latest versions of [event-listener], [rusqlite],
  [async-broadcast], [signature], [config]. ([!2001], [!2004])

### Acknowledgments

Thanks to everybody who's contributed to this release, including
Alexander Færøy and Jim Newsome.

Also, our deep thanks to [Zcash Community Grants] and our [other sponsors]
for funding the development of Arti!

[!1297]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1297
[!1961]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1961
[!1952]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1952
[!1958]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1958
[!1959]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1959
[!1960]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1960
[!1963]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1963
[!1965]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1965
[!1966]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1966
[!1968]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1968
[!1969]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1969
[!1970]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1970
[!1971]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1971
[!1972]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1972
[!1973]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1973
[!1974]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1974
[!1975]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1975
[!1976]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1976
[!1977]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1977
[!1980]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1980
[!1981]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1981
[!1982]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1982
[!1983]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1983
[!1986]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1986
[!1987]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1987
[!1988]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1988
[!1991]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1991
[!1993]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1993
[!1994]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1994
[!1995]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1995
[!1996]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1996
[!1998]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1998
[!1999]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1999
[!2000]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/2000
[!2001]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/2001
[!2003]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/2003
[!2004]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/2004
[!2010]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/2010
[#1083]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1083
[#1100]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1100
[#1115]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1115
[#1163]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1163
[#1165]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1165
[#1182]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1182
[#1198]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1198
[#1202]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1202
[#1209]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1209
[#1241]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1241
[#1257]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1257
[#1263]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1263
[#1264]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1264
[#1266]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1266
[#1269]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1269
[#1271]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1271
[#1280]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1280
[#1283]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1283
[#1287]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1287
[#1297]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1297
[#1298]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1298
[1040df929f643a2f]: https://gitlab.torproject.org/tpo/core/arti/-/commit/1040df929f643a2fd2a1ccb0400f1dd2f2beac98
[1a900081e945679e]: https://gitlab.torproject.org/tpo/core/arti/-/commit/1a900081e945679e80d29797ae00c206f2cd78f1
[489a2555f28daa6d]: https://gitlab.torproject.org/tpo/core/arti/-/commit/489a2555f28daa6d5f523480f434f27292783abd
[72c021555e1095f1]: https://gitlab.torproject.org/tpo/core/arti/-/commit/72c021555e1095f1be3f658acac5655b54842347
[83c29b0d805f908e]: https://gitlab.torproject.org/tpo/core/arti/-/commit/83c29b0d805f908e98ed1742491f3145f547fb2e
[b03e5d5e11c52faf]: https://gitlab.torproject.org/tpo/core/arti/-/commit/b03e5d5e11c52faf441294c8c883a2dfbc0d2021
[b515baf27f194470]: https://gitlab.torproject.org/tpo/core/arti/-/commit/b515baf27f1944708285849503dfcd08bb7ac73b
[bd85bffd0a388f57]: https://gitlab.torproject.org/tpo/core/arti/-/commit/bd85bffd0a388f579d42c8a0758091232bf901a0
[f3720ac2c0f16883]: https://gitlab.torproject.org/tpo/core/arti/-/commit/f3720ac2c0f16883abc1597ad828f99022a0e320
[Shadow]: https://shadow.github.io/
[TROVE-2024-001]: https://gitlab.torproject.org/tpo/core/team/-/wikis/NetworkTeam/TROVE
[`arti-client`]: https://tpo.pages.torproject.net/core/doc/rust/arti_client/index.html
[`arti`]: https://tpo.pages.torproject.net/core/doc/rust/arti/index.html
[`list_crates_publish`]: https://gitlab.torproject.org/tpo/core/arti/-/tree/main/maint/list_crates_publish
[`semver-checks`]: https://gitlab.torproject.org/tpo/core/arti/-/tree/main/maint/semver-checks
[`tor-cell`]: https://tpo.pages.torproject.net/core/doc/rust/tor_cell/index.html
[`tor-circmgr`]: https://tpo.pages.torproject.net/core/doc/rust/tor_circmgr/index.html
[`tor-guardmgr`]: https://tpo.pages.torproject.net/core/doc/rust/tor_guardmgr/index.html
[`tor-hsclient`]: https://tpo.pages.torproject.net/core/doc/rust/tor_hsclient/index.html
[`tor-hsrproxy`]: https://tpo.pages.torproject.net/core/doc/rust/tor_hsrproxy/index.html
[`tor-hsservice`]: https://tpo.pages.torproject.net/core/doc/rust/tor_hsservice/index.html
[`tor-keymgr`]: https://tpo.pages.torproject.net/core/doc/rust/tor_keymgr/index.html
[`tor-persist`]: https://tpo.pages.torproject.net/core/doc/rust/tor_persist/index.html
[async-broadcast]: https://crates.io/crates/async-broadcast
[config]: https://crates.io/crates/config
[curve25519-dalek]: https://crates.io/crates/curve25519-dalek
[educe]: https://crates.io/crates/educe
[event-listener]: https://crates.io/crates/event-listener
[rusqlite]: https://crates.io/crates/rusqlite
[signature]: https://crates.io/crates/signature


# Arti 1.1.13 — 5 February 2024

Arti 1.1.13 continues work on support for running onion services.
You can now launch an onion service and expect it to run.

We have fixed a number of bugs.  The user experience is still not
great, and the onion-service-service feature is still experimental.
We have reorganised the on-disk state and key storage, to make it more
sensible; we hope (but don't promise!) it's now the final layout.
Don't rely on this onion service implementation for security yet;
there are a number of [missing security features]
we will need to develop before we can recommend them
for actual use.

See `doc/OnionService.md` for instructions and caveats.

### Breaking changes in lower-level crates

- [`tor-hsclient`]\: Replaced `HsClientKeyRole`,
  `HsClientSecretKeySpecifier` with `HsClientDescEncKeypairSpecifier`.
  Renamed `HsClientSpecifier` to `HsClientNickname`.
  ([!1864], [!1931])
- [`tor-hscrypto`]\: `AesOpeKey::encrypt` now takes a
  `SrvPeriodOffset`; Replaced `TimePeriodOffset` with
  `SrvPeriodOffset`; Removed `TimePeriod::offset_within_period`.
  ([!1904], [#1166])
- [`tor-netdir`]\: `hs_dirs_download` parameters changed;
  `hs_intro_*_lifetime` parameters renamed.
  ([!1903], [!1904], [#1254])

### Onion service development

- Complete overhaul of the way the hidden service code stores non-key
  persistent state.  Pathnames have changed as a result.
  ([!1853], [#1183], [!1941])
- Many improvements to keystore, key and `KeySpecifier` handling,
  including incompatible changes to on-disk key paths.
  ([!1864], [!1863], [!1883], [#1260], [!1949], [#1074], [!1948])
- Fix "service fails after approx 12 hours" bug.
  ([#1242], [!1901])
- Fix time period processing bugs including `HSS: "internal error"
  "current wallclock time not within TP?!"`.
  ([#1155], [#1166], [#1254], [!1903], [!1904], [!1914])
- Correctly rate-limit descriptor publication.
  ([!1951])
- Fixes to services shutdown.
  ([!1875], [!1895], [!1897], [#1236], [!1899], [!1917], [!1921])
- Improve error and corner case handling in descriptor publisher.
  ([!1861])
- Work on expiring keys: we expire descriptor keys now (although we
  don't actually properly delete all keys when we need to, yet).
  ([!1909])
- Only choose Stable relays for introduction points.
  ([!1884], [#1240], [#1211])
- Better handling of introduction point establishment failures.
  ([!1889], [!1915])
- Better handling of anomalous situations (including excessive
  requests) on introduction circuits.
  ([#1188], [#1189], [!1892], [!1916])
- Tolerate `INTRO_ESTABLISHED` messages with (unknown) extensions.
  ([!1898])
- Correct and improve various timing and tuning parameters.
  ([!1911], [!1924])
- Improve status reporting from hidden services.
  ([!1902])
- Public API of `tor-hsservice` crate overhauled.
  ([#1227], [#1220], [!1887])
- Mark lower-level hs-service features non-experimental.
  ([!1908])
- Defend against partial writes of introduction point replay log
  entries.
  ([!1920])
- Corrections to error handling, including to handling of introduction
  point failures, and attempts to launch the same service
  concurrently.
  ([!1906], [#1237], [#1225], [#1255])
- Detect and reject configurations with onion services, when
  onion-service-server support has been compiled out.
  ([!1885], [#1184])
- Temporarily disable parsing of AF_UNIX socket addresses (which
  aren't implemented right now anyway).
  ([!1886])
- Rate limit one log message, downgrade one, and remove another.
  ([!1871], [!1951])
- Add higher-level documentation to tor-hsservice (and fix a broken
  docs link).
  ([!1918], [!1945])
- Hide the `OnionServiceState` type.
  ([!1946], [#1261])
- Many internal cleanups including much triage of TODO comments in the code.
  ([!1859], [!1862], [!1861], [!1868], [!1866], [!1863], [!1870], [!1874])
  ([!1872], [!1869], [!1876] !1867 [!1873], [!1877], [!1878], [!1875])
  ([!1879], [!1882], [!1881], [!1880], [!1894], [!1888], [!1887], [!1896])
  ([!1864], [!1951])

### Other major new features in our Rust APIs

- New `fslock-guard` crate for on-disk lockfiles which can be deleted,
  and which have a Rust API that returns a guard object.
  [fslock!15](https://github.com/brunoczim/fslock/pull/15)
  !1900 !1910
- `tor-persist` has a `Slug` type which is used for nicknames, key
  paths, etc., unifying the rules used for different kinds of name.
  ([!1912], [#1092], [#1193], [!1926], [!1929], [!1922], [!1933], [#1092])
  ([!1931], [!1934])
- `tor-persist` has `StateDirectory` for handling persistent state
  relating to particular instances of a facility (used for hidden
  serivces).
  ([!1853], [#1205], [!1913], [#1163], [!1935])

### Documentation and examples

- New examples using `hyper v1`.
  ([!1845])
- Fix a broken link.
  ([!1938])

### Testing

- New `test-temp-dir` crate for convenient handling of temporary files
  in tests.
  ([!1925])

### Cleanups, minor features, and bugfixes

- `fs-mistrust`: Expose `CheckedDir::verifier`
  and provide `CheckedDir::make_secure_dir`.
  ([!1927], [!1928])
- Instructions for building `arti-extra` in `tests/shadow/README.md`.
  ([!1891])

### Acknowledgments

Thanks to everybody who's contributed to this release, including
Alexander Færøy, Jim Newsome, and ramidzkh.

Also, our deep thanks to [Zcash Community Grants] and our [other sponsors]
for funding the development of Arti!


[!1845]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1845
[!1853]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1853
[!1859]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1859
[!1861]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1861
[!1862]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1862
[!1863]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1863
[!1864]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1864
[!1866]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1866
[!1868]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1868
[!1869]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1869
[!1870]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1870
[!1871]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1871
[!1872]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1872
[!1873]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1873
[!1874]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1874
[!1875]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1875
[!1876]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1876
[!1877]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1877
[!1878]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1878
[!1879]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1879
[!1880]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1880
[!1881]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1881
[!1882]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1882
[!1883]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1883
[!1884]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1884
[!1885]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1885
[!1886]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1886
[!1887]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1887
[!1888]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1888
[!1889]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1889
[!1891]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1891
[!1892]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1892
[!1894]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1894
[!1895]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1895
[!1896]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1896
[!1897]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1897
[!1898]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1898
[!1899]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1899
[!1901]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1901
[!1902]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1902
[!1903]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1903
[!1904]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1904
[!1906]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1906
[!1908]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1908
[!1909]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1909
[!1911]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1911
[!1912]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1912
[!1913]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1913
[!1914]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1914
[!1915]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1915
[!1916]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1916
[!1917]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1917
[!1918]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1918
[!1920]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1920
[!1921]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1921
[!1922]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1922
[!1924]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1924
[!1925]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1925
[!1926]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1926
[!1927]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1927
[!1928]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1928
[!1929]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1929
[!1931]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1931
[!1933]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1933
[!1934]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1934
[!1935]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1935
[!1938]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1938
[!1941]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1941
[!1945]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1945
[!1946]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1946
[!1948]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1948
[!1949]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1949
[!1951]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1951
[#1074]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1074
[#1092]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1092
[#1155]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1155
[#1163]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1163
[#1166]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1166
[#1183]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1183
[#1184]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1184
[#1188]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1188
[#1189]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1189
[#1193]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1193
[#1205]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1205
[#1211]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1211
[#1220]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1220
[#1225]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1225
[#1227]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1227
[#1236]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1236
[#1237]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1237
[#1240]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1240
[#1242]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1242
[#1254]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1254
[#1255]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1255
[#1260]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1260
[#1261]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1261
[`tor-hscrypto`]: https://tpo.pages.torproject.net/core/doc/rust/tor_hscrypto/index.html
[`tor-hsclient`]: https://tpo.pages.torproject.net/core/doc/rust/tor_hsclient/index.html

# Arti 1.1.12 — 9 January 2024

Arti 1.1.12 continues work on support for running onion services.
You can now launch an onion service and expect it to run,
though the user experience leaves a lot to be desired.
Don't rely on this onion service implementation for security yet;
there are a number of [missing security features]
we will need to develop before we can recommend them
for actual use.

### Breaking changes

### Breaking changes in lower-level crates

- In `tor_dirmgr`, rename the `cache_path` parameter to `cache_dir`
  for consistency. ([!1789])
- In `tor-error`, the `ErrorReport` trait is now sealed.
  ([00903e22bb978295])
- Change the domain name used to tag our extended SSH key types.
  This will break any keys created using earlier releases,
  though it is unlikely that anybody actually managed to do so.
  ([#1108], [!1838])
- In `tor-netdoc`, `HsDescBuilder::auth_clients` now takes an
  `Option`, to distinguish the case where no clients are allowed from
  the case where all clients are allowed. ([#1019], [!1840])

### Onion service development

- Fix a set of bugs bug that caused onion services to upload far too
  many descriptors. ([#1130], [#1142], [!1787], [!1806])
- Improve reporting of descriptor upload failures. ([#1132],
  [f26b00b3179a7e13], [1990bbdffd87abaa], [!1799])
- Ensure that the list of published introduction points is
  recorded correctly.  ([#1097], [!1805])
- Implement persistence for introduction point information,
  so that onion services can restart with the same introduction points
  and behave correctly. ([#967], [!1782])
- Refactor key manager code to prevent the creation of invalid
  `KeySpecifier`s, and extend the `KeySpecifier` macro to also
  generate `KeyInfoExtractor` implementations for extracting
  information out of `&KeyPath`s ([#1127], [f7772f127e895d96]).
- Add lower-level support for deleting expired keys and associated information.
  ([#1043], [!1784], [!1796])
- Onion services can now be stopped, started, or reconfigured while
  arti is running. ([#1089], [!1798])
- Implement an API for onion services to report their
  status. ([#1083], [!1797], [!1808])
- Produce useful, rate-limited log messages on certain kinds of
  onion service failures. ([!1809])
- Warn on some onion service configurations that are unlikely to be
  intentional. ([!1822])
- Add documentation for how to run an onion service, in
  [`doc/OnionService.md`].  This documentation also records areas where
  the implementation is lacking, and notes areas where the current
  process has bad usability. ([!1825], [!1826], [!1841])
- Fix a bug that would occur when trying to create an onion service
  descriptor for a time period that had not yet begun. ([#1155],
  [!1828])
- Always log the onion sevice's `.onion` address, when starting with
  `log_sensitive_information` enabled. ([!1830])
- Ensure that no extra features beyond `onion-service-service` are
  needed in `arti` to enable onion service support. ([49ece08bafc115ce])
- Use our regular sub-builder pattern for key-manager configuration,
  so that default option values can be omitted. ([4d7aeeab57577c98])
- Various improvements to descriptor publisher error
  handling. ([#1129], [!1812], [!1821])
- Record a replay-log of incoming `INTRODUCE2` requests, to prevent
  replay attacks. ([!1824])
- Add a CLI for learning the `.onion` address for a given onion service.
  ([#1071], [!1837])
- Refactor the `KeySpecifier` macro and its implementations to improve
  usability and reduce the API surface. ([#1151], [#1147], [#1126],
  [!1851])

### Other major features

- Arti now supports the [`ntor_v3`] circuit extension handshake, which
  enables clients to send circuit paramaters to the relays on their paths.
  ([#1084], [!1766])

### Documentation

- Improve documentation of state and cache directories. ([!1789])
- Improve internal documentation about how we implement the onion
  service specifications. ([!1795], [!1813])
- Various typo fixes. ([!1852])

### Testing

- Fix an (unreached) bug in test_tmp_dir code. ([!1792])
- Include an onion service in our [Shadow] CI tests. ([!1827])


### Cleanups, minor features, and bugfixes

- Various cleanups enabled by our transition to requiring
  Rust 1.70.  ([!1785])
- Refactor high-level reconfiguration code so that it sends its
  configuration to each of a set of modules, rather than hardcoding a
  list of functions to call. ([1ac515c183bf8c1d])
- The `traits` module is now unconditionally present in
  the `tor-llcrypto` crate. ([!1815])
- In `tor-error`, the `ErrorReport` is now implemented for `dyn StdError`,
  which allows us to use it with `anyhow::Error`. ([#1157], [!1818])
- Fix a busy-loop that would occur if a channel was due to expire in
  less than a second, and another race condition when expiring
  channels. ([!1834])
- In `tor-cell`, `{Any}RelayCell` has been renamed to `{Any}RelayMsgOuter`,
  in order to prepare for work on [proposal 340]. This name is a placeholder;
  eventually, there will be a followup renaming. ([#775], [!1839], [!1840])
- Improve the output of `tokio`'s tracing feature when used with our
  `tor-rtcompat` wrappers. ([!1843])
- Expose a `dir_mgr_config()` accessor from `TorClientConfig`.
  ([#1175], [!1847])

### Acknowledgments

Thanks to everybody who's contributed to this release, including
Alexander Færøy, Dimitris Apostolou, Emil Engler, and Jim Newsome.

Also, our deep thanks to [Zcash Community Grants] and our [other sponsors]
for funding the development of Arti!

[!1766]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1766
[!1782]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1782
[!1784]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1784
[!1785]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1785
[!1787]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1787
[!1789]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1789
[!1792]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1792
[!1795]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1795
[!1796]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1796
[!1797]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1797
[!1798]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1798
[!1799]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1799
[!1805]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1805
[!1806]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1806
[!1808]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1808
[!1809]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1809
[!1812]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1812
[!1813]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1813
[!1815]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1815
[!1818]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1818
[!1821]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1821
[!1822]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1822
[!1824]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1824
[!1825]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1825
[!1826]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1826
[!1827]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1827
[!1828]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1828
[!1830]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1830
[!1834]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1834
[!1837]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1837
[!1838]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1838
[!1839]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1839
[!1840]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1840
[!1841]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1841
[!1843]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1843
[!1847]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1847
[!1852]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1852
[#775]: https://gitlab.torproject.org/tpo/core/arti/-/issues/775
[#967]: https://gitlab.torproject.org/tpo/core/arti/-/issues/967
[#1019]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1019
[#1043]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1043
[#1071]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1071
[#1083]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1083
[#1084]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1084
[#1089]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1089
[#1097]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1097
[#1108]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1108
[#1127]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1127
[#1129]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1129
[#1130]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1130
[#1132]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1132
[#1142]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1142
[#1155]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1155
[#1157]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1157
[#1175]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1175
[!1851]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1851
[#1126]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1126
[#1147]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1147
[#1151]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1151
[00903e22bb978295]: https://gitlab.torproject.org/tpo/core/arti/-/commit/00903e22bb9782958135a7061dcfb523e4ebc91f
[1990bbdffd87abaa]: https://gitlab.torproject.org/tpo/core/arti/-/commit/1990bbdffd87abaa6fa70fc29a9b2d191e35575a
[1ac515c183bf8c1d]: https://gitlab.torproject.org/tpo/core/arti/-/commit/1ac515c183bf8c1d7e07bccd0fdbd3644041b250
[49ece08bafc115ce]: https://gitlab.torproject.org/tpo/core/arti/-/commit/49ece08bafc115ce99ced38f659ac7f72bab947b
[4d7aeeab57577c98]: https://gitlab.torproject.org/tpo/core/arti/-/commit/4d7aeeab57577c98a15aa78ef5cd5de7652f39e8
[f26b00b3179a7e13]: https://gitlab.torproject.org/tpo/core/arti/-/commit/f26b00b3179a7e135960972e8c922d824a62ee0e
[f7772f127e895d96]: https://gitlab.torproject.org/tpo/core/arti/-/commit/f7772f127e895d9655346cf69fd2134ac8e225de
[Shadow]: https://shadow.github.io
[Zcash Community Grants]:  https://zcashcommunitygrants.org/
[`doc/OnionService.md`]: https://gitlab.torproject.org/tpo/core/arti/-/blob/main/doc/OnionService.md?ref_type=heads
[`ntor_v3`]: https://spec.torproject.org/tor-spec/create-created-cells.html#ntor-v3
[missing security features]: https://gitlab.torproject.org/tpo/core/arti/-/issues/?label_name%5B%5D=Onion%20Services%3A%20Improved%20Security
[other sponsors]:  https://www.torproject.org/about/sponsors/
[proposal 340]: https://spec.torproject.org/proposals/340-packed-and-fragmented.html



# Arti 1.1.11 — 4 December 2023

Arti 1.1.11 continues work on support for running onion services.
Onion services are now working in our testing, and we expect we'll
have something testable by others in our next release.

Arti 1.1.11 also increases our MSRV (Minimum Supported Rust Version)
to 1.70, in accordance with our [MSRV policy].

### Breaking changes

- Arti now requires Rust 1.70 or later. ([!1773])

### Breaking changes in lower-level crates

- The `LockStatus` type in tor-persist is now `#[must_use]`. ([#1753])
- The `tor-dirclient` crate now exposes `http::Error` from
  http 1.0. ([c5b386fb1009a1d9])
- The `tor-dirclient` crate's `RequestError` type now includes status text
  from the directory server, to help diagnose problems. ([!1780])
- We've upgraded to the latest versions of [dalek-cryptography].  This
  is a breaking change to every internal Arti API that takes a
  curve25519 or ed25519 key as its input. ([#808], [!1767])
- In `tor-cell`, `HandshakeType` is now used in several places
  in place of `u16`. ([5d7f70c0fe515aee])

### Onion service development

- Correct our handling of BEGIN and END messages to bring them
  into conformance with the C Tor implementation and the specification.
  ([#1077], [!1694], [!1738])
- In our key manager, use macros to define key specifiers, instead of
  repeating the same boilerplate code. ([#1069], [#1093], [!1710],
  [!1733])
- Refactoring and refinement on the definitions of onion-service-related
  errors. ([!1718], [!1724], [!1750], [!1751], [!1779])
- Add a "time-store" mechanism for (as correctly as possible) storing and loading
  future timestamps, even in the presence of system clock skew ([!1723], [!1774])
- Implement a replay-log backend to prevent INTRODUCE replay attacks
  against onion services. ([!1725])
- Improved encoding for key-denotators in the key manager. ([#1063],
  [#1070], [!1722])
- Allow a single key to have more than one denotator in its path.
  ([#1112], [!1747])
- Use an order-preserving-encryption back-end to generate
  monotonically increasing revision counters for onion service
  descriptors.  We do this to ensure a reproducible series of counters
  without leaking our clock skew.  ([#1053], [!1741], [!1744])
- Deprecate key types for INTRODUCE-based authentication:
  C tor has never implemented this, and we do not plan to implement it
  without additional specification work. ([#1037], [!1749])
- When establishing an introduction point, send the `intro_dos`
  extension as appropriate. ([#723], [!1740])
- Added conversion functions and initial persistence support for
  introduction point keys. ([!1756])
- Start work on introduction point persistence. ([!1755], [!1765]).
- Make a `Builder` type for key managers. ([#1114], [!1760])
- Revert to our intended configuration format for onion service proxy rules.
  ([#1058], [!1771])
- Resolve miscellaneous "TODO" items throughout the onion service
  code. ([#1066], [!1728], [!1731], [!1732], [!1742])

### Client features

- Backend and API code for the "ntor-v3" circuit-extension handshake.
  This handshake adds the ability to send additional options
  from the client to the relay when creating or extending a circuit,
  and will eventually be used to negotiate protocol features like
  RTT-based congestion control and UDP-over-Tor support.
  ([!1720], [!1739])

### Testing

- Simplify the usage of time-simulating mock runtimes.
  ([ee96e5e454ba5db2])
- Use time-simulating mock runtimes in more circuit-manager tests, to
  make them more reliable. ([#1090], [!1727])
- Add a `spawn_join` method to mock runtimes, to simplify
  tests. ([!1746])
- Prototype a "testing temp dir" facitility to ensure that temporary
  directories used in tests can be persistent if desired, and that
  they live for long enough. ([!1762])

### Cleanups, minor features, and bugfixes

- Fix various warnings from Clippy. ([!1719])
- Solve a bug that prevented `Conversation::send_message` from working.
  ([#1085], [!1726])
- Upgrade to version 4 of the `clap` option-parsing library.
  ([!1735])
- New backend to generate rate limited problem reports without
  spamming the logs.  ([#1076], [!1734], [!1752])
- Correct our decisions about sending Content-Length on HTTP
  requests. Previously we had sent it unconditionally. ([#1024],
  [!1671])
- Add directory-listing and file-deletion support to
  `fs-mistrust::CheckedDir`. ([#1117], [!1759])

### Acknowledgments

Thanks to everybody who's contributed to this release, including
Alexander Færøy, Andrew, Jim Newsome, rdbo, Saksham Mittal, and
Trinity Pointard.

Also, our deep thanks to [Zcash Community Grants] and our [other sponsors]
for funding the development of Arti!







[!1671]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1671
[!1694]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1694
[!1710]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1710
[!1718]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1718
[!1719]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1719
[!1720]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1720
[!1722]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1722
[!1723]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1723
[!1724]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1724
[!1725]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1725
[!1726]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1726
[!1727]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1727
[!1728]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1728
[!1731]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1731
[!1732]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1732
[!1733]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1733
[!1734]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1734
[!1735]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1735
[!1738]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1738
[!1739]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1739
[!1740]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1740
[!1741]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1741
[!1742]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1742
[!1744]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1744
[!1746]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1746
[!1747]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1747
[!1749]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1749
[!1750]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1750
[!1751]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1751
[!1752]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1752
[!1755]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1755
[!1759]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1759
[!1760]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1760
[!1762]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1762
[!1756]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1756
[!1765]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1765
[!1767]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1767
[!1771]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1771
[!1773]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1773
[!1774]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1774
[!1779]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1779
[!1780]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1780
[#723]: https://gitlab.torproject.org/tpo/core/arti/-/issues/723
[#808]: https://gitlab.torproject.org/tpo/core/arti/-/issues/808
[#1024]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1024
[#1037]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1037
[#1053]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1053
[#1058]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1058
[#1063]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1063
[#1066]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1066
[#1069]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1069
[#1070]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1070
[#1076]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1076
[#1077]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1077
[#1085]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1085
[#1090]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1090
[#1093]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1093
[#1112]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1112
[#1114]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1114
[#1117]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1117
[#1753]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1753
[c5b386fb1009a1d9]: https://gitlab.torproject.org/tpo/core/arti/-/commit/c5b386fb1009a1d91a830aeb67921c6057b98a1e
[ee96e5e454ba5db2]: https://gitlab.torproject.org/tpo/core/arti/-/commit/ee96e5e454ba5db27daaab0f8757732994454f0b
[MSRV policy]: https://gitlab.torproject.org/tpo/core/arti/#minimum-supported-rust-version
[Zcash Community Grants]:  https://zcashcommunitygrants.org/
[dalek-cryptography]: https://github.com/dalek-cryptography/
[other sponsors]:  https://www.torproject.org/about/sponsors/






# Arti 1.1.10 — 31 October 2023

Arti 1.1.10 continues work on support for onion services in Arti.
At last, we can (technically) run as an onion service... though
not yet in a useful way. (Onion services don't yet recover correctly
after a restart, outdated keys are not removed,
and we are missing other important security features.)

### Breaking changes in lower-level crates

- The [`IoErrorExt`] trait in [`tor-basic-utils`] is now
  sealed. ([!1654])
- The [`Requestable`] trait in [`tor-dirclient`] is now sealed,
  and most of its members are now private. ([!1679])
- In [`tor-cell`], stream and circuit IDs are now inherently non-zero.
  To represent an ID that might be zero on the wire, we now use
  `Option<StreamId>` or `Option<CircId>`. ([#1080], [!1697])
- In [`tor-cell`], `CREATE2` handshake types are no longer raw
  `u16` values. ([!1703])
- In [`tor-cert`], `encode_and_sign` now returns an
  `Ed25519EncodedCert` rather than a raw `Vec<u8>`. ([!1702])

### Onion service development

- The `arti` binary can now be configured to invoke the code that
  launch onion services, and the code that proxies them to local
  ports. ([!1644])
- Configuration support for onion services, and for the `rproxy`
  facility that directs incoming onion service connections to local
  services. ([!1638], [!1640])
- The introduction points are now exposed by the code that manages
  them to the code that publishes onion service descriptors. ([!1636],
  [!1645])
- Implement reconfiguration support in the lower level onion service
  code. ([!1651])
- Temporarily changed the configuration format for onion service ports
  to work around [a bug in `config-rs`]. ([21605d2c9e601c3a])
- As-yet-unused code to build a list of authorized clients. ([#1051],
  [!1642])
- Auto-generate missing keys rather than failing when we are
  about to publish. ([!1688])
- Log onion service Ids when they are created, so we can test them.
  ([!1689])
- Move responsibility for generating descriptor signing key certificates
  into `tor-hsservice` from `tor-netdoc`; refactor accordingly.
  ([!1702])
- Resolve a number of pending "TODO" items in [`tor-proto`] affecting
  the onion service implementation. ([!1658])
- Resolve a number of pending "TODO" items in [`tor-dirclient`] affecting
  the onion service implementation. ([!1675])
- Sort introduction point lists by ntor public key before publication,
  to avoid leaking information. ([#1039], [!1674])
- Numerous bugfixes, cleanups, and backfills found during testing and
  integrating the pieces of the onion service
  implementation. ([!1634], [!1637], [!1659], [!1673], [!1682],
  [!1684], [!1686], [!1695], [!1711])


### Client features

- Arti can now be configured to listen for connections on multiple arbitrary
  addresses—not just `localhost`. ([!1613])

### Key manager

- The key manager code now has improved support for generating
  keypairs, keys with derived data, and other structures needed for
  onion services. ([!1653])
- The key manager now encodes whether a key is private or public in its
  file extension. ([!1672])
- The key manager now disallows path components that could lead
  (under some programming errors) to directory traversal. ([!1661])
- We can now list keys by path and type; this is important so that
  we can identify disused keys and eventually expire them. ([!1677])

### Documentation and examples

- Correct our example for how to connect to onion services. ([!1653])
- Update download location in `download-manager` example.
  ([!1691])

### Infrastructure

- Our release scripts and processes are now more robust against
  several kinds of mistake that have frustrated previous releases,
  including crates that change only when their dependencies get new
  versions, accidental inclusion of wildcard dependencies, and
  dependencies on unpublished crates.  ([!1646])
- Clean up use of `after_script` in our CI to behave more sensibly
  ([#1061], [!1663])


### Testing

- Even-more-improved support for tests that depend on a simulated view
  of the passage of time. ([!1639], [!1650])

### Cleanups, minor features, and bugfixes

- Refactored the key derivation code for relay cryptography. ([!1629])
- Work around [a bug in `FusedFuture for oneshot::Receiver`] that made
  it dangerous to `select!` on a `oneshot::Receiver` to detect if the
  sender is dropped.  ([#1059], [!1656], [futures-rs#2455](https://github.com/rust-lang/futures-rs/issues/2455))
- Fix handling for escape sequences when talking to a
  pluggable transport. ([!1584])
- Major refactoring and simplifications on the explicit closing of
  pending incoming streams, to prevent double-close bugs and related
  panics. ([#1065], [!1678], [!1681])
- Refactor implementation of ISO-8601 time parsing in descriptors.
  ([#751], [!1693])
- Renamed the function in `tor-hsclient` to launch a circuit to an
  onion service to be less confusing. The old name remains but is
  deprecated. ([#1078], [!1700])
- Do not advertise or accept non-required compression encodings
  when making anonymized requests to an onion service directory:
  to do so is a fingerprinting vector.
  ([#1062], [cfe641613e6b6f4f])
- Use the new typed handshake-type codes when building onion service
  descriptors.  ([!1712])

### Acknowledgments

Thanks to everybody who's contributed to this release, including
Alexander Færøy, Emil Engler, gil, halcyon, Jani Monoses, Jim Newsome,
LowLandMink543, Neel Chauhan, and Trinity Pointard!

Also, our deep thanks to [Zcash Community Grants] and our [other sponsors]
for funding the development of Arti!

[!1584]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1584
[!1613]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1613
[!1629]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1629
[!1634]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1634
[!1636]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1636
[!1637]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1637
[!1638]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1638
[!1639]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1639
[!1640]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1640
[!1642]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1642
[!1644]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1644
[!1645]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1645
[!1646]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1646
[!1650]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1650
[!1651]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1651
[!1653]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1653
[!1654]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1654
[!1656]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1656
[!1658]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1658
[!1659]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1659
[!1661]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1661
[!1663]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1663
[!1672]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1672
[!1673]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1673
[!1674]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1674
[!1675]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1675
[!1677]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1677
[!1678]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1678
[!1679]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1679
[!1681]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1681
[!1682]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1682
[!1684]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1684
[!1686]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1686
[!1688]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1688
[!1689]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1689
[!1691]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1691
[!1693]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1693
[!1695]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1695
[!1697]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1697
[!1700]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1700
[!1702]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1702
[!1703]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1703
[!1711]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1711
[!1712]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1712
[#751]: https://gitlab.torproject.org/tpo/core/arti/-/issues/751
[#1039]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1039
[#1051]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1051
[#1059]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1059
[#1061]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1061
[#1062]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1062
[#1065]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1065
[#1078]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1078
[#1080]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1080
[21605d2c9e601c3a]: https://gitlab.torproject.org/tpo/core/arti/-/commit/21605d2c9e601c3a5099bfd8d8c887cbb3b36c0a
[5d7f70c0fe515aee]:  https://gitlab.torproject.org/tpo/core/arti/-/commit/5d7f70c0fe515aee8640f336cc799b70828fd109
[cfe641613e6b6f4f]: https://gitlab.torproject.org/tpo/core/arti/-/commit/cfe641613e6b6f4f55de87621eadacf24d22a939
[`IoErrorExt`]: https://tpo.pages.torproject.net/core/doc/rust/tor_basic_utils/trait.IoErrorExt.html
[`Requestable`]: https://tpo.pages.torproject.net/core/doc/rust/tor_dirclient/request/trait.Requestable.html
[`tor-basic-utils`]: https://tpo.pages.torproject.net/core/doc/rust/tor_basic_utils/index.html
[`tor-cell`]: https://tpo.pages.torproject.net/core/doc/rust/tor_cell/index.html
[`tor-cert`]: https://tpo.pages.torproject.net/core/doc/rust/tor_cert/index.html
[`tor-dirclient`]: https://tpo.pages.torproject.net/core/doc/rust/tor_dirclient/index.html
[`tor-proto`]: https://tpo.pages.torproject.net/core/doc/rust/tor_proto/index.html
[a bug in `FusedFuture for oneshot::Receiver`]: https://github.com/rust-lang/futures-rs/issues/2455
[a bug in `config-rs`]: https://github.com/mehcode/config-rs/issues/464
[Zcash Community Grants]: https://zcashcommunitygrants.org/
[other sponsors]: https://www.torproject.org/about/sponsors/




# Arti 1.1.9 — 2 October 2023

Arti 1.1.9 continues work on support for onion services in arti.
The pieces are now (mostly) connected; the next month of development
will see extensive testing, bugfixing, and refinement.

### Breaking changes in lower-level crates

- In `tor-hsclient` and `tor-netdoc`'s APIs, secret authentication
  keys are now handled as `HsClientDescKeypair`, rather than as
  individual keys.
- In `tor-circmgr`, the `NoExit` error now includes a possible country
  code.
- In `tor-ptmgr`, `ClientTransportGaveError` have been renamed to
  `TransportGaveError`.

### Onion service development

- The onion service descriptor publisher is now in conformance with
  our spec with respect to how it handles time periods.  ([!1564])
- The descriptor publisher now runs in parallel, so that a blocked
  upload doesn't prevent successful uploads from succeeding. ([!1580])
- The descriptor publisher now includes correct retry and timing
  logic. ([!1592], [!1623])
- The introduction point manager code is now able to integrate with
  the descriptor publisher. ([!1575], [!1576], [!1577] [!1578], [!1603])
- The descriptor publisher code is now integrated with the key
  management system. ([#1042], [!1615])
- The introduction point manager is now integrated with the code that
  accepts user requests via introduction points. ([!1597], [!1598])
- The code responsible for selecting and maintaining introduction
  points is now more robust in the presence of relay selection
  failure. ([!1585])
- We now have a `tor-hsrproxy` crate, to handle running an onion
  service that directs incoming connections to local ports.  Users
  will need this if they want their onion services to run in a
  separate process and not use Rust. ([01f954d3782df57a], [!1622])
- Added configuration logic for onion services. ([!1557], [!1599],
  [!1605], [!1611])
- The `downgrade_dependencies` script now honors the `$CARGO` variable.
  ([!1596])
- We now use a keypair type for `hs_ntor` secret keys. ([#1030],
  [!1590])
- There is now a set of (not working yet!) APIs to actually launch and
  run onion services, by invoking the necessary pieces of the backend,
  and pass requests back to the caller ([!1604], [!1608], [!1610],
  [!1616], [!1620], [!1625])


### Client features

- We now have an experimental feature to select exits by country, with
  geoip support. It is Rust-only, and not yet exposed via a
  configuration option. ([!1537])
- When contacting an onion service, we now pad our `INTRODUCE2`
  message payload to a uniform size in order to conceal what kind of
  data and extensions it contains.  ([#1031], [!1602])

### Documentation and examples

- We've merged several example programs from Saksham Mittal's
  project for this year's [Google Summer of Code].  They include a
  downloading tool, a relay checker, and obfs4 checker, a
  tool to lookup DNS over tor, and a program to run a proxy over
  a pluggable transport. You can find them in `examples/gsoc2023`.
  ([!1574])
- Documentation fixes around our description of
  `localhost_port_legacy`.  ([!1588])

### Infrastructure

- Our version-bumping script now allows options to be applied to
  "$CARGO". ([!1573])
- Our CI scripts now use `cargo install --locked` to avoid
  certain compatibility issues in our tools and their dependencies.
  ([!1587])
- The `ArtiPath` types recognized by the key manager are now better
  documented. ([!1586])


### Testing

- New tests for our `tor-ptmgr` string-escaping logic. ([!1579])
- Our runtime mock code now displays more and better information about
  when and where tasks are sleeping. ([!1591], [!1595])

### Cleanups, minor features, and bugfixes

- Refactoring and API revisions to our experimental backend support
  for launching pluggable transports in server mode. ([!1581])
- Our low-level cryptographic wrappers now have a type to represent
  x25519 (Montgomery) keypairs.  Several internal APIs have adapted
  accordingly. ([!1617])
- The key manager system now supports public keys, for cases where the
  secret key is kept offline. ([!1618])
- The key manager system now supports expanded ed25519 keypairs, so that
  it can represent blinded onion identity keys. ([!1619])
- Cleanups to encryption logic in `tor-proto`. ([!1627])

### Acknowledgments

Thanks to everybody who's contributed to this release, including
Emil Engler and Saksham Mittal!

Also, our deep thanks to [Zcash Community Grants] and our [other sponsors]
for funding the development of Arti!


[!1537]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1537
[!1557]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1557
[!1564]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1564
[!1573]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1573
[!1574]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1574
[!1575]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1575
[!1576]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1576
[!1577]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1577
[!1578]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1578
[!1579]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1579
[!1580]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1580
[!1581]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1581
[!1585]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1585
[!1586]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1586
[!1587]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1587
[!1588]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1588
[!1590]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1590
[!1591]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1591
[!1592]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1592
[!1595]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1595
[!1596]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1596
[!1597]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1597
[!1598]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1598
[!1599]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1599
[!1602]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1602
[!1603]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1603
[!1604]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1604
[!1605]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1605
[!1608]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1608
[!1610]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1610
[!1611]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1611
[!1615]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1615
[!1616]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1616
[!1617]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1617
[!1618]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1618
[!1619]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1619
[!1620]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1620
[!1622]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1622
[!1623]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1623
[!1625]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1625
[!1627]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1627
[#1030]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1030
[#1031]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1031
[#1042]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1042
[01f954d3782df57a]: https://gitlab.torproject.org/tpo/core/arti/-/commit/01f954d3782df57a4ac1d2cd1d323584ccaaac76
[Google Summer of Code]: https://summerofcode.withgoogle.com/
[Zcash Community Grants]: https://zcashcommunitygrants.org/
[other sponsors]: https://www.torproject.org/about/sponsors/




# Arti 1.1.8 — 5 September 2023

Arti 1.1.8 continues work on support for onion services in arti.  It includes
backend support for nearly all of the functionality needed to launch
and publish an onion service and accept incoming requests from onion
service clients.  This functionality is not yet usable, however: we
still need to connect it all together, test and debug it, and provide
high-level APIs to allow the user to actually turn it on.

### Major bugfixes

- Do not allow the user to set `bridges = true` without having
  configured any bridges.  Previously, this configuration was
  possible, and it caused arti to connect without using any
  bridges. This is tracked as [TROVE-2023-002]. ([#1000], [!1481]).

### Breaking changes in lower-level crates

- In `tor-dirclient`, `Requestable::make_request` now returns
  `Request<String>`. ([cd6c4674dc560d9c1dc3])
- In `tor-ptclient`, `PtParameters` been split, and
  `PluggableTransport` has become a trait. ([bbed17ba4a44a4690ad6])
- Additionally, many unstable APIs (marked with the `experimental-api`
  feature and similar) and APIs in unstable crates (like
  `tor-hsservice` and `tor-keymgr`) have changed.

### Onion service development

- We began laying more groundwork for onion services, with a set of
  low-level API designs, algorithm designs, and data
  structures. ([#970], [#971], [#972], [!1452], [!1444], [!1541])
- Fuzzing support and significant speed improvements to the (still
  unused) [HashX]-based proof-of-work code. ([!1446], [!1462],
  [!1459], [!1513], [!1524], [!1529], [!1538], [!1539], [!1555])
- Added low-level support in [`tor-proto`] for accepting incoming data
  streams on a circuit. Onion services will use this to accept `BEGIN`
  messages. ([#864], [#994], [#998], [#1009], [!1451], [!1474], [!1475],
  [!1476], [!1477], [!1484], [!1519])
- Keystore directory configuration is now derived from the configured
  state directory when using `TorClientConfigBuilder::from_directories`.
  ([#988], [!1498])
- Expose the `KH` circuit-binding material, as needed for the
  rendezvous handshake. ([#993], [!1472])
- Backend code to establish an introduction point, keep it
  established, and watch for `INTRODUCE2` messages. ([!1510], [!1511],
  [!1516], [!1517], [!1522], [!1540])
- Backend code to decode an `INTRODUCE2` message, complete the
  necessary cryptographic handshakes, open a circuit to the client's
  chosen rendezvous point, establish a shared virtual hop, and receive
  `BEGIN` messages. ([#980], [#1013], [!1512], [!1520], [!1521],
  [!1536], [!1547])
- Taught the `tor-dirclient` crate how to upload onion service
  descriptors. ([!1505])
- Revise and debug logic for locating items the HsDir ring when
  publishing. ([#960], [!1494], [!1518])
- Refactor onion service error handling. ([!1515])
- Backend code to select introduction points and keep track of which ones
  are running correctly. ([!1523], [!1549], [!1550], [!1559])
- Refactor HsDesc parsing code to remove `inner::IntroPointDesc`. ([!1528])
- Initial backend code to regenerate and publish onion service descriptors
  as needed. ([#977], [!1545])

### Documentation

- Fix documentation about the [`OnionAddressDisabled`] error: it was
  missing a "not".  ([!1467])
- Correct details about upcoming milestones in our [top-level `README.md`].
  ([!1471])

### Infrastructure

- New release script to bump the patchlevel of a crate without
  treating it as a dependency change. ([#945], [!1461])
- New script to make sure that all checked-in `Cargo.lock` files
  are correct. ([!1468])
- Usability improvements to our coverage script. ([!1485])
- In CI, verify that our scripts are using `/usr/bin/env` to find their
  interpreters in the proper locations. ([!1489], [!1490])

### Testing

- Improve test coverage for the `tor-cert` crate. ([!1495], [!1496],
  [!1497])
- Improve test coverage for the `tor-proto` crate. ([!1501])

### Cleanups, minor features, and smaller bugfixes

- Improved error handling when a `[[bridges.transports]]` section does
  not include any required pluggable transport. ([#880], [!1229])
- Key manager APIs are now less tied to the SSH key format, and no
  longer require that x25519 keys be stored as ed25519 keys. ([#936],
  [#965], [!1464], [!1508])
- Downgrade lints for built-in warnings to "warn". Previously two of
  them (`missing_docs`, `unreachable_pub`) were set to "deny", which
  had a risk of breaking compilation in the future. ([#951], [!1470])
- Expose the `HopNum` type from `tor-proto`, to help avoid off-by-one
  errors. ([eee3bb8822dd22a4], [#996], [!1548])
- Deprecate and replace `ClientCirc::start_conversation_last_hop` with a new
  [`start_conversation`] function that can target any hop. ([#959], [!1469])
- New functions in `tor-proto` to wait for a channel or a circuit
  to shut down. ([!1473])
- Improved error messages and behaviors when we can't decide where to
  look for our configuration files. ([!1478], [!1479], [!1480])
- Deprecated and renamed `download` in `tor-dirclent` to
  `send_request`. ([9a08f04a7698ae23])
- Deprecate [`DropNotifyEofSignallable::is_eof`]. ([f4dfc146948d491c])
- New [`ClientCirc::send_raw_msg`] function for cases where we want
  to send a message without starting a conversation. ([#1010], [!1525])
- Experimental backend support for launching pluggable transports in server
  mode, for testing and example code. ([!1504])

### Acknowledgments

Thanks to everybody who's contributed to this release, including
Emil Engler, Jim Newsome, Micah Elizabeth Scott, Saksham Mittal,
and Trinity Pointard.

Also, our deep thanks to [Zcash Community Grants] and our [other sponsors]
for funding the development of Arti!


[!1229]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1229
[!1444]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1444
[!1446]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1446
[!1451]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1451
[!1452]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1452
[!1459]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1459
[!1461]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1461
[!1462]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1462
[!1464]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1464
[!1467]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1467
[!1468]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1468
[!1469]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1469
[!1470]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1470
[!1471]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1471
[!1472]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1472
[!1473]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1473
[!1474]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1474
[!1475]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1475
[!1476]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1476
[!1477]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1477
[!1478]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1478
[!1479]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1479
[!1480]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1480
[!1481]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1481
[!1484]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1484
[!1485]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1485
[!1489]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1489
[!1490]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1490
[!1494]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1494
[!1495]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1495
[!1496]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1496
[!1497]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1497
[!1498]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1498
[!1501]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1501
[!1504]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1504
[!1505]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1505
[!1508]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1508
[!1510]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1510
[!1511]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1511
[!1512]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1512
[!1513]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1513
[!1515]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1515
[!1516]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1516
[!1517]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1517
[!1518]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1518
[!1519]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1519
[!1520]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1520
[!1521]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1521
[!1522]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1522
[!1523]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1523
[!1524]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1524
[!1525]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1525
[!1528]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1528
[!1529]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1529
[!1536]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1536
[!1538]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1538
[!1539]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1539
[!1540]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1540
[!1541]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1541
[!1545]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1545
[!1547]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1547
[!1548]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1548
[!1549]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1549
[!1550]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1550
[!1555]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1555
[!1559]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1559
[#864]: https://gitlab.torproject.org/tpo/core/arti/-/issues/864
[#880]: https://gitlab.torproject.org/tpo/core/arti/-/issues/880
[#936]: https://gitlab.torproject.org/tpo/core/arti/-/issues/936
[#945]: https://gitlab.torproject.org/tpo/core/arti/-/issues/945
[#951]: https://gitlab.torproject.org/tpo/core/arti/-/issues/951
[#959]: https://gitlab.torproject.org/tpo/core/arti/-/issues/959
[#960]: https://gitlab.torproject.org/tpo/core/arti/-/issues/960
[#965]: https://gitlab.torproject.org/tpo/core/arti/-/issues/965
[#970]: https://gitlab.torproject.org/tpo/core/arti/-/issues/970
[#971]: https://gitlab.torproject.org/tpo/core/arti/-/issues/971
[#972]: https://gitlab.torproject.org/tpo/core/arti/-/issues/972
[#977]: https://gitlab.torproject.org/tpo/core/arti/-/issues/977
[#980]: https://gitlab.torproject.org/tpo/core/arti/-/issues/980
[#988]: https://gitlab.torproject.org/tpo/core/arti/-/issues/988
[#993]: https://gitlab.torproject.org/tpo/core/arti/-/issues/993
[#994]: https://gitlab.torproject.org/tpo/core/arti/-/issues/994
[#996]: https://gitlab.torproject.org/tpo/core/arti/-/issues/996
[#998]: https://gitlab.torproject.org/tpo/core/arti/-/issues/998
[#1000]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1000
[#1009]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1009
[#1010]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1010
[#1013]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1013
[9a08f04a7698ae23]: https://gitlab.torproject.org/tpo/core/arti/-/commit/9a08f04a7698ae237e352c57ebb58456e727fc93
[bbed17ba4a44a4690ad6]: https://gitlab.torproject.org/tpo/core/arti/-/commit/bbed17ba4a44a4690ad68e34844329d6542cc184
[cd6c4674dc560d9c1dc3]: https://gitlab.torproject.org/tpo/core/arti/-/commit/cd6c4674dc560d9c1dc355cac627edac32138f2c
[eee3bb8822dd22a4]: https://gitlab.torproject.org/tpo/core/arti/-/commit/eee3bb8822dd22a48b58bfb9a42cb0eaa952138d
[f4dfc146948d491c]: https://gitlab.torproject.org/tpo/core/arti/-/commit/f4dfc146948d491c2a8da0e5e6c8c58cabdf44b4
[HashX]: https://lists.torproject.org/pipermail/tor-dev/2020-June/014381.html
[TROVE-2023-002]: https://gitlab.torproject.org/tpo/core/team/-/wikis/NetworkTeam/TROVE
[TROVE-2023-003]: https://gitlab.torproject.org/tpo/core/team/-/wikis/NetworkTeam/TROVE
[Zcash Community Grants]: https://zcashcommunitygrants.org/
[`ClientCirc::send_raw_msg`]: https://tpo.pages.torproject.net/core/doc/rust/tor_proto/circuit/struct.ClientCirc.html#method.send_raw_msg
[`DropNotifyEofSignallable::is_eof`]: https://tpo.pages.torproject.net/core/doc/rust/tor_async_utils/trait.DropNotifyEofSignallable.html#method.is_eof
[`OnionAddressDisabled`]: https://tpo.pages.torproject.net/core/doc/rust/arti_client/enum.ErrorDetail.html#variant.OnionAddressDisabled
[`start_conversation`]: https://tpo.pages.torproject.net/core/doc/rust/tor_proto/circuit/struct.ClientCirc.html#method.start_conversation
[`tor-proto`]: https://tpo.pages.torproject.net/core/doc/rust/tor_proto/index.html
[other sponsors]: https://www.torproject.org/about/sponsors/
[top-level `README.md`]: https://gitlab.torproject.org/tpo/core/arti/-/blob/main/README.md
[tor#40833]: https://gitlab.torproject.org/tpo/core/tor/-/issues/40833






# Arti 1.1.7 — 1 August 2023

Arti 1.1.7 focuses on maintenance, bugfixing, and cleanups to earlier
releases.  It also lays groundwork for being able to run as an onion
service.

### Major bugfixes

- We now build with onion service client support by default.  It is
  still not enabled by default, but you no longer need any special
  _compile-time_ options in order to be able to use it. ([#948],
  [!1382])
- Fix an over-strict parsing behavior that had prevented Arti
  from connecting to onion services whose descriptors were
  encoded by Stem. ([#952], [!1389])
- We've fixed a bug where we incorrectly marked bridges as having
  directory information where they did not, and tried to build
  circuits through them without fetching descriptors. ([#638],
  [!1408])
- Fix a deadlock in [`TorClient::reconfigure()`]. ([!1432])

### Breaking changes in lower-level crates

- The [`Conversation`] API has been built as a replacement for the old
  "control message" API on circuits, to better support the needs of
  onion services. ([#917], [!1367], [!1402])
- The `tor-config` crate no longer exposes `ItemOrBool`, which was
  not used. ([5b97b0b2ce31b3db])
- The [`RetryError`] type now requires that its members implement
  `AsRef<dyn Error>`. ([36b9d11ecb122e1e])
- The error type of [`tor_hsclient::ConnError::Failed`] has changed.
  ([36b9d11ecb122e1e])

### Onion service development

- Continued improvements to our key manager infrastructure. ([#903], [#937],
  [#939] [#954], [!1372], [!1398], [!1399], [!1404], [!1413], [!1421], [!1433])
- Design work and API backend designs for implementing the service
  side of onion services. ([!1422], [!1429])
- Rust implementations of the [HashX] ASIC-resistant hash function and
  the related [EquiX] proof-of-work function, for eventual use
  in protecting onion services from denial-of-service attacks.
  Note that for now, the license on these crates is "LGPL-3.0-only";
  we hope to relicense under "MIT OR Apache-2.0" if the author
  of the C version of this code approves.
  ([#889], [!1368])

### Documentation

- Improved documentation for how Arti is validated and released.
  ([#942], [!1366])
- Improvement to bridge and transport-related documentation.
  ([#706], [!1370])
- Add documentation to explain how to build an `arti` binary that
  will not include build path details. ([#957], [!1435])

### Infrastructure

- Our [Shadow] CI tests now include support for onion service clients.
  ([!1292])
- Our Runtime logic now has much improved support for test cases that
  need to handle time and waiting, and more consistently generated
  mock implementations.  This has enabled us to clean up various unit
  tests. ([!1375], [!1378], [!1381])
- Fix a compatibility issue that had been preventing our Chutney CI
  tests from passing. ([c98894cebc60e223], [!1391], [!1393])

### Logging improvements

- We now ensure that all panics from `arti` are sent to our logs.
  Formerly, they were only reported on stderr.  ([#921], [!1377])
- Our logfile messages now have a configurable granularity, to avoid
  logging excessive detail that could help with traffic analysis
  attacks.  The default is one second granularity, and can be
  overridden with the `logging.time_granularity` option.  Note that
  this granularity does not apply to systems like `journald` that have
  their own ideas about how to record messages. ([#551], [!1376])
- When logging errors, we now check whether the type of the error
  indicates a bug.  If it does, we always escalate the logging
  severity to "warn" or higher.  ([!1379], [!1383], [!1386], [!1390])
- When reporting errors caused by the failure of multiple retry
  attempts, we take more care to report the source failure
  causes. ([#958], [!1416])

### Cleanups, minor features, and smaller bugfixes

- Rename some mocking-related functions to avoid accidental
  infinite-recursion bugs. ([!1365])
- Fix or disable a series of new warnings from Clippy. ([!1369],
  [!1394], [!1395], [!1396])
- Our (not yet used) GeoIP code now encodes country codes
  as two _nonzero_ bytes, which enables the [niche optimization].
  ([!1384])
- Our (not yet used) GeoIP code now treats zero-values ASNs
  as indicating an unknown ASN, for compatibility with the format
  used by the C tor implementation. ([#961], [!1417])
- We now try to avoid using [`Rng::gen_range()`], due to the
  possibility of panics.  We have instead added a
  `gen_range_checked()` and a `gen_range_infallible()` call. ([#920], [!1385],
  [!1387])
- The `ChanMgr` API now exposes a function to build unmanaged channels,
  in order to support external code that wants to build
  channels that are not managed by or shared with the rest of
  Arti. ([!1374], [!1403], [!1406])
- The [`NetDir`] API now has optional support for recording the
  associated country codes of its relays. ([!1364])
- Bridges no longer contain addresses twice. This prevents us from
  making unnecessary connections. ([!1409])
- In [`fs-mistrust`], we now detect several kinds of errors related
  to failed user or group lookup. ([cdafa2ce0191f612])
- We have migrated our Unix user info lookups from the
  no-longer-maintained `users` crate to the new [`pwd-grp`]
  crate. ([#877], [!1410])
- Add accessors for several bridge-related config builder types.
  ([!1425], [!1426])
- Refactor handling of initial `CREATE` cells when opening a circuit,
  to clean up our reactor loop logic a bit. ([!1441])

### Removed features

- We no longer publish the crate `arti-bench` to crates.io.  It has no
  use outside of development.  ([!1371])
- We no longer publish our as-yet-unused `tor-events` and
  `tor-congestion` crates to crates.io.  They aren't used in the rest
  of Arti yet. ([!1371])
- We no longer validate our code with Clippy's `missing_panics_doc`
  lint, since it has begun to warn about all use of `expect()`
  in nightly. ([#950], [!1380])

### Acknowledgments


Thanks to everybody who's contributed to this release, including
Alexander Færøy, Dimitris Apostolou, Jim Newsome, juga, Kunal Mehta,
Micah Elizabeth Scott, Saksham Mittal, sw1tch, and Trinity Pointard.

Also, our deep thanks to [Zcash Community Grants] and our [other sponsors]
for funding the development of Arti!

[!1292]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1292
[!1364]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1364
[!1365]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1365
[!1366]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1366
[!1367]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1367
[!1368]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1368
[!1369]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1369
[!1370]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1370
[!1371]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1371
[!1372]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1372
[!1374]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1374
[!1375]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1375
[!1376]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1376
[!1377]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1377
[!1378]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1378
[!1379]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1379
[!1380]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1380
[!1381]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1381
[!1382]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1382
[!1383]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1383
[!1384]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1384
[!1385]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1385
[!1386]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1386
[!1387]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1387
[!1389]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1389
[!1390]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1390
[!1391]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1391
[!1393]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1393
[!1394]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1394
[!1395]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1395
[!1396]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1396
[!1398]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1398
[!1399]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1399
[!1402]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1402
[!1403]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1403
[!1404]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1404
[!1406]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1406
[!1408]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1408
[!1409]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1409
[!1410]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1410
[!1413]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1413
[!1416]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1416
[!1417]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1417
[!1421]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1421
[!1422]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1422
[!1425]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1425
[!1426]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1426
[!1429]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1429
[!1432]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1432
[!1433]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1433
[!1435]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1435
[!1441]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1441
[#551]: https://gitlab.torproject.org/tpo/core/arti/-/issues/551
[#638]: https://gitlab.torproject.org/tpo/core/arti/-/issues/638
[#706]: https://gitlab.torproject.org/tpo/core/arti/-/issues/706
[#877]: https://gitlab.torproject.org/tpo/core/arti/-/issues/877
[#889]: https://gitlab.torproject.org/tpo/core/arti/-/issues/889
[#903]: https://gitlab.torproject.org/tpo/core/arti/-/issues/903
[#917]: https://gitlab.torproject.org/tpo/core/arti/-/issues/917
[#920]: https://gitlab.torproject.org/tpo/core/arti/-/issues/920
[#921]: https://gitlab.torproject.org/tpo/core/arti/-/issues/921
[#937]: https://gitlab.torproject.org/tpo/core/arti/-/issues/937
[#939]: https://gitlab.torproject.org/tpo/core/arti/-/issues/939
[#942]: https://gitlab.torproject.org/tpo/core/arti/-/issues/942
[#948]: https://gitlab.torproject.org/tpo/core/arti/-/issues/948
[#950]: https://gitlab.torproject.org/tpo/core/arti/-/issues/950
[#952]: https://gitlab.torproject.org/tpo/core/arti/-/issues/952
[#954]: https://gitlab.torproject.org/tpo/core/arti/-/issues/954
[#957]: https://gitlab.torproject.org/tpo/core/arti/-/issues/957
[#958]: https://gitlab.torproject.org/tpo/core/arti/-/issues/958
[#961]: https://gitlab.torproject.org/tpo/core/arti/-/issues/961
[36b9d11ecb122e1e]: https://gitlab.torproject.org/tpo/core/arti/-/commit/36b9d11ecb122e1ea82a13fa963c35e023f14d3a
[5b97b0b2ce31b3db]: https://gitlab.torproject.org/tpo/core/arti/-/commit/5b97b0b2ce31b3dbe1ab9cf0d33109457d1aea47
[c98894cebc60e223]: https://gitlab.torproject.org/tpo/core/arti/-/commit/c98894cebc60e223d9067636337b8e737d08ad51
[cdafa2ce0191f612]: https://gitlab.torproject.org/tpo/core/arti/-/commit/cdafa2ce0191f612342252e56dfeee86cf29e68f
[other sponsors]: https://www.torproject.org/about/sponsors/
[EquiX]: https://github.com/tevador/equix/blob/master/devlog.md
[HashX]: https://lists.torproject.org/pipermail/tor-dev/2020-June/014381.html
[Shadow]: https://shadow.github.io/
[Zcash Community Grants]: https://zcashcommunitygrants.org/
[`Conversation`]: https://tpo.pages.torproject.net/core/doc/rust/tor_proto/circuit/struct.Conversation.html
[`NetDir`]: https://tpo.pages.torproject.net/core/doc/rust/tor_netdir/struct.NetDir.html
[`RetryError`]: https://tpo.pages.torproject.net/core/doc/rust/retry_error/struct.RetryError.html
[`Rng::gen_range()`]: https://docs.rs/rand/latest/rand/trait.Rng.html#method.gen_range
[`TorClient::reconfigure()`]: https://tpo.pages.torproject.net/core/doc/rust/arti_client/struct.TorClient.html#method.reconfigure
[`fs-mistrust`]: https://tpo.pages.torproject.net/core/doc/rust/fs_mistrust/index.html
[`pwd-grp`]: https://docs.rs/crate/pwd-grp/latest
[`tor_hsclient::ConnError::Failed`]: https://tpo.pages.torproject.net/core/doc/rust/tor_hsclient/enum.ConnError.html#variant.Failed
[niche optimization]: https://internals.rust-lang.org/t/forbidden-niche-values/14237




# Arti 1.1.6 — 30 June 2023

Arti 1.1.6 completes the core of the work needed for a client
to connect to onion services on the Tor network.  This is not yet
enabled by default: we do not yet recommend using this feature for
security-sensitive purposes, because of some
[missing security features][#98].
Instructions for enabling it and trying it out can be found in the
[README.md] file.
(Note that version 1.1.6 also requires a non-default cargo feature to
be enabled: you must build with `--features=arti/onion-service-client`.)

Additionally, this version includes an experimental key manager
implementation. Currently it's used to store the keys needed for
client authentication, but in the future it will store the keys for
onion services themselves, and eventually relays.  In this release it
is still missing some import functionality for interoperability;
the interface is likely to change significantly.

Work on our RPC subsystem has also continued; we have achieved several
prerequisites needed for applications' SOCKS connections to
integrate correctly with the RPC subsystem.

And as usual, there are a large number of smaller fixes and improvements
throughout the codebase.

### Major bugfixes

- Downgrade our dependency on x25519-dalek from "2.0.0-rc.2" to
  "2.0.0-pre.1".  The former had a compatibility bug that made it stop
  working once a newer version of `curve25519-dalek` was released.  We
  hope to [re-upgrade] to a more recent version of this crate in a
  future release. ([#926], [!1317])

### Breaking changes in lower-level crates

- We have removed an empty `relaycell::restrict` module from the
  `tor-cell` crate.  This module was added in error.  This change will
  break any code that (pointlessly) tried to import
  it. ([589fefd581e962a7])

### Onion service development

- Implement the core logic of an onion service client.  Having fetched a
  descriptor for an onion service, we now establish a rendezvous
  circuit, and try to send INTRODUCE1 requests to the service's
  introduction points, while waiting for a RENDEZVOUS2 message in
  response on the rendezvous circuit. Once the message is received, we
  can launch streams to the service over that circuit. ([!1228],
  [!1230], [!1235], [!1238], [!1240])
- Re-launch and retry onion service connection attempts as
  appropriate. ([!1246])
- Onion service descriptors now have accessor functions to enable their
  actual use. ([!1220])
- We can transform the information about relays used in onion service
  descriptors, and in introduce1 cells, into the format needed to connect
  to the relay described. ([!1221])
- Generate random rendezvous cookies to identify circuits at a client's
  rendezvous point. ([!1227])
- Ensure that specific information about onion services, rendezvous
  points, and introduction points are treated as sensitive or redacted
  in our error messages. ([!1326], [!1335])
- Reduce the cost of duplicating HsDir rings in our network
  objects. ([#883], [!1234])
- Refactor and simplify our `hs_ntor` APIs to better reuse state
  information. ([bb6115103aad177c])
- Return a more informative error type from our time-period manipulation
  code. ([!1244])
- Remember our introduction point experiences, and try to use known-good
  ones before ones that have failed recently. ([!1247], [!1295])
- We now adjust the size of our pre-constructed circuit pool dynamically
  based on past demand for onion-service circuits (or lack
  thereof). ([686d5cf2093322e4])
- Speed improvements to the algorithm we use to select pre-constructed
  circuits for onion services, and correctness fixes to those speed
  improvements. ([1691c353924f89cc], [#918], [!1296], [!1301])
- The `StreamPrefs::connect_to_onion_services` method now can be used to
  enable or disable onion service connections, and TorClients can handle
  onion services correctly. ([!1257])
- Provide the extended SOCKS5 error codes as documented in [proposal
  304]. ([#736], [!1248], [!1279])
- Drop introduction circuits after they are no longer needed. ([!1299],
  [!1303])
- Expire long-unused onion service circuits. ([!1287], [!1302])
- Expire long-unused onion service descriptors. ([!1290])
- Provide a higher-level HsDescError to explain what, exactly, has gone
  wrong with parsing or decrypting an onion service
  descriptor. ([!1289])
- Respect the maximum onion service descriptor size in the consensus and
  change the default maximum from 50 KiB to 50 KB per the specification.
  ([!1323])
- Go through all of our remaining "TODO HS" comments and make sure that
  they are not issues that should block a release. ([#892], [#928], etc)
- We support enabling or disabling onion service connections via a new
  `allow_onion_addrs` option, and configuring these connections through
  other parameters. ([!1305])
- Ensure that our directory ring parameters are taken from the consensus
  parameters, rather than set unconditionally to defaults. ([!1310])
- Enforce upper bounds on the number of introduction points in an
  onion service descriptor. ([!1332])
- Use correct circuit parameters when creating onion service circuits.
  ([#935], [!1340])
- Use more accurate timeout predictions for building and using onion
  service circuits. ([!1342])


### RPC development

- Our RPC engine now supports holds a list of SOCKS connections,
  so that applications can register their SOCKS connections with their
  RPC sessions. ([545984b095119ecc])
- `TorClient`s, and similar RPC-visible, can now be exposed with a
  secure global identifier so applications can refer to them outside of
  an RPC session. This will allow applications to name a `TorClient` from
  e.g. within the parameters of a SOCKS connection. ([#863], [!1208])
- Enable `rpc::Object`s to be downcast to (some of) the `&dyn Trait`s
  that they implement. This is in tension with some of Rust's current
  limitations, but we need it so that we can downcast a `TorClient` from
  an `Object` into a type we can use in the SOCKS code for opening a
  data stream. ([!1225], [!1253])
- Major refactoring to our RPC session initialization code. ([!1254])

### New crates

- New `tor-keymgr` crate to handle persistent cryptographic keys that
  can be stored to disk. In the future this will be used for all client,
  service, and relay keys. ([!1223], [!1255], [!1256], [!1263], [!1267],
  [!1269], [!1278], [!1280], [!1284], [!1319], [!1321], [!1315],
  [!1321], [!1328], [!1337], etc.)
- New `tor-geoip` crate to handle a static in-binary or on-disk
  IP-to-country lookup table. We will use this in the future to support
  country restrictions on selected paths through the network. ([!1239],
  [!1268])

### Documentation

- Clarify behavior of `ClientCirc::send_control_message`. ([#885],
  [!1219], [58babcb756f6427c])
- Clarify required behavior for `NetDocProvider`. ([!1224])
- More information about how to configure snowflake and other pluggable
  transports. ([#875], [#879], [!1216], [!1249])
- New examples and documentation for how to implement error
  reporting. ([!1213])
- Clarify some error cases for onion service descriptor
  validation. ([!1250], [!1252])
- Improve documentation on the channel and circuit lifecycle. ([!1316],
  [!1318])
- Clarify descriptions in `NetDir`'s documentation of what we mean by
  a "usable" Relay. ([a902f320b5b31812])

### Infrastructure

- For now we ignore an "unmaintained crate" warning for the [`users`] crate
  while we work on [finding a replacement][#877]. ([!1217])
- Our CI now tests each crate individually with its default
  features. This helps detect bugs where a crate was only working
  because it had been built with the features required of it by another
  crate. ([!1250])
- We now supplement our existing system for tracking semver-breaking
  issues with the [`cargo-semver-checks`] tool. We require version
  0.22.1 or later. ([!1339])

### Cleanups, minor features, and smaller bugfixes

- We no longer use the [`arrayref`] crate to convert slice-references
  into array references.  In recent versions of Rust, we can simply use
  TryFrom and const generics. ([#872], [!1214])
- Our consensus directory objects now expose accessors that list
  required and recommended protocol versions.  ([205b6d176c4a619b])
- The `tor-error` crate now exposes a convenience macro to derive
  `AsRef<dyn Error>` for our specific error types. ([33c90e5b7243c3b3])
- The formerly experimental `send_control_message` API now takes an
  `AnyRelayMsg` rather than a cell, as does its associated `MsgHandler`
  API. ([#881], [#887], [!1232], [!1236])
- Backend code to more readily display and redact relay
  identities. ([#882], [!1233]).
- `tor-proto` no longer gives an error when trying to use `SENDME`
  messages with a relay digest algorithm with an output length of other
  than 20.  ([!1242])
- `tor-llcrypto` now exposes a method to try to look up an element from
  a slice in constant time. ([25db56777c0042a9])
- Apply two now-universally-available clippy lints to all of our crates.
  ([!1271])
- Add experimental API to expose a `chanmgr` method from
  `TorClient`. ([!1275])
- The `ClientCirc::path_ref()` method now returns an `Arc<Path>` type,
  which can be used to find information about a circuit's path without
  extensive copying.  The old `path()` method still exists, but is
  deprecated. ([#787], [!1286])
- `CircMgr` now exposes its estimates for good timeouts for circuit
  operations. ([!1281].)
- Fix a compilation warning on Windows. ([!1294])
- Make sure DirProviderBuilder is `Send + Sync`, so that
  TorClientBuilder is always `Send + Sync`. ([#924], [!1307])
- Implement conversion from ed25519 private keys to curve25519 private
  keys, as part of our eventual compatibility with ssh's key storage
  format. ([!1297])
- Numerous improvements and fixes to our configuration handling tests.
  ([!1320], [!1330])
- Refactor some duplicate logic in our circuit-retention code. ([!1322])
- Experimentally expose some of `NetDir`'s information about whether
  a relay is in the consensus (independent of whether we have full
  information about it). ([!1325])


### Removed features

- We no longer support ancient (pre-0.3.6) versions of Tor without
  support for authenticated SENDME messages. ([#914], [!1283])

### Acknowledgments

Thanks to everybody who's contributed to this release, including
Alexander Færøy, Andy, Jim Newsome, nate\_d1azzz, pinkforest,
Saksham Mittal, and Trinity Pointard.

Also, our deep thanks to [Zcash Community Grants] for funding the
development of Arti!

[!1208]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1208
[!1213]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1213
[!1214]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1214
[!1216]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1216
[!1217]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1217
[!1219]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1219
[!1220]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1220
[!1221]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1221
[!1223]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1223
[!1224]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1224
[!1225]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1225
[!1227]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1227
[!1228]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1228
[!1230]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1230
[!1232]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1232
[!1233]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1233
[!1234]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1234
[!1235]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1235
[!1236]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1236
[!1238]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1238
[!1239]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1239
[!1240]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1240
[!1242]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1242
[!1244]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1244
[!1246]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1246
[!1247]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1247
[!1248]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1248
[!1249]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1249
[!1250]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1250
[!1252]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1252
[!1253]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1253
[!1254]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1254
[!1255]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1255
[!1256]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1256
[!1257]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1257
[!1263]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1263
[!1267]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1267
[!1268]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1268
[!1269]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1269
[!1271]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1271
[!1275]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1275
[!1278]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1278
[!1279]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1279
[!1280]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1280
[!1281]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1281
[!1283]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1283
[!1284]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1284
[!1286]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1286
[!1287]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1287
[!1289]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1289
[!1290]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1290
[!1294]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1294
[!1295]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1295
[!1296]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1296
[!1297]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1297
[!1299]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1299
[!1301]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1301
[!1302]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1302
[!1303]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1303
[!1305]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1305
[!1307]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1307
[!1310]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1310
[!1315]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1315
[!1316]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1316
[!1317]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1317
[!1318]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1318
[!1319]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1319
[!1320]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1320
[!1321]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1321
[!1322]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1322
[!1323]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1323
[!1325]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1325
[!1326]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1326
[!1328]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1328
[!1330]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1330
[!1332]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1332
[!1335]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1335
[!1337]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1337
[!1339]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1339
[!1340]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1340
[!1342]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1342
[#98]: https://gitlab.torproject.org/tpo/core/arti/-/issues/98
[#736]: https://gitlab.torproject.org/tpo/core/arti/-/issues/736
[#787]: https://gitlab.torproject.org/tpo/core/arti/-/issues/787
[#863]: https://gitlab.torproject.org/tpo/core/arti/-/issues/863
[#872]: https://gitlab.torproject.org/tpo/core/arti/-/issues/872
[#875]: https://gitlab.torproject.org/tpo/core/arti/-/issues/875
[#877]: https://gitlab.torproject.org/tpo/core/arti/-/issues/877
[#879]: https://gitlab.torproject.org/tpo/core/arti/-/issues/879
[#881]: https://gitlab.torproject.org/tpo/core/arti/-/issues/881
[#882]: https://gitlab.torproject.org/tpo/core/arti/-/issues/882
[#883]: https://gitlab.torproject.org/tpo/core/arti/-/issues/883
[#885]: https://gitlab.torproject.org/tpo/core/arti/-/issues/885
[#887]: https://gitlab.torproject.org/tpo/core/arti/-/issues/887
[#892]: https://gitlab.torproject.org/tpo/core/arti/-/issues/892
[#914]: https://gitlab.torproject.org/tpo/core/arti/-/issues/914
[#918]: https://gitlab.torproject.org/tpo/core/arti/-/issues/918
[#924]: https://gitlab.torproject.org/tpo/core/arti/-/issues/924
[#926]: https://gitlab.torproject.org/tpo/core/arti/-/issues/926
[#928]: https://gitlab.torproject.org/tpo/core/arti/-/issues/928
[#935]: https://gitlab.torproject.org/tpo/core/arti/-/issues/935
[1691c353924f89cc]: https://gitlab.torproject.org/tpo/core/arti/-/commit/1691c353924f89cc9026b67578a84959840bb987
[205b6d176c4a619b]: https://gitlab.torproject.org/tpo/core/arti/-/commit/205b6d176c4a619b8665ca4095471aea07be29ca
[25db56777c0042a9]: https://gitlab.torproject.org/tpo/core/arti/-/commit/25db56777c0042a93daa7b37fc4a31e27181dc7d
[33c90e5b7243c3b3]: https://gitlab.torproject.org/tpo/core/arti/-/commit/33c90e5b7243c3b3526ae73f2fd3ebf76d785b74
[545984b095119ecc]: https://gitlab.torproject.org/tpo/core/arti/-/commit/545984b095119ecc656afe69683e820a8d1a67de
[589fefd581e962a7]: https://gitlab.torproject.org/tpo/core/arti/-/commit/589fefd581e962a7f071142bbc047b6e22adea19
[58babcb756f6427c]: https://gitlab.torproject.org/tpo/core/arti/-/commit/58babcb756f6427cc76f2d44a1663f07405563d7
[686d5cf2093322e4]: https://gitlab.torproject.org/tpo/core/arti/-/commit/686d5cf2093322e4408513daf832af6693fa67a9
[a902f320b5b31812]: https://gitlab.torproject.org/tpo/core/arti/-/commit/a902f320b5b31812fabc42b95a38b5453f050e7f
[bb6115103aad177c]: https://gitlab.torproject.org/tpo/core/arti/-/commit/bb6115103aad177c0b57918b1cb8cf0e8280223e
[README.md]: https://gitlab.torproject.org/tpo/core/arti/-/blob/main/README.md
[Zcash Community Grants]: https://zcashcommunitygrants.org/
[`arrayref`]: https://docs.rs/arrayref/latest/arrayref/
[`cargo-semver-checks`]: https://crates.io/crates/cargo-semver-checks
[`users`]: https://crates.io/crates/users
[missing security features]: https://blog.torproject.org/announcing-vanguards-add-onion-services/
[proposal 304]: https://gitlab.torproject.org/tpo/core/torspec/-/blob/main/proposals/304-socks5-extending-hs-error-codes.txt
[re-upgrade]: https://gitlab.torproject.org/tpo/core/arti/-/issues/808







# Arti 1.1.5 — 1 June 2023

Arti 1.1.5 fixes a local-only denial-of-service attack, and continues
our work towards support for providing a working RPC mechanism and an
onion service client.

### Major bugfixes (service)

- Fix a local-only CPU denial-of-service bug. Previously, an attacker
  with access to our SOCKS port (only open by default on localhost)
  could cause Arti to loop forever, consuming CPU. This issue was
  discovered by Jakob Lell. This is also tracked as
  TROVE-2023-001. ([#861], [!1196])

### Breaking changes in lower-level crates

- In [`tor-netdoc`], the `ParseErrorKind` and `ParseErrorSource` types
  have been renamed to `NetdocErrorKind` and `NetdocErrorSource`
  respectively, to better reflect their meaning. ([!1176], [!1179])
- In [`tor-linkspec`] and [`tor-cell`], we have renamed
  `UnparsedLinkSpec` to `EncodedLinkSpec` to correctly reflect its
  purpose. ([02785ca6505572bd])
- In [`tor-cell`], the `Extend2` message now takes a list of `EncodedLinkSpec`.
  ([7ce808b75bb500f2])
- In [`tor-linkspec`], `CircTarget::linkspecs()` now returns an encoded
  list instead of a `Vec` of unencoded link specifiers. This is needed
  for passing linkspecs verbatim in the onion service
  implementation. ([7ce808b75bb500f2])
- `ClientCirc` no longer implements `Clone`.  In various crates,
  functions that used to return `ClientCirc` now return
  `Arc<ClientCirc>`.  This allows us to be more explicit about how
  circuits are shared, and to make circuits visible to our RPC
  code. ([#846], [!1187])

### Onion service development

- Improved API for parsing onion service descriptors. ([#809], [!1152])
- More APIs for deriving onion service keys from one another.
  ([18cb1671c4135b3d])
- Parse onion service descriptors after receiving them. ([!1153])
- When fetching an onion service descriptor, choose the HS
  directory server at random. ([!1155])
- Refactoring and improvements to our handling for sets of link
  specifiers (components of a Tor relay's address) in order to support
  lists of link specifiers that we receive as part of an INTRODUCE2
  message or onion service descriptor. ([#794], [!1177])
- Code to enforce rules about consistency of link specifier lists.
  ([#855], [!1186])
- Correctly handle onion service descriptor lifetimes, and introduce
  necessary helper functions to handle overlapping sets of lifetime
  bounds. ([!1154])
- Additional design and specification about a key management system.
  ([!1185])
- Finish, refactor, debug, and test the hs-ntor handshake used to
  negotiate keys with onion services ([#865], [!1189])
- Export the unencrypted portion of an INTRODUCE1 message as needed
  to implement the hs-ntor handshake. ([#866], [!1188])
- Add support for adding the "virtual" hop for an onion service
  rendezvous circuit based on a set of cryptographic material negotiated via
  the `hs-ntor` handshake. ([#726], [!1191])

### RPC development

- Improved description of our work-in-progress RPC API design.
  ([!1005])
- Expose an initial TorClient object to our RPC sessions.
  ([d7ab388faf96f53e])
- Implement object-handle management backend for RPC sessions,
  so that RPC commands can refer to objects by a capability-style
  ID that doesn't make objects visible to other sessions.
  This has required significant design refinement, and will likely
  need more in the future.
  ([#820], [#848], [!1160], [!1183], [!1200])
- Add an experimental `StreamCtrl` mechanism to allow code (like the RPC
  module) that does not own the read or write side of a data stream to
  nonetheless monitor and control the stream. ([#847], [!1198])

### Infrastructure

- Our license checking code now allows the MPL-2.0 license on an
  allow-list basis. ([#845], [e5fa42e1c7957db0])
- Our [`fixup-features`] script now works correctly to enforce our rules
  about the `full` feature (notably, that it must include all
  features not labelled as experimental or non-additive).
  ([!1180], [!1182])
- The script that generates our Acknowledgments section now
  looks at various Git trailers in order to better acknowledge bug reporters.
  ([!1194])
- Use the latest version of Shadow in our integration tests ([!1199])

### Cleanups, minor features, and smaller bugfixes

- Improved logging in directory manager code when deciding what to
  download and when to download it. ([#803], [!1163])
- Downgrade and clarify log messages about directory replacement time.
  ([#839])
- Revise and downgrade other directory-manager logs. ([#854], [!1172])
- When listing the features that are enabled, list static features
  correctly. ([!1169])
- Refactor the `check_key` function in `tor-cert` to provide a more
  reasonable API. ([#759], [!1184])
- Improve or downgrade certain verbose log messages in `tor-guardmgr`
  and `tor-proto`. ([!1190])
- Throughout our codebase, avoid the use of ed25519 secret keys without
  an accompanying public key. Instead, store the two as a
  keypair. (Using ed25519 secret keys alone creates the risk of using
  them with mismatched public keys, with
  [catastrophic cryptographic results].)  ([#798], [!1192])

### Network updates

- Update to the latest list of Tor fallback directories. ([!1210])

### Acknowledgments

Thanks to everybody who's contributed to this release, including
Alexander Færøy, Jakob Lell, Jim Newsome, Saksham Mittal, and Trinity
Pointard.
Also, our deep thanks to [Zcash Community Grants] for funding the
development of Arti!

[!1005]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1005
[!1152]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1152
[!1153]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1153
[!1154]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1154
[!1155]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1155
[!1160]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1160
[!1163]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1163
[!1169]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1169
[!1172]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1172
[!1176]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1176
[!1177]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1177
[!1179]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1179
[!1180]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1180
[!1182]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1182
[!1183]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1183
[!1184]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1184
[!1185]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1185
[!1186]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1186
[!1187]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1187
[!1188]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1188
[!1189]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1189
[!1190]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1190
[!1191]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1191
[!1192]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1192
[!1194]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1194
[!1196]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1196
[!1198]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1198
[!1199]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1199
[!1200]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1200
[!1210]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1210
[#726]: https://gitlab.torproject.org/tpo/core/arti/-/issues/726
[#759]: https://gitlab.torproject.org/tpo/core/arti/-/issues/759
[#794]: https://gitlab.torproject.org/tpo/core/arti/-/issues/794
[#798]: https://gitlab.torproject.org/tpo/core/arti/-/issues/798
[#803]: https://gitlab.torproject.org/tpo/core/arti/-/issues/803
[#809]: https://gitlab.torproject.org/tpo/core/arti/-/issues/809
[#820]: https://gitlab.torproject.org/tpo/core/arti/-/issues/820
[#839]: https://gitlab.torproject.org/tpo/core/arti/-/issues/839
[#845]: https://gitlab.torproject.org/tpo/core/arti/-/issues/845
[#846]: https://gitlab.torproject.org/tpo/core/arti/-/issues/846
[#847]: https://gitlab.torproject.org/tpo/core/arti/-/issues/847
[#848]: https://gitlab.torproject.org/tpo/core/arti/-/issues/848
[#854]: https://gitlab.torproject.org/tpo/core/arti/-/issues/854
[#855]: https://gitlab.torproject.org/tpo/core/arti/-/issues/855
[#861]: https://gitlab.torproject.org/tpo/core/arti/-/issues/861
[#865]: https://gitlab.torproject.org/tpo/core/arti/-/issues/865
[#866]: https://gitlab.torproject.org/tpo/core/arti/-/issues/866
[02785ca6505572bd]: https://gitlab.torproject.org/tpo/core/arti/-/commit/02785ca6505572bdbfaa560178f299e30f7bc7e8
[18cb1671c4135b3d]: https://gitlab.torproject.org/tpo/core/arti/-/commit/18cb1671c4135b3d875dd0a296f5d2ae19c3d0c5
[7ce808b75bb500f2]: https://gitlab.torproject.org/tpo/core/arti/-/commit/7ce808b75bb500f27ce7837d4f76cbf7fc1ee705
[d7ab388faf96f53e]: https://gitlab.torproject.org/tpo/core/arti/-/commit/d7ab388faf96f53e7981e8307f51a16e7891627b
[e5fa42e1c7957db0]: https://gitlab.torproject.org/tpo/core/arti/-/commit/e5fa42e1c7957db06e051207b450bd88c2427c85
[Zcash Community Grants]: https://zcashcommunitygrants.org/
[`fixup-features`]: https://gitlab.torproject.org/tpo/core/arti/-/tree/main/maint/fixup-features
[`tor-cell`]: https://gitlab.torproject.org/tpo/core/arti/-/tree/main/crates/tor-cell
[`tor-linkspec`]: https://gitlab.torproject.org/tpo/core/arti/-/tree/main/crates/tor-linkspec
[`tor-netdoc`]: https://gitlab.torproject.org/tpo/core/arti/-/tree/main/crates/tor-netdoc
[catastrophic cryptographic results]: https://moderncrypto.org/mail-archive/curves/2020/001012.html


# Arti 1.1.4 — 3 May 2023

Arti 1.1.4 fixes a major bug in the directory downloading code that
could cause clients to stay stuck with an old version of the
directory.

Additionally, this version advances our efforts on onion services:
we have implementations for descriptor downloading, and a design for
improved key management.

For this month and the next, our efforts are divided between onion
services and work on a new RPC API (a successor to C Tor's "control
port") that will give applications a safe and powerful way to work
with Arti without having to write their code in Rust or link Arti as
a library (unless they want to).  We have an early version of this
protocol implemented, but it does not yet expose any useful
functionality.

Arti 1.1.4 also increases our MSRV (Minimum Supported Rust Version)
to Rust 1.65, in accordance with our [MSRV Policy], and renames a
few other inconsistently-named APIs.


### Major Bugfixes

- Download directories correctly in the case where we start with our cache
  containing all the microdescriptors from the previous directory.
  Previously, we had a bug where we only checked whether it was time
  to fetch a new consensus when we added a new microdescriptor from
  the network.  This bug could lead to Arti running for a while
  with an expired directory. ([#802] [!1126])

### Breaking changes

- We now require Rust 1.65 or later for all of our crates.
  This change is required so that we can work correctly with several
  of our dependencies, including the [`typetag`] crate which we
  will need for RPC. ([#815] [!1131] [!1137])
- In all crates, rename `*ProtocolFailed` errors to `*ProtocolViolation`.
  This is a more correct name, but does potentially break API users
  depending on the old versions. ([#804] [!1121] [!1132])


### Breaking changes in lower level crates

- Convert the DirClient request type for `RouterDesc`s into an enum,
  and remove its `push()` method.
  ([!1112])
- Rename `BridgeDescManager` to `BridgeDescMgr` for consistency
  with other type names. ([#805] (!1122))
- In `tor-async-utils`, rename `SinkExt` to `SinkPrepareExt`, since it is not
  actually an extension trait on all `Sink`s. ([5cd5e6a3f8431eab])

### Onion service development

- Added and refactored some APIs in `tor-netdir` to better support onion
  service HSDir rings. ([!1094])
- Clean up APIs for creating encrypted onion service descriptors. ([!1097])
- Support for downloading onion service descriptors on demand.  ([!1116]
  [!1118])
- Design an API and document on-disk behavior for a
  [key-management subsystem], to be used not
  only for onion services, but eventually for other kinds of keys. ([#834]
  [!1147])

### RPC/Embedding development

- New specification for our capabilities-based RPC meta-protocol in
  [`rpc-meta-draft`]. ([!1078] [!1107] [!1141])
- An incomplete work-in-progress implementation of our new RPC framework,
  with a capabilities-based JSON-encoded protocol that allows for
  RPC-visible methods to be implemented on objects throughout our
  codebase.  For now, it is off-by-default, and exposes nothing useful.
  ([!1092] [!1136] [!1144] [!1148])

### Documentation

- Better explain how to build our documentation. ([!1090])
- Explain that we explicitly support `--document-private-items`. ([!1090])
- Fix incorrect documentation of OSX configuration location. ([!1125])
- Document some second-order effects of our semver conformance. ([!1129])


### Cleanups, minor features, and minor bugfixes

- Improvements to [`TimerangeBound`] API. ([!1105])
- Fix builds with several combinations of features. ([#801] [!1106])
- Code to join an `AsyncRead` and `AsyncWrite` into a single object
  implementing both traits. ([!1115])
- Expose the `MiddleOnly` flag on router status objects, for tools that want
  it. ([#833] [!1145] [!1146])
- Only run doctest for `BridgesConfig` when the `pt-client` feature
  is enabled; otherwise it will fail. ([#843], [!1166])
- Refactoring in and around `RelayId`. ([!1156])

### Acknowledgments

Thanks to everybody who's contributed to this release, including
Alexander Færøy, juga, Neel Chauhan, tranna, and Trinity Pointard.
Also, our deep thanks to [Zcash Community Grants] for funding the
development of Arti!

[!1078]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1078
[!1090]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1090
[!1092]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1092
[!1094]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1094
[!1097]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1097
[!1105]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1105
[!1106]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1106
[!1107]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1107
[!1112]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1112
[!1115]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1115
[!1116]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1116
[!1118]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1118
[!1121]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1121
[!1125]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1125
[!1126]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1126
[!1129]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1129
[!1131]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1131
[!1132]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1132
[!1136]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1136
[!1137]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1137
[!1141]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1141
[!1144]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1144
[!1145]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1145
[!1146]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1146
[!1147]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1147
[!1148]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1148
[!1156]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1156
[!1166]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1166
[#801]: https://gitlab.torproject.org/tpo/core/arti/-/issues/801
[#802]: https://gitlab.torproject.org/tpo/core/arti/-/issues/802
[#804]: https://gitlab.torproject.org/tpo/core/arti/-/issues/804
[#805]: https://gitlab.torproject.org/tpo/core/arti/-/issues/805
[#815]: https://gitlab.torproject.org/tpo/core/arti/-/issues/815
[#833]: https://gitlab.torproject.org/tpo/core/arti/-/issues/833
[#834]: https://gitlab.torproject.org/tpo/core/arti/-/issues/834
[#843]: https://gitlab.torproject.org/tpo/core/arti/-/issues/843
[5cd5e6a3f8431eab]: https://gitlab.torproject.org/tpo/core/arti/-/commit/5cd5e6a3f8431eab20e43fcdaa4e93d9afc9b729
[MSRV Policy]: https://gitlab.torproject.org/tpo/core/arti/#minimum-supported-rust-version
[Zcash Community Grants]: https://zcashcommunitygrants.org/
[`TimerangeBound`]: https://tpo.pages.torproject.net/core/doc/rust/tor_checkable/timed/struct.TimerangeBound.html
[`rpc-meta-draft`]: https://gitlab.torproject.org/tpo/core/arti/-/blob/main/doc/dev/notes/rpc-meta-draft.md
[`typetag`]: https://crates.io/crates/typetag
[key-management subsystem]: https://gitlab.torproject.org/tpo/core/arti/-/blob/main/doc/dev/notes/key-management.md




# tor-llcrypto patch release 0.4.4 — 4 April 2023

On 4 April 2023, we put out a patch release (0.4.4) to `tor-llcrypto`,
to fix a compatibility issue.  We had previously configured the
`tor-llcrypto` crate to work with any version of [`x25519-dalek`]
version "2.0.0-pre.1" or later, but the recent release of version
"2.0.0-rc.2" had a breaking change that stopped `tor-llcrypto` from
compiling.  The new version of `tor-llcrypto` now properly pins the
old version of `x25519-dalek`, to avoid picking up such incompatible
pre-releases.  We hope that our next release of tor-llcrypto will
upgrade to the newer `x25519-dalek` release.
Additional resources: [#807] [!1108].

[!1108]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1108
[#807]: https://gitlab.torproject.org/tpo/core/arti/-/issues/807
[`x25519-dalek`]: https://github.com/dalek-cryptography/x25519-dalek


# Arti 1.1.3 — 31 March 2023

Arti 1.1.3 continues our work on onion services.  We can now parse all
of the relevant message types, build circuits as needed to target
relays, build and sign onion service descriptors, and deliver onion service
requests to our `hsclient` code.

We've also solved a few annoying bugs, made our CI more bulletproof against
certain programming mistakes, and exposed a few APIs that had been missing
before elsewhere in our code.

### Major bugfixes

- Prevent a fatal error when finding a usable consensus in a read-only
  directory store. ([#779], [!1055])

### Breaking changes in lower level crates

- Moved futures-related utilities from `tor-basic-utils` to a new
  `tor-async-utils` crate. ([!1091])
- When the `expand-paths` Cargo feature is not enabled, we now reject
  paths in our configuration containing unescaped `$` and `~` strings.
  Previously we would treat them as literals, which would break
  when `expand-paths` was provided. ([#790], [!1069])

### Onion service development

- We now have working implementations for all of the message types that Tor
  uses to implement onion services. These are included in our fuzzing, and
  are cross-validated against the C Tor implementation. ([!1038], [!1043],
  [!1045], [!1052])
- Our onion service descriptor parsing code now validates the inner
  certificates embedded in the descriptors, for parity with C Tor's behavior.
  ([#744], [!1044])
- Refactor responsibility for HS circuit management out of `CircMgr`
  ([!1047])
- Revise APIs and outline implementations for the initial parts of a state
  manager and client implementation.  ([!1034], [!1086])
- Handle requests for `.onion` addresses by routing them to our onion service
  code.  (This code does not yet do anything useful.) ([!1060], [!1071],
  [!1098])
- Our circuit implementation now has APIs needed to send special-purpose
  messages and receive replies for them.  We'll use this to implement
  onion service handshakes outside of the `tor-proto` module. ([!1051])
- Implement functionality to pre-construct and launch circuits as needed for
  onion service directory, introduction, and rendezvous
  communications. ([#691], [!1065])
- Implement code to construct, encrypt, and sign onion service
  descriptors. ([#745], [!1070], [!1084])
- More work on usable APIs for HSDir ring. ([!1095])

### Infrastructure

- Add a new `check_env` script to detect whether the environment is set
  up correctly to build Arti. ([!1030])
- We have the beginnings of a `fixup-features` tool, to make sure that our
  "full" and "experimental" Cargo features behave in the way we expect,
  and eventually to enable us to use [`cargo-semver-checks`] on our
  non-experimental features only.  This tool is not yet ready for
  use; its semantics are subtly wrong. ([#771], [!1059])
- Our CI scripts now rejects merges containing the string
  "XX<!-- look, a squirrel -->XX";
  we use this string to indicate places where the code must be fixed
  before it can be merged. ([#782], [!1067])

### Testing

- More of our tests now specify times using [`humantime`] (rather than as
  a number of seconds since the Unix epoch). ([!1037])
- Our fuzzers now compile again.
  ([53e44b58f5fa0cfa], [!1063])

### Documentation

- New example code for building a `BridgeConfig` and launching a TorClient
  with bridges, without having a config file. ([#791], [!1074])


### Cleanups, minor features, and minor bugfixes

- Our `caret` macro now works correctly for uninhabited
  enumerations. ([841905948f913f73])
- Defend against possible misuse of [`tor_bytes::Reader::extract_n`].
  This wasn't a security hole, but could have become one in the
  future. ([!1053])
- Do not ask exits to resolve IP addresses: we already know the IP address
  for an IP address. ([!1057])
- Fix a bunch of new warnings from Rust 1.68. ([!1062])
- Expose builder for [`TransportConfigList`] as part of the public
  API. ([455a7a710917965f])
- Enforce use of blinded keys in places where they are required. ([!1081])
- Add accessors for the [`Blockage`] type, so other programs can
  ask what has gone wrong with the connection to the network. ([#800],
  [!1088]).


### Acknowledgments

Thanks to everybody who's contributed to this release, including
Alexander Færøy, Dimitris Apostolou, Emil Engler, Saksham Mittal, and
Trinity Pointard. Also, our welcome to Gabi Moldovan as she joins
the team!

Also, our deep thanks to [Zcash Community Grants] for funding the
development of Arti!


[!1030]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1030
[!1034]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1034
[!1037]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1037
[!1038]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1038
[!1043]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1043
[!1044]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1044
[!1045]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1045
[!1047]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1047
[!1051]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1051
[!1052]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1052
[!1053]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1053
[!1055]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1055
[!1057]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1057
[!1059]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1059
[!1060]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1060
[!1062]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1062
[!1063]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1063
[!1065]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1065
[!1067]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1067
[!1069]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1069
[!1070]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1070
[!1071]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1071
[!1074]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1074
[!1081]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1081
[!1084]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1084
[!1086]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1086
[!1088]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1088
[!1091]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1091
[!1095]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1095
[!1098]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1098
[#691]: https://gitlab.torproject.org/tpo/core/arti/-/issues/691
[#744]: https://gitlab.torproject.org/tpo/core/arti/-/issues/744
[#745]: https://gitlab.torproject.org/tpo/core/arti/-/issues/745
[#771]: https://gitlab.torproject.org/tpo/core/arti/-/issues/771
[#779]: https://gitlab.torproject.org/tpo/core/arti/-/issues/779
[#782]: https://gitlab.torproject.org/tpo/core/arti/-/issues/782
[#790]: https://gitlab.torproject.org/tpo/core/arti/-/issues/790
[#791]: https://gitlab.torproject.org/tpo/core/arti/-/issues/791
[#800]: https://gitlab.torproject.org/tpo/core/arti/-/issues/800
[455a7a710917965f]: https://gitlab.torproject.org/tpo/core/arti/-/commit/455a7a710917965f0b3977d4381752975184def1
[53e44b58f5fa0cfa]: https://gitlab.torproject.org/tpo/core/arti/-/commit/53e44b58f5fa0cfa57073618d18bd71a1632afff
[841905948f913f73]: https://gitlab.torproject.org/tpo/core/arti/-/commit/841905948f913f73b3bd9cfeeb11e8b9ab9f06ea
[Zcash Community Grants]: https://zcashcommunitygrants.org/
[`Blockage`]: https://tpo.pages.torproject.net/core/doc/rust/arti_client/status/struct.Blockage.html
[`TransportConfigList`]: https://tpo.pages.torproject.net/core/doc/rust/arti_client/config/struct.TransportConfigListBuilder.html
[`cargo-semver-checks`]: https://crates.io/crates/cargo-semver-checks
[`humantime`]: https://crates.io/crates/humantime
[`tor_bytes::Reader::extract_n`]: https://tpo.pages.torproject.net/core/doc/rust/tor_bytes/struct.Reader.html#method.extract_n






# Arti 1.1.2 — 28 February 2023

Arti 1.1.2 continues our work on onion services, and builds out more of
the necessary infrastructure, focusing on backend support for the onion
service directories.

We've also done a significant revision on our handling of incoming
messages on circuits, to avoid a fair amount of unnecessary copying, and
defer message parsing until we're certain that the message type would be
acceptable in a given context.  Doing this turned up several bugs, which
are now fixed too.

### Breaking changes in lower level crates

- The APIs for `tor-cell` have changed significantly, to help
  implement [#525] and prepare for [#690]. This has no downstream
  implications outside of `tor-proto`.
- Our [`IntegerMinutes`] type no longer has an erroneous `days()` accessor.
  (This accessor did not work correctly, and actually returned a
  number of minutes!) ([bb2ab7c2a3e0994bb43])
- The [`PartialNetDir::fill_from_previous_netdir()`] function has
  changed its argument types and semantics. ([f69d7f96ac40dda5])

(Breaking changes in experimental APIs are not noted here.)

### New features

- We now have the facility to give a helpful "error hint" in response to
  a given failure. Right now, we use this to improve the error message
  given for file-system permission errors, so that it suggests either
  changing the permissions on a directory, or suppressing the error.
  ([#578], [#579], [!976], [!994], [!1018])
- When we log an error message from inside our code (at "info" or higher), we
  now make sure to log a full _error report_, including the cause of the
  error, its cause, and so on. ([#680], [!997])
- When receiving messages on channels, circuits, and streams, we now
  defer parsing those messages until we know whether their types
  are acceptable. This shrinks our attack surface, simplifies our code,
  and makes our protocol handling less error-prone. ([#525], [!1008],
  [!1013], [!1017])
- We now copy relay cell bodies much less than previously. ([#7],
  [ca3b33a1afc58b84])
- We have support for handling link specifier types verbatim, for cases
  when we need to use them to contact a rendezvous point or introduction
  point without checking them. ([!1029])

### Onion service development

- We can now parse onion service descriptors, including all encrypted layers,
  with support for descriptor-based client authentication. ([#744], [!999],
  [!1015])
- Our network directory code now supports deriving the `HsDir` directory
  ring, to find out where onion service descriptors should be uploaded and
  downloaded. ([#687], [!1012])
- We've refactored our implementation of onion service message
  extensions into a single place, to save on code and avoid type
  confusion.  ([5521df0909ff7afa])
- Our _internal_ onion-service Cargo features have been renamed to
  start with `hs-*`. We're still using `onion-*` as the prefix for our
  high-level onion-service features. ([#756], [!1033])

### Infrastructure

- All our shell scripts now work when `bash` is somewhere other than `/bin`.
  ([!990])
- Our `check_doc_features` script is now a little more reliable.
  ([!1023])
- Our coverage tools now perform better checks to make sure they
  have all of their dependencies. ([#776], [!1025])

### Cleanups, minor features, and bugfixes

- The internal data structures in [`tor-netdir`] now use the
  [`typed_index_collections`] crate to ensure that the indices for one
  list are not mis-used as indices into another. ([!1004])
- We no longer reject authority certificates that contain an unrecognized
  keyword. ([#752], [266c61f7213dbec7])
- Our [`tor-netdoc`] parsing code now requires the caller to specify
  handling for unrecognized keywords explicitly, to avoid future instances
  of bug [#752]. ([!1006])
- Several internal APIs and patterns in [`tor-netdoc`] have been streamlined.
  ([#760], [!1016], [!1021])
- Make extension-handling code in for onion service message decoding more
  generic, since we'll reuse it a lot. ([!1020])
- We now kill off circuits under more circumstances when the other side of
  the circuit violates the protocol. ([#769], [#773], [!1026])
- We now expire router descriptors as soon as _any_ of their internal
  expiration times has elapsed. Previously, we expired them when _all_
  of their expiration times had elapsed, which is incorrect. ([#772],
  [!1022])
- We are much more careful than previous about validating the correctness
  of various message types on half-closed streams. Previously, we
  had separate implementations for message validation; now, we use
  a single object to check messages in both cases. ([#744], [!1026])
- We now treat a `RESOLVED` message as closing a half-closed resolve stream.
  Previously, we left the stream open. ([!1026])

Thanks to everyone who has contributed to this release, including
Dimitris Apostolou, Emil Engler, and Shady Katy.

Also, our deep thanks to [Zcash Community Grants] for funding the
development of Arti!

[!976]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/976
[!990]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/990
[!994]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/994
[!997]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/997
[!999]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/999
[!1004]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1004
[!1006]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1006
[!1008]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1008
[!1012]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1012
[!1013]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1013
[!1015]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1015
[!1016]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1016
[!1017]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1017
[!1018]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1018
[!1020]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1020
[!1021]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1021
[!1022]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1022
[!1023]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1023
[!1025]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1025
[!1026]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1026
[!1029]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1029
[#7]: https://gitlab.torproject.org/tpo/core/arti/-/issues/7
[#525]: https://gitlab.torproject.org/tpo/core/arti/-/issues/525
[#578]: https://gitlab.torproject.org/tpo/core/arti/-/issues/578
[#579]: https://gitlab.torproject.org/tpo/core/arti/-/issues/579
[#680]: https://gitlab.torproject.org/tpo/core/arti/-/issues/680
[#687]: https://gitlab.torproject.org/tpo/core/arti/-/issues/687
[#690]: https://gitlab.torproject.org/tpo/core/arti/-/issues/690
[#744]: https://gitlab.torproject.org/tpo/core/arti/-/issues/744
[#752]: https://gitlab.torproject.org/tpo/core/arti/-/issues/752
[#760]: https://gitlab.torproject.org/tpo/core/arti/-/issues/760
[#769]: https://gitlab.torproject.org/tpo/core/arti/-/issues/769
[#772]: https://gitlab.torproject.org/tpo/core/arti/-/issues/772
[#773]: https://gitlab.torproject.org/tpo/core/arti/-/issues/773
[#776]: https://gitlab.torproject.org/tpo/core/arti/-/issues/776
[266c61f7213dbec7]: https://gitlab.torproject.org/tpo/core/arti/-/commit/266c61f7213dbec7feacac256bd87329837535e2
[5521df0909ff7afa]: https://gitlab.torproject.org/tpo/core/arti/-/commit/5521df0909ff7afa2d78304c9376861dfcf7041a
[bb2ab7c2a3e0994bb43]: https://gitlab.torproject.org/tpo/core/arti/-/commit/bb2ab7c2a3e0994bb438188511688b5b039cae29
[ca3b33a1afc58b84]: https://gitlab.torproject.org/tpo/core/arti/-/commit/ca3b33a1afc58b84cc7a39ea3845a82f17cee0da
[f69d7f96ac40dda5]: https://gitlab.torproject.org/tpo/core/arti/-/commit/f69d7f96ac40dda53a8f4f6c01557195faaeff7c
[Zcash Community Grants]: https://zcashcommunitygrants.org/
[`IntegerMinutes`]: https://tpo.pages.torproject.net/core/doc/rust/tor_units/struct.IntegerMinutes.html
[`PartialNetDir::fill_from_previous_netdir()`]: https://tpo.pages.torproject.net/core/doc/rust/tor_netdir/struct.PartialNetDir.html#method.fill_from_previous_netdir
[`tor-netdir`]: https://tpo.pages.torproject.net/core/doc/rust/tor_netdir/index.html
[`tor-netdoc`]: https://tpo.pages.torproject.net/core/doc/rust/tor_netdoc/index.html
[`typed_index_collections`]: https://docs.rs/typed-index-collections/latest/typed_index_collections/




# Arti 1.1.1 — 1 February 2023

After months of work, we have a new release of Arti!
Arti 1.1.1  is an incremental release, and cleans up a few issues from
previous releases, including a few annoyances and limitations.

More significantly, Arti 1.1.1 begins our work on [Onion Services].
This code won't be finished till later this year, but you can read about
our process below.

### Breaking changes in lower level crates

- Some accessors for the message types in [`tor-cell`] are renamed. ([#608],
  [!948])

### New features

- When logging an error at severity `info` or higher, we now (sometimes)
  include a full report of the error's sources. Previously we only
  logged the highest-level error, which often lacked enough detail to
  make a full diagnosis. This work will be completed in a subsequent
  release.([!936])
- When asked via SOCKS to resolve an address that is already an IP
  address, we now just return the same address, rather than asking the
  Tor network.  ([#714], [!957])
- There is a new release profile, `quicktest`, for development purposes.
  It should run faster than `debug`, but compile faster than `release`.
  It is meant for quick integration and acceptance test purposes.
  ([#639], [!960])
- The `TorClient` object now exposes a [`set_stream_prefs`] API to let
  callers change their stream settings without cloning a new
  `TorClient`.  ([#718], [!977])

### Onion service development

- There is now an unimplemented draft set of high-level and low-level
  APIs throughout our codebase that we will need to implement onion
  services.  These not-yet-functional APIs are gated behind the
  `onion-client` and `onion-service` features.  They are not covered by
  semantic versioning; we will use them to guide our implementation
  efforts in the coming months. ([#525], [#716], [!959], [!966], [!969],
  [!970], [!971], [!972], [!974])
- We have implemented the private-key version of the key-blinding algorithm
  used in onion services. ([#719], [!964])
- We now parse and expose consensus network parameters related to onion
  services. ([!968])
- Our SOCKS backend now supports returning the extended onion service
  SOCKS result codes from [proposal 304]. ([#736], [!978])
- The `tor-netdoc` crate now has a (not-yet-used) backend for
  constructing documents in Tor's metaformat. ([!969], [!984])
- Implement the lower level cryptographic key types
  (and some of the cryptographic algorithms) used by onion
  services. ([#684], [#742], [!980])
- Add support for parsing [Shared Random Values] from consensus
  documents, including the extensions from [proposal 342].
- In `tor-netdir`, implement the algorithms for determining the current
  time period and constructing the cryptographic parameters for each
  period's HsDir ring. ([#686], [!987])


### Network updates

- Update to the latest identity key for the directory authority `moria1`.
  ([!922])
- Retire the directory authority `faravahar`. ([!924], [tor#40688])

### Testing

- Upgrade to a newer version of the [Shadow] simulator, and use it to
  test Arti with bridges. ([#651], [!915])
- More tests for our safe-logging features. ([!928])
- More tests for error cases in persistent-data manager. ([!930])
- We now have a standard block of `clippy` exceptions that we allow in our
  test code, and we apply it uniformly. ([!937])
- In our Shadow scripts, use bare paths to find `tor` and `tgen`. ([!949])

### Documentation

- Move internal-facing documentation into a `doc/dev` subdirectory, so that
  it's easy for downstream users to ignore it. ([#576], [!921])
- Make the summary line style consistent across our `README` files,
  and make the crate list in [`Architecture.md`] match. ([!951])
- Add more high level documentation to [`Architecture.md`], including a
  rough crate-dependency diagram, and an object model diagram for our
  manager types. ([#624], [!963])

### Example code

- Make the `arti-hyper` example code compile and work correctly on
  OSX. ([#569], [#715], [!958])

### Cleanups, minor features, and bugfixes

- Use Rust 1.60's [conditional dependency] feature to simplify our
  dependency and feature logic. ([#434], [!920])
- Upgrade to [`shellexpand`] 3.x. ([!927])
- The `unwrap` method on [`Sensitive`] is renamed to `into_inner`; `unwrap`
  is now deprecated.  ([!926])
- Clean up tests to use [`humantime`] more, and to specify fewer times as raw
  integers. ([#663], [!931], [!941], [!942], [!943])
- We now use a low-level [`CtByteArray`] type to handle the common case
  of declaring a fixed-length array that should always be compared in
  constant time. ([!962])
- There is now much more diagnostic logging in the pluggable transport
  IPC code, and for connection launching.
  ([#677], [!923])
- We have labeled more data throughout our logs and error messages as
  "sensitive" for logging purposes. ([#556], [!934], [!986])
- We've migrated all of our base64 parsing to [`base64ct`]. (This
  work began with [!600] in Arti 0.5.0; now we have migrated even the
  parsing that doesn't _need_ to be constant-time, under the theory
  that having only one implementation is probably better.)
  ([889206cde4ef29d])
- Our scripts now all indirect through `/usr/bin/env`, to support
  platforms that don't put `bash` in `/bin`. ([!988])
- Clean up various warnings introduced in Rust 1.67 ([#748], [#749], [!992])
- Numerous spelling fixes.


Thanks to everyone who has contributed to this release, including
Alexander Færøy, coral, Dimitris Apostolou, Emil Engler, Jim Newsome,
Michael van Straten, Neel Chauhan, and Trinity Pointard.

Also, our deep thanks to [Zcash Community Grants] for funding the
development of Arti 1.1.1!


[!600]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/600
[!915]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/915
[!920]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/920
[!921]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/921
[!922]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/922
[!923]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/923
[!924]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/924
[!926]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/926
[!927]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/927
[!928]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/928
[!930]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/930
[!931]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/931
[!934]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/934
[!936]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/936
[!937]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/937
[!941]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/941
[!942]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/942
[!943]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/943
[!948]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/948
[!949]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/949
[!951]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/951
[!957]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/957
[!958]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/958
[!959]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/959
[!960]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/960
[!962]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/962
[!963]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/963
[!964]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/964
[!966]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/966
[!968]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/968
[!969]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/969
[!970]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/970
[!971]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/971
[!972]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/972
[!974]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/974
[!977]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/977
[!978]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/978
[!980]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/980
[!984]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/984
[!986]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/986
[!987]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/987
[!988]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/988
[!992]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/992
[#434]: https://gitlab.torproject.org/tpo/core/arti/-/issues/434
[#525]: https://gitlab.torproject.org/tpo/core/arti/-/issues/525
[#556]: https://gitlab.torproject.org/tpo/core/arti/-/issues/556
[#569]: https://gitlab.torproject.org/tpo/core/arti/-/issues/569
[#576]: https://gitlab.torproject.org/tpo/core/arti/-/issues/576
[#608]: https://gitlab.torproject.org/tpo/core/arti/-/issues/608
[#624]: https://gitlab.torproject.org/tpo/core/arti/-/issues/624
[#639]: https://gitlab.torproject.org/tpo/core/arti/-/issues/639
[#651]: https://gitlab.torproject.org/tpo/core/arti/-/issues/651
[#663]: https://gitlab.torproject.org/tpo/core/arti/-/issues/663
[#677]: https://gitlab.torproject.org/tpo/core/arti/-/issues/677
[#684]: https://gitlab.torproject.org/tpo/core/arti/-/issues/684
[#686]: https://gitlab.torproject.org/tpo/core/arti/-/issues/686
[#714]: https://gitlab.torproject.org/tpo/core/arti/-/issues/714
[#715]: https://gitlab.torproject.org/tpo/core/arti/-/issues/715
[#716]: https://gitlab.torproject.org/tpo/core/arti/-/issues/716
[#718]: https://gitlab.torproject.org/tpo/core/arti/-/issues/718
[#719]: https://gitlab.torproject.org/tpo/core/arti/-/issues/719
[#736]: https://gitlab.torproject.org/tpo/core/arti/-/issues/736
[#742]: https://gitlab.torproject.org/tpo/core/arti/-/issues/742
[#748]: https://gitlab.torproject.org/tpo/core/arti/-/issues/748
[#749]: https://gitlab.torproject.org/tpo/core/arti/-/issues/749
[889206cde4ef29d]: https://gitlab.torproject.org/tpo/core/arti/-/commit/889206cde4ef29d7d10bda546f8ad518eb09c290
[Onion Services]: https://community.torproject.org/onion-services/
[Shadow]: https://shadow.github.io/
[Shared Random Values]: https://blog.torproject.org/mission-montreal-building-next-generation-onion-services/
[Zcash Community Grants]: https://zcashcommunitygrants.org/
[`Architecture.md`]: https://gitlab.torproject.org/tpo/core/arti/-/blob/main/doc/dev/Architecture.md
[`CtByteArray`]: https://tpo.pages.torproject.net/core/doc/rust/tor_llcrypto/util/ct/struct.CtByteArray.html
[`Sensitive`]: https://tpo.pages.torproject.net/core/doc/rust/safelog/struct.Sensitive.html
[`base64ct`]: https://crates.io/crates/base64ct
[`humantime`]: https://crates.io/crates/humantime
[`set_stream_prefs`]: https://tpo.pages.torproject.net/core/doc/rust/arti_client/struct.TorClient.html#method.set_stream_prefs
[`shellexpand`]: https://crates.io/crates/shellexpand
[`tor-cell`]: https://tpo.pages.torproject.net/core/doc/rust/tor_cell/index.html
[conditional dependency]: https://blog.rust-lang.org/2022/04/07/Rust-1.60.0.html#new-syntax-for-cargo-features
[proposal 304]: https://gitlab.torproject.org/tpo/core/torspec/-/blob/main/proposals/304-socks5-extending-hs-error-codes.txt
[proposal 342]: https://gitlab.torproject.org/tpo/core/torspec/-/blob/main/proposals/342-decouple-hs-interval.md
[tor#40688]: https://gitlab.torproject.org/tpo/core/tor/-/issues/40688





# Arti 1.1.0 — 30 November 2022

Arti 1.1.0 adds support for Tor's anti-censorship features: Bridges
(unlisted relays), and Pluggable Transports (external tools to hide what
protocol you're using).

Use of these features can make Arti more effective at gaining access
to Tor, in spite of censorship (or breakage) between you and the wider
public internet.

These features are still very new, so there are likely to be bugs, and
the user experience may not yet be optimal. (In particular, there are a
bunch of spurious warnings and error messages in the logs.) Nonetheless,
we believe that the quality of these features is good enough to be used.

### Breaking changes

- Arti now requires Rust 1.60 or later. This allows us to use a few new
  features, and to upgrade a few of our dependencies that had grown
  stale. See ["Minimum Supported Rust Version" in `README.md`] for more
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
  - A "reactor" task to monitor PT status and launch pluggable transports
    as needed. ([!901], [!903])

- Paths in the configuration can now be configured using
  `${PROGRAM_DIR}`, which means "the directory containing the current
  executable".  ([#586], [!760])
- Some objects can now be marked as "Redactable". A "Redactable" object
  is one that can be displayed in the logs with some of its contents
  suppressed. For example, whereas a full IP might be "192.0.2.7",
  and a completely removed IP would be logged as "`[scrubbed]`",
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

Thanks to everyone who has contributed to this release, including
Alexander Færøy, arnabanimesh, breezykermo, Dimitris Apostolou,
EliTheCoder, Emil Engler, Gabriel de Perthuis, Jim Newsome, Reylaba, and
Trinity Pointard.

Also, our deep thanks to [Zcash Community Grants] for funding the
development of Arti 1.1.0!

[!634]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/634
[!739]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/739
[!744]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/744
[!745]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/745
[!746]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/746
[!747]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/747
[!755]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/755
[!758]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/758
[!759]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/759
[!760]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/760
[!767]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/767
[!768]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/768
[!769]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/769
[!771]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/771
[!773]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/773
[!774]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/774
[!775]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/775
[!776]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/776
[!779]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/779
[!780]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/780
[!781]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/781
[!782]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/782
[!783]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/783
[!785]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/785
[!790]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/790
[!791]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/791
[!793]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/793
[!795]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/795
[!797]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/797
[!803]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/803
[!804]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/804
[!806]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/806
[!808]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/808
[!810]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/810
[!813]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/813
[!814]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/814
[!815]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/815
[!818]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/818
[!819]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/819
[!820]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/820
[!823]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/823
[!826]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/826
[!827]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/827
[!828]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/828
[!830]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/830
[!831]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/831
[!832]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/832
[!834]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/834
[!837]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/837
[!840]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/840
[!844]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/844
[!845]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/845
[!847]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/847
[!849]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/849
[!850]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/850
[!851]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/851
[!852]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/852
[!857]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/857
[!859]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/859
[!864]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/864
[!868]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/868
[!869]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/869
[!870]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/870
[!874]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/874
[!877]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/877
[!880]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/880
[!881]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/881
[!882]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/882
[!886]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/886
[!887]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/887
[!888]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/888
[!893]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/893
[!901]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/901
[!903]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/903
[#174]: https://gitlab.torproject.org/tpo/core/arti/-/issues/174
[#303]: https://gitlab.torproject.org/tpo/core/arti/-/issues/303
[#394]: https://gitlab.torproject.org/tpo/core/arti/-/issues/394
[#526]: https://gitlab.torproject.org/tpo/core/arti/-/issues/526
[#562]: https://gitlab.torproject.org/tpo/core/arti/-/issues/562
[#585]: https://gitlab.torproject.org/tpo/core/arti/-/issues/585
[#586]: https://gitlab.torproject.org/tpo/core/arti/-/issues/586
[#591]: https://gitlab.torproject.org/tpo/core/arti/-/issues/591
[#599]: https://gitlab.torproject.org/tpo/core/arti/-/issues/599
[#600]: https://gitlab.torproject.org/tpo/core/arti/-/issues/600
[#603]: https://gitlab.torproject.org/tpo/core/arti/-/issues/603
[#606]: https://gitlab.torproject.org/tpo/core/arti/-/issues/606
[#613]: https://gitlab.torproject.org/tpo/core/arti/-/issues/613
[#614]: https://gitlab.torproject.org/tpo/core/arti/-/issues/614
[#616]: https://gitlab.torproject.org/tpo/core/arti/-/issues/616
[#621]: https://gitlab.torproject.org/tpo/core/arti/-/issues/621
[#640]: https://gitlab.torproject.org/tpo/core/arti/-/issues/640
[#647]: https://gitlab.torproject.org/tpo/core/arti/-/issues/647
[#648]: https://gitlab.torproject.org/tpo/core/arti/-/issues/648
[#650]: https://gitlab.torproject.org/tpo/core/arti/-/issues/650
[#659]: https://gitlab.torproject.org/tpo/core/arti/-/issues/659
[19fdf196d89e670f]: https://gitlab.torproject.org/tpo/core/arti/-/commit/19fdf196d89e670f3487caa756a8194076f9226b
[95a95076a77f4447]: https://gitlab.torproject.org/tpo/core/arti/-/commit/95a95076a77f44478736464a6249bee345713ecc
[b08073c2d43d7be5]: https://gitlab.torproject.org/tpo/core/arti/-/commit/b08073c2d43d7be58db62d6c6a51721dc6f797f1
[c41305d1100d9685]: https://gitlab.torproject.org/tpo/core/arti/-/commit/c41305d1100d96854707eef988380e01ad2a5782
[dc55272602cbc9ff]: https://gitlab.torproject.org/tpo/core/arti/-/commit/dc55272602cbc9ff3b792a9e4231533d4a12e007
["Minimum supported Rust Version" in `README.md`]: https://gitlab.torproject.org/tpo/core/arti/-/blob/main/README.md#minimum-supported-rust-version
[Shadow]: https://shadow.github.io
[Zcash Community Grants]: https://zcashcommunitygrants.org/
[`clap` v3]: https://docs.rs/clap/3.2.23/clap/index.html
[`hostname-validator`]: https://crates.io/crates/hostname-validator




# Arti 1.0.1 — 3 October  2022

Arti 1.0.1 fixes a few bugs in our previous releases.

This is a fairly small release: Members of our team have spent a lot of
September at a company meeting, on our vacations, and/or recovering from
COVID-19. The feature work we have managed to get done is
largely behind-the-scenes preparation for our anti-censorship release,
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
  to implement Tor's anti-censorship features.  These APIs are unstable,
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

In our next releases, we will focus on adding anti-censorship
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
- We've gone through and converted _every_ <code>XX&#88;X</code> comment in our code (which
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
