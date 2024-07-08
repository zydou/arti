# Sponsor-101 measurements: Heap usage, download size.

This describes the initial measurement strategy for certain Sponsor-101
metrics.  Namely, we are trying to find:

> 1. Amount of non-mapped memory allocated when used for example workloads.
> 2. The size of the client library for Tor and Arti.

There are lots of ways to measure each of these.  For now I'll aim for
reproducibility and simplicity, at the expense of having to make certain
simplifying assumptions.  As we refine our implementations, we should
also improve our measurements here to better reflect reality.

As we do so, we will ensure our methodology remains reproducible, so
that we can show how much of our changed size is an artifact of our
methodology, and how much of it is real improvements or regressions.

## Configuration files

Please make sure your `~/.arti-testing.toml` file contains the following:

```toml
[storage]

cache_dir = "${USER_HOME}/.arti_testing/cache"
state_dir = "${USER_HOME}/.arti_testing/state"
```

## Memory usage

We're looking specifically at non-mapped memory: That is, heap memory
that isn't backed by a file on "disk".  We're concerned about peak
memory demand, memory can be scarce on cheap devices.

There are many possible loads we could look at here. We will add more
loads in the future, but for now, we'll focus on two cases:

1. Bootstrapping a directory from scratch and making a connection to
   `www.torproject.org`.

2. Starting with a cached directory and making a connection to
   `www.torproject.org`.

These tests are better measures for the efficiency of our directory
storage implementation than they are for our data paths, but that is
reasonable for now: Directory size accounts for the largest portion of
client heap usage right now.

To run these tests, we clear our `${USER_HOME}/.arti-testing/cache` directory,
and run the following command _twice_.  (The first time will download the
directory, the second will use the cache.)

```
valgrind --tool=massif ./target/release/arti-testing connect \
  -c ~/.arti-testing.toml \
  --target www.torproject.org:80
```

The results for 20 July 2022 were:

```
Bootstrapping: 20.3 MiB
Cached: 14.7 MiB
```

The results for 30 September 2022 were (Arti: 0d985b0d):

```
Bootstrapping: 18.9 MiB
Cached: 14.4 MiB
```

The results for 25 October 2022 were (Arti: 547d476e0e):

```
Bootstrapping: 18.2 MiB
Cached: 13.6 MiB
```

The results for  25 January 2023 were (Arti: 3b2848f904):

```
Bootstrapping: 20.7 MiB
Cached: 14.0 MiB
```

The results for 11 April 2023 were (Arti: 2bcd89615):

```
Bootstrapping: 19.8 MiB
Cached: 13.8 MiB
```

The results for 6 July 2023 were (Arti: 1ae06399d03):

```
Bootstrapping: 19.5 MiB
Cached: 13.7 MiB
```

The results for 24 October 2023 were (Arti: 99d8b3a16c283ce6):

```
Bootstrapping: 26.3 MiB
Cached: 21.4 MiB
```

Results as of 18 December 2023 (Arti: 4577399b985f3)

```
Bootstrapping: 28.3 MiB
Cached: 22.0 MiB
```

The results for 30 April 2024 were (Arti: b30ca794cbfe):

```
Bootstrapping: 29.1 MiB
Cached: 23.3 MiB
```

The results for 30 June 2024 were (Arti: dba7b7206eb71):

```
Bootstrapping: 27.4 MiB
Cached: 21.5 MiB
```

To simulate (almost) the same process with C Tor, run Tor under `massif`
with a new data directory, then kill it with ctrl-C:

```
 rm -rf newdir
 valgrind --tool=massif src/app/tor --datadir newdir
 (Wait for bootstrap)
 <Ctrl-C>
```

The results for 20 July 2022 were:

```
Bootstrapping: 18.8 MiB
Cached: 21.9 MiB
```

The results for 30 September 2022 were (Tor: 18b5630a7c):

```
Bootstrapping: 18.5 MiB
Cached: 21.4 MiB
```

The results for 25 October 2022 were (Tor: 2033cc7b5e):

```
Bootstrapping: 18.4 MiB
Cached: 19.9 MiB
```

The results for 25 January 2023 were (Tor: 21109ba5d):

```
Bootstrapping: 18.5 MiB
Cached: 19.8 MiB
```

The results for 11 April 2023 were (Tor: 447775a5e):

```
Bootstrapping: 18.5 MiB
Cached: 19.6 MiB
```

The results for 6 July 2023 were (Tor: 05624b578152f3b):

```
Bootstrapping: 18.4 MiB
Cached: 19.4 MiB
```

The results for 24 October 2023 were (Tor: 2a1fc47d8683fa7):

```
Bootstrapping: 19.1 MiB
Cached: 19.9 MiB
```

The results for 18 December 2023 were (Tor: 0cccc7223c52512):

```
Bootstrapping: 21.2 MiB
Cached: 21.8 MiB
```

The results for 30 April 2024 were (Tor: 51ef4ce09438):

```
Bootstrapping: 23.2 MiB
Cached: 22.8 MiB
```

The results for 30 June 2024 were (Tor: 8bb8ac2d9aba72):

```
Bootstrapping: 22.1 MiB
Cached: 21.7 MiB
```

(This does not yet take into account making a request, but again, the
memory requirements there are negligible in comparison to loading the
directory.)

### Analysis

I'm fairly happy with these results: Arti has not been optimized very
heavily, whereas we've been trying to make Tor use less memory for years
and years.  Looking at the profiles, I see several places where I think
we have a good chance at making Arti use even less RAM.


## Library size

### Preliminaries

With C Tor, download size has been a barrier to mobile adoption, so
we're trying to keep the download size for Arti smaller.

There are some barriers to doing an apples-to-apples comparison with
these two programs at present:

1. Arti does not currently support being built as a shared library: only
   in a static form that gets linked into a binary.

2. Arti currently builds with LTO[^LTO] to a much higher degree than C
   Tor, giving it a compiler advantage that C Tor could easily adopt.

3. Arti and C Tor have different sets of dependencies that may or may
   not be installed on different platforms, and may or may not be
   _required_ on different platforms.


So we'll work under these assumptions and limitations:

1. We're primarily interested in compressed download size.  We'll use
   gzip for compression, since it delivers performance comparable to
   that used for mobile platform archive formats.

2. We don't intend to ship with full debugging symbols, but we do want
   to ship with enough debugging information for stack traces to work.
   We approximate this compromise with `strip --strip-debug`.

3. We'll compile for x86_64 (since that's what we're using for
   development), and assume that binaries compiled for or other CPUs
   (notably ARM64) will not be too different—or at least, that they will
   exhibit similar savings (or not).

4. We'll disable all optional features in C Tor that clients do not use.

5. We'll look at binary size for now, instead of library size. (This
   approach disadvantages Arti, since Tor has no code that is discarded
   when building as a library, and Arti has a bunch of code that is
   CLI-only.)

6. We'll link statically to as many dependencies as we can among those
   not present on Android, and choose smaller dependencies when there
   are alternatives.  (This approach simulates having to ship
   dependencies along with the main binary, to better approximate total
   download size.)

7. We'll use Clang as our C compiler (since it uses the same LLVM
   backend as the Rust compiler).

### Process with Arti

```
./maint/binary_size -p arti \
    --no-default-features \
    --features=tokio,rustls,static-sqlite
```

Note that we are linking statically with SQLite, and using RustTLS
instead of OpenSSL in order to save download size.


Result as of 20 July 2022:

```
   "arti.gz": 4076384 bytes
```

Results for 30 September 2022 were (Arti: 0d985b0d):

```
   "arti.gz": 3918795 bytes
```

Results as of 25 October 2022 (Arti: 547d476e0e):

```
   "arti.gz": 3937197 bytes
```

Results as of 25 January 2023 (Arti: 3b2848f904):

```
   "arti.gz": 3668559 bytes
```

Results as of 11 April 2023 (Arti: 2bcd89615):

```
   "arti.gz": 3747298 bytes
```

Results as of 6 July 2023 (Arti: 1ae06399d03):

```
   "arti.gz": 3723582 bytes
```

Results as of 24 October 2023 (Arti: 99d8b3a16c283ce6)

```
   "arti.gz": 6741218 bytes
```

Results as of 18 December 2023 (Arti: 4577399b985f3)

```
   "arti.gz": 3992937 bytes
```

Results as of 30 April 2024 (Arti: b30ca794cbfe)

```
   "arti.gz": 4049193 bytes
```

Results as of 30 June 2024 (Arti: dba7b7206eb71)

```
   "arti.gz": 4173380 bytes
```

### Process with C Tor


```
./configure \
   CC=clang \
   --enable-static-libevent --with-libevent-dir=${STATIC_LIBEVENT_DIR} \
   --enable-static-openssl --with-openssl-dir=${STATIC_OPENSSL_DIR} \
   --disable-module-relay \
   --disable-module-dirauth \
   --disable-systemd

make clean
make src/app/tor
strip --strip-debug src/app/tor
gzip -9 -c src/app/tor | wc -c
```

Note that this process includes Libevent and Openssl linked statically
with Tor: These aren't part of the download size on most Unix-like
operating systems, but they do have to be downloaded on Android,
Windows, and OSX.

Result (20 July 2022)

```
3646863 bytes
```

Results (30 September 2022) with Tor: 18b5630a7c:

```
3647161 bytes
```

Results (25 October 2022) with Tor: 2033cc7b5e:

```
3648355 bytes
```

Results (25 January 2023) with Tor: 21109ba5d:

```
3647837 bytes
```

Results (11 April 2023) with Tor: 447775a5e:

```
3646434 bytes
```

The results for 6 July 2023 were (Tor: 05624b578152f3b):

```
3504633 bytes
```

The results of 24 October 2023 were (Tor: 2a1fc47d8683fa7):

```
3976434 bytes
```

The results of 18 December 2023 were (Tor: 0cccc7223c52512):

```
3984528 bytes
```

The results for 30 April 2024 were (Tor: 51ef4ce09438):

```
4001484 bytes
```

The results for 30 June 2024 were (Tor: 8bb8ac2d9aba72):

```
4001228 bytes
```

[^LTO]: Link-time optimization: a technique where the compiler optimizes
    the whole program as a single unit, to take advantage of properties
    that cannot be found while compiling a single module.

### Analysis

The Arti download currently stands bigger than the Tor download.  But
for a number of caveats, see the initial list of assumptions above.

Note in particular Android is a worst-case scenario for download size,
since neither Arti nor Tor can use Android's built-in TLS
implementations, and so both need to include a TLS library.  (OpenSSL is
the best option with Tor; Rustls is the smallest with Arti.)  I expect
that it will be fairly easy to deliver an Arti download that's smaller
than Tor on Windows, iOS, or OSX, if we are not there already.

There are several avenues for trying to make Arti's download size
smaller in the future.  Most of them come down to identifying the
largest libraries used by Arti, and replacing them with smaller
alternatives.

Some small part of the current download size of Arti is an artifact of
comparing Arti's binary size to Tor's binary size, and not looking at
library sizes directly. I expect that once we are able to compare both
programs built as a library, we'll see a some modest savings there.

I think that as we continue development, we'll expect to see some
savings in Arti if as we find initial low-hanging fruit to eliminate,
and some regressions as we add more missing features.  I do not think we
will achieve a smaller download than C _on Android_ without major
engineering.

## Methodologies

We use the Valgrind tool, massif, to extract heap information over the
execution duration of the program. We use the `massif-visualizer` tool to
extract peak values from the massif results.

Since there is variance in these results that are outside of our control here,
such as difference between paths through the Tor network, it is important that
when running these tests that you run the experiments multiple times and take
the median value.
