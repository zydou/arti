# Arti profiling methodology

This document describes basic tools for profiling Arti's CPU and memory
usage.  Not all of these tools will make sense for every situation, and
we may want to switch them in the future.  The main reason for recording
them here is so that we don't have to re-learn how to use them the next
time we need to do a big round of profiling tests.

## Building for profiling

When you're testing with `cargo build --locked --release`, use
`CARGO_PROFILE_RELEASE_DEBUG=true` to include extra debugging
information for better output.

## Profiling tools

Here I'll talk about a few tools for measuring CPU usage, memory usage,
and the like.  For now, I'll assume you're on a reasonably modern Linux
environment: if you aren't, you'll have to do some stuff differently.

I'll talk about particular scenarios to profile in the next major
section.

### cargo flamegraph

[cargo-flamegraph](https://github.com/flamegraph-rs/flamegraph) is a
pretty quick-and-easy event profiling visualization tool.  It produces
nice SVG flamegraphs in a variety of pretty colors.  As with all
flamegraphs, these are better for visualization than detailed
drill-down.  On Linux, `cargo-flamegraph` uses
[`perf`](https://perf.wiki.kernel.org/index.php/Main_Page) under the
hood.

To install, make sure you have a working version of `perf`
installed.  Then run `cargo install flamegraph`.

Basic usage:

```
flamegraph {command}
```

Output: `flamegraph.svg`

Also consider using the `--reverse` flag, to reverse the stack and see the
lowest-level functions that get the most use.

### tcmalloc and pprof

This can generate usage graphs showing who allocated your memory when.
(It can get a bit confusing in Rust.)

```
HEAPPROFILE=/tmp/heap.hprof \
 LD_PRELOAD=/usr/lib64/libtcmalloc_and_profiler.so \
 {command}
```

```
pprof --pdf --inuse_space {binary} /tmp/heap.hprof > heap.pdf
```

You might need a longer timeout with this one; it's nontrivial.

### valgrind --massif

This tool can also generate usage graphs like pprof above.

`valgrind --tool=massif {command}`

It will generate a file called `massif.out.PID`.  You can view it with the
`ms_print` tool (included with valgrind) or the `massif-visualizer` tool
(installed separately, highly recommended.)

## Some commands to profile

These should generally run against a chutney network whenever possible;
the `ARTI_CONF` envvar should be set to
e.g. `$(pwd)/chutney/net/nodes/arti.toml`.

### Bootstrapping a directory

`arti-testing bootstrap -c ${ARTI_CONF}`

(This test bootstraps only.  It might make sense to do this one on the
real network, since its data is more complex.  You need to start with an
empty set of state files for this to test bootstrapping instead of
loading.)

### Large number of circuits, focusing on circuit construction

Bootstrap outside of benchmarking, then run:

`arti-bench -u 1 -d 1 -s 100 -C 20 -p 1 -c ${ARTI_CONF}`

(100 samples, 20 circuits per sample, 1 stream per circuit, only 1 byte
to upload or download.)

Note that this test won't necessarily tell you so much about _path
construction_, since path construction on a large real network with
different weights, policies, and families is more complex than on a
chutney network.

(just times out with chutney; directory changes too fast, I think.)


### Running offline

Also

* Bootstrapping failure conditional
* Going offline
* Primary guards go down after bootstrap

(See `HowToBreak.md`)

### Data transfer

`arti-bench -s 20 -C 1 -p 1 {...}`

(No parallelism, 10 MB up and down.)

### Data transfer with many circuits

`arti-bench -s 1 -C 64 -p 1 -c ${ARTI_CONF}`

(Circuit parallelism only, 10 mb up and down)

### Data transfer with many streams

`arti-bench -s 1 -C 1 -p 64 -c ${ARTI_CONF}`

(Stream parallelism only, 10 mb up and down)

### Huge number of simultaneous connection attempts

`arti-bench -s 1 -C 16 -p 16 -c ${ARTI_CONF}`

(stream and circuit parallelism)

# TODO

arti-bench:
  - take a target address as a string.
  - Allow -p 0 to build a circuit only?
  - Some way to build a path only?

Extract chutney boilerplate.

arti-testing:
  - ability to make connections aggressively simultaneous

