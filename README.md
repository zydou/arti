[![Crates.io](https://img.shields.io/crates/v/arti.svg)](https://crates.io/crates/arti)

# Arti: reimplementing Tor in Rust

Arti is a project to produce an embeddable, production-quality implementation
of the [Tor](https://www.torproject.org/) anonymity protocols in the
[Rust](https://www.rust-lang.org/) programming language.

## Links:

This is the README for the Arti project as a whole.
If you want to find more practical information
you might want to check out these links:

   * [The Arti website](https://arti.torproject.org)

   * [The README for the `arti` binary crate](./crates/arti/README.md),
     which includes instructions for how to run Arti with Tor Browser.

   * [Official source repository](https://gitlab.torproject.org/tpo/core/arti)

   * [API-level developer documentation](https://tpo.pages.torproject.net/core/doc/rust/arti_client/index.html)

   * [Guidelines for contributors](./CONTRIBUTING.md)

   * [Architectural overview](./doc/dev/Architecture.md)

   * [Compatibility guide](./doc/Compatibility.md)

   * [Frequently Asked Questions](./doc/FAQ.md)

## Why rewrite Tor in Rust?

Rust is *more secure than C*.  Despite our efforts, it's all too simple to
mess up when using a language that does not enforce memory safety.  We
estimate that at least half of our tracked security vulnerabilities would
have been impossible in Rust, and many of the others would have been very
unlikely.

Rust enables *faster development than C*. Because of Rust's expressiveness
and strong guarantees, we've found that we can be far more efficient and
confident writing code in Rust.  We hope that in the long run this will
improve the pace of our software development.

Arti is *more flexible than our C tor implementation*.  Unlike our C `tor`,
which was designed as SOCKS proxy originally, and whose integration features
were later "bolted on", Arti is designed from the ground up to work as a
modular, embeddable library that other applications can use.

Arti is *cleaner than our C tor implementation*.  Although we've tried to
develop C tor well, we've learned a lot since we started it back in 2002.
There are lots of places in the current C codebase where complicated
"spaghetti" relationships between different pieces of code make our software
needlessly hard to understand and improve.


## <a name="status"></a>Current status

Arti can connect to the Tor network, bootstrap a
view of the Tor directory, and make anonymized connections over the network.
Now that Arti has reached version 1.0.0, we believe it is suitable for
actual use to anonymize connections.

There are a number of areas (especially at the lower layers) where APIs
(especially internal APIs) are not stable,
and we are likely to change them.
Right now that includes the command line interface to the `arti` program.

And of course it's still very new so there are likely to be bugs.

## Building and using Arti

Arti can act as a SOCKS proxy that uses the Tor network.

We expect to be providing official binaries soon.
But, for now, you need to obtain a
[Rust](https://www.rust-lang.org/) development environment,
and build it yourself.

To try it out, compile and run the `arti` binary using the below. It will open a
SOCKS proxy on port 9150.

    $ cargo run -p arti --locked --release -- proxy

You can build a binary (but not run it) with:

    $ cargo build -p arti --locked --release

The result can be found as `target/release/arti`.

⚠ **Safety Note**: if you are using the default build options,
the compiler will include filesystem path information in the
binary that it generates.  If your path is sensitive (for example,
because it includes your username), you will want to take steps
to prevent this.  See [`doc/safer-build.md`](doc/safer-build.md)
for more information.

⚠ **Safety Note**: when building `arti` for "production use",
you should always use the `-p arti` option as documented above.
While a `cargo build` without specifying the `-p arti` will still build `arti`,
it may also enable unintended features (including experimental features)
due to cargo feature unification.

If you run into any trouble building the program, please have a
look at [the troubleshooting guide](doc/TROUBLESHOOTING.md).

### Custom compile-time options

Arti has a number of configurable
[Cargo features](https://doc.rust-lang.org/cargo/reference/features.html)
that, among other things, can affect which asynchronous runtime to use.

See in the
[Arti crate-level docs](https://tpo.pages.torproject.net/core/doc/rust/arti/index.html#compile-time-features)
for details.

## Using Arti as a library

The `arti` command line utility is built on top of the 
[`arti_client`](https://tpo.pages.torproject.net/core/doc/rust/arti_client/index.html)
library (and its dependencies).

That library's API will allow you to
make connections over the Tor network,
and obtain streams/sinks usable from async Rust.

We make fairly frequent semver bumps to the Arti library API,
and to our lower-level crates.
However, in practice, we don't often make disruptive changes
that aren't easy to sort out in a dependency.
When using Arti as a library, you should be prepared to make regular updates,
bumping your versions requirement, not just `cargo update`.
`cargo upgrade` can help with this.

See [our version update and API compatibility policy](doc/Semver.md)
for more details.

## Minimum supported Rust Version

Our current Minimum Supported Rust Version (MSRV) is 1.86.

When increasing this MSRV, we won't require any Rust version released in the
last six months. (That is, we'll only require Rust versions released at least
six months ago.)

We will not increase MSRV on PATCH releases, though our dependencies might.

We won't increase MSRV just because we can: we'll only do so when we have a
reason. (We don't guarantee that you'll agree with our reasoning; only that
it will exist.)

## Roadmap

Thanks to a generous grant from
[Zcash Open Major Grants (ZOMG)](https://zcashomg.org/), we're able to devote
some significant time to Arti in the years 2021-2022.  Here is our _rough_
set of plans for what we hope to deliver when.

The goal times below are complete imagination, based on broad assumptions about
developer availability.  Please don't take them too seriously until we can
get our project manager to sign off on them.

 * Arti 0.0.1: Minimal Secure Client (Goal: end of October 2021??)
   * Target audience: **developers**
   * [x] Guard support
   * [x] Stream Isolation
   * [x] High test coverage
   * [x] Draft APIs for basic usage
   * [x] Code cleanups
   * [and more...](https://gitlab.torproject.org/tpo/core/arti/-/milestones/6)

 * Arti 0.1.0: Okay for experimental embedding (Goal: Mid March, 2022??)
   * Target audience: **beta testers**
   * [x] Performance: preemptive circuit construction
   * [x] Performance: circuit build timeout inference
   * [x] API support for embedding
   * [x] API support for status reporting
   * [x] Correct timeout behavior
   * [and more...](https://gitlab.torproject.org/tpo/core/arti/-/milestones/7)

 * Arti 1.0.0: Initial stable release (Goal: Mid September, 2022??)
   * Target audience: **initial users**
   * [x] Stable API (mostly)
   * [ ] Stable CLI
   * [x] Stable configuration format
   * [x] Automatic detection and response of more kinds of network problems
   * [x] At least as secure as C Tor
   * [x] Client performance similar to C Tor
   * [x] More performance work
   * [and more...](https://gitlab.torproject.org/tpo/core/arti/-/milestones/8)

 * Arti 1.1.0: Anti-censorship features (Goal: End of October, 2022?)
   * Target audience: **censored users**
   * [x] Bridges
   * [x] Pluggable transports
   * [and more...?](https://gitlab.torproject.org/tpo/core/arti/-/milestones/10)

 * Arti ~1.2.0: [Onion service]() support (Goal: End of 2023)
   * [x] [Client support](https://gitlab.torproject.org/tpo/core/arti/-/issues/?label_name%5B%5D=Onion%20Services%3A%20Basic%20Client) (for connecting to onion services)
   * [x] [Service support](https://gitlab.torproject.org/tpo/core/arti/-/issues/?sort=created_date&state=opened&label_name%5B%5D=Onion%20Services%3A%20Basic%20Service&first_page_size=100) (for running onion services)
   * [ ] [Full security features](https://gitlab.torproject.org/tpo/core/arti/-/issues/?label_name%5B%5D=Onion%20Services%3A%20Improved%20Security) (for production-ready quality)

 * Arti ~2.0.0: Feature parity with C tor as a client (Goal: Mid 2024)
   * [some possible details...](https://gitlab.torproject.org/tpo/core/arti/-/milestones/9#tab-issues)

 * Arti ?.?.?: Relay support

## <a name="reporting-bugs"></a> How can I report bugs?

When you find bugs, please report them
[on our bugtracker](https://gitlab.torproject.org/tpo/core/arti/). If you
don't already have an account there, you can either
[request an account](https://gitlab.onionize.space/) or
[report a bug anonymously](https://anonticket.torproject.org/).

## How can I help out?

Have a look at our [contributor guidelines](./CONTRIBUTING.md) for a few ideas
on how to get started.

## License

This code is licensed under either of

 * [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](https://opensource.org/licenses/MIT)

at your option.

**However**, some optional parts are licensed under the GNU Lesser General
Public License, version 3.0,
as indicated in the `Cargo.toml`.
This applies to `crates/equix` and `crates/hashx`.
See [`LGPL-and-rust.md`](./doc/LGPL-and-rust.md)
for discussion of issues concerning redistributing binaries
containing these crates.


## Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.

>(The above notice, or something like it, seems to be pretty standard in Rust
>projects, so I'm using it here too.  This instance of it is copied from
>the RustCrypto project's README.md file.)
