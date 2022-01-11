[![Crates.io](https://img.shields.io/crates/v/arti.svg)](https://crates.io/crates/arti)

# Arti: reimplementing Tor in Rust

Arti is a project to produce an embeddable, production-quality implementation
of the [Tor](https://www.torproject.org/) anonymity protocols in the
[Rust](https://www.rust-lang.org/) programming language.

Arti is **not ready for production use**; [see below](#status) for more information.

## Links:

   * [Official source repository](https://gitlab.torproject.org/tpo/core/arti)

   * [API-level developer documentation](https://tpo.pages.torproject.net/core/doc/rust/arti_client/index.html)

   * [Guidelines for contributors](./CONTRIBUTING.md)

   * [Architectural overview](./doc/Architecture.md)

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

Arti is a work-in-progress.  It can connect to the Tor network, bootstrap a
view of the Tor directory, and make anonymized connections over the network.

We're not _aware_ of any critical security features missing in Arti; but
however, since Arti is comparatively new software, you should probably be
cautious about using it in production.

There are no guarantees about API stability yet: if you write code
that uses Arti, you should expect it to break with future versions.  If you
write an a configuration file for Arti, it might stop working in the future.

## Trying it out today

Arti can act as a SOCKS proxy that uses the Tor network.
It knows how to download directory
information and how to load it from cache, but it doesn't try to
download more than one directory per run.

To try it out, run the demo program in `arti` as follows.  It will open a
SOCKS proxy on port 9150.

    % cargo run --release -- proxy

Again, do not use this program yet if you seriously need anonymity, privacy,
security, or stability.

## Minimum supported Rust Version

Arti should always build with the most recent _stable_ Rust release, and
_may_ build with one or two older Rust releases.  Eventually, we may
declare some long-term Minimum Supported Rust Version (MSRV), but while
Arti is still in its early stages, you'll need to stay up-to-date.

As of this writing (24 August 2021), Arti works with Rust 1.53 and later.

## Helping out

Have a look at our [contributor guidelines](./CONTRIBUTING.md).

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
   * [ ] API support for status reporting
   * [x] Correct timeout behavior
   * [and more...](https://gitlab.torproject.org/tpo/core/arti/-/milestones/7)

 * Arti 1.0.0: Initial stable release (Goal: Mid September, 2022??)
   * Target audience: **initial users**
   * [ ] Security audit
   * [ ] Stable API
   * [ ] Stable CLI
   * [ ] Stable configuration format
   * [ ] Automatic detection and response of more kinds of network problems
   * [ ] More performance work
   * [and more...](https://gitlab.torproject.org/tpo/core/arti/-/milestones/8)

 * Arti 1.1.0: Anti-censorship features (Goal: End of October, 2022?)
   * Target audience: **censored users**
   * [ ] Bridges
   * [ ] Pluggable transports
   * [and more...?](https://gitlab.torproject.org/tpo/core/arti/-/milestones/10)

 * Arti 1.2.0: Onion service support (not funded, timeframe TBD)

 * Arti 2.0.0: Feature parity with C tor as a client (not funded, timeframe TBD)

 * Arti ?.?.?: Relay support

## How can I help out?

See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for a few ideas for how to get
started.

## License

This code is licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.

>(The above notice, or something like it, seems to be pretty standard in Rust
>projects, so I'm using it here too.  This instance of it is copied from
>the RustCrypto project's README.md file.)
