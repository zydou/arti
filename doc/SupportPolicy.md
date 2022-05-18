# Support policy for Arti (draft)

We intend, in the long term, that Arti should work and provide privacy
on all major desktop and mobile operating systems.  In actuality,
however, our current resources and infrastructure only allow us to run
Arti's tests on a subset of the environments that we want to support.

Please read this document as a rough statement of intent, not as a formal
promise. For now, we'll deviate from these policies whenever it we think it
makes sense, and we'll amend from time to time without notice.


## Operating systems

Our top priorities are the following:

  * Android
  * Linux
  * OSX
  * Windows
  * iOS

We only support modern versions of these operating systems.  (If the
upstream providers of the operating system no longer support it, neither
do we.)

We currently have automated builds and tests on Linux only.  On OSX and
Windows, we have automated builds, but the tests are not (yet) run.  In the
long run, we aim to have automated builds and testing for all of our priority
platforms.

For other Free operating systems, we're happy to fix bugs as they're
encountered, and we're happy to take good clean patches.

We don't support other proprietary operating systems.

## Dependencies

Our _minimal_ dependencies, as listed in our `Cargo.toml` files, are
expected to work.  We have automated tools to make sure that Arti builds
and passes tests with these minimal dependencies on Linux.

We do not guarantee that these minimal dependencies are free of security
issues: If you use Arti as a library, you need to use tools like `cargo
audit` to regularly check for reported security advisories with the
crates that you use.

Our _production_ dependencies, as listed in our `Cargo.lock` file and as
used to build binaries, are what we actually recommend.  We will
actively work ourselves to keep them up-to-date and secure.


## Rust versions

We define our "minimum supported rust version" (MSRV) as the oldest
version of Rust that we expect Arti to build with.

We have automated tools to make sure that Arti builds and passes tests
with our MSRV and our minimal (`Cargo.toml`) dependencies.  Production
dependencies (`Cargo.lock`) are not tested with our MSRV, and may or may
not work.

Our current MSRV is 1.56.  We may update our MSRV to a newer version in
the future: when we do, we'll only require a version released at least
six months in the past, and we won't update our requirements for no
reason.


## Supported versions of Arti

For now (pre 1.0.0), only the most recent release of Arti is supported.
We won't consider patches for older releases.

We will revisit and change this policy in the future.

## Security Advisories

We will classify security issues as Research, Critical, High, Medium and
Low-severity, as per [tor's security policy].

For now (pre 1.0.0) we will issue advisories for High and Critical
security vulnerabilities only.



[tor's security policy]: https://gitlab.torproject.org/tpo/core/team/-/wikis/NetworkTeam/SecurityPolicy
