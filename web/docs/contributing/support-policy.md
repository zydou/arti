---
title: Support Policy
---

# Support policy

We intend, in the long term, that Arti should work and provide privacy on all major desktop and mobile operating systems. In actuality, however, our current resources and infrastructure only allow us to run Arti's tests on a subset of the environments that we want to support.

Please read this document as a rough statement of intent, not as a formal promise. For now, we'll deviate from these policies whenever it we think it makes sense, and we'll amend from time to time without notice.

## Elements of support

For this document, we define the following support tiers.

If a configuration is **unsupported**:

  * We do not typically accept patches related to the configuration.
  * We do not issue security advisories related to the configuration.
  * We close tickets related to the configuration as wont-fix.

If a configuration is **community-supported**:

  * We accept clean patches for improved features on the configuration.
  * We accept clean patches for bugfixes on the configuration.
  * At our discretion, we work on fixing bugs that affect the
    configuration.

Additionally, if configuration is **maintained**:

  * We commit not to knowingly make releases that break the configuration.
  * If we learn that the configuration is broken, we prioritize fixing it.
  * We write and announce security advisories if we learn about security issues in the configuration.


Additionally, if configuration is a  **target**:

  * It is a higher priority for us than other **maintained** configurations.
  * We'd like to make it a **tested** configuration, if we have the resources.  We intend to add more testing to it until it can become **tested**.

Additionally, if a configuration is **tested**:

  * We have automated systems to make sure that the configuration builds and runs tests correctly.
  * We have one or more team members who "dogfood" the configuration, using it ourselves to get rapid notifications about usability problems.

(Note that no broad configuration can be fully **tested** in all of its permutations.  For example, our automated tests can only be run on a limited set of the number of Linux distributions and versions, when in fact there are vast numbers of possible Linux installations whose variations might affect our behavior.)

## Operating systems

Our top priorities are the following operating systems:

  * Android (**target**)
  * Linux (**target**, **tested**)
  * OSX (**target**)
  * Windows (**target**)
  * iOS (**target**)

We only support modern versions of these operating systems. If the upstream providers of the operating system no longer provides security patches for it, it is usually **unsupported**. Some old versions may be **maintained** or **community-supported**, depending on their age and the difficulty of working with them.

We currently have automated tests on Linux only.  On OSX and Windows, we have automated builds, but the tests are not (yet) run.  In the long run, we aim to have automated builds and testing for all of these platforms.

All other modern Free operating systems are **community-supported**: we're happy to fix bugs as they're encountered, and we're happy to take good clean patches. Some may become **maintained** in the future, depending on the level of interest, the size of the userbase, and resources available.

Other proprietary operating systems are **unsupported**.

## CPU Architectures

Only X86-64 is currently **tested**.

32-bit X86, and 64-bit ARM are **target**.

Modern-enough 32-bit ARM is **maintained**.

All other CPUs are **community-supported** or **unsupported**.

## Dependencies

Our _minimal_ dependencies, as listed in our [`Cargo.toml`](https://gitlab.torproject.org/tpo/core/arti/-/blob/main/Cargo.toml) files, are expected to work.  We have automated tools to make sure that Arti builds and passes tests with these minimal dependencies on Linux.

We do not guarantee that these minimal dependencies are free of security issues: If you use Arti as a library, you need to use tools like `cargo audit` to regularly check for reported security advisories with the crates that you use.

Our _production_ dependencies, as listed in our [`Cargo.lock`](https://gitlab.torproject.org/tpo/core/arti/-/blob/main/Cargo.lock) file and as used to build binaries, are what we actually recommend.  We will actively work ourselves to keep them up-to-date and secure.

Dependency versions older than those listed in our [`Cargo.toml`](https://gitlab.torproject.org/tpo/core/arti/-/blob/main/Cargo.toml) files are **unsupported**.

## Rust versions

We define our "minimum supported rust version" (MSRV) as the oldest version of Rust that we expect Arti to build with.

We have automated tools to make sure that Arti builds and passes tests with our MSRV and our minimal (`Cargo.toml`) dependencies. Production dependencies (`Cargo.lock`) are not tested with our MSRV, and may or may not work.

Our [current MSRV and MSRV policy](https://gitlab.torproject.org/tpo/core/arti/#minimum-supported-rust-version) are listed in our top-level README.
Rust versions older than our MSRV are **unsupported**.

## Supported versions of Arti

For now (as of December 2023), only the most recent version of Arti is supported at all.

In more detail:

 * The only versions that get any automated testing are the latest version from the git `main` branch, and other branches that are considered for merge to it.
 * We don't accept patches that aren't written to apply to `main`.
 * If we have to make any urgent bugfix-only releases, we will apply those fixes only to the most recently released version of Arti.

We will revisit and change this policy in the future.

## API compatibility

Although we aim to provide a forward-compatible API for some of our high-level crates (notably `arti-client`) in the future, we aren't yet at a point where we can do that. Between now and Arti 1.0.0, users should expect that each Arti release will possibly break API compatibility.

## Security Advisories

We will classify security issues as Research, Critical, High, Medium and Low-severity, as per [tor's security policy](https://gitlab.torproject.org/tpo/core/team/-/wikis/NetworkTeam/SecurityPolicy).

For now (as of December 2023), we will issue advisories for High and Critical security vulnerabilities only.
Also we will not typically issue advisories for older Arti releases: we assume that all developers are upgrading regularly.
