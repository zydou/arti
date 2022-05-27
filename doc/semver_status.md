# Semver tracking

We no longer use this file for semver tracking.  Instead, we use one
`semver.md` file per crate.

When you make a change to a crate that affects source compatibility,
please append a paragraph to that crate's `semver.md`, creating it as
necessary.

Every line should begin with one of the following:
  * BREAKING
  * MODIFIED

A "BREAKING" change is one that may break other crates that depend on
this crate directly.

A "MODIFIED" change is one the introduces a new API, such that crates
using the new API will not work with older versions of the crate.

When we release a new version, we use these files to determine which
crates need major-version, minor-version, or patch-level version bumps.
We also use them to help write the "breaking changes" section of the
changelog. They aren't user-facing, so they don't go into much detail.

Here is an example `semver.md` file:

>```
>BREAKING: Removed the obsolete `detect_thylacine()` function.
>
>MODIFIED: New `Wombat::feed()` method.
>
>MODIFIED: `Numbat` now implements `Display`.
>
>BREAKING: The `Quokka` trait now inherits from Debug.
>```

# What is a breaking change?

We will add guidance to this section as we come up with it. For now, see
[SemVer compatibility] in the Cargo book.

[SemVer Compatibility]: https://doc.rust-lang.org/cargo/reference/semver.html

# DO NOT EDIT BELOW.

(We used to append here, so I've added an explicit note not to do that.)

