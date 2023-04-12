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

## What is a breaking change?

We will add guidance to this section as we come up with it. For now, see
[SemVer compatibility] in the Cargo book.

[SemVer Compatibility]: https://doc.rust-lang.org/cargo/reference/semver.html

### When types from lower-level crates appear in the APIs of higher-level crates

If a type (concrete type or trait) from a lower-level crate
is returned (or accepted)
by an API of a higher-level crate,
then a breaking change to that lower-level crate is a breaking change
for the higher-level crate, too.

This includes any case where a higher-layer type
implements a public trait from a lower-layer;
even if the type is not itself re-exported by the higher-layer crate.

#### Reasoning, and worked example:

Suppose `tor_error::ErrorKind` gets a breaking change,
and we bump the major[1] for `tor_error` but not for `arti_client`.
Obviously our new `arti_client` uses the new `tor_error`.

A downstream might use both `tor-error` and `arti-client`.
If they do this in the usual way,
a `cargo update` will get them the new `arti_client` but old `tor_error`.
Now their program has *two* instances of `tor_error`:
one whose `ErrorKind` is implemented by `arti_client::Error`,
and one that the downstream application code sees.
The effect is that the downstream application
can no longer call `.has_kind()` on an `arti_client::Error`
because they don't have the *right* `HasKind` method in scope.

Note that this does not depend on the nature of the breaking change,
nor on the re-export of any names.
It only depends on the exposure of the type and its trait implementations.

(The ["semver trick"](https://github.com/dtolnay/semver-trick)
can sometimes be used to help multiple different versions
of the same crate share global state, or perhaps, traits etc.)

[1] "Major" here includes the 2nd component in a 0.x version.
