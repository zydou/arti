# tor-error

Support for error handling in Tor and Arti

Primarily, this crate provides the [`ErrorKind`] enum,
and associated [`HasKind`] trait.

There is also some other miscellany, supporting error handling in
crates higher up the dependency stack.

## Features

`backtrace` -- Enable backtraces in internal errors.  (On by default.)

### Experimental and unstable features

Note that the APIs enabled by these features are NOT covered by
semantic versioning[^1] guarantees: we might break them or remove
them between patch versions.

* `experimental-api`: Add additional non-stable APIs to our public
  interfaces.

[^1]: Remember, semantic versioning is what makes various `cargo`
features work reliably. To be explicit: if you want `cargo update`
to _only_ make safe changes, then you cannot enable these
features.

License: MIT OR Apache-2.0
