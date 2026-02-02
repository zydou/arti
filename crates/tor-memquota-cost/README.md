# tor-memquota-cost

Cost-tracking trait for use with [`tor-memquota`].

This is a separate crate so that crates that want to add a memory cost to a
struct can do so without depending on the full [`tor-memquota`].

## Compile-time features

 * `memquota` -- Actually enable memory quota tracking.
   Without this feature, all the actual functionality is stubbed out.
   This provides a convenient way of conditionally enabling memory tracking.

 * `full` -- Enable all features above.

License: MIT OR Apache-2.0

[`tor-memquota`]: https://docs.rs/tor-memquota/latest/tor_memquota/
