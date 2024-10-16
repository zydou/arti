# tor-memquota

Memory use quota, tracking and reclamation, for use in Tor DoS resistance

## Compile-time features

 * `memquota` (default) -- Actually enable memory quota tracking.
   Without this feature, all the actual functionality is stubbed out.
   This provides a convenient way of conditionally enabling memory tracking.

 * `full` -- Enable all features above.

### Experimental and unstable features

Note that the APIs enabled by these features are NOT covered by
semantic versioning[^1] guarantees: we might break them or remove
them between patch versions.

 * `testing`: Additional APIs for testing,
   used in our whole-workspace tests.

 * `experimental`: Enable all the above experimental features.

[^1]: Remember, semantic versioning is what makes various `cargo`
features work reliably. To be explicit: if you want `cargo update`
to _only_ make safe changes, then you cannot enable these
features.

License: MIT OR Apache-2.0
