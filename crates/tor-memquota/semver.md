BREAKING: `ConfigBuilder::max()` and `ConfigBuilder::low_water()` (which are effectively part of the
          public "arti-client" API) now take a `impl Into<ExplicitOrAuto<usize>>` instead of a
          `usize`. This should generally be backwards compatible, but may cause type inference
          errors.
