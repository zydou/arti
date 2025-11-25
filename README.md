# `saturating-time`

A trait for limits and saturations on types inside [`std::time`].

* **Easy**: `saturating-time` only adds a single trait, [`SaturatingTime`] that
  is implemented for various types from the standard library.
* **Future-Proof**: In the case that [`SaturatingTime::saturating_add()`] and
  [`SaturatingTime::saturating_sub()`] become a part of the standard library,
  developers would only have to remove the `use saturating_time::SaturatingTime`
  line from their code.[^1] [^2].
* **Portable**: The algorithm for determining the limits is portable across
  operating systems: enjoy this crate from Windows, Darwin, and Linux, across
  the BSD systems, up to exotic ones such as Hermit OS and Redox.
* **Secure**: This crate does not make any use of `unsafe` Rust code.

## Overview

`saturating-time` is a very minimal crate that only exposes a minimal trait:
[`SaturatingTime`].

The trait itself offers the following methods:
* [`SaturatingTime::max_value()`] – Returns the maximum value for this type.
* [`SaturatingTime::min_value()`] – Returns the minimum value for this type.
* [`SaturatingTime::saturating_add()`] – Saturating addition for this type.
* [`SaturatingTime::saturating_sub()`] – Saturating subtraction for this type.
* [`SaturatingTime::saturating_duration_since()`] - Saturating time deltas for this type.

This trait is sealed, meaning applications may not implement it themselves.
However, this crate implements this trait for two structures:
* [`std::time::Instant`]
* [`std::time::SystemTime`]

## Example

Add the following to your `Cargo.toml`:
```toml
[dependencies]
saturating-time = "0.3.0"
```

Now, you can use `saturating-time` in your code:
```rust
use std::time::{Duration, SystemTime};
use saturating_time::SaturatingTime;

// Get the maximum and minimum.
let max = SystemTime::max_value();
let min = SystemTime::min_value();

assert_eq!(max.saturating_add(Duration::new(1, 0)), max);
assert_eq!(min.saturating_sub(Duration::new(1, 0)), min);
assert!(max.saturating_duration_since(SystemTime::UNIX_EPOCH) >= Duration::ZERO);
```

## Standardization Efforts

The eventual goal is to get this functionality into the Rust standard library.

### `SystemTime`

#### `SystemTime::MIN` and `SystemTime::MAX`

There is an ACP that has been approved in November 2025.[^3]
Please follow the tracking issue[^4] for more information about this in
particular.

#### `SystemTime::saturating_add()` and `SystemTime::saturating_sub()`

None yet.

### `Instant`

None yet.

[^1]: This is an effort the maintainers are actively working upon.
[^2]: Assuming the name, signature, and behavior does not change.
[^3]: <https://github.com/rust-lang/libs-team/issues/692>
[^4]: <https://github.com/rust-lang/rust/issues/149067>

## License and Copyright

This crate is licensed under `MIT OR Apache-2.0`.
See the respective `LICENSE-*` files in the repository for more information.
