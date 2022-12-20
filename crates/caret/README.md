# caret

Integers with some named values.

## Crikey! Another Rust Enum Tool?

Suppose you have an integer type with some named values.  For
example, you might be implementing a protocol where "command" can
be any 8-bit value, but where only a small number of commands are
recognized.

In that case, you can use the [`caret_int`] macro to define a
wrapper around `u8` so named values are displayed with their
preferred format, but you can still represent all the other values
of the field:

```rust
use caret::caret_int;
caret_int!{
    struct Command(u8) {
       Get = 0,
       Put = 1,
       Swap = 2,
    }
}

let c1: Command = 2.into();
let c2: Command = 100.into();

assert_eq!(c1.to_string().as_str(), "Swap");
assert_eq!(c2.to_string().as_str(), "100");

assert_eq!(c1, Command::Swap);
```

This crate is developed as part of
[Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
implement [Tor](https://www.torproject.org/) in Rust.
Many other crates in Arti depend on it, but it should be of general
use.

License: MIT OR Apache-2.0
