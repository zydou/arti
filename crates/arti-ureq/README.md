# arti-ureq

A library to use Arti in combination with the [`ureq`](https://github.com/algesten/ureq) HTTP client.

## Usage

Use `cargo add arti-ureq` to add the dependency to your project.

```rust,no_run
// Include the library.
use arti_ureq;

// Retrieve a `ureq::Agent`.
let ureq_agent = arti_ureq::default_agent().expect("Failed to create agent.");

// Make the request.
let request = ureq_agent
    .get("https://check.torproject.org/api/ip")
    .call()
    .expect("Failed to make request.");
```

`arti-ureq` uses version 3.0 of `ureq`. Use `arti_ureq::ureq` to access the `ureq` crate.

View more examples in the [examples](https://gitlab.torproject.org/tpo/core/arti/-/tree/main/examples/ureq-examples) directory.

## Feature flags

- `tokio` (default) -- Build with [Tokio](https://docs.rs/tokio/latest/tokio) support.
- `async-std` -- Build with [async-std](https://docs.rs/async-std/latest/async_std) support.
- `rustls` (default) -- Build with [Rustls](https://docs.rs/rustls/latest/rustls) support.
- `native-tls` -- Build with [native-tls](https://docs.rs/native-tls/latest/native_tls) support.    

License: MIT OR Apache-2.0
