# oneshot-fused-workaround

Thin veneer over `futures::channel::oneshot` to fix use with `futures::select!`.
See [`futures-rs` ticket #2455](https://github.com/rust-lang/futures-rs/issues/2455).

License: MIT OR Apache-2.0
