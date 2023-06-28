# equix

`equix`: Rust reimplementation of tevador's [Equi-X], a client puzzle for Tor based on the Equihash and HashX algorithms

Check out [tevador's dev log] for more information. The Equihash layer is based on Equihash60,3 and the underlying hash function HashX is another new project built as a lightweight ASIC-resistant hash function in the spirit of RandomX.

This crate implements a compact Equihash solver with the same memory footprint as the original Equi-X implementation. HashX is delegated to the [`hashx`] crate.

[Equi-X]: https://gitlab.torproject.org/tpo/core/tor/-/tree/main/src/ext/equix
[tevador's dev log]: https://gitlab.torproject.org/tpo/core/tor/-/blob/main/src/ext/equix/devlog.md

This is for Tor client puzzle support in Arti. ([#889])

[#889]: https://gitlab.torproject.org/tpo/core/arti/-/issues/889
