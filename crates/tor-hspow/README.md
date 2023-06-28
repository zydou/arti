# tor-hspow

Tor supports optional proof-of-work client puzzles, for mitigating denial of
service attacks on onion services. This crate implements the specific puzzle
algorithms we use, and infrastructure for solving puzzles asynchronously.

[Proposal 327] introduced our first algorithm variant, named `v1`.
It is based on the Equi-X asymmetric puzzle and an adjustable effort check
using a Blake2b hash of the proof. The underlying algorithm is provided by
the [`equix`] crate.

[Proposal 327]: https://gitlab.torproject.org/tpo/core/torspec/-/blob/main/proposals/327-pow-over-intro.txt

## EXPERIMENTAL DRAFT

Just here as a proof-of-concept and to test the algorithms.
None of the API here is final, the current status is that lower layers are
exposed unnecessarily and upper layers are unwritten.

For Tor client puzzle support in Arti. ([#889])

[#889]: https://gitlab.torproject.org/tpo/core/arti/-/issues/889


