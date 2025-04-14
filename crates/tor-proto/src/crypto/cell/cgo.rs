//! Implementation for Counter Galois Onion (CGO) relay cell encryption
//!
//! CGO is an improved approach for encrypting relay cells, with better support
//! for tagging resistance, better forward secrecy, and other improvements.
//! It is described in [a paper][CGO] by Degabriele, Melloni, Münch, and Stam,
//! and specified in [proposal 359].
//!
//! [CGO]: https://eprint.iacr.org/2025/583
//! [proposal 359]: https://spec.torproject.org/proposals/359-cgo-redux.html

// TODO:
//  - polyval dependency.
//  - tweakable block cipher
//  - PRF
//  - UIV+
//  - KDF code
//  - Relay operations
//    - Forward
//    - Backward
//    - Originating
//  - Client operations
//    - Originating
//    - Receiving
