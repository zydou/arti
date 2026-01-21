//! An abstract circuit reactor, to be used by clients and relays.
//!
//! This module exposes the new [multi-reactor circuit subsystem].
//!
//! Note: this is currently only used by relays,
//! but we plan to eventually rewrite client circuit implementation
//! to use these new reactor types as well.
//!
//! [multi-reactor circuit subsystem]: https://gitlab.torproject.org/tpo/core/arti/-/blob/main/doc/dev/notes/relay-conflux.md
