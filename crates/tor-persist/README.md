# tor-persist

Persistent data storage for use with Tor.

This crate is part of
[Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
implement [Tor](https://www.torproject.org/) in Rust.

For now, users should construct storage objects directly with (for
example) [`FsStateMgr::from_path_and_mistrust()`], but use them primarily via the
interfaces of the [`StateMgr`] trait.

License: MIT OR Apache-2.0
