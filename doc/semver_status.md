# Semver tracking

This is a helpful file that we use for checking which crates will have
breaking or nonbreaking API changes in the next release of Arti.

For each crate, please write "BREAKING" if there is an API change that counts
as breaking in semver, and "MODIFIED" if there is a backward-compatible API
change.

You can change from MODIFIED to BREAKING, but never from BREAKING to
MODIFIED.

You don't need to list details; this isn't the changelog.

Don't document other changes in this file.

We can delete older sections here after we bump the releases.


## Since Arti 0.0.1

tor-client: MODIFIED
tor-dirclient: BREAKING
tor-dirmgr: BREAKING
tor-llcrypto: BREAKING
tor-netdoc: BREAKING
tor-persist: BREAKING if `testing` feature is enabled.
tor-proto: BREAKING
