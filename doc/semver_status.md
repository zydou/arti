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

## Since Arti 0.2.0

### tor-circmgr

MODIFIED: Added a new variant in tor_circmgr::Error.

### tor-rtmock

MODIFIED: Added add_blackhole to MockNetwork.

### tor-socksproto

BREAKING: Removed some unused accessors.
