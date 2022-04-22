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

### configuration (affecting arti, arti-client, tor-dirmgr, tor-guardmgr

BREAKING: Configuration of fallback directories overhauled; now uses FalllbadkDirBuilder more.

### arti

BREAKING: Replaced LoggingConfigBuilder::file (taking Vec) with LoggingConfigBuilder::files
BREAKING: LoggingConfigBuilder::build() throws ConfigBuildError, not a bespoke error
MODIFIED: LoggingConfigBuilder is now Deserialize

### tor-basic-util

MODIFIED: Added `reset()` method to RetrySchedule.

### tor-chanmgr

BREAKING: Added members to `Error::Proto`
BREAKING: Added `ChanProvenance` to `ChanMgr::get_or_launch`.

### tor-circmgr

MODIFIED: Added a new variant in tor_circmgr::Error.
BREAKING: Made internal scheduled entry points non-public.

### tor-guardmgr

MODIFIED: New functions to get estimated clock skew.
MODIFIED: New functions to report observed clock skew.

### tor-proto

MODIFIED: New accessors in tor_proto::Channel.
BREAKING: Removed clock skew from Error::HandshakeCertsExpired.
MODIFIED: New functions on ClockSkew.

### tor-rtmock

MODIFIED: Added add_blackhole to MockNetwork.

### tor-socksproto

BREAKING: Removed some unused accessors.
