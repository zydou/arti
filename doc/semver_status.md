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

### All crates

BREAKING: Requiring Rust 1.56, edition 2021.

### configuration (affecting arti, arti-client, tor-dirmgr, tor-guardmgr

BREAKING: Configuration of fallback directories overhauled; now uses FalllbadkDirBuilder more.
BREAKING: Configuration of directory authoorities overhauled; now uses AuthorityListBuilder.
BREAKING: Configuration of preemptive ports overhauled; now uses PredictedPortsListBuilder..
BREAKING: Configuration of download schedules overhauled; now uses builders
BREAKING: download schedules: "num_retries" configuration field renamed to (accurate) "attempts"
BREAKING: download schedules: Setting zero values for attempts or parallelism is now rejected

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

### tor-dirmgr

BREAKING: AuthorityBuilder::build now throws ConfigBuildError, not a custom error type
BREAKING: DownloadSchedule::new() replaced with DownloadScheduleBuilder
BREAKING: DownloadScheduleConfigBuilder now has accessors for the schedules, not setters
BREAKING: DirMgrCfg: schedule and network fields rename (`_config` removed)

### tor-guardmgr

BREAKING: FallbackDirBuilder::orport() removed, and orports() now gives &mut SocketAddrListBuilder
MODIFIED: New functions to get estimated clock skew.
MODIFIED: New functions to report observed clock skew.
BREAKING: Guard restriction builder interface changed to new list builder API.

### tor-llcrypto

BREAKING: AES implementations now implement cipher 0.4 traits.

### tor-proto

MODIFIED: New accessors in tor_proto::Channel.
BREAKING: Removed clock skew from Error::HandshakeCertsExpired.
MODIFIED: New functions on ClockSkew.

### tor-rtmock

MODIFIED: Added add_blackhole to MockNetwork.

### tor-socksproto

BREAKING: Removed some unused accessors.

### tor-config

MODIFIED: New facilities for lists in builders (list_builder module, etc.)
MODIFIED: New macro macro_first_nonempty
