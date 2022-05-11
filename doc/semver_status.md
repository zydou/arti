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

## Since Arti 0.3.0

### arti-client

MODIFIED: Code to configure fs-mistrust.
BREAKING: TorConfig no longer implements TryInto<DirMgrConfig>

### fs-mistrust

MODIFIED: New APIs for CachedDir, Error.

### tor-dirmgr

BREAKING: Added new cache_trust element to DirMgrConfig.

### tor-netdoc

BREAKING: Routerstatus::nickname() now returns &str, not &String.

### tor-persist

+BREAKING: Replaced from_path with from_path_and_mistrust

### tor-rtcompat

BREAKING: Runtime now requires the Debug trait to be implemented.

### arti-config

BREAKING: default_config_file moved to arti_client, and changed to return Result
GREAKING: ConfigurationSource::new_empty renamed from ::new
BREAKING: ConfigurationSource methods take Into<String> and Into<PathBuf> now
