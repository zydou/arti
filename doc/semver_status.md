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

### arti

ADDED: ARTI_EXAMPLE_CONFIG introduced

### arti-client

MODIFIED: Code to configure fs-mistrust.
BREAKING: TorConfig no longer implements TryInto<DirMgrConfig>

### arti-config

BREAKING: default_config_file moved to arti_client, and changed to return Result
GREAKING: ConfigurationSource::new_empty renamed from ::new
BREAKING: ConfigurationSource methods take Into<String> and Into<PathBuf> now
BREAKING: ARTI_DEFAULTS removed, in favour of ARTI_EXAMPLE_CONFIG in the arti crate
BREAKING: ConfigurationSource is now in the tor-config crate.
DEPRECATION: arti-config is to be abolished.  Currently it is merely an empty tombstone.

### fs-mistrust

MODIFIED: New APIs for CachedDir, Error.

### tor-dirclient

MODIFIED: new max_skew api

### tor-dirmgr

BREAKING: Added new cache_trust element to DirMgrConfig.
BREAKING: Delete Error::BadNetworkConfig

### tor-netdoc

BREAKING: Routerstatus::nickname() now returns &str, not &String.
MODIFIED: Lifetime has a valid_at() method.

### tor-persist

+BREAKING: Replaced from_path with from_path_and_mistrust

### tor-proto

MODIFIED: channel() method on ClientCirc.

### tor-rtcompat

BREAKING: Runtime now requires the Debug trait to be implemented.
