# Live reloading the restricted discovery config

Given a hidden service restricted discovery config:
```toml
[onion_services."allium-cepa".restricted_discovery]
enabled = true

[onion_services."allium-cepa".restricted_discovery.static_keys]
alice = "descriptor:x25519:PU63REQUH4PP464E2Y7AVQ35HBB5DXDH5XEUVUNP3KCPNOXZGIBA"
bob = "descriptor:x25519:B5ZQGTPERMMUDA6VC63LHJUF5IHPOKJMUK26LY2XKSF7VG52AESQ"

[[onion_services."allium-cepa".restricted_discovery.key_dirs]]
path = "/var/lib/tor/hidden_service/authorized_clients"
```

there are multiple ways to update the list of authorized clients:

  * Case 0: toggling `enabled` on or off.
  * Case 1: updating the `static_keys` mapping by adding/removing a key:
  ```diff
   [onion_services."allium-cepa".restricted_discovery.static_keys]
   alice = "descriptor:x25519:PU63REQUH4PP464E2Y7AVQ35HBB5DXDH5XEUVUNP3KCPNOXZGIBA"
   bob = "descriptor:x25519:B5ZQGTPERMMUDA6VC63LHJUF5IHPOKJMUK26LY2XKSF7VG52AESQ"
  +carol = "descriptor:x25519:dz4q5xqlb4ldnbs72iarrml4ephk3du4i7o2cgiva5lwr6wkquja"

   [[onion_services."allium-cepa".restricted_discovery.key_dirs]]
   path = "/var/lib/tor/hidden_service/authorized_clients"
   ```

  * Case 2: updating the `key_dirs` list by adding/removing a key directory:
  ```diff
   [[onion_services."allium-cepa".restricted_discovery.key_dirs]]
   path = "/var/lib/tor/hidden_service/authorized_clients"
  +
  +[[onion_services."allium-cepa".restricted_discovery.key_dirs]]
  +path = "/home/foo/hidden_service/authorized_clients"
  ```

  * Case 3: updating the contents of one of the configured `key_dirs`, either by
    adding/removing a key file, or by modifying an existing one

In all three cases, the hidden service should be able to detect that a change
has happened, and respond by generating and publishing a new descriptor.

## Updating the `authorized_clients`

Currently, the `RunningOnionServices` contains an `Arc`'d `authorized_clients`
list, shared with the descriptor publisher. It would be better if we moved it
inside the publisher, as it's not really used anywhere else.

**Suggested resolution**:
  * move `authorized_clients` from `RunningOnionService` to `Publisher`
  * make `restricted_discovery: simply_update` (it's currently `unchangeable`)
  * make the publisher's `handle_svc_config_change` recompute the
    `authorized_clients` using `new_config.restricted_discovery.read_keys()`. We
    need to be careful here though: `handle_svc_config_change` receives the new
    svc config sent from `RunningOnionService::reconfigure`. But checking if the
    new config is different from the old one is no longer enough, we now also
    need to check if the contents of any of the `key_dirs` have changed. This is
    not something we can currently find out via the `reconfigure()` mechanism)

### Handling `static_keys` changes (case 1)

Case 1 is the simplest to handle, because any changes to `static_keys` will be
detected by the existing config watching mechanism

### Watching for changes within the configured `key_dirs` (cases 2 and 3)

This will involve adding a watcher for each `key_dirs` directory, and generating
and publishing a new descriptor on change. We most likely don't want to
republish the descriptor on *every* change though. Consider a hidden service
operator copying client keys to the key directory one by one while the service
is running: updating on *every* change would trigger a burst of descriptor
uploads (this is covered in the `When to republish?` section below).

The directories from `key_dirs` will need to be watched for changes similarly to
how we watch `ConfigurationSource::Dir`s. Additionally, if a directory is added
or removed, we will need to update the watch list.

Some of the existing directory watching logic can be reused. We have several
options wrt which parts we reuse and how we reuse them.

#### Option 1: Move `FileWatcher` to `tor-config`

One option would be to move `FileWatcher` from the `arti` crate to `tor-config`,
so it can be reused by `tor-hsservice` to watch the
`restricted_discovery.key_dirs` for changes. We will also need to decouple it
from `ConfigurationSources`, because `ConfigurationSources` is geared towards
TOML configuration.

This option is kludgey, because it will involve spawning an extra, ad-hoc
directory watcher thread from within `tor-hsservice` (the thread would probably
be spawned by the descriptor publisher, as that is the only part that cares
about the authorized clients list changing).

With this option, the publisher would
  * spawn a thread for watching for changes in the contents of the configured
    `key_dirs`
  * watch for changes to `static_keys` and `key_dirs` via
    `handle_svc_config_change` (which receives the new config via the usual
    `reconfigure()` mechanism)
     * if the `key_dirs` change, it will update its `FileWatcher` by calling
       `watch_dir`/`unwatch_dir` for each of the added/removed dirs

In other words, the publisher will watch for restricted discovery config changes
from two different places (the directory watcher thread and
`handle_svc_config_change`), which is quite fiddly and error-prone.

**Missing features**:
  1. `FileWatcher::unwatch_{file, dir}` functionality

OTOH, because the client authorization keys from `key_dirs` are, in a sense, an
extension of the service's configuration, the `key_dirs` could conceivably be
viewed as a special kind of `ConfigurationSource`s, so perhaps they *should* be
watched by the main configuration watching logic. However, `ConfigurationSource`
was designed for watching and loading *TOML files*, so it will require some
modification if we want to repurpose it for watching `key_dirs`. This is `Option
2` described below.

> Note: the "client authorization" terminology is deprecated.
> "Client authorizatio" is now known as "restricted discovery".

#### Option 2: Make each dir in `key_dirs` a `ConfigurationSource`

For this we'll need to extend the configuration watching mechanism to support
watching for changes to files that *aren't* TOML configs. This way, we can let
the existing config watching mechanism from `reload_cfg` watch for changes to
`restricted_discovery.key_dirs` (so unlike `Option #1`, this option wouldn't
involve spawning any additional watcher threads)

**Missing features**:
  1. the ability to watch `ConfigurationSource::Dir`s for changes to non-TOML
     files
  2. the ability to add or remove `ConfigurationSource::Dir`s on-the-fly, based
     on the contents of the config (in this case, based on the value of
     `restricted_discovery.key_dirs`)
  3. `ConfiurationSource`s with custom mistrust settings: currently, a
     `ConfiurationSources` applies the same `mistrust` to of its all
     `ConfiurationSource`, whereas in `restricted_discovery.key_dirs`, each
     directory has its own mistrust settings
  4. somehow extend the `reconfigure()` machinery to support this (it currently
     cannot convey this sort of change, as it doesn't affect the value of the
     `TOML` config).

For 1:

We will modify the `ConfigurationSource::Dir` variant to support watching for
files that don't necessarily end in `.toml`:
```diff
diff --git a/crates/tor-config/src/sources.rs b/crates/tor-config/src/sources.rs
index 32a2a7a42..618fc7b26 100644
--- a/crates/tor-config/src/sources.rs
+++ b/crates/tor-config/src/sources.rs
@@ -71,7 +71,12 @@ pub enum ConfigurationSource {
     File(PathBuf),

     /// A directory
-    Dir(PathBuf),
+    Dir {
+        /// The path
+        path: PathBuf,
+        /// The extension of the files to watch
+        extension: &'static str,
+    }

     /// A verbatim TOML file
     Verbatim(Arc<String>),
```

When scanning for files in `ConfigurationSources::scan`, we will look for the
specified `extension`:
```diff
             use ConfigurationSource as CS;
             match &source {
-                CS::Dir(dirname) => {
+                CS::Dir { path: dirname, extension } => {
                     let dir = match fs::read_dir(dirname) {
                         Ok(y) => y,
                         Err(e) => {
@@ -307,7 +312,7 @@ impl ConfigurationSources {
                         let leaf = found.file_name();
                         let leaf: &Path = leaf.as_ref();
                         match leaf.extension() {
-                            Some(e) if e == "toml" => {}
+                            Some(e) if e == *extension => {}
                             _ => continue,
                         }
                         entries.push(found.path());
```

`FoundConfigFiles` will need to be adapted to support (or, rather, ignore)
non-TOML files.

Each `FoundConfigFile` will have a `file_kind: ConfigFileKind`, where
`ConfigFileKind` will be
```rust
pub enum ConfigFileKind {
    Toml,
    Other { extension: &'static str },
}
```

`FoundConfigFiles::load` will skip over any non-toml files, and
`FoundConfigFiles::add_sources` will ignore the `FoundConfigFiles` that have
`file_kind != ConfigFileKind::Toml`.

For 2:

If the `key_dirs` list changes, we will need to somehow update the
`ConfigurationSources` list. We could, for example, let the reconfigurable
modules somehow return instructions about which `ConfigurationSources` to keep.

**Suggested resolution**:
  * do not implement any of this (this option doesn't seem worth the added
    complexity)
  * in the future, if we have other use cases for this, consider adding a more
    general-purpose directory watching mechanism

## When to republish?

  * if `restricted_discovery.enabled` is `false`, we will generate a new
    descriptor and republish immediately
  * if `restricted_discovery.enabled` is set to `true`, or if the authorized
    clients have changed, we will only republish the descriptor after
    `CLIENT_CHANGE_REPUBLISH_DEBOUNCE_INTERVAL` seconds of inactivity

Initially `CLIENT_CHANGE_REPUBLISH_DEBOUNCE_INTERVAL` will be set to 60s.
(Perhaps we will eventually want to make it configurable?)

### Should we also rotate IPTs?

If an authorized client is removed, we might also want to also rotate the IPTs
as part of this process, to prevent any no-longer-authorized clients from
reaching the service.

If so, we will need the IPT manager to watch for changes in the
`restricted_discovery` config, and to react by rotating the IPTs.

Alternatively, we could keep the existing IPTs and make it very clear that
removing one of the client keys does not necessarily revoke the access of that
client.

**Suggested resolution**:
  * do not rotate the IPTs
  * make sure the restricted discovery documentation is clear about it not being
    a substitute for real client authorization mechanism
