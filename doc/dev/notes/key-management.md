# Key management backend

> This document uses deprecated terminology: "client authorization" is
> now known as "restricted discovery".

## Motivation
Arti will need to be able to manage various types of keys, including:
   * HS client authorization keys (`KS_hsd_desc_enc`, `KS_hsc_intro_auth`)
   * HS service keys (`KS_hs_id`, `KS_hs_desc_sign`)
   * relay keys
   * dirauth keys
   * ...

This document describes a possible design for a key manager that can read, add,
or remove keys from persistent storage. It is based on some ideas proposed by
@Diziet.

See also: [#728]

## Usage example

```rust
let client_spec = HsClientSpecifier::from_str("alice")?;

let intro_auth_key_spec: HsClientSecretKeySpecifier =
    (client_spec, hs_id, HsClientKeyRole::IntroAuth).into();

// Get KP_hsc_intro_auth
// TODO #798, TODO HS: We should not use "unescorted" ed25519 secrets.
let sk: Option<ed25519::SecretKey> = keymgr.get::<ed25519::SecretKey>(&intro_auth_key_spec)?;

// Alternatively, instead of returning a type-erased value, KeyStore::get could return a `Key`
// (TODO hs: come up with a better name), `Key` being an enum over all supported key types.
// `Key` could then have a `Key::as` convenience function that returns the underlying key (or
// an error if none of the variants have the requested type):
// let sk: Option<ed25519::SecretKey> = keymgr.get(&key_spec)?.as::<ed25519::SecretKey>().unwrap();
```

## Key stores

The key manager is an interface to one or more key stores.

Supported key stores:

* C Tor key store: an on-disk store that is backwards-compatible with C Tor (new
  keys are stored in the format used by C Tor, and any existing keys are
  expected to be in this format too).
* Arti key store: an on-disk store that stores keys in OpenSSH key
  format.

In the future we plan to also support HSM-based key stores.

## Use cases

### Hidden service with on-disk keys

The user makes a minimal configuration:
they specify the nickname of the hidden service in the Arti configuration,
and where to forward http(s) requests.

The default Arti keystore is instantiated, and is initially empty.

All keys including `K_hs_id` are automatically generated as needed.

`K_hs_id` is stored on disk in the default location
within the Arti keystore.
`K_hs_blind_id` are calculated as needed and aren't stored.
`K_hs_desc_sign` is generated and certified as needed;
it need not be stored
(so service restarts might involve a new `K_hs_desc_sign`).

### Hidden service with on-disk keys, migration from C Tor

The user specifies, for the service: its nickname,
and the C Tor `HiddenServiceDirectory`.

When Arti starts up, a C Tor compatibility key store is created
(for that specific service, so one per HS if there are several).

The `private_key` file is `K_hs_id`.
Other keys (`K_hs_blind_id`, `K_hs_desc_sign`, etc.)
are created dynamically,
and not stored.
(These do not have a C Tor compatibility path.)

Additionally, other Arti-specific C Tor compatibility code
reads other information from the `HiddenServiceDirectory`.
Notably, it checks the `hostname` file,
and reads the `client_keys` directory.
(In the initial Arti HS release,
perhaps Arti doesn't know how to handle C Tor `client_keys`
and instead refuses to run on the grounds that it can't
enforce the authentication.)

### Relay with `K_relayid` in hardware (HSM)

Suppose an HSM with the following properties:

 * Limited number of keyslots, identified by number.
 * Requires user interaction (passphrase, touch permission) for key use.

User configures or specifies:

 * The HSM, giving it a keystore name
   (there might be several distinct keystores with the same hardware driver,
   referring to distinct hardware tokens)
   and details needed to find it
 * That this Arti is supposed to be a relay.
 * Some linkage that allows the `K_relayid_*` to be found in the HSM.
   This must link:
     * the HSM keystore nickname
     * that this is for the relay keys
     * the slots within the HSM (HSM-specific value)
       for the `K_relayid_rsa` and `K_relayid_ed`.

Perhaps the linkage is done by an entry in the HSM's config section,
linking the `ArtiPath`s for the keys to to the HSM keyslot numbers;
or perhaps it is done in the relay config section,
and specifies, for both the RSA and ED identities,
the HSM keystore nickname and
the keystore-specific location information (in this case, the keyslot).

A separate tool provided by Arti generates the subsidiary keys
`K_relaysign_*` etc., for a specified time into the future,
using the `K_relayid_*` via the HSM keystore.
This tool manages the interaction between the user and the HSM
(eg touch or passphrase).

The main Arti relay process picks up those subsidiary keys
automatically and uses them.
It does not need to (and cannot) use the main identity key.

### Ephemeral hidden service

Some application that embeds Arti wishes to create an ephemeral hidden service.

It chooses a nickname which is used only for logging,
and makes the appropriate API calls to `TorClient`.

Arti generates a `K_hs_id` and all subsidiary keys automatically.
The keys are not stored anywhere.
(Probably, the HS code knows that this is ephemeral and doesn't call the storage APIs.
But maybe there is a dummy keystore that is always empty and which never stores anything.)

### Hidden service with offline identity key

There are two hosts: the online host runs the service, but has no access to `K_hs_id`.
The offline host has `K_hs_id`.

The user configures, on both hosts, the HS nickname.

On the offline host the user never runs the main Arti daemon.
Instead, they run a special hidden service offline key management tool.
This key management tool works with *two* on-disk keystores:
the private one (which exists only on the offline host),
and the shared one (which exists on both).
The private keystore contains `K_hs_id`
(and the key is generated there if there isn't one already).
The shared keystore contains the subsidiary keys.

The offline tool generates a specified number of
`K_hs_desc_sign` for future time periods,
and certifies them with the appropriate `K_hs_blind_id`.
(The `K_hs_blind_id` are never stored.)
The `K_hs_desc_sign` are stored in the shared keystore,
each with its corresponding `descriptor-signing-key-cert`.

The offline tool generates a copy of `KP_hs_id`
and stores it in the shared keystore.
(`KP_hs_id` is sort-of a secret, and sort-of a certificate.
Technical note:
the protocol in rend-spec-v3 is quite close to allowing operation
of a hidden service whose online component *doesn't know*
its own `.onion` address.
But it is not quite there.)

The whole shared keystore is copied
from the offline to the online host.

On the online host,
Arti uses the provided keys and certificates.

If the online Arti ends up running off the end of
the pre-generated keys/certs,
it knows that it shouldn't generate a new `K_hs_id`
(even though it thinks it needs to,
since it finds it needs to sign an absent `K_hs_desc_sign`)
because the `KP_hs_id` is present.

The user can also configure, in the online Arti,
the `.onion` address for the service.
This will also prevent Arti from ever generating a `K_hs_id`,
since it would have to somehow generate the indented identity.
(If provided, it is checked.)

## Proposed configuration changes

We introduce a new `[keys]` section for configuring the key stores. The
`[keys.permissions]` section specifies the permissions all top-level key store
directories are expected to have. It serves a similar purpose to
`[storage.permissions]`.

Initially, it will only be possible to configure two disk-backed key stores: the
Arti key store via the `[keys.arti_store]` section, and the C Tor key store via
the `[keys.ctor_store]` section. Future versions will be able to support the
configuration of arbitrary key store implementations.

The order of the key store sections is important, because keys are looked up in
each of the configured key stores, in the order they are specified in the
config. For example, if the Arti key store comes before the C Tor key store in
the config, when prompted to retrieve a key, the key manager will search
for the key in the Arti key store before checking the C Tor one:

```toml
[keys.arti_store]
...

[keys.ctor_store]
...
```

Note that both key stores are optional. It is possible to run Arti without
configuring a key store (for example, when running Arti as a client).

TODO hs: pick reasonable default values for the various top-level key store
directories (`root_dir`, `client_dir`, `key_dir`).

### Arti key store configuration

```toml
# Key store options
[keys]

# Describe the filesystem permissions to enforce.
[keys.permissions]
# If set to true, we ignore all filesystem permissions.
#dangerously_trust_everyone = false

# What user (if any) is trusted to own files and directories?  ":current" means
# to trust the current user.
#trust_user = ":current"

# What group (if any) is trusted to have read/write access to files and
# directories?  ":selfnamed" means to trust the group with the same name as the
# current user, if that user is a member.
#trust_group = ":username"

# If set, gives a path prefix that will always be trusted.  For example, if this
# option is set to "/home/", and we are checking "/home/username/.cache", then
# we always accept the permissions on "/" and "/home", but we check the
# permissions on "/home/username" and "/home/username/.cache".
#
# (This is not the default.)
#
#     ignore_prefix = "/home/"
#ignore_prefix = ""

# The Arti key store.
[keys.arti_store]
# The root of the key store. All keys are stored somewhere in the `root_dir`
# hierarchy
root_dir = ""
```

### C Tor key store configuration

The client and relay keys are stored in a different part of the config than the
onion service keys: the client/relay key directories are read from the
`[keys.ctor_store]` section, whereas the onion service ones are read from the
`[onion_service.hs_service_dirs]` of each `[[onion_service]]` section (note
there can be multiple `[[onion_service]]` sections, one for each hidden service
configured). As a result, the C Tor key store is not rooted at a specific
directory (unlike the Arti key store). Instead, it is configured with:
  * (for each onion service configured) a `hs_service_dir`, for onion service keys
  * a `client_dir`, for onion service client authorization keys.
  * a `key_dir`, for relay and directory authority keys

The exact structure of the `[[onion_service]]` config is not yet
specified, see [#699].

A downside of this approach is that there is no `CTorKeyStoreConfig` to speak
of: the `CTorKeyStore` is created from various bits of information taken from
different parts of the Arti config (`CTorKeyStore::new(client_dir, key_dir,
hs_service_dirs)`).

```toml
# The C Tor key store.
[keys.ctor_store]
# The client authorization key directory (if running Arti as a client).
#
# This corresponds to C Tor's ClientOnionAuthDir option.
client_dir = ""
# The key directory.
#
# This corresponds to C Tor's KeyDirectory option.
key_dir = ""

# Hidden service options
[[onion_service]]
# This corresponds to C Tor's HiddenServiceDir option.
hs_service_dir = "/home/bob/hs1"
# The maximum number of streams per rendezvous circuit.
#
# This corresponds to C Tor's HiddenServiceMaxStreams.
max_streams = 0
# TODO arti#699: figure out what the rest of the options are
...

# Hidden service options
[[onion_service]]
# This corresponds to C Tor's HiddenServiceDir option.
hs_service_dir = "/home/bob/hs2"
# The maximum number of streams per rendezvous circuit.
#
# This corresponds to C Tor's HiddenServiceMaxStreams.
max_streams = 9000
# TODO arti#699: figure out what the rest of the options are
...
 ```

## Key specifiers

We introduce the concept of a "key specifier" (specified for each supported key
type via the `KeySpecifier` trait). A "key specifier" uniquely identifies an
instance of a type of key. From an implementation standpoint, `KeySpecifier`
implementers must specify:
* `arti_path`: the location of the key in the Arti key store. This also serves
  as a unique identifier for a particular instance of a key.
* `ctor_path`: the location of the key in the C Tor key store (optional).

For example, an Arti key store might have the following structure (note that
each path within the `keys.arti_store.root_dir` directory, minus the extension,
is the `arti_path` of a particular key):
```
<keys.arti_store.root_dir>
├── client
│   ├── alice                               # HS client specifier "alice"
│   │   ├── foo.onion
│   │   │   ├── hsc_desc_enc.arti_priv      # arti_path = "client/alice/foo.onion/hsc_desc_enc"
│   │   │   │                               # (HS client Alice's x25519 hsc_desc_enc keypair for decrypting the HS
│   │   │   │                               # descriptors of foo.onion")
│   │   │   └── hsc_intro_auth.arti_priv    # arti_path = "client/alice/foo.onion/hsc_intro_auth"
│   │   │                                   # (HS client Alice's ed25519 hsc_intro_auth keypair for computing
│   │   │                                   # signatures to prove to foo.onion she is authorized")
│   │   │                                   # Note: this is not implemented in C Tor
│   │   └── bar.onion
│   │       ├── hsc_desc_enc.arti_priv      # arti_path = "client/alice/foo.onion/hsc_desc_enc"
│   │       │                               # (HS client Alice's x25519 hsc_desc_enc keypair for decrypting the HS
│   │       │                               # descriptors of bar.onion")
│   │       └── hsc_intro_auth.arti_priv    # arti_path = "client/alice/bar.onion/hsc_intro_auth"
│   │                                       # (HS client Alice's ed25519 hsc_intro_auth keypair for computing
│   │                                       # signatures to prove to bar.onion she is authorized")
│   └── bob                                 # HS client specifier "bob"
│       └── foo.onion
│           ├── hsc_desc_enc.arti_priv      # arti_path = "client/bob/foo.onion/hsc_desc_enc"
│           │                               # (HS client Bob's x25519 hsc_desc_enc keypair for decrypting the HS
│           │                               # descriptors of foo.onion")
│           └── hsc_intro_auth.arti_priv    # arti_path = "client/bob/foo.onion/hsc_intro_auth"
│                                           # (HS client Bob's ed25519 hsc_intro_auth keypair for computing
│                                           # signatures to prove to foo.onion he is authorized")
│                                           # Note: this is not implemented in C Tor
├── hs
│   └── baz.onion                           # Hidden service baz.onion
│       ├── authorized_clients              # The clients authorized to access baz.onion
│       │   └── dan
│       │        └── hsc_desc_enc.arti_pub  # arti_path = "hs/baz.onion/authorized_clients/dan/hsc_desc_enc"
│       │                                   # (The public part of HS client Dan's x25519 hsc_desc_enc keypair for
│       │                                   # decrypting baz.onions descriptors)
│       │
│       │
│       │  
│       ├── hs_id.arti_priv                 # arti_path = "hs/baz.onion/hs_id" (baz.onion's identity key)
│       └── hs_blind_id.arti_priv           # arti_path = "hs/baz.onion/hs_blind_id" (baz.onion's blinded identity key)
│
├── relay
│   └── Carol                     # Relay Carol
│        └── ...
...
```

### The `KeySpecifier` trait

```rust
/// The path of a key in the Arti key store,
/// relative to the root of the store.
/// This path does not contain double-dot (..) elements.
///
/// NOTE: There is a 1:1 mapping between a value that implements
/// `KeySpecifier` and its corresponding `ArtiPath`.
/// A `KeySpecifier` can be converted to an `ArtiPath`,
/// but the reverse conversion is not supported.
//
// TODO hs: restrict the character set and syntax for values of this type
// (it should not be possible to construct an ArtiPath out of a String that
// uses disallowed chars, or one that is in the wrong format (TBD exactly what
// this format is supposed to look like)
pub struct ArtiPath(PathBuf);

/// The path of a key in the C Tor key store.
///
/// To construct the path of the key on disk, the `CTorPath` is appended to the
/// `hs_service_dir`/`client_dir`/`key_dir` (depending on the role of the
/// requested key) followed by the extension.
///
/// This path does not contain double-dot (..) elements.
pub struct CTorPath(PathBuf);

/// The "specifier" of a key.
///
/// `KeySpecifier::arti_path()` uniquely identifies an instance of a key.
pub trait KeySpecifier {
    /// The location of the key in the Arti key store.
    ///
    /// This also acts as a unique identifier for a specific key instance.
    fn arti_path(&self) -> ArtiPath;

    /// The file extension for a key of this type in an Arti key store.
    ///
    /// The Arti key store will ignore any files that don't have a recognized extension.
    fn arti_extension(&self) -> &'static str;

    /// The location of the key in the C Tor key store (if supported).
    fn ctor_path(&self) -> Option<CTorPath>;

    /// The file extension for a key of this type in a C Tor key store.
    ///
    /// The C Tor key store will ignore any files that don't have a recognized extension.
    fn ctor_extension(&self) -> &'static str;

    /// The type of user (client, service, relay, etc.) that uses this key.
    fn user_kind(&self) -> UserKind;
}

/// The type of user (client, service, relay, etc.) that uses a key.
#[non_exhaustive]
pub enum UserKind {
    Client,
    Service(HsId),
    Relay,
    DirAuth,
    ...
}

/// An identifier for an HS client.
#[derive(AsRef, Into, ...)]
struct HsClientSpecifier(String);

impl FromStr for HsClientSpecifier { /* check syntax rules */ }

/// The role of a HS client key.
enum HsClientKeyRole {
    /// A key for deriving keys for decrypting HS descriptors (KP_hsc_desc_enc).
    DescEnc,
    /// A key for computing INTRODUCE1 signatures (KP_hsc_intro_auth).
    IntroAuth,
}

struct HsClientSecretKeySpecifier {
    /// The client associated with this key.
    client_spec: HsClientSpecifier,
    /// The hidden service this authorization key is for.
    hs_id: HsId,
    /// The role of the key.
    role: HsClientKeyRole,
}

impl KeySpecifier for HsClientSecretKeySpecifier {
    fn arti_path(&self) -> ArtiPath {
        ArtiPath(
            Path::new("client")
                .join(self.client_spec.to_string())
                .join(self.hs_id.to_string())
                .join(self.role.to_string()),
        )
    }

    fn arti_extension(&self) -> &'static str {
        // We use nonstandard extensions to prevent keys from being used in
        // unexpected ways (e.g. if the user renames a key from
        // KP_hsc_intro_auth.arti_priv to KP_hsc_intro_auth.arti_priv.old, the
        // arti key store should disregard the backup file).
        "arti_priv"
    }

    fn ctor_path(&self) -> Option<CTorPath> {
        Some(CTorPath(
            Path::new("client").join(self.client_spec.to_string()),
        ))
    }

    fn ctor_extension(&self) -> &'static str {
        "auth_private"
    }
}

```

## Proposed key manager API

```rust
/// A key that can be stored in, or retrieved from, a `KeyStore.`
pub trait EncodableKey {
    /// The underlying key type.
    fn key_type() -> KeyType
    where
        Self: Sized;
}

// Implement `EncodableKey` for all the key types we wish to support.
impl EncodableKey for ed25519::SecretKey {
    fn key_type() -> KeyType {
        KeyType::Ed25519Private
    }
}
...

/// The key manager.
#[derive(Default)]
struct KeyMgr {
    /// The underlying persistent stores.
    key_store: Vec<Box<dyn KeyStore>>,
}

impl KeyMgr {
    /// Read a key from the key store, attempting to deserialize it as `K`.
    pub fn get<K: Any + EncodableKey>(&self, key_spec: &dyn KeySpecifier) -> Result<Option<K>> {
        // Check if the requested key specifier exists in any of the key stores:
        for store in &self.key_store {
            let key = store.get(key_spec, K::key_type())?;

            if key.is_some() {
                // Found it! Now try to downcast it to the right type (the
                // downcast should _not_ fail, because K::key_type() tells the
                // store to return a key of type `K` constructed from the key
                // material read from disk)
                return key
                    .map(|k| k.downcast::<K>().map(|k| *k).map_err(|e| /* bug */ ...))
                    .transpose();
            }
        }

        // Not found
        Ok(None)
    }

    /// Insert the specified key into the appropriate key store.
    ///
    /// If the key bundle (key family?) of this `key` exists in one of the key stores, the key is
    /// inserted there. Otherwise, the key is inserted into the first key store.
    ///
    /// If the key already exists, it is overwritten.
    ///
    /// TODO hs: update the API to return a Result<Option<K>> here (i.e. the old key)
    pub fn insert<K: EncodableKey>(
        &self,
        key_spec: &dyn KeySpecifier,
        key: K,
    ) -> Result<()> {
        for store in &self.key_store {
            if store.has_key_bundle(key_spec) {
                return store.insert(&key, key_spec, K::key_type());
            }
        }

        // None of the stores has the key bundle of key_spec, so we insert the key into the first key
        // store.
        if let Some(store) = self.key_store.first() {
            return store.insert(&key, key_spec, K::key_type());
        }

        // Bug: no key stores were configured
        Err(...)
    }

    /// Remove the specified key.
    ///
    /// If the key exists in multiple key stores, this will only remove it from the first one. An
    /// error is returned if none of the key stores contain the specified key.
    pub fn remove(&self, key_spec: &dyn KeySpecifier) -> Result<()> {
        for store in &self.key_store {
            match store.remove(key_spec) {
                Ok(()) => return Ok(()),
                Err(e) if e is NotFound => continue,
                Err(e) => return Err(e),
            }
        }

        Err(not found)
    }
}
```

## Proposed key store API

The key manager reads from (and writes to) the configured key stores. The key
stores all implement the `KeyStore` trait:

```rust
/// A generic key store.
pub trait KeyStore {
    /// Retrieve the key identified by `key_spec`.
    fn get(&self, key_spec: &dyn KeySpecifier, key_type: KeyType) -> Result<Option<ErasedKey>>;

    /// Write `key` to the key store.
    fn insert(&self, key: &dyn EncodableKey, key_spec: &dyn KeySpecifier, key_type: KeyType) -> Result<()>;

    /// Remove the specified key.
    fn remove(&self, key_spec: &dyn KeySpecifier) -> Result<()>;
}
```

We will initially support 2 key store implementations (one for the C Tor key
store, and one for the Arti store).


### The Arti key store

```rust

impl KeyStore for ArtiNativeKeyStore {
    fn get(&self, key_spec: &dyn KeySpecifier, key_type: KeyType) -> Result<Option<ErasedKey>> {
        let key_path = self.key_path(key_spec);

        let input = match fs::read(key_path) {
            Ok(input) => input,
            Err(e) if matches!(e.kind(), ErrorKind::NotFound) => return Ok(None),
            Err(e) => return Err(...),
        };

        key_type.read_ssh_format_erased(&input).map(Some)
    }

    fn insert(&self, key: &dyn EncodableKey, key_spec: &dyn KeySpecifier, key_type: KeyType) -> Result<()> {
        let key_path = self.key_path(key_spec);

        let ssh_format = key_type.write_ssh_format(key)?;
        fs::write(key_path, ssh_format).map_err(|_| ())?;

        Ok(())
    }

    fn remove(&self, key_spec: &dyn KeySpecifier) -> Result<()> {
        let key_path = self.key_path(key_spec);

        fs::remove_file(key_path).map_err(|e| ...)?;

        Ok(())
    }
}

impl ArtiNativeKeyStore {
    /// The path on disk of the key with the specified specifier and type.
    fn key_path(&self, key_spec: &dyn KeySpecifier) -> PathBuf {
        let mut arti_path = self.keystore_dir.join(key_spec.arti_path().0);
        arti_path.set_extension(key_spec.arti_extension());

        arti_path
    }
}

#[derive(Copy, Clone, ...)]
pub enum KeyType {
    Ed25519Private,
    Ed25519Public,

    X25519StaticSecret,
    X25519Public,
    // ...plus all the other key types we're interested in.
}

impl KeyType {
    /// Whether the key is public or private.
    fn is_private(&self) -> bool {
        match self {
            // Secret key types
            KeyType::Ed25519Private | KeyType::X25519StaticSecret => true,
            // Public key types
            KeyType::Ed25519Public | KeyType::X25519Public => false,
        }
    }
}

pub enum Algorithm {
    Ed25519,
    X25519,
    ...
}

impl Algorithm {
    fn as_str(&self) -> &'static str {
        ...
    }
}

```

The `ArtiNativeKeyStore` uses the `SshKeyType` implementation of `KeyType`
to read and write OpenSSH key files:
```rust

pub trait SshKeyType: Send + Sync + 'static {
    fn ssh_algorithm(&self) -> Algorithm;

    /// Read an OpenSSH key, parse the key material into a known key type, returning the
    /// type-erased value.
    ///
    /// The caller is expected to downcast the value returned to a concrete type.
    fn read_ssh_format_erased(&self, input: &[u8]) -> Result<ErasedKey>;

    /// Encode an OpenSSH-formatted key.
    fn write_ssh_format(&self, key: &dyn EncodableKey) -> Result<Vec<u8>>;
}

impl SshKeyType for KeyType {
    fn ssh_algorithm(&self) -> Algorithm {
        ...
    }

    fn read_ssh_format_erased(&self, input: &[u8]) -> Result<ErasedKey> {
        match self {
            KeyType::Ed25519Private => {
                let sk = ssh_key::PrivateKey::from_bytes(input).map_err(|_| ())?;

                // Build the expected key type (i.e. convert ssh_key key types to the key types
                // we use internally).
                let sk = match sk.key_data() {
                    KeypairData::Ed25519(kp) => {
                        ed25519::SecretKey ::from_bytes(&kp.private.to_bytes())?
                    }
                    _ => {
                        // bug
                        return Err(...);
                    }
                };

                Ok(Box::new(sk))
            }
            KeyType::Ed25519Public => {
                let pk = ssh_key::PublicKey::from_bytes(input).map_err(|_| ())?;

                // Build the expected key type (i.e. convert ssh_key key types to the key types
                // we use internally).
                let pk = match pk.key_data() {
                    KeyData::Ed25519(pk) => ed25519::PublicKey::from_bytes(&pk.0)?,
                    _ => {
                        // bug
                        return Err(...);
                    }
                };

                Ok(Box::new(pk))
            }
            KeyType::X25519StaticSecret | KeyType::X25519Public => {
                // The ssh-key crate doesn't support arbitrary key types. We'll probably
                // need a more general-purpose crate for parsing OpenSSH (one that allows
                // arbitrary values for the algorithm), or to roll our own (we
                // could also fork ssh-key and modify it as required).
                todo!()
            }
        }
    }

    fn write_ssh_format(&self, key: &dyn EncodableKey) -> Result<Vec<u8>> {
        /* Encode `key` in SSH key format. */
    }
}

```

#### Versioning

As Arti evolves, it is likely we will eventually need to make changes to the
structure of its key store (for example, to support new key specifiers, or to
change something about the existing ones). This means we'll need to be able to
distinguish between the different supported key store versions. To achieve this,
the root of the Arti key store will have a `.VERSION` file that contains 2
version numbers (the format of the `.VERSION` file is TBD):
  * `version`: the version of the key store
  * `min_version`: the minimum `ArtiKeyStore` version required to
    read/manipulate the store

The `ArtiKeyStore` won't be constructed if the `.VERSION` file of the configured
store is malformed, or if `ArtiKeyStore::VERSION` is less than its
`min_version`. This should likely be treated as a fatal error (i.e. Arti should
refuse to start if the keystore exists but is inaccessible or malformed).

#### Key passphrases

OpenSSH keys can have passphrases. While the first version of the key manager
won't be able to handle such keys, we will add passphrase support at some point
in the future.

### The C Tor key store

TODO

```rust

impl KeyStore for CTorKeyStore {
    ...
}

impl CTorKeyStore {
    /// The path on disk of the key with the specified specifier and type.
    fn key_path(&self, key_spec: &dyn KeySpecifier) -> Option<PathBuf> {
        let ext = key_spec.ctor_extension();
        let root_dir = match key_spec.user_kind() {
            UserKind::Client => self.client_dir,
            UserKind::Relay => self.key_dir,
            UserKind::Service(hs_id) => {
                // CTorKeyStore contains a mapping from hs_id to
                // `HiddenServiceDir`. We work out which HiddenServiceDir to
                // load keys from based on the hs_id of the KeySpecifier.
                self.hs_service_dirs.get(hs_id)?
            }
            ...
        };

        let mut ctor_path = root_dir.join(key_spec.ctor_path().0);
        ctor_path.set_extension(ext);

        Some(ctor_path)
    }
}

```

## Concurrent access for disk-based key stores

The key stores will allow concurrent modification by different processes. In
order to implement this safely without locking, the key store operations (get,
insert, remove) will need to be atomic. Reading and removing keys atomically is
trivial. To create/import a key atomically, we write the new key to a temporary
file before using `rename(2)` to atomically replace the existing one (this
ensures preexisting keys are replaced atomically).

Note: on Windows, we can't use `rename` to atomically replace an existing file
with a new one (`rename` returns an error if the destination path already
exists). As such, on Windows we will need some sort of synchronization mechanism
(unless it exposes some other APIs we can use for atomic renaming).

[#728]: https://gitlab.torproject.org/tpo/core/arti/-/issues/728
[#699]: https://gitlab.torproject.org/tpo/core/arti/-/issues/699
