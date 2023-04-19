# Key management backend

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
    let key_id: HsClientSecretKeyIdentity =
       (LocalUserIdentity, HsId, HsClientSecretKeySpecifier).into();
    let sk: Option<ed25519::SecretKey> = keymgr.get::<ed25519::SecretKey>(key_id)?;
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

## Key passphrases

OpenSSH keys can have passphrases. While the first version of the key manager
won't be able to handle such keys, we will add passphrase support at some point
in the future.

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
# heirarchy
root_dir = ""

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
```

## Key identities

A key by itself is not very useful. In order for Arti to be able to use it, it
needs to also know the _role_ of the key (i.e., what that key is supposed to be
used for), among other things. As such, we need to store some metadata alongside
each key.

For client authorization keys, C Tor achieves this using a passwd-style format
(see the `CLIENT AUTHORIZATION` section of the `tor` manpage), which stores keys
and their associated metadata in the same file. Other keys don't have other
metadata than their _role_ (i.e. "Ed25519 permanent identity key", "medium-term
Ed25519 signing key", etc.), which can be unambiguously determined by looking at
the path/file name of the key file (e.g. the role of
`<KeyDirectory>/ed25519_master_id_private_key` is "Ed25519 permanent identity
key of a relay", `<HiddenServiceDirectory>/private_key` is "the private key of
the hidden service whose data is stored at `<HiddenServiceDirectory>`", etc.).

For this reason, we introduce the concept of a "key identity" (specified for
each supported key type via the `KeyIdentity` trait). A "key identity" uniquely
identifies an instance of a type of key. From an implementation standpoint,
`KeyIdentity` implementers must specify:
* `arti_path`: the location of the key in the Arti key store. This also serves
  as a unique identifier for a particular instance of a key.
* `ctor_path`: the location of the key in the C Tor key store (optional).

For the keys stored in the Arti key store (i.e. in the OpenSSH format), the
`KeyIdentity::arti_path()` is converted to a string and placed in the `coment`
field of the key. When retrieving keys from the Arti store, the key manager
compares the `comment` of the stored key with the `KeyIdentity::arti_path()` of
the requested key identity. If the values match, it retrieves the key.
Otherwise, it returns an error.

To identify the path of a key in the Arti key store, the key manager prepends
`keys.arti_store.root_dir` to `KeyIdentity::arti_path()` and appends an
extension.

For example, an Arti key store might have the following structure (note that
each path within the `keys.arti_store.root_dir` directory, minus the extension,
is the `arti_path` of a particular key):
```
<keys.arti_store.root_dir>
├── alice                     # HS client identity "alice"
│   ├── foo.onion
│   │   ├── hsc_desc_enc      # arti_path = "alice/foo.onion/hsc_desc_enc"
│   │   │                     # (HS client Alice's x25519 hsc_desc_enc keypair for decrypting the HS
│   │   │                     # descriptors of foo.onion")
│   │   └── hsc_intro_auth    # arti_path = "alice/foo.onion/hsc_intro_auth"
│   │                         # (HS client Alice's ed25519 hsc_intro_auth keypair for computing
│   │                         # signatures to prove to foo.onion she is authorized")
│   │                         # Note: this is not implemented in C Tor
│   └── bar.onion
│       ├── hsc_desc_enc      # arti_path = "alice/foo.onion/hsc_desc_enc"
│       │                     # (HS client Alice's x25519 hsc_desc_enc keypair for decrypting the HS
│       │                     # descriptors of bar.onion")
│       └── hsc_intro_auth    # arti_path = "alice/bar.onion/hsc_intro_auth"
│                             # (HS client Alice's ed25519 hsc_intro_auth keypair for computing
│                             # signatures to prove to bar.onion she is authorized")
├── bob                       # HS client identity "bob"
│   └── foo.onion
│       ├── hsc_desc_enc      # arti_path = "bob/foo.onion/hsc_desc_enc"
│       │                     # (HS client Bob's x25519 hsc_desc_enc keypair for decrypting the HS
│       │                     # descriptors of foo.onion")
│       └── hsc_intro_auth    # arti_path = "bob/foo.onion/hsc_intro_auth"
│                             # (HS client Bob's ed25519 hsc_intro_auth keypair for computing
│                             # signatures to prove to foo.onion he is authorized")
│                             # Note: this is not implemented in C Tor
│
├── baz.onion                 # Hidden service baz.onion
│   ├── authorized_clients    # The clients authorized to access baz.onion
│   │   └── dan
│   │        └── hsc_desc_enc # arti_path = "baz.onion/authorized_clients/dan/hsc_desc_enc.pub"
│   │                         # (The public part of HS client Dan's x25519 hsc_desc_enc keypair for
│   │                         # decrypting baz.onions descriptors)
│   │
│   │
│   │  
│   ├── hs_id                 # arti_path = "baz.onion/hs_id" (baz.onion's identity key)
│   └── hs_blind_id           # arti_path = "baz.onion/hs_blind_id" (baz.onion's blinded identity key)
├── Carol                     # Relay Carol
│   └── ...
└── ....
```

### Comment field format

TODO hs: decide what format to store the `arti_path` in. One option would be
to encode it as an email address: `<arti_path>@_artikeyid.arti.torproject.org`.
Another would be to simply store it as-is.

### The `KeyIdentity` trait

```rust
    /// The path of a key in the Arti key store.
    ///
    /// NOTE: There is a 1:1 mapping between a value that implements
    /// `KeyIdentity` and its corresponding `ArtiPath`.
    /// A `KeyIdentity` can be converted to an `ArtiPath`,
    /// but the reverse conversion is not supported.
    //
    // TODO hs: restrict the character set and syntax for values of this type
    // (it should not be possible to construct an ArtiPath out of a String that
    // uses disallowed chars, or one that is in the wrong format (TBD exactly what
    // this format is supposed to look like)
    pub struct ArtiPath(String);

    /// The path of a key in the C Tor key store.
    pub struct CTorPath(PathBuf);

    /// Information about where a particular key could be stored.
    pub trait KeyIdentity: Serialize + Deserialize {
        /// The location of the key in the Arti key store.
        ///
        /// This also acts as a unique identifier for a specific key instance.
        fn arti_path(&self) -> ArtiPath;

        /// The location of the key in the C Tor key store (if supported).
        fn ctor_path(&self) -> Option<CTorPath>;
    }

    /// An identifier for a client/relay/...
    #[derive(AsRef, Into, ...)]
    pub struct LocalUserIdentity(String);

    impl FromStr for LocalUserIdentity { /* check syntax rules */ }

    struct HsClientSecretKeyIdentity { ... }


    impl KeyIdentity for HsClientSecretKeyIdentity {
        ...
    }

```

## Proposed key manager API

```rust
pub trait EncodableKey {
    /// The underlying key type.
    fn key_type() -> KeyType
    where
        Self: Sized;
}

// Implement `EncodableKey` for all the key types we wish to support.
impl EncodableKey for ed25519::SecretKey {
    ...
}

...

enum KeyStoreKind {
    /// A C Tor-style key store.
    CTor(PathBuf),
    /// An Arti key store that uses OpenSSH key format.
    Arti(PathBuf),
}

/// The key manager.
struct KeyMgr {
    /// The type of persistent store.
    store_kind: KeyStoreKind,
   ...
}

impl KeyMgr {
    /// Read a key from the key store, attempting to deserialize it as `K`.
    pub fn get<K: EncodableKey>(
        &self,
        key_id: &dyn KeyIdentity
    ) -> Result<Option<EncodableKey::Key>> {
        match self.store_kind {
            KS_hs_ipt_sidKeyStoreKind::Arti(keystore) => {
                let key_path = keystore.join(key_id.arti_path());
                if !key_path.exists() {
                    // Not found
                    return Ok(None);
                }

                let raw_key = fs::read(key_path)?;
                // TODO hs: compare the comment field of the key with
                // key_id.arti_path(), returning an error (or maybe `Ok(None)`) if
                // they don't match
                K::arti_decode(raw_key, key_id).map(Some)
            }
            KeyStoreKind::CTor(keystore) => {
                let key_path = keystore.join(key_id.ctor_path());
                if !key_path.exists() {
                    // Not found
                    return Ok(None);
                }

                let raw_key = fs::read(key_path)?;
                K::ctor_decode(raw_key, key_id).map(Some)
            }
        }
    }

    /// Write `key` to the key store.
    pub fn insert<K: EncodableKey>(
        &self,
        key_id: &dyn KeyIdentity,
        key: K,
    ) -> Result<()> {
        for store in &self.key_store {
            if store.has_key_bundle(key_id) {
                return store.insert(&key, key_id, K::key_type());
            }
            KeyStoreKind::CTor(keystore) => {
                let key_path = keystore.join(key_id.ctor_path());
                let key = K::arti_encode(key_id)?;

                fs::write(key_path, key)
            }
        }
    }

    pub fn remove(
        &self,
        key_id: &dyn KeyIdentity,
    ) -> Result<()> {
        unimplemented!()
    }
}
```

[#728]: https://gitlab.torproject.org/tpo/core/arti/-/issues/728
