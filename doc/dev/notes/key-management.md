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
needs to know what the key is supposed to be used for. As such, we need to store
some metadata alongside each key.

C Tor achieves this using a passwd-style format (see the `CLIENT AUTHORIZATION`
section of the `tor` manpage), which stores keys and their associated metadata
in the same file.

In addition to the C Tor key format, Arti will also be able to store keys
in OpenSSH format. The key metadata we're interested in is:
* `arti_path`: the location of the key in the Arti key store.
* `ctor_path`: the location of the key in the C Tor key store.
* `hsm_slot`: the slot where the key is located on the smartcard
* a string that includes the key name (from the spec), as well as information
  about that specific instance of the key:
  ```
   {
     "type": "HsClientSecretKeyIdentity",
     "key_name": "k_hsc_desc_enc",
     "service": "foo.onion",
     "user_identity": "wombat"
   }
  ```
  This string will be included in the `comment` section of any newly generated
  key. It is also expected to be present (and in the correct format) for all
  existing keys in an Arti key store.

Keys make their metadata available via the `KeyIdentity` trait.

### Metadata format

TODO: decide what the metadata is serialized to

### The `KeyIdentity` trait

```rust
    /// The path of a key in the Arti key store.
    pub struct ArtiPath(PathBuf);

    /// The path of a key in the C Tor key store.
    pub struct CTorPath(PathBuf);

    /// The location of a key on a smartcard
    pub struct HsmLocation {
        /// The slot where the key is located.
        slot: usize
        // TODO hs: what other fields does this need?
    }

    /// Information about where a particular key could be stored.
    pub trait KeyIdentity: Serialize + Deserialize {
        type CTorKey;

        /// The location of the key in the Arti key store.
        fn arti_path(&self) -> ArtiPath;

        /// The location of the key in the C Tor key store (if supported).
        fn ctor_path(&self) -> Option<CTorPath>;

        /// The slot where the key is located on the smartcard.
        fn hsm_slot(&self) -> Option<HsmLocation>;

        /// The string representation of this key identity;
        fn string_rep(self) -> String {
            // TODO hs: serialize as what?
            serde_json::to_string(&self)
        }

        // TODO hs: other methods?
    }

    /// The result of deserializing the comment field of an openSSH key.
    // TODO hs: we might not actually need this
    #[derive(Serialize, Deserialize)]
    enum KeyIdentityResult<K: KeyIdentity> {
        /// A known key identity.
        Key(K),
        /// An unsupported key type.
        Unknown(String),
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
    /// An HSM key store (TODO hs: figure out how this is going to work).
    Hsm,
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
                // key_id.string_rep(), returning an error (or maybe `Ok(None)`) if
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
            KeyStoreKind::Hsm => unimplemented!(),
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
            KeyStoreKind::Hsm => unimplemented!(),
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
