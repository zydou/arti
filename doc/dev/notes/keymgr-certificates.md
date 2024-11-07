# Storing certificates in the Arti key store

To support running with offline identity keys,
the `K_relayid_ed` identity key of a relay is only used for
signing its `K_relaysign_ed` medium-term signing key (which must be kept online).
The resulting certificate is used in the `CERTS` cell during channel negotiation,
and needs to be available even if the `K_relayid_ed` key
(or, more specifically, the `KS_relayid_ed` private key)
is not.
To that end, we decided to add support for storing certificates in the Arti keystore
(see #1617).

## Proposed design: Reusing the existing KeyMgr functions to manipulate certs (rejected)

Rejected in favor of option 2.
See https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/2565#note_3099397

### Certificate `KeySpecifier`s

The certificate of a key will have the same `ArtiPath` as the key it certifies.

For example, the keystore entries for the `K_relaysign_ed` key are

| Key                            | Description                                                  |
|--------------------------------|--------------------------------------------------------------|
| `KS_relaysign_ed`              | medium-term signing keypair                                  |
| `KP_relaysign_ed`              | public part of `KS_relaysign_ed`                             |
| `KP_relaysign_ed` certificate  | `KP_relaysign_ed` signed by the `KS_relayid_ed` identity key |

In the on-disk Arti key store, their paths will be

| Key                            | `ArtiPath`                      | Path                                              |
|--------------------------------|---------------------------------|---------------------------------------------------|
| `KS_relaysign_ed`              | `relay/relaysign_ed+<uid-tbd>` | `relay/relaysign_ed+<uid-tbd>.ed25519_private`   |
| `KP_relaysign_ed`              | `relay/relaysign_ed+<uid-tbd>` | `relay/relaysign_ed+<uid-tbd>.ed25519_public`    |
| `KP_relaysign_ed` certificate  | `relay/relaysign_ed+<uid-tbd>` | `relay/relaysign_ed+<uid-tbd>.tor_ed25519_cert`  |

Where `<uid-tbd>` is a unique identifier added to each key.
The exact format of this identifier is outside the scope of this document
(it will be specified later, as part of #1692).

We will introduce a new `ed25519_tor_cert` extension for Tor Ed25519 certificates
(internally represented by a new `KeyType::Ed25519TorCert` variant).
Note: the type of the certified key is not encoded in the `KeyType`,
because it is included
in the [`CERT_TYPE` field](https://spec.torproject.org/cert-spec.html#list-key-types)
of the certificate.

### Storage format

For the `K_relaysign_ed` cert, the storage format is Tor's
[certificate format](https://spec.torproject.org/cert-spec.html).

If we choose to support other types of certificates in the future,
they will likely have a different format (not specified here).

If we ever decide to change the format of the `K_relaysign_ed` certificate,
we will deprecate the existing `.tor_ed25519_cert` key type,
and introduce a new one for certificates using the new format.

#### Alternatives considered

We could also store the key certificate *inside* the (OpenSSH) key entry
it certifies, by encoding it in its comment field.
The main advantage of this approach is that certificates are always associated
with the keys they certify (if the certificate is in the comment field,
it's impossible to store "standalone" certificates in the key store).
There are several disadvantages, however, that IMO make this approach less
desirable than the alternative proposed earlier in this document.
One of our design goals for Arti native keystore was to have
a transparent storage format, ideally one that can be manipulated by external tools
(which is why the keys are in OpenSSH format).
A (e.g. base64) encoded comment field containing a certificate
(and possibly other information)
would be rather opaque, and making sense of it using standard tooling
would be pretty cumbersome. Storing the certificate as a separate,
non-OpenSSH keystore entry isn't ideal either,
but at least the `.tor_ed25519_cert` extension makes it
obvious that the cert is a tor-specific binary blob.

#### Implementation details

##### KeyMgr changes

The `KeySpecifier` trait will be extended with a function for getting the
certificate specifier of a key:

```rust
pub trait KeySpecifier {
    ...

    /// If this is the specifier of a key that has an associated certificate,
    /// the specifier for the corresponding certificate.
    fn certificate_specifier(&self) -> Option<KeyCertificateSpecifier>;
}

/// The "specifier" of a key certificate, which identifies an instance of a cert.
///
/// Obtained from the [`certificate_specifier`](KeySpecifier::certificate_specifier)
/// of the subject key.
#[non_exhaustive]
pub struct KeyCertificateSpecifier {
    /// The key specifier of the certificate.
    pub certificate: Box<dyn KeySpecifier>,
    /// The key specifier of the signing key.
    pub signing_key: Box<dyn KeySpecifier>,
}
```

`KeyMgr::{get, get_entry}` will validate the certificate
of the requested key (if there is one), returning an error
if the certificate is invalid (i.e. if it's expired or not yet valid,
or if it's not well-signed).

In addition to generating the specified key,
`KeyMgr::get_or_generate` will also generate a certificate for it,
if its `KeySpecifier::certificate_specifier()` impl returns `Some`.
If the signing key can't be found,
`KeyMgr::get_or_generate` will return an error.

##### Key encoding traits

To retrieve a certificate from the keystore (for example, in `KeyMgr::get`),
we need to know the concrete type of the certificate,
so we will need to extend the `EncodableKey` trait like so:

```diff
 pub trait EncodableKey: Downcast {
     type KeyPair: ToEncodableKey;

+    /// The type of certificate associated with this key.
+    ///
+    /// For certificates, this type is Self.
+    type Certificate: KeyCertificate<Self>;
+
     /// Convert this key to a type that implements [`EncodableKey`].
     fn to_encodable_key(self) -> Self::Key;
+}

+/// A trait representing a key certificate.
+pub trait KeyCertificate<K: ToEncodableKey>: ToEncodableCert {
+    /// The type of the signing key.
+    type SigningKey: ToEncodableKey;
+
+    /// Validate this certificate.
+    /// TODO: explain how
+    fn validate(&self, subject: &K, signed_with: &Self::SigningKey) -> Result<()>;
+}

+/// A trait representing an encodable certificate.
+pub trait ToEncodableCert {
+    /// The cert type this can be converted to/from.
+    type Cert: EncodableKey + 'static;
+
+    /// Convert this cert to a type that implements [`EncodableKey`].
+    fn to_encodable_cert(self) -> Self::Cert;
+
+    /// Convert an [`EncodableKey`] to another cert type.
+    fn from_encodable_cert(cert: Self::Cert) -> StdResult<Self, Bug>
+    where
+        Self: Sized;
+}
```

Note: the `ToEncodableCert::Cert` type is an `EncodableKey`:
despite its now-misleading name, `EncodableKey` is still our trait representing objects
that can be encoded and stored in the keystore (we might want to rename it soon though).

If we implement this, the Arti keystore storage format will no longer be just OpenSSH
(it'll be OpenSSH for keys + the C Tor custom cert format for certificates),
so we ought to rename `SshKeyData` (the serializable storage type)
to `ArtiKeyMaterial` (or something else that doesn't mention "ssh").

###### In even more detail...

To support certificate retrieval, we need to specialize methods like `KeyMgr::get<K>`
for keys (`K: ToEncodableKey`) and certs (`K: ToEncodableCert`).
Since specialization in Rust doesn't apply to inherent methods,
the `KeyMgr` will need be refactored like so:
  * all of the current `KeyMgr` methods will be moved to a `KeyAccess: Sealed`
    trait
  * the methods for cert retrieval/manipulation will be added to a new
    `CertAccess: Sealed` trait
  * `KeyMgr` will implement `KeyAccess` and `CertAccess`

## Proposed design 2

The previous design was based on the following assumptions:
  * `KeyMgr::get` would handle certificate validation internally:
    when fetching a key that has an associated certificate
    (i.e. a key that is the subject key of a certificate),
    `KeyMgr::get` would also fetch its certificate
    (given by `KeySpecifier::certificate_specifier()`)
    and validate it, returning an error if the certificate is invalid
  * there would always be a 1:1 relationship between certificates
    and subject keys

The assumption that there won't ever be a key that has multiple certificates for
different purposes is particularly problematic, because we could conceivably
have such keys in the future. Instead of baking this assumption into the KeyMgr
(by adding a `Certificate` associated type to `EncodableKey`), we can design
this API such that it is possible to support certificates that have a many:1
relationship with their subject keys.

### Key certificate representation

The purpose and meaning of the certificate, as well as the algorithms
of the subject and signing keys, will be given by the `KeyType`
of the certificate (i.e. the file extension).

Mote specifically, the `KeyType` of a certificate encodes the following:

1. The cryptographic algorithms of the subject key and the signing key
2. How the subject key value and its properties are encoded before
   the signing key key makes its signature
3. How the signature and the other information is encoded for storage.

> Note: the name of the `KeyType` enum now makes little sense,
> because it no longer represents a key type, but rather a type of object
> we're able to serialize and write to the keystore.

> Recall that the `KeyType` of an object is given by its `EncodableKey` impl:
> ```rust
> pub trait EncodableKey: Downcast {
>     /// The type of the key.
>     fn key_type() -> KeyType
>     where
>         Self: Sized;
>
>     /// Return the [`SshKeyData`] of this key.
>     fn as_ssh_key_data(&self) -> Result<SshKeyData>;
> }
> ```
>
> Like keys, certificates are encodable in the keystore,
> so like keys, they must implement `EncodableKey`
> (and therefore have an associated  `KeyType`, and `SshKeyData`).
>
> As a result, `EncodableKey`, `KeyType`, and `SshKeyData`
> will need to be renamed (see the "Proposed renamings" section below).

For example, the keystore entries for the `K_relaysign_ed` key are

| Key                            | Description                                                  |
|--------------------------------|--------------------------------------------------------------|
| `KS_relaysign_ed`              | medium-term signing keypair                                  |
| `KP_relaysign_ed`              | public part of `KS_relaysign_ed`                             |
| `KP_relaysign_ed` certificate  | `KP_relaysign_ed` signed by the `KS_relayid_ed` identity key |

In the on-disk Arti key store, their paths will be

| Key                            | `ArtiPath`                      | Path                                              |
|--------------------------------|---------------------------------|---------------------------------------------------|
| `KS_relaysign_ed`              | `relay/relaysign_ed+<uid-tbd>` | `relay/relaysign_ed+<uid-tbd>.ed25519_private`   |
| `KP_relaysign_ed`              | `relay/relaysign_ed+<uid-tbd>` | `relay/relaysign_ed+<uid-tbd>.ed25519_public`    |
| `KP_relaysign_ed` certificate  | `relay/relaysign_ed+<uid-tbd>` | `relay/relaysign_ed+<uid-tbd>.tor_ed25519_cert`  |

Where `<uid-tbd>` is a unique identifier added to each key.
The exact format of this identifier is outside the scope of this document
(the `uid` will likely be a timestamp -- see !2577).

We will introduce a new `tor_ed25519_cert` extension for Tor Ed25519 certificates
(internally represented by a new `CertType::Ed25519TorCert` variant -- see below).

### Storage format

For certs like `K_relaysign_ed`, we won't have a separate "storage format".
The cert will be stored in the keystore as-is
(in Tor's [certificate format](https://spec.torproject.org/cert-spec.html#ed-certs)).

If at some point we choose to support other kinds of certificates
(i.e. with a different purpose and meaning),
we will likely use a different certificate format (not specified here).

If we ever decide to change the format of the `K_relaysign_ed` certificate,
we will deprecate the existing `.tor_ed25519_cert` key type,
and introduce a new one for certificates using the new format.

#### Implementation details

```rust
/// The "specifier" of a key certificate, which identifies an instance of a cert.
#[non_exhaustive]
pub struct KeyCertificateSpecifier {
    /// The key specifier of the certificate.
    pub certificate: Box<dyn CertSpecifier>,
    /// The key specifier of the signing key.
    pub signing_key: Box<dyn KeySpecifier>,
    /// The key specifier of the subject key.
    pub subject_key: Box<dyn KeySpecifier>,
    // Note: the specifier of the subject key is somewhat redundant,
    // since most (all?) of the KeyMgr APIs that receive a KeyCertificateSpecifier
    // also get the KeySpecifier of the subject key as a separate arg.

    // other fields TBD
}

/// The "specifier" of a certificate, which identifies an instance of a cert.
///
/// [`CertSpecifier::arti_path()`] should uniquely identify an instance of a cert.
///
/// Certificates can only be fetched from Arti key stores
/// (`ArtiNativeKeystore` or `ArtiEphemeralKeystore`).
pub trait CertSpecifier {
    /// The location of the cert in the Arti key store.
    ///
    /// This also acts as a unique identifier for a specific cert instance.
    fn arti_path(&self) -> StdResult<ArtiPath, ArtiPathUnavailableError>;

    // NOTE: if at some point we decide to support loading certificates from C Tor key stores,
    // we will add a ctor_path() -> Option<CTorPath> function here
}
```

`KeyMgr` will be extended with some new functions
for cert retrieval and validation:

```rust
impl KeyMgr {
    /// Read the specified key and certificate from one of the key stores,
    /// deserializing the key as `K::Key` and the cert as `C::Cert`.
    ///
    /// Returns `Ok(None)` if none of the key stores have the requested key.
    ///
    /// This function validates the certificate,
    /// returning an error if it is invalid or missing.
    /// More specifically, it returns an error if
    ///    * the certificate is not timely
    ///      (i.e. it is expired, or not yet valid), or
    ///    * the certificate is not well-signed, or
    ///    * the subject key or signing key in the certificate do not match
    ///      the subject and signing keys specified in `cert_spec`
    fn get_key_and_cert<K: ToEncodableKey, C: ToEncodableCert<K>>(
        &self,
        key_spec: &dyn KeySpecifier,
        cert_spec: KeyCertificateSpecifier
      ) -> Result<Option<(K, C)>> {
        ...
    }

    /// Read the specified key and certificate from one of the key stores,
    /// and deserializing the key as `K::Key` and the cert as `C::Cert`,
    /// generating the key and its corresponding certificate
    /// if either does not exist.
    ///
    /// See [`KeyMgr::get_key_and_cert`] for possible errors.
    ///
    /// Generates the missing key and/or certificate as follows:
    ///
    /// | Subject Key exists | Signing Key exists | Cert exists | Action                                 |
    /// |--------------------|--------------------|-------------|----------------------------------------|
    /// | Y                  | Y/N                | Y           | Validate cert,                         |
    /// |                    |                    |             | return key and cert if valid,          |
    /// |                    |                    |             | error otherwise                        |
    /// |--------------------|--------------------|-------------|----------------------------------------|
    /// | N                  | Y                  | N           | Generate subject key and               |
    /// |                    |                    |             | a new cert signed with signing key     |
    /// |--------------------|--------------------|-------------|----------------------------------------|
    /// | Y                  | Y                  | N           | Generate cert signed with signing key  |
    /// |--------------------|--------------------|-------------|----------------------------------------|
    /// | Y                  | N                  | N           | Error - cannot generate cert           |
    /// |                    |                    |             | if signing key is not available        |
    /// |--------------------|--------------------|-------------|----------------------------------------|
    /// | N                  | N                  | N           | Error - cannot generate cert           |
    /// |                    |                    |             | if signing key is not available        |
    /// |--------------------|--------------------|-------------|----------------------------------------|
    /// | N                  | Y/N                | Y           | Error - subject key was removed?       |
    /// |                    |                    |             | (we already have a cert for it,        |
    /// |                    |                    |             | but it's unavailable)                  |
    //
    // TODO: this will need an extra argument specifying the expiry
    // and other data that needs to go into the certificate
    fn get_or_generate_key_and_cert<K: ToEncodableKey, C: ToEncodableCert>(
        &self,
        key_spec: &dyn KeySpecifier,
        cert_spec: CertificateSpecifier
      ) -> Result<(K, C)> {
        ...
    }

    // This function already exists in KeyMgr
    ///
    // ** Important note for the reviewer **
    //
    // Don't confuse the KeystoreEntry type here with the one mentioned
    // below!! This function references the _existing_ KeystoreEntry type
    // (which will need to be renamed to something else, like `KeystoreEntryDescriptor`),
    // whereas the sections below talk about a _new_ KeystoreEntry type that represents
    // the thing we call SshKeyData today.
    pub fn get_entry<K: ToEncodableKey>(&self, entry: &KeystoreEntry) -> Result<Option<K>> {
       ...
    }

    // This function is new
    //
    /// Used for fetching a certificate listed using list_matching
    //
    // See the note on get_entry() above
    pub fn get_cert_entry<C: ToEncodableCert>(&self, entry: &KeystoreEntry) -> Result<Option<K>> {
       ...
    }

    // Note: this list of proposed additions is non-exhaustive.
    // In the future, we might decide to also add
    // e.g. a get_cert() function for retrieving a certificate
}
```

where `ToEncodableCert` is a new trait of the form:

```rust
/// A trait representing an encodable certificate.
///
/// `K` represents the (Rust) type of the subject key.
pub trait ToEncodableCert<K: ToEncodableKey> {
    /// The low-level type this can be converted to/from.
    type Cert: EncodableKey + 'static;

    /// The (Rust) type of the signing key.
    type SigningKey: ToEncodableKey;

    /// Validate this certificate.
    //
    // This function will be called from functions such as KeyMgr::get_key_and_cert()
    // to validate the cert using the provided subject key
    // (the concrete type of which is given by the `K` in KeyMgr::get_key_and_cert())
    // and ToEncodableCert::SigningKey.
    //
    /// TODO: explain how
    /// TODO: perhaps fold this into from_encodable_cert
    /// (i.e. change the signature of from_encodable_cert to also take a subject
    /// key and signing key, and have it handle validation internally).
    fn validate(&self, subject: &K, signed_with: &Self::SigningKey) -> Result<()>;

    /// Convert this cert to a type that implements [`EncodableKey`].
    fn to_encodable_cert(self) -> Self::Cert;

    /// Convert an [`EncodableKey`] to another cert type.
    fn from_encodable_cert(cert: Self::Cert) -> Self
    where
        Self: Sized;
}
```

Note: the `ToEncodableCert::Cert` type is an `EncodableKey`:
despite its now-misleading name, `EncodableKey` is still our trait representing objects
that can be encoded and stored in the keystore.

As mentioned before, once we add support for storing certificates,
the Arti keystore storage format will no longer be just OpenSSH
(it'll be OpenSSH for keys + the C Tor custom cert format for certificates),
so we ought to rename `SshKeyData` (the serializable storage type)
to `KeystoreEntry` or `ArtiKeyMaterial` (or something else that doesn't mention "ssh").

##### Proposed renamings

* preemptively rename `KeystoreEntry` to `KeystoreEntryDescriptor` or `KeystoreEntryHandle`
  or `KeyMgrEntry` or `KeyMgrEntryDescriptor`
  (I want to use `KeystoreEntry` to represent a key retrieved from the keystore
  or ready to be written to the keystore)
* rename `EncodableKey::as_ssh_key_data()` to `EncodableKey::as_keystore_entry()`
* replace `SshKeyData` with a new `KeystoreEntry` type
* Rename the `EncodableKey` trait to `KeystoreEncodable`
  (other possible names: `EncodableEntry`, `EncodableKeystoreEntry`)
* Rename `KeyType` to `KeystoreEntryType`

IOW, I propose we rewrite the `EncodableKey` trait like so

```rust
/// An object that can be converted to and from `KeystoreEntry`.
///
/// Types implementing this trait can be written to the keystore.
//
// When adding a new `KeystoreEncodable` impl, you must also update
// [`KeystoreEntry::into_erased`](crate::KeystoreEntry::into_erased) to
// return the corresponding concrete type implementing `KeystoreEncodable`
// (as a `dyn KeystoreEncodable`).
pub trait KeystoreEncodable: Downcast {
    /// The kind of keystore entry this is.
    fn entry_type() -> KeystoreEntryType
    where
        Self: Sized;

    /// Return the [`KeystoreEntry`] representation of this object.
    fn as_keystore_entry(&self) -> Result<KeystoreEntry>;
}

/// A type of [`KeystoreEncodable`] entry
#[non_exhaustive]
enum KeystoreEntryType {
    /// A key
    // KeyType is the same as before,
    // except its Unknown variant is moved to KeystoreEntryType
    Key(KeyType),
    /// A key certificate
    Cert(CertType),
    /// An unrecognized entry type.
    Unknown {
        /// The extension used for entries of this type in an Arti keystore.
        arti_extension: String,
    },
}

#[non_exhaustive]
enum CertType {
    /// A Tor Ed25519 certificate.
    /// See https://spec.torproject.org/cert-spec.html#ed-certs
    Ed25519TorCert,
}

/// A public key, keypair, or key certificate.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct KeystoreEntry(KeystoreEntryInner);

/// The inner representation of a KeystoreEntry.
#[derive(Clone, Debug)]
#[non_exhaustive]
enum KeystoreEntryInner {
    /// A public key or a keypair.
    Key(SshKeyData),
    /// A certificate.
    Cert(CertData),
}

enum CertData {
    /// A tor-specific ed25519 cert.
    TorEd25519Cert(Vec<u8>),
}

// ======= unchanged =========

/// A public key or a keypair.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct SshKeyData(SshKeyDataInner);

/// The inner representation of a public key or a keypair.
#[derive(Clone, Debug)]
#[non_exhaustive]
enum SshKeyDataInner {
    /// The [`KeyData`] of a public key.
    Public(KeyData),
    /// The [`KeypairData`] of a private key.
    Private(KeypairData),
}
// ======= unchanged end =========
```
