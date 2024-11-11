# Storing certificates in the Arti key store

## Motivation

To support running with offline identity keys,
the `K_relayid_ed` identity key of a relay is only used for
signing its `K_relaysign_ed` medium-term signing key (which must be kept online).
The resulting certificate is used in the `CERTS` cell during channel negotiation,
and needs to be available even if the `K_relayid_ed` key
(or, more specifically, the `KS_relayid_ed` private key)
is not.
To that end, we decided to add support for storing certificates in the Arti keystore
(see #1617).

## Assumptions

Here are the assumptions that motivate the design proposed here:

  * keys may have multiple certificates for different purposes.
  While we don't have such keys right now,
  we might conceivably need to support this in the future.
  For this reason, the new APIs described here support certificates
  that have a many:1 relationship with their subject keys.
  * the keys that are expected to have
  an associated certificate[^1] stored in the keystore
  will be accessed through the new
  `KeyMgr::{get_key_and_cert, get_or_generate_key_and_cert}` APIs
  instead of the `KeyMgr::{get, get_or_generate}` ones.
  In addition to retrieving the key/certificate,
  the new `*_and_cert` APIs will also validate the key certificate
  (by checking if it is well-signed and timely).
  * the `ArtiPath` of a certificate is derived from the `ArtiPath`
  of the key it certifies. More specifically, it is formed by
  concatenating the `ArtiPath` of the subject key with the
  denotators provided by
  `KeyCertificateSpecifier::cert_denotators()`.
  The reason we are not giving certificates their own
  `KeyCertificateSpecifier`-defined `ArtiPath`
  is because we want to ensure the certificates stored
  in the keystore are always for subject keys that we own
  (that is, the subject key **must** be a key
  the key management system knows about)

[^1]: The key is said to have an "associated certificate" if
it is the subject key of a certificate used in the Tor protocol

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

The key certificates for `K_relaysign_ed` keys will be stored in the keystore
in Tor's [certificate format](https://spec.torproject.org/cert-spec.html#ed-certs).

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
    ///
    /// Exactly one of `signing_key` and `cert_spec.signing_key` can be `Some`.
    /// If both are missing, or both are present, an error is returned.
    //
    // TODO: this function takes a lot of args.
    // When we implement it, we should rethink its args.
    // Alternatively, we might choose to make the signing_key specifier
    // from KeyCertificateSpecifier non-optional,
    // and provide a *different* certificate specifier type for key certificates
    // where the signing key is not present in the keystore.
    // We would also provide a different set of `KeyMgr::get*` functions
    // for retrieving such key certificates.
    // These new `KeyMgr::get* functions would take a non-optional
    // signing key argument.
    fn get_key_and_cert<K: ToEncodableKey, C: ToEncodableCert<K>>(
        &self,
        key_spec: &dyn KeySpecifier,
        key_type: KeyType,
        signing_key: Option<<C as ToEncodableCert<K>>::SigningKey>,
        cert_spec: KeyCertificateSpecifier,
        cert_key_type: KeyType,
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
    ///
    /// Exactly one of `signing_key` and `cert_spec.signing_key` can be `Some`.
    /// If both are missing, or both are present, an error is returned.
    //
    // TODO: this function takes a lot of args.
    // When we implement it, we should rethink its args.
    // Alternatively, we might choose to make the signing_key specifier
    // from KeyCertificateSpecifier non-optional,
    // and provide a *different* certificate specifier type for key certificates
    // where the signing key is not present in the keystore.
    // We would also provide a different set of `KeyMgr::get*` functions
    // for retrieving such key certificates.
    // These new `KeyMgr::get* functions would take a non-optional
    // signing key argument.
    fn get_or_generate_key_and_cert<K: ToEncodableKey, C: ToEncodableCert>(
        &self,
        key_spec: &dyn KeySpecifier,
        key_type: KeyType,
        signing_key: Option<<C as ToEncodableCert<K>>::SigningKey>,
        cert_spec: KeyCertificateSpecifier,
        cert_key_type: KeyType,
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
