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

## Certificate `KeySpecifier`s

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

## Storage format

For the `K_relaysign_ed` cert, the storage format is Tor's
[certificate format](https://spec.torproject.org/cert-spec.html).

If we choose to support other types of certificates in the future,
they will likely have a different format (not specified here).

If we ever decide to change the format of the `K_relaysign_ed` certificate,
we will deprecate the existing `.tor_ed25519_cert` key type,
and introduce a new one for certificates using the new format.

### Alternatives considered

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

### Implementation details

#### KeyMgr changes

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

#### Key encoding traits

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

##### In even more detail...

To support certificate retrieval, we need to specialize methods like `KeyMgr::get<K>`
for keys (`K: ToEncodableKey`) and certs (`K: ToEncodableCert`).
Since specialization in Rust doesn't apply to inherent methods,
the `KeyMgr` will need be refactored like so:
  * all of the current `KeyMgr` methods will be moved to a `KeyAccess: Sealed`
    trait
  * the methods for cert retrieval/manipulation will be added to a new
    `CertAccess: Sealed` trait
  * `KeyMgr` will implement `KeyAccess` and `CertAccess`
