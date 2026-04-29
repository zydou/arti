ADDED: Implement `Debug` and `Clone` on `SigCheckedCert`
ADDED: impl `From<Ed25519Identity>` for `CertifiedKey`
ADDED: impl `tor_bytes::Writeable` for `UncheckedCert` and `KeyUnknownCert`
ADDED: impl `tor_bytes::Readable` for `KeyUnknownCert`
ADDED: `Ed25519Cert::builder`, `Ed25519CertBuilder`, `EncodedRsaCrosscert`, etc.
