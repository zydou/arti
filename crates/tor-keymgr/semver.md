REMOVED (experimental)": `KeyType::X25519StaticSecret`
ADDED (experimental): `KeyType::X25519StaticKeypair`
REMOVED (experimental): `EncodableKey` impl for `curve25519::StaticSecret`
ADDED (experimental): `EncodableKey` impl for `curve25519::StaticKeypair`
REMOVED (experimental): `ToEncodableKey` impl for `HsClientDescEncSecretKey`
ADDED (experimental): `ToEncodableKey` impl for `HsClientDescEncKeypair`
