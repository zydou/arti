REMOVED: `KeyType::X25519StaticSecret`
ADDED: `KeyType::X25519StaticKeypair`
REMOVED: `EncodableKey` impl for `curve25519::StaticSecret`
ADDED: `EncodableKey` impl for `curve25519::StaticKeypair`
REMOVED: `ToEncodableKey` impl for `HsClientDescEncSecretKey`
ADDED: `ToEncodableKey` impl for `HsClientDescEncKeypair`
