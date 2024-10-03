# Keys supported by the Arti key store

The key manager will need to be able to generate all the keys documented here.

Here is a description of the security levels referenced in this document:

| Security lvl | Description                                                                                                                                          |
|--------------|------------------------------------------------------------------------------------------------------------------------------------------------------|
| 0            | extremely sensitive, should ideally be stored offline; used for long-term identity keys                                                              |
| 1            | sensitive, should ideally be stored offline; used for medium-term keys that can only be abused for a limited time if leaked, and that can be rotated |
| 2            | sensitive, **cannot** be stored offline; used for keys that must be stored online, but that have limited validity or can be revoked                  |
| 3            | not sensitive                                                                                                                                        |

## Onion service keys

| Key                 | Type    | Dependencies                  | Description                                                             | Managed by key manager? | Expected lifetime                                                         | Security lvl |
|---------------------|---------|-------------------------------|-------------------------------------------------------------------------|-------------------------|---------------------------------------------------------------------------|--------------|
| `hs_id`             | ed25519 | none                          | long-term identity key                                                  | yes                     | long-term/never rotated                                                   | 0            |
| `hs_blind_id`       | ed25519 | `hs_id`                       | blinded signing key (derived from `hs_id`)                              | yes                     | 1 time period                                                             | 1            |
| `hs_desc_sign`      | ed25519 | none                          | descriptor signing key                                                  | yes                     | 1 time period                                                             | 2            |
| `hs_desc_sign_cert` | ed25519 | `hs_blind_id`, `hs_desc_sign` | descriptor signing certificate (`hs_desc_sign` signed by `hs_blind_id`) | no                      | short-term (54h)                                                          | 3            |
| `hsc_desc_enc`      | x25519  | none                          | the client's counterpart to `hss_desc_enc`                              | yes                     | long-term/until the client rotates it/service revokes the client's access | 2            |
| `hsc_intro_auth`    | ed25519 | none                          | client auth key for use in the introduction protocol                    | yes                     | long-term/until the client rotates it/service revokes the client's access | 2            |

(NOTE: The key names from the `Key` column are the formal key names from
`rend-spec-v3` with the `KS_` prefix removed)

Note: `hss_desc_enc` (used by hidden services to encrypt the inner part of their
descriptors when restricted discovery is enabled) is not listed here, because it is the
public part of the `(KP_hss_desc_enc, KS_hss_desc_enc)` keypair, and Arti key
stores do not store public keys.

That being said, when generating restricted discovery keys, the key management CLI will
need to provide a convenient way to extract the corresponding `hss_desc_enc`
key, both in C Tor's `authorized_clients` format, and in the SSH key format used
by Arti. For example, the command for generating a new descriptor encryption key
might look like this:

```
arti keymgr generate desc_enc_key --keystore <KEYSTORE_ID> \
                                  # plus any other flags we might need
                                  --client <CLIENT_NAME>   \
                                  --service <HSID.ONION>   \
                                  --pubkey <OUT_DIR>
```

In addition to generating `hsc_desc_enc` in the specified key store, this would
also create the corresponding public key entries in `OUT_DIR`:

```
<OUT_DIR>
├── <CLIENT_NAME>.auth          # for C Tor
└── <CLIENT_NAME>.x25519_public # for Arti
```

## Relay keys

| Key                 | Type         | Dependencies                  | Description                                                             | Managed by key manager? | Expected lifetime                                                         | Security lvl |
|---------------------|--------------|-------------------------------|-------------------------------------------------------------------------|-------------------------|---------------------------------------------------------------------------|--------------|
| `relayid_rsa`       | 1024-bit RSA | none                          | long-term identity key                                                  | yes                     | long-term/never rotated                                                   | 0            |
| `onion_tap`         | 1024-bit RSA | none                          | medium-term TAP onion key                                               | yes                     | at least 1 week; see 2.1.1. Server descriptor format (`dir-spec.txt`)     | 2            |
| `conn_tls`          | 1024-bit RSA | none                          | short-term connection key for negotiating TLS connections               | yes                     | at most 1 day; see 1.1 Keys and names (`tor-spec.txt`)                    | 2            |
| `ntor`              | x25519       | none                          | medium-term onion key for handling onion key handshakes                 | yes                     | at least 1 week; see 2.1.1. Server descriptor format (`dir-spec.txt`)     | 2            |
| `relayid_ed`        | ed25519      | none                          | long-term identity key                                                  | yes                     | long-term/never rotated                                                   | 0            |
| `relaysign_ed`      | ed25519      | none                          | medium-term signing key                                                 | yes                     | medium-term/rotated periodically                                          | 2            |
| `relaysign_ed_cert` | ed25519      | `relayid_ed`, `relaysign_ed`  | `relaysign_ed` signed by `relayid_ed`                                   | no                      | same lifetime as `relaysign_ed`                                           | 3            |
| `link_ed`           | ed25519      | none                          | short-term link auth key, used to authenticate the link handshake       | maybe                   | regenerated "frequently"                                                  | 2            |
| `link_ed_cert`      | ed25519      | `relaysign_ed`, `link_ed`     | `link_ed` signed by `relaysign_ed`                                      | no                      | same lifetime as `link_ed`                                                | 3            |

(NOTE: The key names from the `Key` column are the formal key names from
`tor-spec` with the `KS_` prefix removed)


## Directory authority keys

TODO

| Key                 | Dependencies                  | Description                                                             |
|---------------------|-------------------------------|-------------------------------------------------------------------------|
| `dirauth_id`(?)     |                               | long-term authority identity key                                        |
| `dirauth_sign`(?)   |                               | directory server's public signing key                                   |
