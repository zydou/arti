# Keys supported by the Arti key store

The key manager will need to be able to generate all the keys documented here.

## Onion service keys

| Key                 | Type    | Dependencies                  | Description                                                             |
|---------------------|---------|-------------------------------|-------------------------------------------------------------------------|
| `hs_id`             | ed25519 | none                          | long-term identity key                                                  |
| `hs_blind_id`       | ed25519 | `hs_id`                       | blinded signing key (derived from `hs_id`)                              |
| `hs_desc_sign`      | ed25519 | none                          | descriptor signing key                                                  |
| `hs_desc_sign_cert` | ed25519 | `hs_blind_id`, `hs_desc_sign` | descriptor signing certificate (`hs_desc_sign` signed by `hs_blind_id`) |
| `hsc_desc_enc`      | x25519  | none                          | the client's counterpart to `hss_desc_enc`                              |
| `hsc_intro_auth`    | ed25519 | none                          | client auth key for use in the introduction protocol                    |

(NOTE: The key names from the `Key` column are the formal key names from
`rend-spec-v3` with the `KS_` prefix removed)

Note: `hss_desc_enc` (used by hidden services to encrypt the inner part of their
descriptors when client auth is enabled) is not listed here, because it is the
public part of the `(KP_hss_desc_enc, KS_hss_desc_enc)` keypair, and Arti key
stores do not store public keys.

That being said, when generating client auth keys, the key management CLI will
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

| Key                 | Type         | Dependencies                  | Description                                                             |
|---------------------|--------------|-------------------------------|-------------------------------------------------------------------------|
| `relayid_rsa`       | 1024-bit RSA | none                          | long-term identity key                                                  |
| `onion_tap`         | 1024-bit RSA | none                          | medium-term TAP onion key                                               |
| `conn_tls`          | 1024-bit RSA | none                          | short-term connection key for negotiating TLS connections               |
| `ntor`              | x25519       | none                          | medium-term onion key for handling onion key handshakes                 |
| `relayid_ed`        | ed25519      | none                          | long-term identity key                                                  |
| `relaysign_ed`      | ed25519      | none                          | medium-term signing key                                                 |
| `relaysign_ed_cert` | ed25519      | `relayid_ed`, `relaysign_ed`  | `relaysign_ed` signed by `relayid_ed`                                   |
| `link_ed`           | ed25519      | none                          | short-term link auth key, used to authenticate the link handshake       |
| `link_ed_cert`      | ed25519      | `relaysign_ed`, `link_ed`     | `link_ed` signed by `relaysign_ed`                                      |

(NOTE: The key names from the `Key` column are the formal key names from
`tor-spec` with the `KS_` prefix removed)


## Directory authority keys

TODO

| Key                 | Dependencies                  | Description                                                             |
|---------------------|-------------------------------|-------------------------------------------------------------------------|
| `dirauth_id`(?)     |                               | long-term authority identity key                                        |
| `dirauth_sign`(?)   |                               | directory server's public signing key                                   |
