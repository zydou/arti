## Reserved `ArtiPath` values

The following table lists the `ArtiPath`s currently recognized by the key
manager.

**Note**: the `Key` column represents the name of the key as specified in
[rend-spec-v3].


| Key                  | Type             | Description                                                             | `ArtiPath`                                                                |
|----------------------|------------------|-------------------------------------------------------------------------|---------------------------------------------------------------------------|
| `KS_hsc_desc_enc`    | x25519           | Client service discovery key, used for onion descriptor decryption.         | `client/<hsid>/ks_hsc_desc_enc.x25519_private`                            |
| `KS_hsc_intro_auth`  | ed25519          | Client authorization key, used for the introduction protocol.           | `client/<hsid>/ks_hsc_intro_auth.ed25519_private`                         |
| `KS_hs_id`           | expanded ed25519 | Service identity keypair.                                               | `hss/<svc_nickname>/ks_hs_id.expanded_ed25519_private`                     |
| `KS_blind_id`        | expanded ed25519 | Blinded service identity keypair.                                       | `hss/<svc_nickname>/ks_hs_blind_id+<time_period>.expanded_ed25519_private` |
| `KP_blind_id`        | ed25519          | Blinded service identity keypair.                                       | `hss/<svc_nickname>/ks_hs_blind_id+<time_period>.ed25519_public`           |
| `KS_hs_desc_sign`    | ed25519          | Blinded service identity public key.                                    | `hss/<svc_nickname>/ks_hs_desc_sign+<time_period>.ed25519_private`         |

[rend-spec-v3]: https://gitlab.torproject.org/tpo/core/torspec/-/blob/main/rend-spec-v3.txt
