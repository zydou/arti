## Reserved `ArtiPath` values

The following table lists the `ArtiPath`s currently recognized by the key
manager.

**Note**: the `Key` column represents the name of the key as specified in
[rend-spec-v3].


| Key                  | Type             | Description                                                             | `ArtiPath`                                                                |
|----------------------|------------------|-------------------------------------------------------------------------|---------------------------------------------------------------------------|
| `KS_hsc_desc_enc`    | x25519           | Client authorization key, used for onion descriptor decryption.         | `client/<client_id>/<hsid>/KS_hsc_desc_enc.x25519_private`                |
| `KS_hsc_intro_auth`  | ed25519          | Client authorization key, used for the introduction protocol.           | `client/<client_id>/<hsid>/KS_hsc_intro_auth.ed25519_private`             |
| `KS_hs_id`           | expanded ed25519 | Service identity keypair.                                               | `hss/<svc_nickname>/KS_hs_id.expanded_ed25519_private`                     |
| `KP_hs_id`           | ed25519          | Service identity public key.                                            | `hss/<svc_nickname>/KS_hs_id.ed25519_public`                               |
| `KS_blind_id`        | expanded ed25519 | Blinded service identity keypair.                                       | `hss/<svc_nickname>/KS_hs_blind_id+<TIME_PERIOD>.expanded_ed25519_private` |
| `KP_blind_id`        | ed25519          | Blinded service identity keypair.                                       | `hss/<svc_nickname>/KS_hs_blind_id+<TIME_PERIOD>.ed25519_public`           |
| `KS_hs_desc_sign`    | ed25519          | Blinded service identity public key.                                    | `hss/<svc_nickname>/KS_hs_desc_sign+<TIME_PERIOD>.ed25519_private`         |

[rend-spec-v3]: https://gitlab.torproject.org/tpo/core/torspec/-/blob/main/rend-spec-v3.txt
