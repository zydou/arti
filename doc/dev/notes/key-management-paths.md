## Reserved `ArtiPath` values

The following table lists the `ArtiPath`s currently recognized by the key
manager.

**Note**: the `Key` column represents the name of the key as specified in
[rend-spec-v3].


| Key                  | Type         | Description                                                             | `ArtiPath`                                                                |
|----------------------|--------------|-------------------------------------------------------------------------|---------------------------------------------------------------------------|
| `KS_hsc_desc_enc`    | x25519       | Client authorization key, used for onion descriptor decryption.         | `client/<client_id>/<hsid>.onion/KS_hsc_desc_enc.x25519`          |
| `KS_hsc_intro_auth`  | ed25519      | Client authorization key, used for the introduction protocol.           | `client/<client_id>/<hsid>.onion/KS_hsc_intro_auth.ed25519`       |

[rend-spec-v3]: https://gitlab.torproject.org/tpo/core/torspec/-/blob/main/rend-spec-v3.txt
