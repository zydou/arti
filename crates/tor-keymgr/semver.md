ADDED: `EncodableKey::as_ssh_keypair_data`
ADDED: `SshKeypairData` (re-exported from `ssh-key`)
REMOVED: `KeyType::to_ssh_format`
BREAKING: re-export `ssh_key` rather than just `ssh_key::private::KeypairData`
BREAKING: ssh-key is bumped to 0.6.0 (we re-export `ssh_key`)
