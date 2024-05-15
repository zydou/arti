# Generate test OpenSSH keys

The `crates/tor-keymgr/tesdata` test OpenSSH keys were generated with:

```bash
./maint/keygen-openssh-test/generate
```

## `keygen-open-ssh-test` usage

The `keygen-open-ssh-test` binary crate is a helper for
generating expanded-ed25519 and x25519 keys.

You shouldn't need to run `keygen-open-ssh-test` directly.
Instead, prefer using the provided `generate` script to
generate the test keys.

```
Generate an OpenSSH keypair

Usage: generate-custom [OPTIONS] --key-type <KEY_TYPE> --name <NAME>

Options:
      --key-type <KEY_TYPE>
          The type of key to generate.

          Options are `ed25519-expanded`, `x25519`.

          Possible values:
          - expanded-ed25519: An expanded Ed25519 key
          - x25519:           An X25519 key

      --algorithm <ALGORITHM>
          The algorithm name.

          If no algorithm is specified, it defaults to: * `ed25519-expanded@torproject.org` for ed25519-expanded keys * `x25519@torproject.org` for x25519

      --comment <COMMENT>
          The comment

      --name <NAME>
          The output file name

      --public
          Whether to output a public key file

      --private
          Whether to output a private key file

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version

```

### Example

Generate an expanded Ed25519 OpenSSH private key in `expanded-ed25519-ssh-key.private`:

```bash
cargo run -- --key-type expanded-ed25519 \
   --name expanded-ed25519-ssh-key \
   --private
```

Generate an X25519 OpenSSH private key in `x25519-ssh-key.private` that has the
algorithm set to `invalid-algo@bad.org` and the comment to `bar`:
```bash
cargo run -- --key-type x25519 \
   --algorithm invalid-algo@bad.org \
   --name x25519-ssh-key \
   --private \
   --comment bar
```
