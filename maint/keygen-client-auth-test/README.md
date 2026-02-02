# Generates a KP_hsc_desc_enc / KS_hsc_desc_enc keypair.

C Tor client authorization keys used in `crates/arti/tests/` are produced by this tool.

## Usage

The `keygen-client-auth-test` binary crate is a helper for generating `KP_hsc_desc_enc` / `KS_hsc_desc_enc` keypairs deterministically for testing.

In the root directory run:

```bash
cargo run --bin keygen-client-auth-test -- --hsid <HSID> <--priv-path <PRIV_PATH>|--pub-path <PUB_PATH>>
```

Where `PRIV_PATH` is the path where the private key will be saved, `PUB_PATH` is the path for the public key, and `HSID` is the onion address of the service for which the keys will be generated. At least one of the `priv-path` or `pub-path` flags must be provided.

You can set `ARTI_TEST_PRNG` to control the behavior of the PRNG. For example, you can use `ARTI_TEST_PRNG="deterministic"` to use an arbitrary seed that is the same on every run, or `ARTI_TEST_PRNG="random"` for a randomly seeded PRNG.

The C Tor keystore for testing `arti hsc ctor-migrate` has been generated using the script `generate` from the root directory of the project:

```bash
./maint/keygen-client-auth-test/generate
```

> **Note**: This tool is meant to generate keypairs for testing purposes. It is not secure to generate keypairs for production use with this tool.
