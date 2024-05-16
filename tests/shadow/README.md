# Shadow-based integration test

This is an integration test for arti that uses the
[shadow](https://shadow.github.io/) simulator. It creates a simulation of a
small Tor network, uses the `arti` client to perform some transfers across this
simulated network, and validates that the transfers succeeded.

## Running locally

To run locally, you'll need to install shadow itself somewhere on our `PATH`,
following [shadow's installation
instructions](https://shadow.github.io/docs/guide/supported_platforms.html).

Next you'll need to install executables that will run inside the simulation, in the
locations where [`shadow.yaml`](./shadow.yaml) expects to find them.

* Ensure [`tgen`](https://github.com/shadow/tgen/) is on your PATH.

* Ensure [`tor`](https://gitlab.torproject.org/tpo/core/tor) is on your PATH.
  Typically you can install it using your host system's package manager.

* Build an `arti` client with some extra features enabled such that the binary
  ends up at `../../target/x86_64-unknown-linux-gnu/debug/arti-extra`. In the CI
  this done in job `rust-latest-arti-extra-features` with the invocation:

  ```shell
  $ cargo build --locked --verbose \
      --target x86_64-unknown-linux-gnu \
      -p arti -p tor-circmgr \
      --bin arti \
      --features full,experimental-api,arti-client/keymgr,tor-circmgr/ntor_v3,onion-service-service
  $ mv target/x86_64-unknown-linux-gnu/debug/arti target/x86_64-unknown-linux-gnu/debug/arti-extra
  ```

* Build a "vanilla" `arti` client so that the binary is at:
  `../../target/x86_64-unknown-linux-gnu/debug/arti`. In the CI this is done in
  job `rust-latest` with the invocation:

  ```shell
  $ cargo build --locked --verbose --target x86_64-unknown-linux-gnu -p arti
  ```

Once those are installed, you can invoke the [`run`](./run) script from
this directory. 
