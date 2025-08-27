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

* Ensure [`obfs4proxy`](https://gitlab.com/yawning/obfs4) is located at
  `/usr/bin/obfs4proxy`. Typically you can install it using your host system's
  package manager.

* Build an `arti` client. This test assumes that `arti` has been built with the
  `quicktest` profile, putting it at
`../../target/x86_64-unknown-linux-gnu/quicktest/arti`. In the CI this is done
in job `rust-latest` with the invocation:

  ```shell
  $ cargo build --locked --verbose --profile quicktest --target x86_64-unknown-linux-gnu -p arti
  ```

* Build an `arti` client with some extra features enabled, and again using the
  `quicktest` profile, such that the binary ends up at
  `../../target/x86_64-unknown-linux-gnu/quicktest/arti-extra`. In the CI this
  done in job `rust-latest-arti-extra-features` with the invocation:

  ```shell
  $ cargo build --locked --verbose \
      --profile quicktest \
      --target x86_64-unknown-linux-gnu \
      -p arti -p tor-circmgr \
      --bin arti \
      --features full,restricted-discovery,arti-client/keymgr,onion-service-service,vanguards,ctor-keystore
  $ mv target/x86_64-unknown-linux-gnu/quicktest/arti target/x86_64-unknown-linux-gnu/quicktest/arti-extra
  ```

Once those are installed, you can invoke the [`run`](./run) script from
this directory. 

## Reproducibility

Shadow aims to be deterministic. Running this test on a given machine with a
given simulation seed *should* always produce the same result, down to precise
packet sequences and timings, and even dynamically generated keys etc.

Unfortunately this determinism *isn't* guaranteed across different machines. In
particular changing the kernel version, any of the relevant binaries, any of the
dynamically linked libraries (including libc), etc. will change the results.

To more-thoroughly check that the test stably passes across machines (or to
locally attempt to reproduce a failure seen in CI), you can run the test with
multiple seeds. e.g.:

```shell
$ for i in `seq 10`; do if ! ./run -s$i; then break; fi; done
```

Once you've identified a seed that causes a failure or other interesting
behavior, you should be able to reliably reproduce that behavior by rerunning
with that seed on the same machine: `./run -s<seed>`.
