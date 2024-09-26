TODO RPC:

As of this writing (24 Sep 2024)
this directory holds work-in-progress Python wrappers
for the Arti RPC client library.

All of these APIs are unstable, and the Python is in flux:
don't rely on these yet!

----

You probably don't want to try this out yet;
most of the configuration and setup is unstable.
But if you're brave, and you're on a Unix-like platform...


Build arti with RPC support:

```
cargo build --release --all-features -p arti
```

Build `arti-rpc-client-core` with FFI support:

```
cargo build --release --all-features -p arti-rpc-client-core
```

Tell this library where to find `arti-rpc-client-core`:

```
export LIBARTI_RPC_CLIENT_CORE=$(pwd)/target/release/libarti_rpc_client_core.so
```

Start arti:

```
./target/release/arti proxy -o "rpc.rpc_listen = \"${HOME}/.local/run/arti/SOCKET\""
```

Run the demo!

```
PYTHONPATH="./python/arti_rpc/src:${$PYTHONPATH:-}" python3 \
        python/arti_rpc/samples/rpc_demo.py
```


