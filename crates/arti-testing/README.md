# arti-testing

Tool for running an Arti client with unusual behavior or limitations.

Example use:

```sh
$ cat ~/.arti_testing.toml
[storage]

cache_dir = "${USER_HOME}/.arti_testing/cache"
state_dir = "${USER_HOME}/.arti_testing/state"

$ ./target/debug/arti-testing bootstrap --config ~/.arti-testing.toml \
          --timeout 120 --expect=success
[...lots of logs]
Operation succeeded [as expected]
TCP stats: TcpCount { n_connect_attempt: 4, n_connect_ok: 2, n_accept: 0, n_bytes_send: 461102, n_bytes_recv: 3502811 }
Total events: Trace: 6943, Debug: 17, Info: 13, Warn: 0, Error: 0

$ faketime '1 year ago' ./target/debug/arti-testing connect \
          --config ~/.arti-testing.toml
          --target www.torproject.org:80
          --timeout 60
          --expect=timeout
[...lots of logs...]
Timeout occurred [as expected]
TCP stats: TcpCount { n_connect_attempt: 3, n_connect_ok: 3, n_accept: 0, n_bytes_send: 10917, n_bytes_recv: 16704 }
Total events: Trace: 77, Debug: 21, Info: 10, Warn: 2, Error: 0
```

## TODO

- More ways to break
  - make TCP connections fail only sporadically
  - make TLS fail
     - With wrong cert
     - Mysteriously
     - With complete junk
     - TLS succeeds, then sends nonsense
     - Authenticating with wrong ID.
  - Munge directory before using it
     - May require some dirmgr plug-in. :p
     - May require

- More things to look at
  - do something on the connection
  - look at bootstrapping status and events
  - Make streams repeatedly on different circuits with some delay.
- Make sure we can replicate all/most test situations from arti#329
- Actually implement those tests.

License: MIT OR Apache-2.0
