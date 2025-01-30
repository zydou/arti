---
title: Testing 
---

# Simulating failures in Arti

The main reason for simulating failures is to ensure that Arti's behavior is "generally reasonable" when the network is down or misbehaving, when the localhost is set up in a confusing way, etc.

Here "generally reasonable" means that we aren't making a huge number of connections to the network or wasting a huge amount of bandwidth. Similarly, we shouldn't be using huge amounts of CPU, or filling up the logs at level `info` or higher.

The primary purpose of simulating failures is to verify that Arti behaves appropriately in scenarios where the network is down or misconfigured, or when the localhost setup is confusing. This includes avoiding excessive network connections, bandwidth consumption, CPU usage, and preventing log overflow at levels `info` or higher.

It is an extra benefit if we can ensure that our bootstrap reporting mechanisms give us accurate feedback in these cases, and diagnose the problem accurately.

Most of the examples here will use the [`arti-testing`](https://tpo.pages.torproject.net/core/doc/rust/arti_testing/index.html) tool.  Some will also use a small Chutney network. In either case, you'll need an explicit client configuration, since `arti-testing` does not want you to use the default; we'll assume you've put it in `${ARTI_CONF}`.

**Note:** You would not *need* to use chutney in these cases if Arti is in fact well-behaved. Although, it is helpful to do so if you think there might be problems in Arti's behavior because you would not want to flood the real network.

This guide assumes that you have a Linux environment, and explains how to simulate different kinds of bootstrapping and network failures in Arti.

## What to look at

The output from `arti-testing` will tell you whether bootstrapping succeeded or failed. If bootstrapping is not expected to succeed, try adding `--timeout ${DELAY} --expect timeout` to indicate that the
operation isn't supposed to succeed, and should eventually time out.

If bootstrapping or connecting succeeds when it shouldn't, then the test went wrong.

When we're done, `arti-testing` will tell us some statistics about TCP connections and log messages. Here is an example of a not-too-bad attempt to bootstrap over 30 seconds:

```bash
TCP stats: TcpCount { n_connect_attempt: 1, n_connect_ok: 1, n_accept: 0, n_bytes_send: 17223, n_bytes_recv: 59092 }
Total events: Trace: 159, Debug: 14, Info: 16, Warn: 8, Error: 0
```

Whereas, this is an example of problematic behavior over a similar period:

```bash
Timeout occurred [as expected]
TCP stats: TcpCount { n_connect_attempt: 1220, n_connect_ok: 1220, n_accept: 0, n_bytes_send: 1394460, n_bytes_recv: 4267636 }
Total events: Trace: 13431, Debug: 2088, Info: 2383, Warn: 15, Error: 0
```

## Failures related to time

These require the `faketime` tool.

#### System clock set wrong, no directory cached

Start with an empty cache and empty state file, then run:

```bash
faketime ${WHEN} arti-testing bootstrap -c ${ARTI_CONF} --timeout 30
```

Try this with different values of `WHEN`:

- '4 hours ago'
- '1 day ago'
- '1 month ago'
- '1 day'
- '1 month'
- '1 year'

#### System clock set wrong, live directory cached.

Again, if you run the following command with an empty cache and state file as a starting point, it is expected to succeed.

```bash
arti-testing bootstrap -c ${ARTI_CONF}
```

Now run:

```bash
faketime ${WHEN} arti-testing connect -c ${ARTI_CONF} \
        --target www.torproject.org:80 \
        --timeout 30 --retry 0
```

Try this with different values of `WHEN` as above. This simulates a case where we previously bootstrapped with a reasonably live directory, but we wound up with a wrong clock when we restarted.

#### System clock set wrong, obsolete directory cached

You can simulate this with a directory that you made before, then copied into your cache directory. Use `faketime` to set the current time to a point at which the directory was valid, or recently valid.

**Note:** This test won't work well with chutney, since chutney directory lifetimes are very short.

## Failures related to the network

The `arti-testing` tool can simulate multiple kinds of errors:

- connections fail immediately or after a little while(`-tcp-failure error --tcp-failure-delay 1`)
- connections time out and never succeed (`-tcp-failure timeout`)
- connections succeed, but drop all data and say nothing. (`-tcp-failure blackhole`)

You can arrange for these failures to start in the bootstrap phase (`--tcp-failure-stage bootstrap`) or in the connect stage (`--tcp-failure-stage connect`).

With these options, you can simulate different kinds of failures by starting with an empty directory cache (and optionally empty state). The bootstrap phase failures correspond to failures on your fallback directories, while the connect-phase failures correspond to failures on the live network.

> There's an issue here where if you have open connections to the fallbacks, the TCP-failure code won't yet make them start failing when you connect to the network. As a workaround, bootstrap in a separate `arti-testing` call, then connect with TCP failures enabled.
> 

For example:

To fail **during** bootstrapping, clear your cache and run the command:

```bash
arti-testing bootstrap -c ${ARTI_CONF} --timeout 30 --tcp-failure error
```

To fail **after** bootstrapping, clear your cache then run the commands:

```bash
# This should succeed
arti-testing bootstrap -c ${ARTI_CONF}

# This will fail.
arti-testing connect -c ${ARTI_CONF} \
        --target www.torproject.org:80 \
        --timeout 30 --retry 0 \
        --tcp-failure blackhole
```

## Partial network blocking

You can make the above network failures conditional, to simulate different kinds of broken local networks. Try `--tcp-failure-on v4` to simulate an IPv4-only network, or `--tcp-failure-on non443` to simulate
a network that blocks everything but HTTPS.

> These won't work with chutney networks, since a typical chutney network's relays are all on IPv4 with high ports.
> 

## Network identity mismatch

One way to generate a diverse range of failures is to combine and experiment with the `arti.toml` files from two different chutney networks. Older chutney networks can be found in subdirectories of `$CHUTNEY_PATH/net/`, except the `nodes` directory.

If you use an older set of fallback directories, you'll simulate the case where the client can't actually connect to any fallback directories because its beliefs about their identities are all wrong.

If you keep the running set of fallback directories, but use the older set of authorities, you'll simulate the case where the client fetches a directory, but doesn't believe in any authorities that signed it.

For both of these cases, start with an empty cache and use the `arti-testing bootstrap` command.
