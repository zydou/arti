# Running an onion service

As of February 2024, you can run an onion service...
for testing purposes.

In this document, we'll explain how to do it, and why you might not
want to do so yet.

This is a temporary document;
we'll remove most of the limitations here as we do more development,
and integrate these instructions elsewhere.

**Do not follow these instructions**
without looking at the Limitations section!
There are many serious problems right now!

## Building arti with onion service support

When you build arti, make sure that you enable the `onion-service-service`
feature, as in:

```
cargo build -p arti --locked --release \
    --features=onion-service-service
```

## Configuring your onion service(s)

Add a block like this to your arti configuration.

(You will probably want to customize it,
unless you want this exact behavior.)

```
# The second part of this section's name ("allum-cepa") is a local nickname
# for this onion service.
#
# This is saved on disk, and used to tell onion services apart; it is not
# visible outside your own Arti instance.

[onion_services."allium-cepa"]

# A description of what to do with incoming connections to different ports.
# This is given as a list of rules; the first matching rule applies.

proxy_ports = [
     # Forward port 80 on the service to localhost:10080.
     ["80", "127.0.0.1:10080"],
     # Tear down the circuit on attempts to connect to port 22.
     ["22", "destroy"],
     # Ignore attempts to connect to port 265.
     # ("ignore" is not generally a good idea for an anonymous service;
     #  "destroy" is safer.)
     ["265", "ignore"],
     # Any other connection attempts will make us destroy the circuit.
     # (This is the default; you do not need to include this line.)
     ["*", "destroy"]
]
```

## Starting your onion service

Just start arti as usual, as in

./target/release arti proxy -c config_file.toml

## Finding your .onion address

When you start arti, look for a log message like this:

```
2023-12-12T17:25:42Z  INFO tor_hsservice::svc: Generated a new identity for service allium-cepa: [scrubbed]
```

(If it includes a .onion address instead of `[scrubbed]`,
you have disabled safe logging.)

Once this has appeared, 
you can find your onion .address using the `arti hss` command
(replace `<NICKNAME>` with the nickname of your service):
```
./target/release/arti hss --nickname <NICKNAME> onion-name
```

## Limitations

Arti's Onion Service (hidden service) support is
**suitable for testing and experimentation only**
and should not be used for anything you care about.
It
**may even compromise the privacy of your other uses of the same Arti instance!**

The limitations discussed here are only the most important ones.
There are many missing features.

### Stability

We expect that there will be some stability
and reachability issues for now.
You may experience bugs including internal errors and Rust stack backtraces.

### Persistent state (privacy, usability, and disk space hazards)

Arti needs to generate and record various information on-disk
as it operates your hidden service.

There is not currently a built-in way
to decomission a hidden service:
you'll probably want to delete its state
but there is no tooling for that.

So, right now
you'll have to manually remove things.
But there is not even any documentation about what to safely remove.

<!-- #1087 -->

### No client authorization

There is no configuration logic (yet)
to let you enable client authorization.

> (This is #1028.)

### Missing security features; deanonymisation risks

There are a *ton* of missing security features.
You should not expect privacy (yet)
when you are running onion services with Arti.

 * Missing "Vanguard" support means that
   operating a hidden service with Arti
   might enable (or help) attackers to discover your Guard relays
   and deanonymise you.
   <!-- #98 -->

 * No meaningful protection against denial of service attacks.
   Rate limits, per-circuit connection limits,
   proof-of-work, and memory limits
   are not implemented.
   <!-- #102 #351 #102 #1124 -->

 * We do not yet support circuit padding machines
   to hide the patterns onion service circuit setup.
   <!-- #63 -->

# Rust APIs

If you want to write a program in Rust 
that provides an onion service,
see the [`TorClient::launch_onion_service`] API.

Also have a look at the `tor-hsrproxy` crate
if you want to relay the connections from an onion service
to a local port.

[`TorClient::launch_onion_service`]: https://tpo.pages.torproject.net/core/doc/rust/arti_client/struct.TorClient.html#method.launch_onion_service
