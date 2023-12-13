# Running an onion service

As of January 2024, you can run an onion service... barely.

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
and `experimental`
features, as in:

```
cargo build -p arti --release \
    --features=onion-service-service
```

## Configuring your onion service(s)

Add a block like this to your arti configuration:

```
# The second part of this section's name is a local nickname for this
# onion service.
#
# This is saved on disk, and used to tell onion services apart; it is not
# visible outside your own Arti instance.

[onion_services."allium-cepa"]

# A description of what to do with incoming connections to different ports.
# This is given as a list of rules; the first matching rule applies.

proxy_ports = [
     # Forward port 80 on the service to localhost:10080.
     ["80", "127.0.0.1:10080"],
     # Tear down the circuit on attempts to conenct to port 22.
     ["22", "destroy"],
     # Ignore attempts to connect to port 265.
     # ("ignore" is not generally a good idea for an anonymous service;
     #  "destroy" is safer.)
     ["265", "ignore"],
     # Forward connections to other ports in range 1-1024 to
     # a local UNIX-domain socket.  (Unix only)
     ["1-1024", "unix:/var/run/allium-cepa/socket"],
     # Any other connection attempts will make us destroy the circuit.
     # (This is the default; you do not need to include this line.)
     ["*", "destroy"]
]
```

### Disabling safe logs

For now, you'll need to add the following to your `logging`
section:

```
[logging]
log_sensitive_information = true
```

> This is bad for security but for now it's the only way
> to find out your .onion address.


### Overriding key storage location

If you want, you can also override the default location
where arti stores your keys, as follows:

```
[storage.keystore]
path = "~/arti_hax/path-to-my/keystore"
```

> NOTE: This defaults to something relative to ARTI_LOCAL_DIR,
> and not to something relative to state_dir.
> There's a TODO about that, which can be somewhat surprising.
> Also see [#1162](https://gitlab.torproject.org/tpo/core/arti/-/issues/1162).

## Starting your onion service

Just start arti as usual, as in

./target/release arti proxy -c config_file.toml

## Finding your .onion address

When you start arti, look for a log message like this:

```
2023-12-12T17:25:42Z  INFO tor_hsservice::svc: Generated a new identity for service allium-cepa: s6kocstkk2spuifmh6bdajma3veek2r6ecgszgdgxgbvjtlmjohth3id.onion
```

> We intend to add a CLI for this.
> But for now, that is the workaround.

If it says "[scrubbed]" instead of an `.onion address,
you forgot to disable safe logs;
see "Disabling safe logs" above.

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

### Incompatibility with future versions of Arti

We intend to change the on-disk key file formats, <!-- #1095 #1108 -->
and perhaps the layout of the on-disk key storage. <!-- #1082 #1111 -->

Therefore, when you upgrade to later versions of Arti
you won't be able to use the same `.onion` domain!
We currently don't have any plans to provide a convenient migration path.

We may make other incompatible changes too,
for example to the configuration format and command line options.

### Persistent state (privacy, usability, and disk space hazards)

Arti needs to generate and record various information on-disk
as it operates your hidden service.
Currently, there are many kinds of this state that nothing expires.
So your state directory (probably in `~/.local`) will grow indefinitely.
This is a privacy hazard; it's also bad for disk usage,
although in a test deployment the amount of space used should be modest.

Likewise,
if you want to decomission a hidden service 
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

There are a *ton* of missing security featuers.
You should not expect privacy (yet)
when you are running onion services with Arti.

> TODO: List these

 * Missing "Vanguard" support means that
   operating a hidden service with Arti
   might enable (or help) attackers to discover your Guard relays
   and deanonymise you.
   <!-- #98 -->

 * No meaningful protection against denial of service attacks.
   Rate limits, per-circuit connection limits, and memory limits,
   are not implemented.
   <!-- #102 #351 #102 #1124 -->

### Rust API instability

This HOWTO is for using the `arti` command line program.
However, for the avoidance of doubt:
the Tor Hidden Service and key management APIs
in the Arti Rust codebase are quite unstable,
as is indicated by the need to turn on experimental features.

With those experimental features enabled
we do not promise not to violate semver!
