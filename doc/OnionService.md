# Running an onion service

As of January 2024, you can run an onion service... barely.

In this document, we'll explain how to do it, and why you might not
want to do so yet.

This is a temporary document;
we'll remove most of the limitations here as we do more development,
and integrate these instructions elsewhere.

## Building arti with onion service support

When you build arti, make sure that you enable the `onion-service-service`
and `experimental`
features, as in:

```
cargo build -p arti --release \
    --features=onion-service-service,experimental
```

> BUG:
> "experimental" shouldn't be necessary here, but we don't actually
> get all the keymgr stuff in arti-client unless it's present,
> I think.

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
enabled = true
path = "~/arti_hax/path-to-my/keystore"
```

> NOTE: This defaults to something relative to ARTI_LOCAL_DIR,
> and not to something relative to state_dir.
> There's a TODO about that, which can be somewhat surprising.

> NOTE 2: "enabled" needs to be set. Maybe it should default to true?

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

Note that this is only logged on the first startup!

> NOTE: It might be a good idea to have a
> "starting onion service with existing ID {}"
> message for now.

## Limitations

### Stability

We expect that there will be some stability
and reachability issues for now.

### No client authorization

There is no configuration logic (yet)
to let you enable client authorization.

### Missing security features

There are a *ton* of missing security featuers.
You should not expect privacy (yet)
when you are running onion services with Arti.

