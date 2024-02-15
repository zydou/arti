# HS client auth

This based on our previous discussions from #1028, #1027, #696.

It presents a simplified version of what is proposed in #1028, and an
implementation plan (in the form of action items and tickets).

## Generating keys

### Using the `arti hsc` subcommand

Client authorization keys can be manually generated using the `arti hsc
generate-key stealth` command. In addition to generating a client auth
keypair in the keystore, this command also exports the public part of key,
in the format specified using `--pub-format`.

To generate a client authorization key for service xyz.onion in keystore foo:

```
 arti hsc --config arti.toml generate-key stealth --keystore foo  \
     --nickname alice                                             \
     --hsid xyz.onion                                             \
     --pub-format arti
     # or --pub-format ctor (the format is documented in the tor manpage
     # under CLIENT AUTHORIZATION)
```

Some other possible names for `generate-key stealth`:
  * `generate-key hs-auth-stealth`
  * `generate-key hs-auth-desc`
  * `generate-hs-auth-key stealth`
  * ..

Initially, `arti hsc generate-key` will only support `stealth` keys, for use
with services running in **stealth mode** (as defined in #1028). If we implement
other types of client authorization in the future, we'll likely need to also
extend `arti hsc generate-key`.

This command displays an error if the client already has a keypair of the
specified kind. The public part of a preexisting keypair can be extracted using
`arti hsc export-pubkey`.

(Another possibility would be to let the service generate the client auth keys,
but then we'd need to come up with a secure way for it to communicate the
private part of the key to the client; we decided this is a nonstarter)

#### Public key output format

##### `--pub-format ctor`

With `--pub-format ctor`, `arti hsc generate-key stealth` will generate a
`<client_nickname>.auth` file, with the content in the
`<auth-type>:<key-type>:<base32-encoded-public-key>` format, as per the `CLIENT
AUTHORIZATION` section from `tor(1)`.

##### `--pub-format arti`

Regardless of how we choose to implement client auth configuration on the
service side, with `--pub-format arti`, `arti hsc generate-key stealth` will
generate a `kp_hsc_desc_enc.x25519_public` file containing an OpenSSH key (using
our custom `x22519@spec.torproject.org` algorithm name):

```
x25519@spec.torproject.org AAAAGngyNTUxOUBzcGVjLnRvcnByb2plY3Qub3JnAAAAIGmMjbhv/HldaPDU3zGl4YspW84XMqiEoNon1Tre14Eh
```

This file can then be shared with HS operators through a secure channel (there
are many ways to peel this orange, but they're outside the scope of this
document).

**Suggested action items**:
  * [ ] Decide if `arti hsc generate-key stealth` is a good name for the
    command, and come up with a better one if it isn't
  * [ ] Implement the `arti hsc generate-key` subcommand (#1281)
  * [ ] Implement the `arti hsc export-pubkey` subcommand

### Auto-generating client auth keys

We could also provide an HS client config option for auto-generating the client
authorization keys for specific hidden services:

```toml
   [hs_client]
   # Generate client authorization keys for these services, if needed.
   foo_bar_onion_svc_auth = [
       "foo.onion",
       "bar.onion"
   ]
```

However, I think the UX for this would be bad:
  * it's not obvious at all that the client might also have authorization keys for
    services not listed under `foo_bar_onion_svc_auth`
  * we will need to provide a CLI for extracting the public key in a format that
    can be used by an Arti or C Tor hidden service (`arti hsc
    extract-pub-auth-key-foo-bar`). So auto-generating the
    client auth keys doesn't even save us from having to invoke `arti hsc`

**Suggested action items**:
  * [x] Do not implement this

## Configuring client authorization (client side)

Clients wanting to connect to services that require client authorization don't
need to be explicitly configured to do so: the presence of
`client/<client_id>/<hsid>/ks_hsc_desc_enc.x25519_private` in the client
keystore is enough for the client to be able to connect to `<hsid>` (assuming `<hsid>`
is configured to allow connections from this client).

We might need to revisit this decision if we implement additional types of
client authentication (other types of client auth will potentially need to be
enabled selectively, only for the services that expect it). If we do, we need to
make sure the config changes are backwards-compatible (i.e. clients default to
using their `<hsid>/ks_hsc_desc_enc.x25519_private`, if any, when connecting to
`<hsid>`).

**Suggested action items**: none

## Configuring client authorization (service side)

The authorized clients will be configured using the `authorized_clients` service
option. As mentioned in #1028, we might want to support dynamic HS client
providers at some point, but for now we're only going to allow statically
configured clients.

We have several options for the static authorized clients configuration.

### Option 1: Place authorized client keys in the state dir

We could put the authorized client keys in a directory
within the state dir (`<state_dir>/authorized_clients/<client_nick>`).

We will provide a `arti hss auth-clients` CLI (described under `Extra CLI
subcommands for managing authorized clients` below) for managing client
authorization.

We will use the same naming convention as we do for the keys in an
`ArtiNativeKeystore`, so the paths of client authorization keys
will be of the form
```
<state_dir>/authorized_clients/<client_nick>/kp_hsc_desc_enc.x25519_public
```

but we will additionally support keys in the format used by C Tor. So
`authorized_clients` can also contain entries of the form
```
<state_dir>/authorized_clients/<client_nick>/<client_nick>.auth
```

If both `kp_hsc_desc_enc.x25519_public` and `<client_nick>.auth` are present,
the service will use `kp_hsc_desc_enc.x25519_public` and log a warning.

In addition to provisioning the `authorized_clients` directory, HS operators
wanting to enable client authorization must explictly set `enabled = true` in
the toml config:

```toml
[onion_service."allium-cepa"]
authorized_clients.enabled = true
```


If `authorized_clients` is empty, no clients are authorized to access the
service. Alternatively, we could declare an empty directory means no
authorization is required (this is what C Tor does), but that would be redundant
with the `enabled` option.

Pros:
  * this simplifies the distribution and management of client keys: service
    operators can grant/revoke client authorization by simply moving the client
    keys to/from the `authorized_clients` directory
  * the keys are stored in a familiar format (the same one we use in the
    keystore)

Cons:
  * the presence of an empty `authorized_clients` directory can be interpreted
    in multiple ways ("nobody is authorized" or "everyone is authorized").
    However, this is probably disambiguated by the existence
    `authorized_clients.enabled = true` (`authorized_clients.enabled = false`
    means "everyone is authorized")
  * services need to watch the `authorized_clients` directory for changes (and
    update their view of which clients are authorized accordingly)


### Option 2: Encode the authorized clients as a JSON blob

#1028 suggests encoding the authorized clients in a semi-opaque format, and
embedding

```toml
[onion_service."allium-cepa"]
authorized_clients.enabled = true

authorized_clients.static = {
  "alice": "{...}"
}
```

in the config (or reading each client's config from a separate
`<state_dir>/authorized_clients/config.json`)

However, I'm not sure I see the benefit of using JSON here.

Pros:
  * the authorized clients can be reloaded along with the rest of the config in
    `watch_for_config_changes`
  * it might be more user-friendly (readable) than the alternative. OTOH, I'm
    not sure we want it to be readable (we don't want to encourage users to
    manually modify it)

Cons:
  * it complicates the distribution and management of client keys: service
    operators have to fiddle with the config to authorize new clients (they need
    to paste the contents of `kp_hsc_desc_enc.x25519_public` in the config).
    This can be alleviated by providing an `arti hss auth-clients` subcommand
    for managing authorized clients (see `Extra CLI subcommands for managing
    authorized clients` below)

**Suggested action items**:
  * [ ] Implement Option 1 for static authorized client configuration
  * [ ] Make sure the service reloads its authorized clients if there are
    changes to the `authorized_clients` directory

## Extra CLI subcommands for managing authorized clients

We might want to provide an `arti hss auth-clients` command for managing a
service's authorized clients (that is, assuming we implement `Option 1` from
above).

```
NAME
       arti-hss-auth-clients - Manage the authorized clients of this hidden service

SYNOPSIS
       arti hss auth-clients [SUBCOMMAND]

DESCRIPTION
      A command for managing the authorized clients of an Arti hidden service.

      TODO: document how these commands are supposed to work after we reach a
      conclusion in #1028

SUBCOMMANDS
       help                  Print this message or the help of the given subcommand(s)
       list                  List the authorized clients
       import                Import the public keys of a client
       disable               Un-authorize a previously authorized client
       remove                Purge the client authorization keys of a client, unauthorizing them
       enable                Authorize a new client
```

For example, `arti hss auth-clients import --nickname client-foo
~/downloads/kp_hsc_desc_enc.x25519_public` would create an authorized client
called `client-foo`.

Since `import`, `disable`, `enable` are essentially just wrappers around `cp`
and `mv`, this subcommand may not be particularly useful. OTOH, `enable` and
`disable` could be useful for managing temporarily unauthorized clients: arti
would maintain a separate `revoked_clients` (`disabled_clients`?) directory, and
`disable` and `enable` would move keys to and from it.

In addition to the commands listed under `SUBCOMMANDS` above, we might also want
to provide subcommands for:
  * retrieving the absolute path of `<state_dir>/authorized_clients`
  * retrieving the absolute path of
    `<state_dir>/authorized_clients/<client_nick>`

**Suggested action items**:
  * [ ] Make this a low-priority item (and implement it if time permits)
