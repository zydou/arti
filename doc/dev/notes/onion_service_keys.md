Here are some keys that we need to store for onion services.


# Clients

Onion service clients need to remember and configure the following private
keys:

  * For a given onion service:
     * Any authentication keys in use with that onion service.

The keys above can be provisioned offline and generated offline.
The public keys associated with them need to be encoded and transferred
textually or in a file, for use by onion service providers.
There is a passwd-style format for these, described in the C tor manual page,
under `HiddenServiceDirectory/client_keys`  and under the heading `CLIENT
AUTHORIZATION`.


# Services

Each onion service need these keys to operate.
It either needs to generate them online, or get provisioned with them from
some offline process.
They can be regenerated as needed, if the identity key is available.

  * For each time period: 
    * A private descriptor signing key,
    * A certificate for that signing key, signed with the `BlindedOnionId`
      for that time period.

To generate those certificates (online or offline), each onion service needs
these keys:

  * A secret identity key.
    If it is kept offline, then some process needs to provision the service
    with the descriptor signing key and certificate.

To operate, an onion service needs these secret keys, which do not have to be
persistent.
The corresponding public keys are published in the service descriptor:
  * A ntor key for its cryptographic handshake.
  * A signing key associated with each active introduction point.

For client authorization, the onion service needs to have:
  * **a list of authorized keys**

----

# What C tor does

A client has a directory of private keys, called its `ClientOnionAuthDir`.
It contains a list of files, each containing a single private key and a
single associated authentiation key.
Filenames are ignored so long as they end with `auth_private`.


An onion service stores all of its material in a single directory, called its
`HiddenServiceDir`.  That directory contains:
  * `authorized_keys` -- a directory containing a list of authorized client
    keys, one per file. Filenames are ignored.
  * `hostname` -- A file containing the `.onion` address for this service
  * `private_key` -- The secret identity key.
  * `client_keys` -- an under-specified store for client keys of another kind.
  * `onion_service_non_anonymous` -- a file generated for single onion
    services.

Note that C tor only stores only secret identity key for services: it doesn't
persist any other keys to disk.
Because of that, C tor only supports running with an online secret identity
key.

# Modes of Operation for Arti

For authorization and authentication keys:
  * Perhaps there should be a mode where you just create files in a
    directory, and Arti processes them correctly.
  * Perhaps there should be a CLI tool that generates keys for you.
  * Perhaps there should eventually be an option to store keys in some
    password-protected way.  Or we could just punt, and say that if you want
    password-protected storage, you should use an encrypted volume.

For service keys:
  * There needs to be a separate set of keys for each onion service.
    Maybe they could be stored in location specified in the configuration
    file (like Tor does it); or maybe they could be stored in a `keys/hs`
    directory, with a tag derived from a name for the onion service provided
    by the user?
  * There needs to be support for running with an online identity key, and
    generating certificates and signing keys as needed.
  * There should (eventually) be support for running with provisioned keys
    only, and provisioning them offline.
     * We do not need to make any keys besides the identity key persistent
       until this happens.
       However, we should have some idea of _how_ we would store other keys,
       to make sure we are not designing ourselves into a corner.
  * There is no need to make any other keys persistent.


