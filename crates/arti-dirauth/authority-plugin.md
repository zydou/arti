# Notes on authority plugin API

The plugin is an executable binary.  It is invoked by C tor
in order to support using consensus methods implemented in Rust.
For arti authorities, we won't use a plugin.

## General notes

In every mode, the plugin runs to completion or error, and then exits.
It exits with the following exit codes:
 - 0: Success.
 - 8: Invalid inputs or invocation.
 - 10: "Fall back to C tor consensus" (See below.)
 - 32: Internal error.

C Tor must treat any other exit status as a total failure of the plugin.
See "Handling Failure" below.

Because of file encoding issues,
the plugin DOES NOT have to build or run on Windows.
If it builds on Windows, it SHOULD fail when run.

Unless otherwise stated, each of the plugin's input or output files
is in the Tor Network Document metaformat.

The plugin does not write partial files; it does the write-then-rename
trick to make sure that its writes are as atomic as possible.
For an output file OUT, the plugin may use the filename OUT.tmp
in the same directory, for this purpose.
C Tor MUST NOT read such .tmp files;
it MAY delete them (when it's not running the plugiin).

C Tor MUST NOT read any output file
it expects to be created by a plugin invocation
unless the plugin exited with status 0.

The plugin should write error messages to stderr.  C Tor may log those
messages.

C Tor should ensure that all specified output files don't exist
before it invokes the plugin.  (The plugin should never have to overwrite a
file.)

C Tor _and_ the plugin should both verify (using `check_private_dir` or
`fs_mistrust` respectively) that they are reading and writing from locations
that are only under the control of trusted users.

Unless otherwise specified, arguments may be given in any order.

Unless otherwise specified, any filename argument may be replaced
with `-` to indicate `write to stdout` or `read from stdin`.

> In examples below I'll pretend that the name of the plugin binary
> is `plugin`.  It should probably be something different.
>
> The command line options are chosen more or less arbitrarily,
> with no design taste.  Feel free to change to something more sensible.

## Modes of operation

The plugin runs in three modes.  Two are for the voting stage;
one is for the consensus stage.

They are:

1. List consensus methods.
2. Compute microdescriptors.
3. Compute consensus

### Mode 1: List consensus methods.

Invocation:

```
plugin list-methods -o <FILENAME>
```

This method should write every consensus method supported by the plugin to
`FILENAME`, as a space-separated newline-terminated list.
(Therefore, this output file is not in the netdoc metaformat.)

### Mode 2: Compute microdescriptors.

Invocation:

```
plugin compute-mds -t <TIME> -i <FILENAME> [-i <FILENAME>...] --mds-out <MDFILE> --meta-out <METAFILE>
```

Every input file will contain a set of zero or more server descriptors.
These will be concatenated,
with optional "annotation lines" beginning with '@' at the start of each descriptor.
The annotation lines are an extension/exception to the network metaformat.
The plugin MUST ignore all lines starting with `@`.
A file MAY end with a truncated descriptor,
or contain a descriptor that Arti considers invalid.
If it does, the plugin SHOULD ignore any such descriptor.
The files MAY contain duplicate descriptors.
If they do,
the plugins SHOULD ignore all but the first instance of each descriptor.
The files MAY contain multiple distinct descriptors for each router.
The plugin SHOULD process all distinct descriptors.
The plugin SHOULD verify signatures on routerdescs and and check timeliness
with respect to `<TIME>`.

`<TIME>` is a decimal integer representing a Unix timestamp.

> In practice, the authority is likely to use its `cached-descriptors` and
> `cached-descriptors.new` files as the inputs.

From the input files,
the plugin will compute a microdescriptor for every supported
(router descriptor, consensus method) tuple.
The plugin SHOULD de-duplicate identical microdescriptors.
The plugin writes the microdescriptors, concatenated,
to the `MDFILE` file.
The plugin writes a map to the `METAFILE` file.
This map is formatted as a series of lines with the following format.

`m CONSENSUS_VERSION RSAID EDID DD MD`

Where...

* `CONSENSUS_VERSION` is a single decimal integer
  representing the consensus format that
  produced the microdescriptor referenced in this line.

* `RSAID` is the fingerprint of the descriptor's RSA identity
  (`KP_relayid_rsa`). This is exactly the same as the `Identity` field in a
  vote's `r` line.

* `EDID` is the fingerprint of the Ed25519 identity. (`KP_relayid_ed`).
  This is the key itself, encoded in the usual way with unpadded
  base64.

* `DD` is the digest of the signed portion of the relay descriptor, as
  encoded in the "Digest" field of a vote's `r` line.

* `MD` is a SHA256 digest of the microdescriptor, encoded in unpadded base64.
  This is computed in the same way as the "digest" field of a vote's
  `m` line.

C Tor SHOULD ignore extra arguments and spaces in this line.
C Tor SHOULD treat unparseable lines as a total failure of the plugin.

> The formats here are meant to be as close as possible to what we have to
> put in our votes, and to what C tor expects to put into its md cache(s).

### Mode 3: Computing a consensus

Invocation

```
plugin compute-consensus --ids <KEYFILE> \
       --votes <VOTEFILE> [--votes <VOTEFILE>...]
       -o <OUTFILE>
```

The `KEYFILE` file will contain zero or more lines, of the form:
`auth NICKNAME DIGEST`.

* `NICKNAME` is an arbitrary ASCII string without spaces to identify an
authority when producing error messages.

* `DIGEST` is a hex-encoded SHA256 digest of an authority's `KP_auth_id_rsa`
  identity key.

Each entry represents a single valid voting authority.  The number of
authorities is equal to the lines in the file.

This should be parsed in accordance with the regular
[netdoc metaformat](https://spec.torproject.org/dir-spec/netdoc.html).

> This format is chosen to consist entirely of elements present in C tor's
> DirServer configuration line.


Each VOTEFILE contains zero or more concatenated vote documents.

> In C tor, I think this is just the `v3-status-votes` file.
> ahf/dgoulet please confirm?

The plugin MUST reject any votes that cannot be parsed,
or which come from an unrecognized authority,
or which are not correctly signed.

The plugin MUST return an error if more than one vote appears for any
authority.

The plugin MUST return an error if the votes do not have identical
time ranges.

The plugin MUST exit with error code 10 ("Fall back to C tor Consensus")
if it finds that the consensus method that should be used
(that is, "the highest \[method\] supported by more than 2/3 of the authorities voting")
is less than 100.

> This means that C tor authorities should invoke the plugin unconditionally
> once they have decided to vote, and only compute a vote themselves
> if the plugin exits with the error code.

On success, the plugin writes a consensus,
_without its signature_, to the file at `OUTFILE`.


## Sketch of C tor authority behavior

When generating a vote (1):
 - Remove `DATADIR/extra-methods.txt`
 - Invoke `plugin consensus-methods -o DATADIR/extra-methods.txt`.
 - Read extra-methods.txt. Parse the result. Add the methods, sorted, to the
   list of consensus methods that we support natively.  Include this in our
   consensus-methods line.

When generating a vote (2):
 - Remove `DATADIR/{new_mds,mds_meta}`.
 - Invoke `plugin compute-mds -i CACHEDIR/cached-descriptors -i CACHEDIR/cached-descriptors.new
   --mds_out DATADIR/new_mds --meta-out DATADIR/mds_meta`.
 - Read the `new_mds` and `mds_meta` files.  Parse the `new_mds` and add them
   to our cache if they are not already there.  Then use the `mds_meta` file
   contents when building `m` lines for the vote.
   (I.e. C Tor must merge the microdescriptor information
   for Arti consensus methods from the plugin
   with its own internally-generated md information for its own consensus methods.)

When computing a consensus:
 - (After deciding that we will not receive any more votes, like usual...)
 - Ensure that all the votes have been written to
   `CACHEDIR/v3-status-votes`. (Assuming that this is the file where we typically have
   written them.)
 - Write `DATADIR/authority_ids` based on our configured list of authorities.
 - Remove `DATADIR/plugin_consensus_new`.
 - Invoke `plugin compute-consensus --ids DATADIR/authority_ids --votes
   CACHEDIR/v3-status-votes -o DATADIR/plugin_consensus_new`.
 - If the exit code is 0:
   - Read `DATADIR/plugin_consensus_new`.
   - Append a new signature to it.
   - Verify that the signed consensus can be parsed, that our signature can
     be checked, and that the consensus refers to the expected time range.
   - Publish it as usual.
 - If the exit code is 10 ("Fall back to C tor Consensus"):
   - Fall back to our current consensus logic.

## Handling Failure

If the plugin deviates from this spec,
or fails in some way where we do not explicitly specify recovery behavior,
the C tor authority should log a detailed error,
and not use the plugin or its outputs again
for the lifetime of the current process.

> This can result in a single failed consensus,
> if the authorities have voted to use a consensus method
> which they can no longer provide when voting.
