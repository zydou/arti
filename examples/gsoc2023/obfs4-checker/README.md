# Obfs4 Connection Checker

This small tool attempts to check obfs4 bridge status over a long period of time.

A large list of bridges is intended to be ingested into the program once, and then
another endpoint is meant to be polled in order to get updates on those bridges'
states.

## Usage

Launch the program by running `cargo run`

Then, to pass bridges into the program for an initial scan, make the following HTTP POST request.

Here is the `curl` command:

```text
  curl -X POST localhost:5000/bridge-state -H "Content-Type: application/json" -d '{"bridge_lines": ["BRIDGE_LINE"]}'
```

where you should replace `BRIDGE_LINE` by all the bridges that you wish to test

The output would look something like this:

```json
{
  "bridge_results": {
    "obfs4 45.145.95.6:27015 C5B7CD6946FF10C5B3E89691A7D3F2C122D2117C cert=TD7PbUO0/0k6xYHMPW3vJxICfkMZNdkRrb63Zhl5j9dW3iRGiCx0A7mPhe5T2EDzQ35+Zw iat-mode=0": {
      "functional": false,
      "last_tested": "2023-08-16T05:44:06.906005329Z",
      "error": "Channel for [scrubbed] timed out"
    },
    "obfs4 37.218.245.14:38224 D9A82D2F9C2F65A18407B1D2B764F130847F8B5D cert=bjRaMrr1BRiAW8IE9U5z27fQaYgOhX1UCmOpg2pFpoMvo6ZgQMzLsaTzzQNTlm7hNcb+Sg iat-mode=0": {
      "functional": false,
      "last_tested": "2023-08-16T05:44:06.905914678Z",
      "error": "Network IO error, or TLS error, in TLS negotiation, talking to Some([scrubbed]): unexpected EOF"
    },
    "obfs4 192.95.36.142:443 CDF2E852BF539B82BD10E27E9115A31734E378C2 cert=qUVQ0srL1JI/vO6V6m/24anYXiJD3QP2HgzUKQtQ7GRqqUvs7P+tG43RtAqdhLOALP7DJQ iat-mode=1": {
      "functional": true,
      "last_tested": "2023-08-16T05:44:06.905823776Z"
    }
  },
  "time": 21
}
```

For getting updates, right now we have a `/updates` GET endpoint that you can poll for updates.

For that you can run

```text
  curl localhost:5000/updates
```

This has the same output structure as the `/bridge-state` endpoint. 

To add additional bridges for testing, call `/add-bridges`. It is a POST endpoint which takes
the bridge list in the same manner as `/bridge-state`, and only returns a status code indicating
success or failure. From there on, poll `/updates` as usual to get connection info.

### Usage Disclaimers

Note that this tool is currently in active development and needs further work and feedback
from the Tor Project devs in order to one day make it to production

Note that `/updates` often may return an empty list, but that is because at that point 
there may not be updates to give to the user. This is why you should poll this 
endpoint for responses. If we call this endpoint before `/bridge-state`, you 
will always get no results.

Hence you should ALWAYS call `/bridge-state` first and poll `/updates` thereafter.

Also only call `/bridge-state` once, because `/bridge-state` calls also launch
tasks which keep tabs on the bridges that you pass through that API, and calling
it more than once will create more and more tasks. This won't lead to any real
benefit, and `/updates` won't give the right updates to you.

### Design Notes

The current design does leave something to be desired, as the usage disclaimer
section indicates. Here are some alternative design patterns/thoughts for this program
that can be explored in the future:

- Create one endpoint to create a list/override existing list of bridges with a new list,
  and then /bridge-state can be called to get the initial impression of all the bridges.

  Once this is done maybe there is a way to make all future invocations of /bridge-state
  just be what /updates currently does.

- Alternatively, we can at least prevent /updates from being called before /bridge-state or /bridge-state be called more than once

- Decouple /updates from /bridge-state (can we make /updates do the initial set up,
  instead of expecting it to be manually initiated via /bridge-state?), and
  make it possible to get updates for multiple sets of bridges
  (not just the initial set requested via /bridge-state)

For example, it should be possible to POST to /bridge-state more than once
(maybe we want to monitor multiple sets of bridges).
Maybe we can make the /bridge-state endpoint return a UUID that users can then
pass to the /updates endpoint to get updates for a particular bridge set

- Why do we need to deliver deltas? Wouldn't it be easier to have the client
  check the status of the bridges they're interested in (using /bridge-state),
  and let them compute the deltas themselves (or using a separate post-processing tool)?
