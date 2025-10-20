# Sketch and Notes for Relay Tasks

Last Update: Oct 14th, 2025

A relay task is a job that relays do in the background. There are many and they
are listed in this document. This document also has C-tor references to
mainloop callbacks for those. It won't be a 1:1 match with C-tor has arti works
very differently due to its multi threaded nature.

IMPORTANT NOTE: Nothing is final, these are notes from discussions between
dgoulet, opara and gabi. Expect updates or total overhaul. But this is a start
as a foundation to build on.

## Summary

Basic idea is that we want the arti-relay binary to spawn any reactor/tasks and
join its handles. On failure, it can check if transient error or fatal and
attempt a recovery or not. Any of these tasks dying means we have a
malfunctionning relay and we have to stop the relay or possibly take actions.

## Glossary

- Reactor: A background task that has many jobs which may be related to each
  other and has a bidirectionnal communication channel.

- Background task: A standalone task we launch in the background with one and
  one job only which exists on its own. No communication channel.

Finally, still unclear what/who wat this point, but the following tasks will
need access information that is global or update global data. For instance,
bandwidth numbers for the descriptor and the bw testing task. There is likely
more data like this as we go along this journey. We thus assume some of those
tasks might need access to something around the lines of a global state.

The global state is not yet defined at this moment as it is unclear what will
reside inside or even if we'll need one considering the very different arti
design from C-tor.

## Tasks

Bellow are the catalogued tasks from C-tor which will translate to either a
task or rector in arti relay.

1. Circuit Tasks

  C-Tor: circuit_expire_old_circuits_serverside()
    -> Expire non origin circuits that have no streams and been opened for too long.

  This logic should be in the circuit reactor itself. With a timer, it should
  wake up and regurlarly check if it has existed for a long time without
  streams. If so, auto shutdown.

  Hence, no background task needed here, logic is pushed into the circuit
  reactor. But, as opara pointed out, it likely means we'll need to pass to the
  circuit reactor some data such has "is inbound channel a client or relay".

2. Directory Documents Tasks

  - C-Tor: check_descriptor_callback()
    -> Considers to rebuild and upload desrciptor. Looks at IP changes, BW
       changes, valid_until time, rebuilds the descriptor and flag for an upload.
  - C-Tor: launch_descriptor_fetches_callback()
    -> Checks and download if needed new directory data.
  - C-tor: clean_caches_callback()
    -> microdesc_cache_rebuild(): Regenerate the microdesc cache file basically
       removing dead descriptors.

  There are many tasks related to directory and they are critical to a well
  functionning relay so we propose to use a "Reactor" concept as it would need a
  communication channel to receive commands. For example, a command to rebuild a
  new descriptor coming from other subsystems such as key rotation task.

  Note that any subsystems needing to access directory data would NOT ask this
  task but will rather likely use something like this: Arc<RwLock<DirDataView>>
  object instead (name TBD). 

  IMPORTANT: This task is heavily related to the dirauth/dircache
  implementation team (Diziet and cve) so a sync with them is needed to nail
  this one down.

  As gabi pointed out, there is a chance also, depending on the directory team
  that we could split this reactor into two (fetch vs publish). Uncertain.

3. Key and Cert Tasks

  - C-Tor: rotate_onion_key_callback()
    -> Rotate onion keys every period defined by "onion-key-rotation-days"
       consensus parameters.
  - C-Tor: check_ed_keys_callback()
    -> Rotate Ed link cert keys.
  - C-Tor: check_onion_keys_expiry_time_callback()
    -> Check if our old onion keys are still valid after the period of time defined
       by the consensus parameter "onion-key-grace-period-days", otherwise expire them.
  - C-Tor: rotate_x509_certificate_callback()
    -> Does that check_ed_keys_callback() does an also reinit the TLS context
       of the relay which rebuild all X509 cert.

  Considering the extent of key access these task needs, a "Reactor" would
  probably be better especially with the overlapping of some task.

  This way, we can pass a "guard" wrapper around the KeyMgr to this reactor
  which would enforce the reactor to only be able to access relay related keys
  in order to update them.

  We also need to synchronize all these tasks in order to have a single rebuild
  descriptor request made to the directory reactor (2) so to avoid all
  independant tasks to trigger such rebuild. Rebuld and upload are expensive.
  We might require a rate limit approach like onion service publisher has. Or a
  grace period before uploading. Uncertain.

  This task also will need to deal with offline identity key and thus if unable
  to rotate certificate (missing siging key), it needs to remove them from the
  KeyMgr so the rest of arti doesn't use them.

  Considering the offline key case, it could (?) benefit also a bidirectionnal
  communication channel to be told that it is available or any mechanism to
  access it: https://gitlab.torproject.org/tpo/core/arti/-/issues/1927 

4. Rechability Task

  - C-Tor: check_for_reachability_bw_callback()
    -> Launch reachability tests.
  - C-Tor: reachability_warnings_callback()
    -> Emit warnings (log, RPC) on reachability failure.

  This should be a "background task" on its own as it really lives by itself.
  It simply regurlarly checks if the relay is reachable (timer base). The
  likely design we discussed is that this task will control if the directory
  reactor (2) can or not publish.

  It is likely that this task will use a TorClient.

5. Bandwidth Testing Task

  - C-Tor: router_perform_bandwidth_test()
    -> Sends a bunch of DROP down circuits to figure out the relay bandwidth.

  This could be a "background task" on its own. It requires at least 4 "testing
  circuit" to be opened by the task and we would then send DROP cells on those.
  I think it can just take a Arc<ChanMgr> and handle those test. It would then
  update a global state to update our bandwidth.

6. Channels Task

  - C-Tor: check_canonical_channels_callback()
    -> Checks for duplicate channels and only log warns about it. We might want
       to actually close those as a relay, to validate.

  The ChanMgr has "launch_background_task()" already for a client so this could
  just be another task there under the "relay" feature.

  As it needs to iterate over all channels to find duplicates, we have to do it
  from the ChanMgr itself, can't be pushed into the channel reactor.

  This task in C-tor is only logging but it could be that in arti we actually
  want to close channels instead. To be discussed.

7. Statistics and Data History Task

  - C-Tor: reset_padding_counts_callback()
    -> Reset padding counts within the global history data structures. This is
       reported in extra-info/metrics port.
  - C-Tor: clean_caches_callback()
    -> rep_history_clean() => Remove old information from global history.

  A relay has a lot of counters that are reported in the extra-info, metrics
  port or simply used for internal subsystem such as the anti-DoS defenses.

  This could be a "background task" as it is self contained and only needs
  exclusive access to a global data structure containing these counters. We
  could all make them atomic so access would be without contention.

  gabi pointed out that we could maybe just do the cleanup opportunistically as
  this data is only used by extra-info, MetricsPort and maybe RPC subsystem. It
  will depend on the complexity and weight of these data structures.

8. Heartbeat Task

  - C-Tor: heartbeat_callback()
    -> At a specific period, logs global information of the relay.

  This could be a "background task" but requires read access to a lot of history.

  This goes back to the famous possible "global state" mentionned at the
  beginning. As we start designing our stats and history (7), we'll know more
  on how to proceed with this task so at the moment, this is low priority.
  Still many open questions.

9. DNS Task (Exit only)

  - C-Tor: retry_dns_callback()
    -> DNS retry callback in case we are unable to configure the DNS
       nameservers. This can happen if resolv.conf can't be opened or if any DNS
       client rust crate we use results in an error.
  - C-Tor: check_dns_honesty_callback()
    -> Check if DNS is honest. Never at start.

  We'll leave this on ice for now because this could be folded into an entire
  "DNS Reactor" that each circuit reactor would be able to ask to resolve a
  domain.

  That reactor could handle caching as well and thus fold in the above C-Tor
  task.

  C-tor require to handle delicately DNS cache or even responses to clients to
  avoid attacks. As an example, C-tor requires to clip the TTL of replies and
  thus we likely need a full DNS component rather than a simple getaddrinfo().

10. Enforce protocol recommendations

  The relay should monitor the recommended and required protocols as specified
  in the consensus, and either log or exit if the relay does not adhere to the
  recommended/required protocols.

  Arti clients already perform this check using
  `arti_client::protostatus::enforce_protocol_recommendations`. We should make
  this available to arti-relay and run it as a background task.
