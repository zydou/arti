# What is "sensitive" in Arti?

The [`safelog`] crate gives us a few ways to mark data as "sensitive",
and therefore not to be exposed in the logs by default.  This "safe
logging" is a defense-in-depth mechanism against log disclosure: it is
intended to help if a log file is stolen, or if a user posts part of a
logfile in public without considering its contents.

Here we discuss several our rules for what must be marked as sensitive,
when.

## Which logs does this apply to?

The `tracing` crate provides the levels "trace", "debug", "info",
"warn", and "error".   We expect that most users will only care about
messages at level "info" or higher, and that "trace" and "debug" are
only useful for development and diagnostic purposes.

Therefore, most of these rules apply to log messages generated at level
"info" or higher: we expect that "debug" or "trace" logs may be more
dangerous to share.

> TO DO: Add a warning when logging at severity "debug" or lower? (See #552)



## Reasons not to log things

When we treat information as sensitive, we typically do so because it
falls into one of the following categories:

  * **Somebody else's secrets.** This is information that could harm
    somebody else's security on the Tor network. Mostly, it applies to
    relays.
  * **User activity.** This is information about what a particular Tor
    user was doing at a given time.
  * **User identifiers.** This is information that could potentially
    help identify a given user, whether or not it is typically
    considered PII.
  * **Traffic-analysis helpers.** This is information which could be
    useful to an attacker attempting to perform traffic analysis.  (Note
    that this category is extremely broad: even the time when Arti was
    running can potentially help with traffic analysis. We try to limit
    ourselves to issues which help particularly with traffic analysis.)


## Information never to log

We should **never** log any of these kinds of data, at any level:

  * Private keys of any kind.
  * Symmetric encryption keys of any kind.
  * Application data being being sent or received over a stream.

(These are all user activity, or have the potential to expose it.)


## Information that is always sensitive

This information should be treated as sensitive at level "info" or
higher, and may be treated as sensitive at lower levels:

  * The target address of any application stream. (User activity.)
  * The target port of any application stream. (User activity.)
  * Any path over the network. (Traffic-analysis helper.)
  * A full list of guard nodes. (Traffic-analysis helper.)
  * A full bridge address or identity. (Somebody else's secret.)
  * Any onion address. (User activity.)
  * Any user's IP address or hostname. (User identity.)

## Information that _can_ be sensitive.

This information is often sensitive, and should only be logged at
"info" or higher when necessary to make a diagnostic message usable.

  * Any single relay. (Traffic-analysis helper.)
  * The local username. (User identity.)
  * Configuration settings that affect network-visible
    behavior. (Traffic-analysis helper.)
  * Any path on the file system. (User identity.) ❇
  * Specific versions of software and dependencies that the user is
    running. (User identity, traffic-analysis helper.) ❇

Items marked above may be also be logged _at startup_, or _at the head
of a rotated log_ file, to assist with diagnosis.



## Logs to avoid

We should not trigger a message at "info" or higher based on any of the
following events:

  * An application request being made.
  * An application request succeeding.
  * An application request failing because of a normal error condition.

(Rationale: All of these are potentially fine-grained traffic-analysis
helpers.)



## Other ways to mitigate logging

> TO DO: We should recommend that people only use logging mechanisms where
> old logs are discarded after a not-too-long interval.  (See #550)

> TO DO: When possible, we should discourage logging information with
> fine-grained time granularity.  (A 1-to-10 second precision is fine for
> most use cases!)  (See #551)
