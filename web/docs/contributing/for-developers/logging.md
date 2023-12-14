---
title: Logging 
---

# Safelogging

The `safelog` crate gives us a few ways to mark data as "sensitive", and therefore not to be exposed in the logs by default. This "safelogging" is a defense-in-depth mechanism against log disclosure that is intended to help if a log file is stolen, or if a user posts part of a log file in public without considering its contents.

There are certain conditions and rules that must be considered when highlighting logs as sensitive.

### Which logs does this apply to?

The `tracing` crate provides the levels `trace`, `debug`, `info`, `warn`, and `error`. We anticipate that `trace` and `debug` are only helpful for development and diagnostics, and that the majority of users will only be concerned with messages at level `info` or higher.

Therefore, most of these rules apply to log messages generated at level `info` or higher. We expect that `debug` or `trace` logs may be more dangerous to share.

### Reasons not to log things

When we treat information as sensitive, we typically do so because it falls into one of the following categories:

- **Somebody else's secrets.** This is information that could harm somebody else's security on the Tor network. Mostly, it applies to relays.
- **User activity.** This is information about what a particular Tor user was doing at a given time.
- **User identifiers.** This is information that could potentially help identify a given user, whether or not it is typically considered PII.
- **Traffic-analysis helpers.** This is information which could be useful to an attacker attempting to perform traffic analysis. (Note that this category is extremely broad: even the time when Arti was running can potentially help with traffic analysis. We try to limit ourselves to issues which help particularly with traffic analysis.)

### Information never to log

You should **never** log any of these kinds of data, at any level:

- Private keys of any kind.
- Symmetric encryption keys of any kind.
- Application data being being sent or received over a stream.

(These are all user activity, or have the potential to expose it.)

### Information that is always sensitive

This information should be treated as sensitive at level `info` or higher, and may be treated as sensitive at lower levels:

- The target address of any application stream. (User activity)
- The target port of any application stream. (User activity)
- Any path over the network. (Traffic-analysis helper)
- A full list of guard nodes. (Traffic-analysis helper)
- A full bridge address or identity. (Somebody else's secret)
- Any onion address. (User activity)
- Any user's IP address or hostname. (User identity)

### Information that *can* be sensitive.

This information is often sensitive, and should only be logged at `info` or higher when necessary to make a diagnostic message usable.

- Any single relay. (Traffic-analysis helper)
- The local username. (User identity)
- Configuration settings that affect network-visible behavior. (Traffic-analysis helper)
- Any path on the file system. (User identity)  ❇
- Specific versions of software and dependencies that the user is running. (User identity, traffic-analysis helper)  ❇

Items marked above may be also be logged *at startup*, or *at the head of a rotated log* file, to assist with diagnosis.

### Logs to avoid

You should not trigger a message at "info" or higher based on any of the following events:

- An application request being made.
- An application request succeeding.
- An application request failing because of a normal error condition.

(Rationale: All of these are potentially fine-grained traffic-analysis helpers.)
