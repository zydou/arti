# Logging conventions in Arti

Here we document conventions for logging in Arti.

These conventions are approximate;
we can violate them when it seems good to do so.

We expect (as of April 2025) that our current code
does not follow these conventions perfectly.

## Severity for log messages

The `tracing` package defines the following log levels,
in decreasing order of severity:

  * `error`
  * `warn`
  * `info`
  * `debug`
  * `trace`

We use them as follows:

  * `error` means that something has gone _very_ wrong.
    - `error` is appropriate for any fatal error that prevents arti from
      running, or from running correctly.
    - `error` is also appropriate for bugs that are expected never to occur,
      or bugs that we don't know how to handle.
      Panics should be logged at `error`.
    - When the user encounters an `error` message,
      we expect them to _fix_ the underlying condition,
      or to _report_ a bug.
      - If the condition should be fixed by the user,
        the message should explain what to do to fix it.
      - If the condition is a bug to report,
        the message should make it clear that it is a bug:
        ideally, by including "bug" or "internal error".

  * `warn` means that something has gone wrong.
    - We expect that the user will always want to know about a `warn`
      message.  It should be human-readable.
    - A warn message should be clear about whether
      the user is expected to take action.
    - If a warn message indicates that a relay or client has misbehaved,
      it should identify _which one_ if possible.
    - It should be normal to run Arti without warnings.

  * `info` is for non-error messages that appear infrequently
     during normal operation.
     - We expect that the user will probably care about `info` messages.
       If the user won't care about it, it shouldn't be `info`.
     - `info` is not appropriate for errors.
     - (C tor calls this level "notice".)

  * `debug` is for messages that appear frequently during normal operation,
     which might be useful for solving problems.
     - `debug` messages should be readable by people familiar with
       Tor and arti.
     - (C tor calls this level "info".)

  * `trace` is for hyper-verbose messages
     that appear very frequently during normal operation,
     and which are probably not interesting for anybody but developers.
     - `trace` is appropriate for any messages so verbose that
       even developers would only want to enable them selectively.
     - (C tor calls this level "debug".)

We expect that typical users will run with `error`, `warn`, and `info`
messages enabled.  Therefore:
  - None of these messages should "spam the logs".
    If they can occur with high frequency,
    they should either be rate-limited,
    or configured to report only the first occurrence of an issue.
  - It should not be a security risk to log at these levels.
    (Also see notes on [SafeLogging](./Safelogging.md).)

## Open questions

- How do we want to handle conditions corresponding to C tor's
  "`LOG_PROTOCOL_WARN`"?
  (This severity is used for cases where somebody else has violated the
  protocols,
  and so we don't want to let them spam our logs.)
  C tor logs these messages at a level equivalent to `debug` by default,
  and at `warn` if configured to do so.

