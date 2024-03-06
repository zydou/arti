# Rate-limited logging for frequent events

Often we want to tell the user about an event
that is undesirable when it happens, 
but which can happen very frequently.
In that case, we don't want to log `"There was a problem!"`
a thousand times per hour.
Instead, we'd like our logs to look more like
`"connecting to the guard X: error (problem occurred 1310/2000 times in the last hour)"`

This crate is part of `arti`,
and is not adapted for use outside of it:
it assumes that your logging system is [`tracing`],
and that you are using [`tor_rtcompat`] for your asynchronous runtime.

## Setup

Before you can use this crate, you need to call [`install_runtime`],
or messages won't be collected.

## Example

```rust
use tor_log_ratelim::log_ratelim;
# use std::num::ParseIntError;
pub fn parse_u8(source: &str, s: &str) -> u8 {
    let r: Result<u8, ParseIntError> = s.parse();
    log_ratelim!(
        // The activity we were performing
        "parsing an integer from {}", source;
        // A Result to decide whether it succeeded 
        r; 
        // An error message to report on failure, with rate limiting,
        // after some time has elapsed.
        // The error itself is always reported.
        Err(_) => WARN, "Had to use default";
        // A success message to report (without rate limiting)
        // on every success.
        Ok(v) => TRACE, "Got {}", v;
    );
    r.unwrap_or(0)
}
```

The above example might produce `WARN` outputs more or less like these:

```text
WARN: Parsing an integer from cache: error (Problem occurred 7/10 times in the last minute): Had to use default: invalid digit found in string"
WARN: Parsing an integer from cache: error (Problem occurred 81/92 times in the last 5 minutes): Had to use default: number too large to fit in target type"
WARN: Parsing an integer from cache: now working (Problem occurred 0/106 times in the last 5 minutes)
```

and `TRACE` outputs like these:
```text
TRACE: Parsing an integer from cache: Got 7
TRACE: Parsing an integer from cache: Got 14
TRACE: Parsing an integer from the network: Got 2
```

For more information on [`log_ratelim!`],
and simpler ways to invoke it, 
see its documentation.
