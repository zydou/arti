# safelog

Mark data as sensitive for logging purposes.

Some information is too sensitive to routinely write to system logs, but
must nonetheless sometimes be displayed.  This crate provides a way to mark
such information, and log it conditionally, but not by default.

### Examples

There are two main ways to mark a piece of data as sensitive: by storing it
within a [`Sensitive`] object long-term, or by wrapping it in a
[`Sensitive`] object right before passing it to a formatter:

```rust
use safelog::{Sensitive, sensitive};

// With this declaration, a student's name and gpa will be suppressed by default
// when passing the student to Debug.
#[derive(Debug)]
struct Student {
   name: Sensitive<String>,
   grade: u8,
   homeroom: String,
   gpa: Sensitive<f32>,
}

// In this function, a user's IP will not be printed by default.
fn record_login(username: &str, ip: &std::net::IpAddr) {
    println!("Login from {} at {}", username, sensitive(ip));
}
```

You can disable safe-logging globally (across all threads) or locally
(across a single thread).

```rust
# let debug_mode = true;
# let log_encrypted_data = |_|();
# let big_secret = ();
use safelog::{disable_safe_logging, with_safe_logging_suppressed};

// If we're running in debug mode, turn off safe logging
// globally.  Safe logging will remain disabled until the
// guard object is dropped.
let guard = if debug_mode {
   // This call can fail if safe logging has already been enforced.
   disable_safe_logging().ok()
} else {
   None
};

// If we know that it's safe to record sensitive data with a given API,
// we can disable safe logging temporarily. This affects only the current thread.
with_safe_logging_suppressed(|| log_encrypted_data(big_secret));
```

### An example deployment

This crate was originally created for use in the `arti` project, which tries
to implements the Tor anonymity protocol in Rust.  In `arti`, we want to
avoid logging information by default if it could compromise users'
anonymity, or create an incentive for attacking users and relays in order to
access their logs.

In general, Arti treats the following information as [`Sensitive`]:
  * Client addresses.
  * The destinations (target addresses) of client requests.

Arti does _not_ label all private information as `Sensitive`: when
information isn't _ever_ suitable for logging, we omit it entirely.

License: MIT OR Apache-2.0
