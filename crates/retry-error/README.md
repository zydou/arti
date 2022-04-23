# retry-error

An error attempt to represent multiple failures.

This crate implements [`RetryError`], a type to use when you
retry something a few times, and all those attempts can fail differently
each time.  Instead of returning only a single error, it records
_all of the errors received_, in case they are different.

This crate is developed as part of
[Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
implement [Tor](https://www.torproject.org/) in Rust.
It's used by higher-level crates that retry
operations.

### Example

```rust
use retry_error::RetryError;

fn some_operation() -> anyhow::Result<bool> {
   unimplemented!(); // example
}

fn example() -> Result<(), RetryError<anyhow::Error>> {
   const N_ATTEMPTS: usize = 10;
   let mut err = RetryError::in_attempt_to("perform an example operation");
   for _ in 0..N_ATTEMPTS {
       match some_operation() {
           Ok(val) => return Ok(()),
           Err(e) => err.push(e),
       }
   }
   // All attempts failed; return all the errors.
   return Err(err);
}
```

License: MIT OR Apache-2.0
