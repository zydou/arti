ADDED: `RetryError::push_timed` method for adding errors with explicit timestamps (mockable time support).
ADDED: `RetryError` now tracks timestamps for errors using both `Instant` (monotonic) and optional `SystemTime` (wall-clock).
ADDED: Timestamps are displayed when using alternate format `{:#}`, showing when errors occurred and relative offsets.
ADDED: New inherent method `RetryError::extend` for adding multiple errors (uses `push` internally).
BREAKING: `Extend` trait implementation for `RetryError` (replaced with inherent method to avoid implicit `SystemTime::now` calls).

