BREAKING: `RetryError::push_timed` now takes an additional `wall_clock: Option<SystemTime>` parameter for mockable timestamps.
ADDED: `RetryError` now tracks timestamps for errors using both `Instant` (monotonic) and optional `SystemTime` (wall-clock).
ADDED: Timestamps are displayed when using alternate format `{:#}`, showing when errors occurred and relative offsets.
ADDED: New inherent method `RetryError::extend` for adding multiple errors (uses `push` internally).
REMOVED: `Extend` trait implementation for `RetryError` (replaced with inherent method to avoid implicit `SystemTime::now` calls).

