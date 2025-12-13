use retry_error::RetryError;
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime};

fn main() {
    println!("=== Demo: RetryError with Realistic Time Delays ===\n");

    // Simulate multiple retry attempts with delays between them
    let mut err: RetryError<anyhow::Error> = RetryError::in_attempt_to("connect to database");
    let start_time = Instant::now();
    let start_wall = SystemTime::now();

    // First attempt - immediate failure
    err.push_timed(
        anyhow::anyhow!("connection timeout"),
        start_time,
        Some(start_wall),
    );
    println!("Attempt 1 failed immediately");

    // Second attempt - after 2 seconds
    sleep(Duration::from_secs(2));
    err.push_timed(anyhow::anyhow!("host unreachable"), Instant::now(), None);
    println!("Attempt 2 failed after 2s");

    // Third attempt - after another 3 seconds
    sleep(Duration::from_secs(3));
    err.push_timed(anyhow::anyhow!("network error"), Instant::now(), None);
    println!("Attempt 3 failed after 5s total");

    // Fourth attempt - after another 1 second
    sleep(Duration::from_secs(1));
    err.push_timed(
        anyhow::anyhow!("authentication failed"),
        Instant::now(),
        None,
    );
    println!("Attempt 4 failed after 6s total\n");

    println!("{}", "=".repeat(70));
    println!("\n📋 WITHOUT timestamps (normal format - backward compatible):");
    println!("{}", "=".repeat(70));
    println!("{}", err);

    println!("\n{}", "=".repeat(70));
    println!("\n⏰ WITH timestamps (alternate format {{:#}}):");
    println!("{}", "=".repeat(70));
    println!("{:#}", err);

    println!("\n{}", "=".repeat(70));
    println!("\n📝 What you can see in the timestamped output:");
    println!("   • First error timestamp: When the problem started");
    println!("   • Relative offsets: +2s, +5s, +6s (time from first error)");
    println!("   • Time ago: How long since the last error occurred");
    println!("   • This helps debug timing-sensitive issues!");
}
