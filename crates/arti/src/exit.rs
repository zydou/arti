//! Detect a "ctrl-c" notification or other reason to exit.

use crate::Result;

/// Wait until a control-c notification is received, using an appropriate
/// runtime mechanism.
///
/// This function can have pretty kludgy side-effects: see
/// documentation for `tokio::signal::ctrl_c` and `async_ctrlc` for
/// caveats.  Notably, you can only call this once with async_std.
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
pub(crate) async fn wait_for_ctrl_c() -> Result<()> {
    #[cfg(feature = "tokio")]
    {
        tokio_crate::signal::ctrl_c().await?;

        // Avoid an unused crate warning when building with --all-features.
        // (The dependency is already conditional on async-std, but Cargo.toml
        // can't express the not(tokio).)
        #[cfg(feature = "async-std")]
        use async_ctrlc as _;
    }
    #[cfg(all(feature = "async-std", not(feature = "tokio")))]
    {
        async_ctrlc::CtrlC::new().unwrap().await;
    }
    Ok(())
}
