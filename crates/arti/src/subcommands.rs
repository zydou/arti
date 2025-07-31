//! Arti CLI subcommands.

#[cfg(feature = "onion-service-service")]
pub(crate) mod hss;

#[cfg(feature = "hsc")]
pub(crate) mod hsc;

#[cfg(feature = "onion-service-cli-extra")]
pub(crate) mod keys;

#[cfg(feature = "onion-service-cli-extra")]
pub(crate) mod raw;

pub(crate) mod proxy;

use crate::Result;

use anyhow::anyhow;

use std::io::{self, Write};

/// Prompt the user to confirm by typing yes or no.
///
/// Loops until the user confirms or declines,
/// returning true if they confirmed.
///
/// Returns an error if an IO error occurs.
fn prompt(msg: &str) -> Result<bool> {
    /// The accept message.
    const YES: &str = "yes";
    /// The decline message.
    const NO: &str = "no";

    let mut proceed = String::new();

    print!("{} (type {YES} or {NO}): ", msg);
    io::stdout().flush().map_err(|e| anyhow!(e))?;
    loop {
        io::stdin()
            .read_line(&mut proceed)
            .map_err(|e| anyhow!(e))?;

        if proceed.trim_end() == YES {
            return Ok(true);
        }

        match proceed.trim_end().to_lowercase().as_str() {
            NO | "n" => return Ok(false),
            _ => {
                proceed.clear();
                continue;
            }
        }
    }
}
