use std::{fs, path::PathBuf};

use anyhow::Result;
use base32::{Alphabet, encode};
use clap::Parser;
use safelog::DisplayRedacted;
use tor_basic_utils::test_rng::testing_rng;
use tor_hsservice::HsId;
use tor_llcrypto::util::rng::RngCompat;
use x25519_dalek::{PublicKey, StaticSecret};

/// Generates a KP_hsc_desc_enc / KS_hsc_desc_enc keypair.
///
/// Outputs the keys to:
/// ```
/// .auth file content: descriptor:x25519:<PRIVATE_KEY>
/// .auth_private file content: <ADDRESS>:descriptor:x25519:<PUBLIC_KEY>
/// ```
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[clap(group(
    clap::ArgGroup::new("key_paths")
        .args(["priv_path", "pub_path"])
        .multiple(true)
        .required(true)
))]
struct Args {
    /// The address of the hidden service.
    #[arg(long)]
    hsid: HsId,

    /// The path where the private_key key will be saved.
    #[arg(long)]
    priv_path: Option<PathBuf>,

    /// The path where the public key will be saved.
    #[arg(long)]
    pub_path: Option<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let private_key = StaticSecret::random_from_rng(RngCompat::new(testing_rng()));
    let public_key = PublicKey::from(&private_key).to_bytes();
    let private_key = private_key.to_bytes();

    if let Some(pub_path) = args.pub_path {
        let public_b32 = encode(Alphabet::Rfc4648 { padding: false }, &public_key);
        let auth_line = format!("descriptor:x25519:{}\n", public_b32);
        fs::write(pub_path, auth_line)?
    }

    if let Some(priv_path) = args.priv_path {
        let private_b32 = encode(Alphabet::Rfc4648 { padding: false }, &private_key);
        let addr = format!("{}", args.hsid.display_unredacted());
        // NOTE: because `Args::addr` is of type `HsId` `strip_suffix(".onion")` should never fail.
        let addr = addr
            .strip_suffix(".onion")
            .ok_or(anyhow::anyhow!("This should not happen."))?;
        let auth_private_line = format!("{}:descriptor:x25519:{}\n", addr, private_b32);
        fs::write(priv_path, auth_private_line)?
    }

    Ok(())
}
