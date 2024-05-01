mod args;

use args::{Args, KeyType};

use std::fs;

use clap::Parser;
use rand_core::OsRng;

use tor_keymgr::ssh_key::private::OpaqueKeypair;
use tor_keymgr::ssh_key::public::OpaquePublicKey;
use tor_keymgr::ssh_key::{self, Algorithm, AlgorithmName, PrivateKey, PublicKey};
use tor_llcrypto::pk::{curve25519, ed25519};

/// Generate an ed25519-expanded ssh key.
fn generate_expanded_ed25519(args: &Args) -> (PrivateKey, PublicKey) {
    let algo = args
        .algorithm
        .clone()
        .unwrap_or("ed25519-expanded@spec.torproject.org".into());
    let algorithm_name = AlgorithmName::new(algo).unwrap();

    let ed25519_kp = ed25519::Keypair::generate(&mut OsRng);
    let expanded_kp: ed25519::ExpandedKeypair = (&ed25519_kp).into();
    let ssh_public = OpaquePublicKey::new(
        expanded_kp.public().to_bytes().to_vec(),
        Algorithm::Other(algorithm_name),
    );
    let keypair = OpaqueKeypair::new(
        expanded_kp.to_secret_key_bytes().to_vec(),
        ssh_public.clone(),
    );

    let comment = args.comment.clone().unwrap_or("test-key".into());
    let openssh_key = ssh_key::public::PublicKey::new(
        ssh_key::public::KeyData::Other(ssh_public),
        comment.clone(),
    );
    let openssh_private =
        ssh_key::private::PrivateKey::new(ssh_key::private::KeypairData::Other(keypair), comment)
            .unwrap();

    (openssh_private, openssh_key)
}

/// Generate an x25519 ssh key.
fn generate_x25519(args: &Args) -> (PrivateKey, PublicKey) {
    let x25519_sk = curve25519::StaticSecret::random_from_rng(OsRng);
    let x25519_pk = curve25519::PublicKey::from(&x25519_sk);

    let algo = args
        .algorithm
        .clone()
        .unwrap_or("x25519@spec.torproject.org".into());
    let algorithm_name = AlgorithmName::new(algo).unwrap();

    let ssh_public = OpaquePublicKey::new(
        x25519_pk.to_bytes().to_vec(),
        Algorithm::Other(algorithm_name),
    );
    let keypair = OpaqueKeypair::new(x25519_sk.to_bytes().to_vec(), ssh_public.clone());

    let comment = args.comment.clone().unwrap_or("test-key".into());
    let openssh_key = ssh_key::public::PublicKey::new(
        ssh_key::public::KeyData::Other(ssh_public),
        comment.clone(),
    );

    let ssh_keypair_data = ssh_key::private::KeypairData::Other(keypair);
    let openssh_private = ssh_key::private::PrivateKey::new(ssh_keypair_data, comment).unwrap();

    (openssh_private, openssh_key)
}

fn main() {
    let args = Args::parse();

    // Figure out if we're generating a public key, a private key, or both.
    let (gen_pub, gen_priv) = match (args.public, args.private) {
        (false, false) => {
            // If neither --public nor --private is specified, generate both.
            (true, true)
        }
        (gen_pub, gen_priv) => (gen_pub, gen_priv),
    };

    let (openssh_private, openssh_public) = match &args.key_type {
        KeyType::ExpandedEd25519 => generate_expanded_ed25519(&args),
        KeyType::X25519 => generate_x25519(&args),
    };

    let public = openssh_public.to_openssh().unwrap();
    let private = openssh_private
        .to_openssh(ssh_key::LineEnding::LF)
        .unwrap()
        .to_string();

    let pub_file = format!("{}.public", args.name);
    let priv_file = format!("{}.private", args.name);

    if gen_pub {
        fs::write(&pub_file, public).unwrap();
        println!("created {pub_file}");
    }

    if gen_priv {
        fs::write(&priv_file, private).unwrap();
        println!("created {priv_file}");
    }
}
