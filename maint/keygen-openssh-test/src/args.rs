use clap::{Parser, ValueEnum};

/// Generate an OpenSSH keypair.
///
/// Outputs the keys to `<name>.public` and `<name>.private`.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub(crate) struct Args {
    /// The type of key to generate.
    ///
    /// Options are `ed25519-expanded`, `x25519`.
    #[arg(long)]
    pub(crate) key_type: KeyType,

    /// The algorithm name. Only used if the key type is expanded-ed25519 or x25519.
    ///
    /// If no algorithm is specified, it defaults to:
    ///   * `ed25519-expanded@torproject.org` for ed25519-expanded keys
    ///   * `x25519@torproject.org` for x25519
    #[arg(long)]
    pub(crate) algorithm: Option<String>,

    /// The comment.
    #[arg(long)]
    pub(crate) comment: Option<String>,

    /// The output file name.
    #[arg(long)]
    pub(crate) name: String,

    /// Whether to output a public key file.
    #[arg(long)]
    pub(crate) public: bool,

    /// Whether to output a private key file.
    #[arg(long)]
    pub(crate) private: bool,
}

#[derive(Copy, Clone, Debug, PartialEq, ValueEnum)]
pub(crate) enum KeyType {
    /// An Ed25519 key.
    Ed25519,
    /// A DSA key.
    Dsa,
    /// An expanded Ed25519 key.
    ExpandedEd25519,
    /// An X25519 key.
    X25519,
}
