//! This module defines the key types that can be written to a [`Keystore`](crate::Keystore).

// @Diziet's notes regarding why we shouldn't be storing public keys in the key store:
//
// "Let me talk through, a bit, why we have public keys here.
//
// ISTM that primarily, a keystore is a store of secrets (ie, things we use to demonstrate to other
// people).  Ie it corresponds to our identities.  It's not a registry of public data (including
// instructions about who to trust for what).
//
// But we do need to store some ancillary data with some of our identities.  Where this data is
// small or convenient, we can put it into the keystore.  And when we do that we can use the same
// storage format as we use for private keys?  (That's not actually true: openssh private keys and
// openssh public keys are different formats.)
//
// Which public keys are you anticipating storing here?
//
// I would like to rule out, at this stage, using the Arti keystore to store the public keys of
// clients for our HS.  That is, the HS client authentication keys for a particular HS should be
// stored, for that HS, outside the keystore.  (IIRC C Tor does keep the client auth public keys
// for an HS in its keystore, so we need to be compatible with that, but that doesn't necessary
// have to be done in Arti via the keystore API.  Perhaps the "C Tor keystore" object could
// implement both the keystore trait and an "HS client public keys" trait.)
//
// I should explain why I have this opinion:
// Basically, (private) keystores are awkward.  They have to handle private key material, deal with
// privsep (possibly including offline hosts); they have to be transparent and manipulable, but
// also secure.  They might need to be implemented by or associated with HSMs.  All of these things
// make the keystore's APIs (both the caller API and the visible filesystem interface) compromises
// with nontrivial downsides.
//
// Whereas data about who we should trust is totally different.  It can live in normal
// configuration land; it doesn't need to be associated with HSMs.  It doesn't want or need (the
// possibility of) privsep.  And the user might want to override/supplement it in totally different
// ways.  For example, it should be possible for an HS server to look up client authentication keys
// in a database.  But we don't need or want to write a generic "look up stuff in a database" API;
// that can be (at least for now) a bespoke API just for HS client auth."

use thiserror::Error;

pub(crate) mod ssh;

/// A type of key stored in the key store.
//
// TODO HSS: rewrite this enum as
// ```
// pub enum KeyType {
//     Private(Alogrithm),
//     Public(Algorithm),
// }
// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KeyType {
    /// An Ed25519 keypair.
    Ed25519Keypair,
    /// An expanded Ed25519 keypair.
    Ed25519ExpandedKeypair,
    /// A Curve25519 keypair.
    X25519StaticKeypair,
    /// An Ed25519 public key.
    Ed25519PublicKey,
    /// A Curve25519 public key.
    X25519PublicKey,
    /// An unrecognized key type.
    Unknown {
        /// The extension used for keys of this type in an Arti keystore.
        arti_extension: String,
    },
}

impl KeyType {
    /// The file extension for a key of this type.
    //
    // TODO HSS: this is subject to change (i.e. we might also need a `KeySpecifier` argument here
    // to decide the file extension should be).
    pub fn arti_extension(&self) -> String {
        use KeyType::*;

        // TODO HSS:
        //
        // There used to be an explicit _private suffix in the extension, but I ended up dropping it
        // from the name because the "privateness" of the key is encoded in the ArtiPath: !1586
        // (comment 2942278).
        //
        // However, I suppose KS_hsc_desc_enc.x25519 is less obviously a private key than
        // KS_hsc_desc_enc.x25519_private. Perhaps we do want some redundancy in the name after
        // all..
        match self {
            Ed25519Keypair => "ed25519_private".into(),
            Ed25519PublicKey => "ed25519_public".into(),
            X25519StaticKeypair => "x25519_private".into(),
            X25519PublicKey => "x25519_public".into(),
            Ed25519ExpandedKeypair => "ed25519_expanded_private".into(),
            Unknown { arti_extension } => arti_extension.clone(),
        }
    }

    /// The file extension for a key of this type, for use in a C Tor key store.
    //
    // TODO HSS: this is subject to change (i.e. we might also need a `KeySpecifier` argument here
    // to decide the file extension should be).
    pub fn ctor_extension(&self) -> &'static str {
        todo!() // TODO HSS
    }
}

// TODO HSS: rewrite this (and the display impl) using strum.
impl From<&str> for KeyType {
    fn from(key_type: &str) -> Self {
        use KeyType::*;

        match key_type {
            "ed25519_private" => Ed25519Keypair,
            "ed25519_public" => Ed25519PublicKey,
            "x25519_private" => X25519StaticKeypair,
            "x25519_public" => X25519PublicKey,
            "ed25519_expanded_private" => Ed25519ExpandedKeypair,
            _ => Unknown {
                arti_extension: key_type.into(),
            },
        }
    }
}

/// An error that happens when we encounter an unknown key type.
#[derive(Error, PartialEq, Eq, Debug, Clone)]
#[error("unknown key type: arti_extension={arti_extension}")]
pub struct UnknownKeyTypeError {
    /// The extension used for keys of this type in an Arti keystore.
    arti_extension: String,
}

#[cfg(test)]
mod tests {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;

    #[test]
    fn unknown_key_types() {
        const UNKNOWN_KEY_TYPE: &str = "rsa";

        let unknown_key_ty = KeyType::from(UNKNOWN_KEY_TYPE);
        assert_eq!(
            unknown_key_ty,
            KeyType::Unknown {
                arti_extension: UNKNOWN_KEY_TYPE.into()
            }
        );
        assert_eq!(unknown_key_ty.arti_extension(), UNKNOWN_KEY_TYPE);
    }
}
