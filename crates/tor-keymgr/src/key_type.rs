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

use ssh_key::private::KeypairData;
use ssh_key::public::KeyData;
use ssh_key::Algorithm;
use thiserror::Error;
use tor_error::internal;

use crate::ssh::{ED25519_EXPANDED_ALGORITHM_NAME, X25519_ALGORITHM_NAME};
use crate::Result;

/// Declare and implement the `KeyType` enum.
///
/// Each of the `variant`s is mapped to the specified `str_repr`.
///
/// `str_repr` is returned from [`KeyType::arti_extension`].
///
/// The `str_repr` is also used for implementing `From<&str>` for `KeyType`.
/// Note `KeyType` implements `From<&str>` rather than `FromStr`,
/// because the conversion from string is infallible
/// (unrecognized strings are mapped to `KeyType::Unknown`)
macro_rules! declare_key_type {
    {
        $(#[$enum_meta:meta])*
        $vis:vis enum KeyType {
            $(
                $(#[$meta:meta])*
                $variant:ident => $str_repr:expr,
            )*
        }
    } => {

        $(#[$enum_meta])*
        $vis enum KeyType {
            $(
                $(#[$meta])*
                $variant,
            )*

            /// An unrecognized key type.
            Unknown {
                /// The extension used for keys of this type in an Arti keystore.
                arti_extension: String,
            },
        }

        impl KeyType {
            /// The file extension for a key of this type.
            //
            // TODO: this is subject to change (i.e. we might also need a `KeySpecifier` argument here
            // to decide the file extension should be).
            pub fn arti_extension(&self) -> String {
                use KeyType::*;

                match self {
                    $(
                        $variant => $str_repr.into(),
                    )*
                    Unknown { arti_extension } => arti_extension.clone(),
                }
            }

            /// The file extension for a key of this type, for use in a C Tor key store.
            //
            // TODO (#858): this is subject to change (i.e. we might also need a `KeySpecifier` argument here
            // to decide the file extension should be).
            pub fn ctor_extension(&self) -> &'static str {
                todo!() // TODO (#858)
            }
        }

        impl From<&str> for KeyType {
            fn from(key_type: &str) -> Self {
                use KeyType::*;

                match key_type {
                    $(
                        $str_repr => $variant,
                    )*
                    _ => Unknown {
                        arti_extension: key_type.into(),
                    },
                }
            }
        }
    }
}

impl KeyType {
    /// Return the `KeyType` of the specified [`KeyData`].
    ///
    /// Returns an error if the [`KeyData`] is of an unsupported type.
    pub(crate) fn try_from_key_data(key: &KeyData) -> Result<KeyType> {
        match key.algorithm() {
            Algorithm::Ed25519 => Ok(KeyType::Ed25519PublicKey),
            Algorithm::Other(algo) if algo.as_str() == X25519_ALGORITHM_NAME => {
                Ok(KeyType::X25519PublicKey)
            }
            _ => Err(internal!("invalid key data").into()),
        }
    }

    /// Return the `KeyType` of the specified [`KeypairData`].
    ///
    /// Returns an error if the [`KeypairData`] is of an unsupported type.
    pub(crate) fn try_from_keypair_data(key: &KeypairData) -> Result<KeyType> {
        let algo = key.algorithm().map_err(|e| internal!("invalid algr {e}"))?;
        match algo {
            Algorithm::Ed25519 => Ok(KeyType::Ed25519Keypair),
            Algorithm::Other(algo) if algo.as_str() == X25519_ALGORITHM_NAME => {
                Ok(KeyType::X25519StaticKeypair)
            }
            Algorithm::Other(algo) if algo.as_str() == ED25519_EXPANDED_ALGORITHM_NAME => {
                Ok(KeyType::Ed25519ExpandedKeypair)
            }
            _ => Err(internal!("invalid keypair data").into()),
        }
    }
}

declare_key_type! {
    /// A type of key stored in the key store.
    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    #[non_exhaustive]
    pub enum KeyType {
        /// An Ed25519 keypair.
        Ed25519Keypair => "ed25519_private",
        /// An Ed25519 public key.
        Ed25519PublicKey => "ed25519_public",
        /// A Curve25519 keypair.
        X25519StaticKeypair => "x25519_private",
        /// A Curve25519 public key.
        X25519PublicKey => "x25519_public",
        /// An expanded Ed25519 keypair.
        Ed25519ExpandedKeypair => "ed25519_expanded_private",
    }
}

/// An error that happens when we encounter an unknown key type.
#[derive(Error, PartialEq, Eq, Debug, Clone)]
#[error("unknown key type: arti_extension={arti_extension}")]
pub struct UnknownKeyTypeError {
    /// The extension used for keys of this type in an Arti keystore.
    pub(crate) arti_extension: String,
}

#[cfg(test)]
mod tests {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
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
